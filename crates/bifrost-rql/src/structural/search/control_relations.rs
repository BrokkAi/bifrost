//! The execution adapter between the query engine and the shared control-flow
//! algorithms (#2443, the first slice of #2102's exposure).
//!
//! One *control relation* says how two program points of one procedure's
//! production control-flow graph relate: `dominates`, `postdominates`,
//! `control_depends_on`, `reachable` (from the procedure entry), `reaches`,
//! and `in_loop`.
//! Every row joins on the same stable wire ids the `program_point` and
//! `control_edge` rows publish, so a policy relates "the point that calls
//! validate" to "the point that calls store" by id equality rather than by
//! comparing ranges.
//!
//! `crate::analyzer::semantic::cfg_algorithms` owns the shared CFG algorithms.
//! This adapter derives requested families, retains compact bitsets/trees,
//! and expands rows lazily while counting visits in [`CfgAlgorithmBudget`].
//!
//! Three properties the rows are built to keep:
//!
//! * Cancellation and deadlines are *absence of evidence*. Rows already
//!   returned are kept. Every relation not fully returned, whether the
//!   derivation never built it or the expansion stopped part way through it,
//!   is named by one Stopped reason per procedure, so an empty or short
//!   `postdominates` set is never readable as "nothing postdominates".
//! * A backward claim states the exit universe it was computed against.
//!   Postdominance and control dependence are computed against one universe
//!   holding both real exits, which every row spells as
//!   `normal_and_exceptional`. A partitioned derivation would add a value, not
//!   change a column.
//! * A live region with no path to either exit makes every postdominance and
//!   control-dependence claim in the procedure a claim about terminating
//!   executions only, so those rows are downgraded to `may` and `partial`
//!   rather than presented as exact.
//!
//! Deliberately not stored: like the flow-state and rewrite-path row families,
//! these rows are derived on demand from one already-materialized artifact and
//! memoised per request. Nothing is added to the semantic IR, so no language
//! adapter version moves and no cached semantic artifact rotates.

use super::DerivationExecutionCause;
use super::results::{
    CodeQueryControlRelation, CodeQueryDiagnostic, CodeQueryDiagnosticCode,
    CodeQueryDiagnosticImpact, CodeQueryResultRef, DetailedCodeQueryKey,
};
use super::semantic::SemanticProcedureValue;
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::semantic::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, CfgAlgorithmWork,
    LoopEntryStructure, Postdominators, dominators, forward_reachability, loop_regions,
    postdominators, visit_control_dependence_pairs,
};
use crate::analyzer::semantic::{ControlEdgeId, ProcedureHandle, ProgramPointId};
use crate::analyzer::{IAnalyzer, Language, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_analysis::analyzer::workspace_authority::{CaptureScopedMemo, memo_attribution};
use brokk_bifrost_core::analyzer::structural::control_relation::{
    ALL_CONTROL_RELATION_KINDS, ControlExitPartition, ControlRelationKind,
};
use brokk_bifrost_core::analyzer::structural::flow_state::FlowCertainty;
use brokk_bifrost_rql::ControlRelationFilter;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

/// One derived control relation between two program points of one procedure.
///
/// Dense procedure-local ids travel here; the wire ids a policy joins on are
/// minted at projection time from the same procedure handle the derivation ran
/// over, so the two row families cannot disagree about a point's identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ControlRelationRow {
    pub(super) relation: ControlRelationKind,
    pub(super) source: ProgramPointId,
    pub(super) target: ProgramPointId,
    /// The branch edge whose outcome governs the target, present exactly for
    /// `control_depends_on`.
    pub(super) controlling_edge: Option<ControlEdgeId>,
    pub(super) certainty: FlowCertainty,
}

/// Why a derivation's rows are less than the whole truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ControlRelationIncompleteReason {
    Capacity {
        relation: ControlRelationKind,
        capacity: ControlRelationCapacity,
    },
    /// Cancellation or the request deadline stopped these unfinished families.
    Stopped {
        cause: ControlRelationStop,
        relations: u8,
        work: CfgAlgorithmWork,
        sources_done: usize,
        rows_produced: Option<usize>,
        /// Unknown until the entry walk finishes identifying the live domain.
        sources_total: Option<usize>,
    },
    /// The procedure has a live region with no path to either real exit, so a
    /// postdominance claim is a claim about terminating executions only.
    NonExitingRegion { points: usize },
    /// A cyclic region no edge enters from outside, so no program point is its
    /// header and its membership rows have no source to hang off.
    LoopWithoutEntry { regions: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ControlRelationStop {
    Cancelled,
    Deadline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ControlRelationCompleteness {
    reasons: Vec<ControlRelationIncompleteReason>,
}

impl ControlRelationCompleteness {
    pub(super) fn reasons(&self) -> &[ControlRelationIncompleteReason] {
        &self.reasons
    }

    /// Whether rows for `relation` can be trusted to be the complete set.
    ///
    /// Total over the reason vocabulary on purpose: a reason added later must
    /// be classified deliberately rather than defaulting into silence.
    pub(super) fn covers(&self, relation: ControlRelationKind) -> bool {
        use ControlRelationIncompleteReason::*;
        !self.reasons().iter().any(|reason| match reason {
            Stopped { relations, .. } => requested(*relations, relation),
            Capacity {
                relation: affected, ..
            } => *affected == relation,
            NonExitingRegion { .. } => relation.depends_on_exit_partition(),
            LoopWithoutEntry { .. } => relation == ControlRelationKind::InLoop,
        })
    }

    fn from_reasons(reasons: Vec<ControlRelationIncompleteReason>) -> Self {
        Self { reasons }
    }
}

/// One family's refused RESIDENT allocation, never a work refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ControlRelationCapacity {
    pub(super) requested_bytes: usize,
    pub(super) available_bytes: usize,
}

#[derive(Debug)]
struct AncestorTree {
    parents: Box<[Option<ProgramPointId>]>,
    first_child: Box<[Option<ProgramPointId>]>,
    next_sibling: Box<[Option<ProgramPointId>]>,
}

impl AncestorTree {
    fn new(parents: Box<[Option<ProgramPointId>]>) -> Self {
        let mut first_child = vec![None; parents.len()].into_boxed_slice();
        let mut next_sibling = vec![None; parents.len()].into_boxed_slice();
        for (child, parent) in parents.iter().enumerate().rev() {
            if let Some(parent) = parent {
                next_sibling[child] = first_child[parent.index()];
                first_child[parent.index()] =
                    Some(ProgramPointId::try_from_index(child).expect("validated point fits u32"));
            }
        }
        Self {
            parents,
            first_child,
            next_sibling,
        }
    }

    fn children(&self, parent: ProgramPointId) -> impl Iterator<Item = ProgramPointId> + '_ {
        debug_assert_eq!(self.parents.len(), self.first_child.len());
        std::iter::successors(self.first_child[parent.index()], |child| {
            self.next_sibling[child.index()]
        })
    }

    fn bytes(points: usize) -> usize {
        points.saturating_mul(3 * std::mem::size_of::<Option<ProgramPointId>>())
    }
}

#[derive(Debug)]
enum CompactControlRelation {
    Reachable {
        entry: ProgramPointId,
    },
    Reaches {
        words: Box<[u64]>,
        words_per_source: usize,
        sources_done: usize,
    },
    Ancestors {
        relation: ControlRelationKind,
        tree: AncestorTree,
        certainty: FlowCertainty,
    },
    Dependence {
        rows: Box<
            [crate::analyzer::semantic::cfg_algorithms::ControlDependenceRow<
                ControlEdgeId,
                ProgramPointId,
            >],
        >,
        certainty: FlowCertainty,
    },
    Loops {
        regions:
            crate::analyzer::semantic::cfg_algorithms::LoopRegions<ProgramPointId, ControlEdgeId>,
        entries: Box<[(ProgramPointId, usize)]>,
    },
}

impl CompactControlRelation {
    fn kind(&self) -> ControlRelationKind {
        match self {
            Self::Reachable { .. } => ControlRelationKind::Reachable,
            Self::Reaches { .. } => ControlRelationKind::Reaches,
            Self::Ancestors { relation, .. } => *relation,
            Self::Dependence { .. } => ControlRelationKind::ControlDependsOn,
            Self::Loops { .. } => ControlRelationKind::InLoop,
        }
    }
}

#[derive(Debug)]
pub(super) struct ControlRelationMetadata {
    pub(super) completeness: ControlRelationCompleteness,
    pub(super) generation: u64,
}

/// Per-expansion coverage is separate from the cached derivation. Rows already
/// emitted must observe a later stop, while a fresh traversal of the same facts
/// starts with its own coverage. This retains no bitsets, trees or workspace.
#[derive(Debug)]
pub(super) struct ControlRelationExpansionMetadata {
    derivation: Arc<ControlRelationMetadata>,
    incomplete_relations: AtomicU8,
}

/// Cached facts stay compact. Emitted values retain only their row and coverage,
/// so closing a cache window can release its bitsets and trees.
#[derive(Debug)]
pub(super) struct ProcedureControlRelations {
    pub(super) metadata: Arc<ControlRelationMetadata>,
    live: Box<[ProgramPointId]>,
    families: Vec<CompactControlRelation>,
    ancestor_workspace: Mutex<Option<Vec<ProgramPointId>>>,
    resident_bytes: usize,
    reaches_allocations: usize,
    dependence_allocations: usize,
}

impl std::ops::Deref for ProcedureControlRelations {
    type Target = ControlRelationMetadata;
    fn deref(&self) -> &Self::Target {
        &self.metadata
    }
}

fn requested_control_relations(filter: &ControlRelationFilter) -> u8 {
    let kinds = if filter.relations.is_empty() {
        ALL_CONTROL_RELATION_KINDS
    } else {
        &filter.relations
    };
    kinds
        .iter()
        .fold(0, |mask, kind| mask | (1 << (*kind as u8)))
}

fn requested(mask: u8, kind: ControlRelationKind) -> bool {
    mask & (1 << (kind as u8)) != 0
}

/// Only requested families are computed. A failed resident admission withholds
/// that family's compact facts, while cancellation stops subsequent WORK.
fn control_relations_for_procedure(
    handle: &ProcedureHandle,
    generation: u64,
    cancellation: &CancellationToken,
    budget: &mut CfgAlgorithmBudget,
    requested_mask: u8,
    mut admit: impl FnMut(usize) -> Result<(), ControlRelationCapacity>,
) -> ProcedureControlRelations {
    let procedure = handle.semantics();
    let entry = procedure.entry_point();
    let points = procedure.points().len();
    let mut families = Vec::new();
    let mut ancestor_workspace = Vec::new();
    let mut live = Box::default();
    let mut reasons = Vec::new();
    let mut finished = 0u8;
    let mut sources_done = 0;
    let mut sources_total = None;
    let mut resident_bytes = 0usize;
    let mut reaches_allocations = 0usize;
    let mut dependence_allocations = 0usize;
    // Postdominance serves both Postdominates and ControlDependsOn (counting and
    // materializing passes): derive it at most once. It is transient, dies with
    // the derivation, and is therefore not charged, like the other work queues.
    let mut postdominance: Option<Postdominators<ProgramPointId>> = None;
    let cpu_started = brokk_bifrost_core::profiling::enabled()
        .then(brokk_bifrost_core::profiling::thread_cpu_time);
    let mut request = CfgAlgorithmRequest::new(budget, cancellation);
    // Reserve exact vector capacities, including metadata, before allocation.
    let base_bytes = std::mem::size_of::<ProcedureControlRelations>()
        + std::mem::size_of::<ControlRelationMetadata>()
        + 4 * std::mem::size_of::<usize>()
        + requested_mask.count_ones() as usize * std::mem::size_of::<CompactControlRelation>()
        + 10 * std::mem::size_of::<ControlRelationIncompleteReason>();
    let base_admission = admit(base_bytes);
    if base_admission.is_ok() {
        resident_bytes += base_bytes;
        families = Vec::with_capacity(requested_mask.count_ones() as usize);
        reasons = Vec::with_capacity(10);
    }
    let mut admit_family = |kind, bytes, reasons: &mut Vec<_>| match admit(bytes) {
        Ok(()) => {
            resident_bytes += bytes;
            true
        }
        Err(capacity) => {
            reasons.push(ControlRelationIncompleteReason::Capacity {
                relation: kind,
                capacity,
            });
            false
        }
    };
    let outcome = (|| -> Result<(), CfgAlgorithmError<ProgramPointId>> {
        if let Err(capacity) = base_admission {
            for kind in ALL_CONTROL_RELATION_KINDS
                .iter()
                .copied()
                .filter(|kind| requested(requested_mask, *kind))
            {
                reasons.push(ControlRelationIncompleteReason::Capacity {
                    relation: kind,
                    capacity,
                });
            }
            finished = requested_mask;
            return Ok(());
        }
        let forward_mask = requested_mask & !(1 << (ControlRelationKind::InLoop as u8));
        let reachable = if forward_mask != 0 {
            control_relation_checkpoint(&request)?;
            Some(forward_reachability(procedure, entry, &mut request)?)
        } else {
            None
        };
        if let Some(reachable) = &reachable {
            let count = reachable
                .membership()
                .iter()
                .filter(|reached| **reached)
                .count();
            sources_total = Some(count);
            let bytes = count * std::mem::size_of::<ProgramPointId>();
            match admit_family(ControlRelationKind::Reachable, bytes, &mut reasons) {
                true => {
                    live = reachable
                        .membership()
                        .iter()
                        .enumerate()
                        .filter(|(_, reached)| **reached)
                        .map(|(index, _)| {
                            ProgramPointId::try_from_index(index).expect("validated point fits u32")
                        })
                        .collect::<Vec<_>>()
                        .into_boxed_slice();
                }
                false => {
                    // One shared live domain serves all requested forward families.
                    let ControlRelationIncompleteReason::Capacity { capacity, .. } = reasons
                        .pop()
                        .expect("failed live-domain admission has a capacity reason")
                    else {
                        unreachable!()
                    };
                    // Control dependence expands only its precomputed pair rows and
                    // never reads the live list, so this refusal does not touch it.
                    let live_dependent =
                        forward_mask & !(1 << (ControlRelationKind::ControlDependsOn as u8));
                    for kind in ALL_CONTROL_RELATION_KINDS
                        .iter()
                        .copied()
                        .filter(|kind| requested(live_dependent, *kind))
                    {
                        reasons.push(ControlRelationIncompleteReason::Capacity {
                            relation: kind,
                            capacity,
                        });
                    }
                    finished |= live_dependent;
                }
            }
        }
        for kind in [
            ControlRelationKind::Reachable,
            ControlRelationKind::Reaches,
            ControlRelationKind::Dominates,
            ControlRelationKind::Postdominates,
            ControlRelationKind::ControlDependsOn,
            ControlRelationKind::InLoop,
        ] {
            if !requested(requested_mask & !finished, kind) {
                continue;
            }
            control_relation_checkpoint(&request)?;
            match kind {
                ControlRelationKind::Reachable => {
                    families.push(CompactControlRelation::Reachable { entry })
                }
                ControlRelationKind::Reaches => {
                    let words_per_source = live.len().div_ceil(64);
                    let word_count = live.len().saturating_mul(words_per_source);
                    let bytes = word_count.saturating_mul(std::mem::size_of::<u64>());
                    if admit_family(kind, bytes, &mut reasons) {
                        let words = vec![0; word_count].into_boxed_slice();
                        reaches_allocations += 1;
                        families.push(CompactControlRelation::Reaches {
                            words,
                            words_per_source,
                            sources_done: 0,
                        });
                        let Some(CompactControlRelation::Reaches {
                            words,
                            sources_done: completed_sources,
                            ..
                        }) = families.last_mut()
                        else {
                            unreachable!()
                        };
                        for (source_index, source) in live.iter().copied().enumerate() {
                            control_relation_checkpoint(&request)?;
                            let walked;
                            let reached = if source == entry {
                                reachable.as_ref().expect("entry walk exists")
                            } else {
                                walked = forward_reachability(procedure, source, &mut request)?;
                                &walked
                            };
                            for (target_index, target) in live.iter().copied().enumerate() {
                                if target != source && reached.contains(procedure, target) {
                                    words[source_index * words_per_source + target_index / 64] |=
                                        1 << (target_index % 64);
                                }
                            }
                            sources_done += 1;
                            *completed_sources = sources_done;
                        }
                    }
                }
                ControlRelationKind::Dominates => {
                    let dominance = dominators(procedure, entry, &mut request)?;
                    let workspace_bytes = if ancestor_workspace.capacity() == 0 {
                        points * std::mem::size_of::<ProgramPointId>()
                    } else {
                        0
                    };
                    if admit_family(
                        kind,
                        AncestorTree::bytes(points) + workspace_bytes,
                        &mut reasons,
                    ) {
                        // Cache-owned workspace is admitted once and borrowed by each
                        // serialized pipeline expansion, then returned on drop.
                        ancestor_workspace.reserve_exact(points);
                        let parents = (0..points)
                            .map(|index| {
                                dominance.immediate_dominator(
                                    procedure,
                                    ProgramPointId::try_from_index(index)
                                        .expect("validated point fits u32"),
                                )
                            })
                            .collect();
                        families.push(CompactControlRelation::Ancestors {
                            relation: kind,
                            tree: AncestorTree::new(parents),
                            certainty: FlowCertainty::Exact,
                        });
                    }
                }
                ControlRelationKind::Postdominates => {
                    if postdominance.is_none() {
                        postdominance = Some(postdominators(
                            procedure,
                            entry,
                            procedure.normal_exit_point(),
                            procedure.exceptional_exit_point(),
                            &mut request,
                        )?);
                    }
                    let dominance = postdominance.as_ref().expect("derived above");
                    let diverging = dominance
                        .non_exiting_regions
                        .iter()
                        .map(|region| region.members.len())
                        .sum::<usize>();
                    if diverging > 0
                        && !reasons.iter().any(|reason| {
                            matches!(
                                reason,
                                ControlRelationIncompleteReason::NonExitingRegion { .. }
                            )
                        })
                    {
                        reasons.push(ControlRelationIncompleteReason::NonExitingRegion {
                            points: diverging,
                        });
                    }
                    let workspace_bytes = if ancestor_workspace.capacity() == 0 {
                        points * std::mem::size_of::<ProgramPointId>()
                    } else {
                        0
                    };
                    if admit_family(
                        kind,
                        AncestorTree::bytes(points) + workspace_bytes,
                        &mut reasons,
                    ) {
                        // Cache-owned workspace is admitted once and borrowed by each
                        // serialized pipeline expansion, then returned on drop.
                        ancestor_workspace.reserve_exact(points);
                        let parents = (0..points)
                            .map(|index| {
                                dominance.immediate_postdominator(
                                    procedure,
                                    ProgramPointId::try_from_index(index)
                                        .expect("validated point fits u32"),
                                )
                            })
                            .collect();
                        families.push(CompactControlRelation::Ancestors {
                            relation: kind,
                            tree: AncestorTree::new(parents),
                            certainty: if diverging > 0 {
                                FlowCertainty::May
                            } else {
                                FlowCertainty::Exact
                            },
                        });
                    }
                }
                ControlRelationKind::ControlDependsOn => {
                    if postdominance.is_none() {
                        postdominance = Some(postdominators(
                            procedure,
                            entry,
                            procedure.normal_exit_point(),
                            procedure.exceptional_exit_point(),
                            &mut request,
                        )?);
                    }
                    let postdom = postdominance.as_ref().expect("derived above");
                    let mut pair_count = 0usize;
                    visit_control_dependence_pairs(procedure, postdom, &mut request, |_| {
                        pair_count += 1
                    })?;
                    let diverging = postdom
                        .non_exiting_regions
                        .iter()
                        .map(|region| region.members.len())
                        .sum::<usize>();
                    if diverging > 0
                        && !reasons.iter().any(|reason| {
                            matches!(
                                reason,
                                ControlRelationIncompleteReason::NonExitingRegion { .. }
                            )
                        })
                    {
                        reasons.push(ControlRelationIncompleteReason::NonExitingRegion {
                            points: diverging,
                        });
                    }
                    let bytes = pair_count.saturating_mul(std::mem::size_of::<
                        crate::analyzer::semantic::cfg_algorithms::ControlDependenceRow<
                            ControlEdgeId,
                            ProgramPointId,
                        >,
                    >());
                    if admit_family(kind, bytes, &mut reasons) {
                        control_relation_checkpoint(&request)?;
                        let mut rows = Vec::with_capacity(pair_count);
                        dependence_allocations += usize::from(pair_count != 0);
                        visit_control_dependence_pairs(procedure, postdom, &mut request, |row| {
                            rows.push(row)
                        })?;
                        assert_eq!(
                            rows.len(),
                            pair_count,
                            "same graph emits the same pairs in both passes"
                        );
                        rows.sort_unstable_by_key(|row| {
                            (
                                procedure
                                    .control_edge(row.controlling_edge)
                                    .expect("validated edge")
                                    .source_point
                                    .index(),
                                row.governed.index(),
                                row.controlling_edge.index(),
                            )
                        });
                        rows.dedup();
                        families.push(CompactControlRelation::Dependence {
                            rows: rows.into_boxed_slice(),
                            certainty: if diverging > 0 {
                                FlowCertainty::May
                            } else {
                                FlowCertainty::Exact
                            },
                        });
                    }
                }
                ControlRelationKind::InLoop => {
                    let mut regions = loop_regions(procedure, &mut request)?;
                    let mut bytes = std::mem::size_of_val(regions.regions.as_ref());
                    let mut entry_count = 0;
                    let mut headerless = 0;
                    for region in regions.regions.iter_mut() {
                        region.members.sort_unstable();
                        bytes += std::mem::size_of_val(region.members.as_ref())
                            + std::mem::size_of_val(region.entries.as_ref())
                            + std::mem::size_of_val(region.back_edges.as_ref());
                        entry_count += region.entries.len();
                        headerless += usize::from(region.entries.is_empty());
                    }
                    if headerless > 0 {
                        reasons.push(ControlRelationIncompleteReason::LoopWithoutEntry {
                            regions: headerless,
                        });
                    }
                    bytes += entry_count * std::mem::size_of::<(ProgramPointId, usize)>();
                    if admit_family(kind, bytes, &mut reasons) {
                        let mut entries = Vec::with_capacity(entry_count);
                        for (index, region) in regions.regions.iter().enumerate() {
                            entries.extend(region.entries.iter().map(|point| (*point, index)));
                        }
                        entries.sort_unstable_by_key(|(point, _)| point.index());
                        families.push(CompactControlRelation::Loops {
                            regions,
                            entries: entries.into_boxed_slice(),
                        });
                    }
                }
            }
            finished |= 1 << (kind as u8);
        }
        Ok(())
    })();
    match outcome {
        Ok(()) => {}
        Err(CfgAlgorithmError::Cancelled { work }) => {
            reasons.push(ControlRelationIncompleteReason::Stopped {
                cause: if cancellation.is_timed_out() {
                    ControlRelationStop::Deadline
                } else {
                    ControlRelationStop::Cancelled
                },
                relations: requested_mask & !finished,
                work,
                sources_done,
                rows_produced: None,
                sources_total,
            })
        }
        Err(CfgAlgorithmError::ExceededBudget(exceeded)) => {
            unreachable!("telemetry cannot refuse work: {exceeded:?}")
        }
        Err(CfgAlgorithmError::InvalidNode(node)) => {
            unreachable!("validated procedure owns {node:?}")
        }
    }
    families.sort_unstable_by_key(|family| family.kind() as u8);
    brokk_bifrost_core::profiling::note_with(|| {
        format!(
            "control_relations cumulative_work={:?} sources_done={sources_done} sources_total={sources_total:?} resident_bytes={resident_bytes} reaches_allocations={reaches_allocations} build_cpu_seconds={:.9}",
            request.budget.used(),
            cpu_started.map_or(0.0, |started| {
                brokk_bifrost_core::profiling::thread_cpu_time()
                    .saturating_sub(started)
                    .as_secs_f64()
            })
        )
    });
    ProcedureControlRelations {
        metadata: Arc::new(ControlRelationMetadata {
            completeness: ControlRelationCompleteness::from_reasons(reasons),
            generation,
        }),
        live,
        families,
        ancestor_workspace: Mutex::new(Some(ancestor_workspace)),
        resident_bytes,
        reaches_allocations,
        dependence_allocations,
    }
}

/// A lazy canonical expansion: relation, source, target, controlling edge.
pub(super) struct ControlRelationRows {
    relations: Arc<ProcedureControlRelations>,
    procedure: SemanticProcedureValue,
    cancellation: CancellationToken,
    expansion: Arc<ControlRelationExpansionMetadata>,
    family: usize,
    source: usize,
    target: usize,
    sparse: usize,
    ancestor_targets: Vec<ProgramPointId>,
    rows_produced: usize,
    expansion_visits: usize,
    cpu: std::time::Duration,
    stopped: bool,
}

#[derive(Debug)]
pub(super) struct ControlRelationExpansionStop {
    pub(super) metadata: Arc<ControlRelationMetadata>,
    pub(super) reason: ControlRelationIncompleteReason,
}

impl ControlRelationRows {
    pub(super) fn new(
        relations: Arc<ProcedureControlRelations>,
        procedure: SemanticProcedureValue,
        cancellation: CancellationToken,
    ) -> Self {
        // The pipeline consumes each expansion before starting another for the
        // same cached product. Fail at construction if that ownership changes.
        let ancestor_targets = relations
            .ancestor_workspace
            .lock()
            .expect("control-relation workspace mutex poisoned")
            .take()
            .expect("one active expansion per cached control-relation product");
        let expansion = Arc::new(ControlRelationExpansionMetadata {
            derivation: Arc::clone(&relations.metadata),
            incomplete_relations: AtomicU8::new(0),
        });
        Self {
            relations,
            procedure,
            cancellation,
            expansion,
            family: 0,
            source: 0,
            target: 0,
            sparse: 0,
            ancestor_targets,
            rows_produced: 0,
            expansion_visits: 0,
            cpu: std::time::Duration::ZERO,
            stopped: false,
        }
    }

    /// The one Stopped reason of this procedure. Its uncovered set is every
    /// family the derivation did not build, united with every family this
    /// expansion did not finish yielding (including a partly yielded one).
    /// The derivation's own Stopped reason is not reported separately (see
    /// `report_completeness`), so a built family whose rows were cut short is
    /// never left looking complete.
    fn stopped(
        &mut self,
    ) -> Option<Result<ControlRelationCandidate, ControlRelationExpansionStop>> {
        if self.stopped {
            return None;
        }
        self.stopped = true;
        let derivation = self
            .relations
            .metadata
            .completeness
            .reasons()
            .iter()
            .find_map(|reason| match reason {
                ControlRelationIncompleteReason::Stopped {
                    cause,
                    relations,
                    work,
                    sources_done,
                    sources_total,
                    ..
                } => Some((*cause, *relations, *work, *sources_done, *sources_total)),
                _ => None,
            });
        let unfinished = self.relations.families[self.family..]
            .iter()
            .fold(0, |mask, family| mask | (1 << family.kind() as u8));
        let mask = unfinished | derivation.map_or(0, |(_, relations, ..)| relations);
        self.expansion
            .incomplete_relations
            .store(mask, Ordering::Release);
        Some(Err(ControlRelationExpansionStop {
            metadata: Arc::clone(&self.relations.metadata),
            reason: ControlRelationIncompleteReason::Stopped {
                cause: match derivation {
                    Some((cause, ..)) => cause,
                    None if self.cancellation.is_timed_out() => ControlRelationStop::Deadline,
                    None => ControlRelationStop::Cancelled,
                },
                relations: mask,
                // A stop inside the derivation reports the derivation's own work
                // and source cursor, plus the expansion visits made since; the
                // derivation's reason is not reported separately.
                work: match derivation {
                    Some((_, _, work, ..)) => CfgAlgorithmWork {
                        node_visits: work.node_visits.saturating_add(self.expansion_visits),
                        ..work
                    },
                    None => CfgAlgorithmWork {
                        node_visits: self.expansion_visits,
                        ..Default::default()
                    },
                },
                sources_done: derivation.map_or(self.source, |(_, _, _, done, _)| done),
                sources_total: match derivation {
                    Some((_, _, _, _, total)) => total,
                    None => match self.relations.families.get(self.family) {
                        Some(CompactControlRelation::Reachable { .. }) => Some(1),
                        Some(CompactControlRelation::Loops { entries, .. }) => Some(entries.len()),
                        Some(_) => Some(self.relations.live.len()),
                        None => None,
                    },
                },
                rows_produced: Some(self.rows_produced),
            },
        }))
    }
}

impl Drop for ControlRelationRows {
    fn drop(&mut self) {
        self.ancestor_targets.clear();
        let mut workspace = self
            .relations
            .ancestor_workspace
            .lock()
            .expect("control-relation workspace mutex poisoned");
        assert!(
            workspace.is_none(),
            "only the active expansion owns its workspace"
        );
        *workspace = Some(std::mem::take(&mut self.ancestor_targets));
        drop(workspace);
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "control_relations expansion_rows={} expansion_visits={} expansion_cpu_seconds={:.9}",
                self.rows_produced,
                self.expansion_visits,
                self.cpu.as_secs_f64()
            )
        });
    }
}

impl Iterator for ControlRelationRows {
    type Item = Result<ControlRelationCandidate, ControlRelationExpansionStop>;
    fn next(&mut self) -> Option<Self::Item> {
        let started = brokk_bifrost_core::profiling::enabled()
            .then(brokk_bifrost_core::profiling::thread_cpu_time);
        let row = self.next_row();
        if let Some(started) = started {
            self.cpu += brokk_bifrost_core::profiling::thread_cpu_time().saturating_sub(started);
        }
        row
    }
}

impl ControlRelationRows {
    fn next_row(
        &mut self,
    ) -> Option<Result<ControlRelationCandidate, ControlRelationExpansionStop>> {
        if self.stopped {
            return None;
        }
        let live = &self.relations.live;
        while let Some(family) = self.relations.families.get(self.family) {
            if self.cancellation.is_cancelled() {
                return self.stopped();
            }
            let row = match family {
                CompactControlRelation::Reachable { entry } => {
                    let mut found = None;
                    while let Some(target) = live.get(self.target).copied() {
                        self.target += 1;
                        self.expansion_visits += 1;
                        if target != *entry {
                            found = Some((*entry, target, None, FlowCertainty::Exact));
                            break;
                        }
                    }
                    found
                }
                CompactControlRelation::Reaches {
                    words,
                    words_per_source,
                    sources_done,
                } => {
                    let mut found = None;
                    while self.source < *sources_done {
                        while self.target < live.len() {
                            let target = self.target;
                            self.target += 1;
                            self.expansion_visits += 1;
                            if words[self.source * words_per_source + target / 64]
                                & (1 << (target % 64))
                                != 0
                            {
                                found = Some((
                                    live[self.source],
                                    live[target],
                                    None,
                                    FlowCertainty::Exact,
                                ));
                                break;
                            }
                        }
                        if found.is_some() {
                            break;
                        }
                        self.source += 1;
                        self.target = 0;
                        if self.cancellation.is_cancelled() {
                            return self.stopped();
                        }
                    }
                    found
                }
                CompactControlRelation::Ancestors {
                    tree, certainty, ..
                } => {
                    let mut found = None;
                    while self.source < live.len() {
                        if self.target == 0 {
                            // Walk only actual tree descendants, then retain canonical target
                            // order. The admitted linear buffer holds point IDs, never rows.
                            self.ancestor_targets.clear();
                            self.ancestor_targets
                                .extend(tree.children(live[self.source]));
                            let mut scan = 0;
                            while scan < self.ancestor_targets.len() {
                                if self.cancellation.is_cancelled() {
                                    return self.stopped();
                                }
                                let target = self.ancestor_targets[scan];
                                self.expansion_visits += 1;
                                self.ancestor_targets.extend(tree.children(target));
                                scan += 1;
                            }
                            self.ancestor_targets
                                .retain(|target| live.binary_search(target).is_ok());
                            self.ancestor_targets.sort_unstable();
                        }
                        if let Some(target) = self.ancestor_targets.get(self.target) {
                            self.target += 1;
                            found = Some((live[self.source], *target, None, *certainty));
                            break;
                        }
                        self.source += 1;
                        self.target = 0;
                        if self.cancellation.is_cancelled() {
                            return self.stopped();
                        }
                    }
                    found
                }
                CompactControlRelation::Dependence { rows, certainty } => {
                    rows.get(self.sparse).map(|row| {
                        self.sparse += 1;
                        self.expansion_visits += 1;
                        let edge = self
                            .procedure
                            .handle
                            .semantics()
                            .control_edge(row.controlling_edge)
                            .expect("validated edge");
                        self.source = live.partition_point(|point| *point < edge.source_point);
                        (
                            edge.source_point,
                            row.governed,
                            Some(row.controlling_edge),
                            *certainty,
                        )
                    })
                }
                CompactControlRelation::Loops { regions, entries } => {
                    let mut found = None;
                    while let Some((source, index)) = entries.get(self.source) {
                        let region = &regions.regions[*index];
                        if let Some(target) = region.members.get(self.target) {
                            self.target += 1;
                            self.expansion_visits += 1;
                            let certainty = match region.entry_structure {
                                LoopEntryStructure::Single => FlowCertainty::Exact,
                                _ => FlowCertainty::May,
                            };
                            found = Some((*source, *target, None, certainty));
                            break;
                        }
                        self.source += 1;
                        self.target = 0;
                    }
                    found
                }
            };
            if let Some((source, target, controlling_edge, certainty)) = row {
                self.rows_produced += 1;
                let row = ControlRelationRow {
                    relation: family.kind(),
                    source,
                    target,
                    controlling_edge,
                    certainty,
                };
                return Some(Ok(ControlRelationCandidate {
                    relations: Arc::clone(&self.expansion),
                    row,
                }));
            }
            self.family += 1;
            self.source = 0;
            self.target = 0;
            self.sparse = 0;
        }
        // Everything built was yielded. A derivation that stopped still owes
        // its one diagnostic for the families it never built.
        if self
            .relations
            .metadata
            .completeness
            .reasons()
            .iter()
            .any(|reason| matches!(reason, ControlRelationIncompleteReason::Stopped { .. }))
        {
            return self.stopped();
        }
        None
    }
}

fn control_relation_checkpoint(
    request: &CfgAlgorithmRequest<'_>,
) -> Result<(), CfgAlgorithmError<ProgramPointId>> {
    if request.cancellation.is_cancelled() {
        Err(CfgAlgorithmError::Cancelled {
            work: request.budget.used(),
        })
    } else {
        Ok(())
    }
}

/// Per-request memo of compact requested-family sets and reported diagnostics.
/// A repeated procedure/filter pair reuses its facts and reports each reason once.
///
/// Visit telemetry is cumulative across procedures and completed file windows.
/// The request token, including its deadline, is the only work stop.
#[derive(Default)]
pub(super) struct ControlRelationTraversalCache {
    procedures: CaptureScopedMemo<HashMap<(ProcedureHandle, u8), Arc<ProcedureControlRelations>>>,
    reported: HashSet<(String, &'static str, u8)>,
    // The shared algorithms' default has no practical visit cap. This ledger
    // measures work; it must never refuse graph visits (#13216).
    budget: CfgAlgorithmBudget,
}

impl ControlRelationTraversalCache {
    /// Release procedure relations for a completed artifact-independent file
    /// window. The request-wide visit telemetry and diagnostic deduplication
    /// remain cumulative.
    pub(super) fn release_file_window(&mut self) {
        self.procedures = CaptureScopedMemo::default();
    }

    pub(super) fn for_procedure(
        &mut self,
        analyzer: &dyn IAnalyzer,
        semantic: &mut super::semantic::SemanticQueryContext<'_>,
        procedure: &SemanticProcedureValue,
        generation: u64,
        filter: &ControlRelationFilter,
        cancellation: Option<&CancellationToken>,
    ) -> Arc<ProcedureControlRelations> {
        let mask = requested_control_relations(filter);
        let key = (procedure.handle.clone(), mask);
        if let Some(cached) = self
            .procedures
            .read(&memo_attribution(analyzer), |procedures| {
                procedures.get(&key).cloned()
            })
        {
            return cached;
        }
        let token = cancellation.cloned().unwrap_or_default();
        let derived = Arc::new(control_relations_for_procedure(
            &procedure.handle,
            generation,
            &token,
            &mut self.budget,
            mask,
            |bytes| semantic.admit_control_relation_bytes(bytes),
        ));
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "control_relations cache_resident_bytes={} reaches_allocations={} dependence_allocations={}",
                derived.resident_bytes, derived.reaches_allocations, derived.dependence_allocations
            )
        });
        // Failed base admission permits only a transient diagnostic product,
        // never an uncharged negative cache entry.
        if derived.resident_bytes > 0 {
            self.procedures
                .read_mut(&memo_attribution(analyzer), |procedures| {
                    procedures.insert(key, Arc::clone(&derived))
                });
        }
        derived
    }

    /// Turn one derivation's completeness into typed diagnostics.
    ///
    /// Reported before any filter runs, so a `:relation postdominates` filter
    /// that drops every row still leaves the reason the answer is partial on
    /// the response. `subject` is the procedure's own wire id.
    pub(super) fn report_completeness(
        &mut self,
        analyzer: &dyn IAnalyzer,
        subject: &str,
        language: Language,
        relations: &ProcedureControlRelations,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        // A derivation Stopped reason is reported by the expansion's own stop,
        // which also covers the families that expansion did not finish
        // yielding: one Stopped diagnostic per procedure, never two.
        let metadata = ControlRelationMetadata {
            generation: relations.metadata.generation,
            completeness: ControlRelationCompleteness::from_reasons(
                relations
                    .metadata
                    .completeness
                    .reasons()
                    .iter()
                    .filter(|reason| {
                        !matches!(reason, ControlRelationIncompleteReason::Stopped { .. })
                    })
                    .cloned()
                    .collect(),
            ),
        };
        self.report_reasons(analyzer, subject, language, &metadata, diagnostics);
    }

    pub(super) fn report_expansion_stop(
        &mut self,
        analyzer: &dyn IAnalyzer,
        subject: &str,
        language: Language,
        stop: ControlRelationExpansionStop,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        let metadata = ControlRelationMetadata {
            generation: stop.metadata.generation,
            completeness: ControlRelationCompleteness::from_reasons(vec![stop.reason]),
        };
        self.report_reasons(analyzer, subject, language, &metadata, diagnostics);
    }

    fn report_reasons(
        &mut self,
        analyzer: &dyn IAnalyzer,
        subject: &str,
        language: Language,
        relations: &ControlRelationMetadata,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        for reason in relations.completeness.reasons() {
            let (code, detail, cause) = classify_reason(reason);
            let family = match reason {
                ControlRelationIncompleteReason::Capacity { relation, .. } => {
                    1 << (*relation as u8)
                }
                ControlRelationIncompleteReason::Stopped { relations, .. } => *relations,
                _ => 0,
            };
            if !self.reported.insert((subject.to_string(), detail, family)) {
                continue;
            }
            let work_detail = match reason {
                ControlRelationIncompleteReason::Stopped {
                    cause,
                    work,
                    sources_done,
                    sources_total,
                    rows_produced,
                    ..
                } => format!(
                    "; stop={cause:?}; visits={work:?}; sources_done={sources_done}; sources_total={sources_total:?}; expansion_rows={rows_produced:?}"
                ),
                ControlRelationIncompleteReason::Capacity { relation, capacity } => format!(
                    "; relation={relation:?}; requested_bytes={}; available_bytes={}",
                    capacity.requested_bytes, capacity.available_bytes
                ),
                ControlRelationIncompleteReason::NonExitingRegion { .. }
                | ControlRelationIncompleteReason::LoopWithoutEntry { .. } => String::new(),
            };
            diagnostics.push(super::QueryExecutionState::diagnostic(
                analyzer,
                CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                    has_non_utf8_refusal: false,
                    refusal_sites: Default::default(),
                    call_relation_facts: None,
                    uses_omissions: Vec::new(),
                    incompleteness: match cause {
                        Some(cause) => brokk_bifrost_rql::Incompleteness::Operational(cause),
                        None => brokk_bifrost_rql::Incompleteness::Content,
                    },
                    related: Vec::new(),
                    source: None,
                    code,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: language.config_label(),
                    message: format!(
                        "procedure {subject} has an incomplete control-relation derivation in \
                     generation {} ({detail}); uncovered relations: [{}]{work_detail}",
                        relations.generation,
                        uncovered_relations(&relations.completeness).join(", ")
                    ),
                    exhausted_roots: Vec::new(),
                    withheld_rows_path: None,
                    step_index: None,
                    step_op: None,
                    no_rows_reason: None,
                    cause_codes: Vec::new(),
                }),
                cause,
            ));
        }
    }
}

/// The diagnostic code and human reason of one incompleteness.
///
/// Total on purpose: a reason added to the derivation above must be classified
/// here deliberately rather than defaulting into a generic message.
fn classify_reason(
    reason: &ControlRelationIncompleteReason,
) -> (
    CodeQueryDiagnosticCode,
    &'static str,
    Option<DerivationExecutionCause>,
) {
    match reason {
        ControlRelationIncompleteReason::Capacity { .. } => (
            CodeQueryDiagnosticCode::ControlRelationDerivationIncomplete,
            "the control-relation structure exceeded resident capacity",
            Some(DerivationExecutionCause::Budget),
        ),
        ControlRelationIncompleteReason::Stopped { cause, .. } => (
            CodeQueryDiagnosticCode::ControlRelationDerivationIncomplete,
            match cause {
                ControlRelationStop::Cancelled => "the derivation was cancelled",
                ControlRelationStop::Deadline => "the request deadline stopped the derivation",
            },
            // Hard deadlines cancel the request token. Keep its existing
            // operational category; the typed local cause distinguishes them.
            Some(DerivationExecutionCause::Cancelled),
        ),
        ControlRelationIncompleteReason::NonExitingRegion { .. } => (
            CodeQueryDiagnosticCode::ControlRelationExitPartitionPartial,
            "the procedure has a live region with no path to either exit, so a backward claim \
             covers terminating executions only",
            None,
        ),
        ControlRelationIncompleteReason::LoopWithoutEntry { .. } => (
            CodeQueryDiagnosticCode::ControlRelationDerivationIncomplete,
            "a cyclic region has no entry edge, so its membership has no header to hang off",
            None,
        ),
    }
}

/// One lazily expanded pair, before the relation filter and public projection.
/// It owns neither the procedure artifact nor the compact closure.
#[derive(Debug)]
pub(super) struct ControlRelationCandidate {
    relations: Arc<ControlRelationExpansionMetadata>,
    pub(super) row: ControlRelationRow,
}

impl ControlRelationCandidate {
    pub(super) fn project(self, procedure: &SemanticProcedureValue) -> ControlRelationValue {
        let (file, range) = super::procedure_point_anchor(
            procedure,
            self.row.target,
            "a validated procedure owns the point its own relation names",
        );
        ControlRelationValue {
            public: project_control_relation(
                procedure,
                &self.row,
                self.relations.derivation.generation,
            ),
            relations: self.relations,
            row: self.row,
            file,
            range,
        }
    }
}

/// One control-relation row travelling through the pipeline.
///
/// Each emitted value owns one row and shares its expansion's coverage plus
/// immutable derivation metadata. Wire ids and anchors are projected while the
/// source artifact is live. The row and its provenance retain no procedure
/// handle, so the consuming step can close each file window (#13216).
#[derive(Debug, Clone)]
pub(super) struct ControlRelationValue {
    pub(super) relations: Arc<ControlRelationExpansionMetadata>,
    pub(super) row: ControlRelationRow,
    pub(super) file: ProjectFile,
    range: Range,
    public: CodeQueryControlRelation,
}

impl ControlRelationValue {
    pub(super) fn key(&self) -> ControlRelationKey {
        ControlRelationKey {
            procedure: self.public.procedure_id.clone(),
            relation: self.row.relation,
            source: self.row.source,
            target: self.row.target,
            controlling_edge: self.row.controlling_edge,
        }
    }

    fn uncovered_relations(&self) -> Vec<&'static str> {
        let incomplete = self.relations.incomplete_relations.load(Ordering::Acquire);
        ALL_CONTROL_RELATION_KINDS
            .iter()
            .copied()
            .filter(|kind| {
                requested(incomplete, *kind)
                    || !self.relations.derivation.completeness.covers(*kind)
            })
            .map(|kind| kind.label())
            .collect()
    }
}

/// The value domain the `control_relation.completeness` row field publishes,
/// minted by [`public_control_relation`] (issue #2515).
pub(super) const CONTROL_RELATION_COMPLETENESS_LABELS: &[&str] = &["complete", "partial"];

/// Dedup identity uses the procedure, family and semantic endpoints rather
/// than a rank that could collide across different requested-family sets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ControlRelationKey {
    pub(super) procedure: String,
    pub(super) relation: ControlRelationKind,
    pub(super) source: ProgramPointId,
    pub(super) target: ProgramPointId,
    pub(super) controlling_edge: Option<ControlEdgeId>,
}

pub(super) fn control_relation_filter_matches(
    filter: &ControlRelationFilter,
    row: &ControlRelationRow,
) -> bool {
    if !filter.relations.is_empty() && !filter.relations.contains(&row.relation) {
        return false;
    }
    // Every row carries the one partition the derivation computes, so a filter
    // naming a reserved partition matches nothing -- which is the truth, not a
    // silent empty answer: the value domain publishes the reserved labels and
    // the row's own `exit_partition` states what was computed.
    if !filter.exit_partitions.is_empty()
        && !filter
            .exit_partitions
            .contains(&ControlExitPartition::DERIVED_TODAY)
    {
        return false;
    }
    true
}

/// Domain separator for the row family's stable ids.
const CONTROL_RELATION_ID_DOMAIN: &[u8] = b"bifrost.code_query.control_relation.v1";

/// The public projection of one control-relation row.
///
/// Both endpoints are rendered inline from the same procedure handle the
/// derivation ran over, so `source.id` and `target.id` are literally the ids a
/// `program_point` row publishes and `controlling_edge_id` is literally a
/// `control_edge` row's id.
fn project_control_relation(
    procedure: &SemanticProcedureValue,
    row: &ControlRelationRow,
    generation: u64,
) -> CodeQueryControlRelation {
    let source = procedure
        .point_value(row.source)
        .expect("a validated procedure owns the point its own relation names")
        .point_ref();
    let target = procedure
        .point_value(row.target)
        .expect("a validated procedure owns the point its own relation names")
        .point_ref();
    let controlling_edge_id = row.controlling_edge.map(|edge| {
        procedure
            .edge_value(edge)
            .expect("a validated procedure owns the edge its own relation names")
            .public()
            .id
    });
    let procedure = procedure.public();
    let mut digest = LengthDelimitedDigest::new(CONTROL_RELATION_ID_DOMAIN);
    digest.push(procedure.id.as_bytes());
    digest.push(row.relation.label().as_bytes());
    digest.push(ControlExitPartition::DERIVED_TODAY.label().as_bytes());
    digest.push(source.id.as_bytes());
    digest.push(target.id.as_bytes());
    digest.push(controlling_edge_id.as_deref().unwrap_or("").as_bytes());
    CodeQueryControlRelation {
        id: digest.finish().to_string(),
        procedure_id: procedure.id,
        path: procedure.path,
        language: procedure.language,
        range: target.range,
        relation: row.relation.label(),
        certainty: row.certainty.label(),
        exit_partition: ControlExitPartition::DERIVED_TODAY.label(),
        source,
        target,
        controlling_edge_id,
        completeness: "complete",
        uncovered_relations: Vec::new(),
        generation,
    }
}

pub(super) fn public_control_relation(value: &ControlRelationValue) -> CodeQueryControlRelation {
    let mut public = value.public.clone();
    // Use one coverage snapshot for both public fields, including rows yielded
    // before a later cancellation or deadline stopped this expansion.
    public.uncovered_relations = value.uncovered_relations();
    public.completeness = super::completeness_label_for_coverage(
        !public.uncovered_relations.contains(&public.relation),
    );
    public
}

/// The typed key that addresses one control-relation row in detailed evidence.
pub(super) fn detailed_key(value: &ControlRelationValue) -> DetailedCodeQueryKey {
    let public = public_control_relation(value);
    DetailedCodeQueryKey::ControlRelation {
        id: public.id,
        procedure_id: public.procedure_id,
        relation: public.relation.to_string(),
        certainty: public.certainty.to_string(),
    }
}

/// The row's own source anchor: the target point, which is the position an
/// author is asking about when they ask what dominates or governs it.
pub(super) fn anchor(value: &ControlRelationValue) -> (ProjectFile, Range) {
    (value.file.clone(), value.range)
}

/// The trace reference of one control-relation row: enough to name the claim
/// and find it again, without re-rendering both endpoints.
pub(super) fn control_relation_ref(value: &ControlRelationValue) -> CodeQueryResultRef {
    let public = public_control_relation(value);
    CodeQueryResultRef::ControlRelation {
        id: public.id,
        path: public.path,
        range: public.range,
        procedure_id: public.procedure_id,
        relation: public.relation,
        certainty: public.certainty,
        exit_partition: public.exit_partition,
    }
}

fn uncovered_relations(completeness: &ControlRelationCompleteness) -> Vec<&'static str> {
    ALL_CONTROL_RELATION_KINDS
        .iter()
        .filter(|relation| !completeness.covers(**relation))
        .map(|relation| relation.label())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::cfg_algorithms::visit_control_dependence;

    fn stopped(relation: ControlRelationKind) -> ControlRelationCompleteness {
        ControlRelationCompleteness {
            reasons: vec![ControlRelationIncompleteReason::Stopped {
                cause: ControlRelationStop::Cancelled,
                relations: 1 << (relation as u8),
                work: CfgAlgorithmWork::default(),
                sources_done: 1,
                rows_produced: None,
                sources_total: Some(2),
            }],
        }
    }

    /// A hole in one relation is a hole in that relation only. This is the
    /// property that lets a dominance policy stay conclusive when the loop
    /// derivation was cancelled.
    #[test]
    fn one_relations_stop_leaves_the_others_covered() {
        let completeness = stopped(ControlRelationKind::InLoop);
        assert!(!completeness.covers(ControlRelationKind::InLoop));
        assert!(completeness.covers(ControlRelationKind::Dominates));
        assert_eq!(uncovered_relations(&completeness), vec!["in_loop"]);
    }

    /// Divergence is a property of the exit universe, so it blocks exactly the
    /// two relations computed backward from the exits.
    #[test]
    fn a_non_exiting_region_blocks_only_the_backward_relations() {
        let completeness = ControlRelationCompleteness {
            reasons: vec![ControlRelationIncompleteReason::NonExitingRegion { points: 3 }],
        };
        assert!(!completeness.covers(ControlRelationKind::Postdominates));
        assert!(!completeness.covers(ControlRelationKind::ControlDependsOn));
        assert!(completeness.covers(ControlRelationKind::Dominates));
        assert!(completeness.covers(ControlRelationKind::Reachable));
        assert!(completeness.covers(ControlRelationKind::InLoop));
    }

    #[test]
    fn cancellation_covers_nothing() {
        let completeness = ControlRelationCompleteness {
            reasons: vec![ControlRelationIncompleteReason::Stopped {
                cause: ControlRelationStop::Cancelled,
                relations: (1u8 << ALL_CONTROL_RELATION_KINDS.len()) - 1,
                work: CfgAlgorithmWork::default(),
                sources_done: 0,
                rows_produced: None,
                sources_total: None,
            }],
        };
        for relation in ALL_CONTROL_RELATION_KINDS {
            assert!(!completeness.covers(*relation), "{relation:?}");
        }
    }

    #[test]
    fn an_incomplete_derivation_reports_every_reason_once_per_procedure() {
        let directory = tempfile::tempdir().unwrap();
        let analyzer =
            crate::analyzer::JavascriptAnalyzer::from_project(crate::analyzer::TestProject::new(
                directory.path().to_path_buf(),
                crate::analyzer::Language::JavaScript,
            ));

        let mut cache = ControlRelationTraversalCache::default();
        let relations = ProcedureControlRelations {
            live: Box::default(),
            families: Vec::new(),
            ancestor_workspace: Mutex::new(Some(Vec::new())),
            resident_bytes: 0,
            reaches_allocations: 0,
            dependence_allocations: 0,
            metadata: Arc::new(ControlRelationMetadata {
                completeness: ControlRelationCompleteness {
                    reasons: vec![
                        ControlRelationIncompleteReason::Capacity {
                            relation: ControlRelationKind::Dominates,
                            capacity: ControlRelationCapacity {
                                requested_bytes: 2,
                                available_bytes: 1,
                            },
                        },
                        ControlRelationIncompleteReason::NonExitingRegion { points: 2 },
                    ],
                },
                generation: 7,
            }),
        };
        let mut diagnostics = Vec::new();
        cache.report_completeness(
            &analyzer,
            "procedure-1",
            Language::Java,
            &relations,
            &mut diagnostics,
        );
        crate::structural::search::test_support::assert_incomplete_diagnostics(&diagnostics, 2);
        // The second call adds nothing: one reason is reported once per subject.
        cache.report_completeness(
            &analyzer,
            "procedure-1",
            Language::Java,
            &relations,
            &mut diagnostics,
        );
        crate::structural::search::test_support::assert_incomplete_diagnostics(&diagnostics, 2);
    }
    fn with_rust_procedure(
        source: &str,
        run: impl FnOnce(
            &dyn IAnalyzer,
            &mut super::super::semantic::SemanticQueryContext<'_>,
            SemanticProcedureValue,
        ),
    ) {
        use super::super::{CodeQuerySemanticLimits, SeedMatch};
        use crate::analyzer::AnalyzerConfig;
        use crate::structural::search::tests::inline_project::InlineTestProject;
        let project = InlineTestProject::with_language(Language::Rust)
            .file("subject.rs", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("subject.rs");
        let facts = workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == Language::Rust)
            .expect("Rust structural provider")
            .structural_facts(&file)
            .expect("Rust facts");
        let query = crate::structural::CodeQuery::from_source("(function :name \"subject\")")
            .expect("subject query");
        let fact_match =
            crate::structural::matcher::match_query(query.seed().expect("seed"), &facts, 1)
                .into_iter()
                .next()
                .expect("subject function");
        let seed = SeedMatch {
            language: Language::Rust,
            file,
            facts,
            fact_match,
            python_import: None,
        };
        let mut semantic = super::super::semantic::SemanticQueryContext::new(
            &workspace,
            None,
            CodeQuerySemanticLimits::default(),
        );
        let [procedure] = semantic
            .cfg()
            .procedure_of_match(&seed)
            .try_into()
            .expect("one subject procedure");
        run(workspace.analyzer(), &mut semantic, procedure);
    }

    #[test]
    fn resident_capacity_withholds_only_reaches_and_keeps_other_families_complete() {
        let source = format!(
            "fn subject(mut value: i32, flag: bool) -> i32 {{\n{}\nif flag {{ value += 2; }}\nwhile value < 1000 {{ value += 1; }}\nvalue\n}}",
            "value += 1;\n".repeat(200)
        );
        with_rust_procedure(&source, |analyzer, semantic, procedure| {
            // The real artifact is already admitted. Leave 64 KiB for compact
            // facts: trees/loops fit, but the live-source bitsets do not.
            semantic.set_remaining_control_relation_bytes_for_test(64 * 1024);
            let mut cache = ControlRelationTraversalCache::default();
            let derived = cache.for_procedure(
                analyzer,
                semantic,
                &procedure,
                0,
                &ControlRelationFilter::default(),
                None,
            );
            assert!(derived.resident_bytes <= 64 * 1024);
            assert!(
                !semantic.work().budget_exhausted,
                "a family refusal cannot poison other families"
            );
            assert_eq!(derived.reaches_allocations, 0);
            assert_eq!(uncovered_relations(&derived.completeness), vec!["reaches"]);
            assert!(matches!(
                derived.completeness.reasons(),
                [ControlRelationIncompleteReason::Capacity {
                    relation: ControlRelationKind::Reaches,
                    ..
                }]
            ));
            let mut diagnostics = Vec::new();
            cache.report_completeness(
                analyzer,
                &procedure.wire_id(),
                Language::Rust,
                &derived,
                &mut diagnostics,
            );
            assert_eq!(diagnostics.len(), 1);
            assert!(diagnostics[0].message.contains("resident capacity"));
            assert_eq!(
                diagnostics[0].incompleteness,
                brokk_bifrost_rql::Incompleteness::Operational(DerivationExecutionCause::Budget)
            );
            for kind in ALL_CONTROL_RELATION_KINDS
                .iter()
                .copied()
                .filter(|kind| *kind != ControlRelationKind::Reaches)
            {
                assert!(derived.completeness.covers(kind), "{kind:?}");
                assert!(
                    ControlRelationRows::new(
                        Arc::clone(&derived),
                        procedure.clone(),
                        CancellationToken::new()
                    )
                    .any(|row| row.unwrap().row.relation == kind),
                    "{kind:?}"
                );
            }
            let cached = cache
                .procedures
                .read(&memo_attribution(analyzer), |memo| memo.len());
            semantic.set_remaining_control_relation_bytes_for_test(0);
            let filter = ControlRelationFilter {
                relations: vec![ControlRelationKind::Reaches],
                ..Default::default()
            };
            let refused = cache.for_procedure(analyzer, semantic, &procedure, 0, &filter, None);
            assert_eq!(refused.resident_bytes, 0);
            assert!(!refused.completeness.covers(ControlRelationKind::Reaches));
            assert_eq!(
                cache
                    .procedures
                    .read(&memo_attribution(analyzer), |memo| memo.len()),
                cached,
                "a refused header must not accumulate uncharged cache entries"
            );
        });
    }

    #[test]
    fn loop_only_query_allocates_no_reaches_structure() {
        let source = format!(
            "fn subject(mut value: i32) -> i32 {{\n{}\nwhile value < 1000 {{ value += 1; }}\nvalue\n}}",
            "value += 1;\n".repeat(200)
        );
        with_rust_procedure(&source, |analyzer, semantic, procedure| {
            let mut cache = ControlRelationTraversalCache::default();
            let filter = ControlRelationFilter {
                relations: vec![ControlRelationKind::InLoop],
                ..Default::default()
            };
            let derived = cache.for_procedure(analyzer, semantic, &procedure, 0, &filter, None);
            // Counter increments at the allocation site, not a timing proxy.
            assert_eq!(derived.reaches_allocations, 0);
            assert!(derived.live.is_empty());
            assert!(matches!(
                derived.families.as_slice(),
                [CompactControlRelation::Loops { .. }]
            ));
            assert!(derived.completeness.reasons().is_empty());
            assert!(
                ControlRelationRows::new(derived, procedure, CancellationToken::new())
                    .next()
                    .is_some()
            );
        });
    }

    /// After a cancellation at any check count, each requested family either
    /// yielded exactly the rows of an uncancelled run or is named by the one
    /// Stopped reason; and there is never more than one such reason.
    #[test]
    fn cancelled_run_reports_one_stop_covering_every_family_not_fully_yielded() {
        with_rust_procedure(
            "fn subject(mut value: i32, flag: bool) -> i32 { if flag { value += 1; } while value < 10 { value += 1; } value }",
            |analyzer, semantic, procedure| {
                let filter = ControlRelationFilter {
                    relations: ALL_CONTROL_RELATION_KINDS.to_vec(),
                    ..Default::default()
                };
                let rows_by_family =
                    |derived: Arc<ProcedureControlRelations>, token: CancellationToken| {
                        let mut rows = HashMap::<ControlRelationKind, Vec<_>>::default();
                        let mut stops = Vec::new();
                        for item in ControlRelationRows::new(derived, procedure.clone(), token) {
                            match item {
                                Ok(candidate) => rows
                                    .entry(candidate.row.relation)
                                    .or_default()
                                    .push(candidate.row),
                                Err(stop) => stops.push(stop.reason),
                            }
                        }
                        (rows, stops)
                    };
                let mut cache = ControlRelationTraversalCache::default();
                let full = cache.for_procedure(analyzer, semantic, &procedure, 0, &filter, None);
                assert!(full.completeness.reasons().iter().all(|reason| !matches!(
                    reason,
                    ControlRelationIncompleteReason::Stopped { .. }
                )));
                let (expected, stops) = rows_by_family(full, CancellationToken::new());
                assert!(stops.is_empty());
                let requested_mask = requested_control_relations(&filter);
                let (mut cut_in_derivation, mut cut_in_expansion, mut uncut) = (0, 0, 0);
                // The derivation consumes most checks; sweep until a count
                // is large enough that nothing is cut, covering expansion cuts too.
                for checks in 0.. {
                    if uncut > 0 {
                        break;
                    }
                    assert!(checks < 100_000, "derivation never completed");
                    let token = CancellationToken::cancel_after_checks_for_test(checks);
                    let mut cache = ControlRelationTraversalCache::default();
                    let derived = cache.for_procedure(
                        analyzer,
                        semantic,
                        &procedure,
                        0,
                        &filter,
                        Some(&token),
                    );
                    let derivation_stopped = derived.completeness.reasons().iter().any(|reason| {
                        matches!(reason, ControlRelationIncompleteReason::Stopped { .. })
                    });
                    // The eager report must not already carry the stop.
                    let mut eager = Vec::new();
                    cache.report_completeness(
                        analyzer,
                        &procedure.wire_id(),
                        Language::Rust,
                        &derived,
                        &mut eager,
                    );
                    assert!(
                        eager.iter().all(|d| !d.message.contains("cancelled")),
                        "checks={checks}: {eager:?}"
                    );
                    let (rows, stops) = rows_by_family(derived, token);
                    assert!(stops.len() <= 1, "checks={checks}: {stops:?}");
                    let uncovered = match stops.as_slice() {
                        [] => 0,
                        [ControlRelationIncompleteReason::Stopped { relations, .. }] => *relations,
                        other => panic!("checks={checks}: not a stop: {other:?}"),
                    };
                    assert!(!derivation_stopped || !stops.is_empty(), "checks={checks}");
                    match (stops.is_empty(), derivation_stopped) {
                        (true, _) => uncut += 1,
                        (false, true) => cut_in_derivation += 1,
                        (false, false) => cut_in_expansion += 1,
                    }
                    for kind in ALL_CONTROL_RELATION_KINDS.iter().copied() {
                        if !requested(requested_mask, kind) {
                            continue;
                        }
                        let got = rows.get(&kind).cloned().unwrap_or_default();
                        let want = expected.get(&kind).cloned().unwrap_or_default();
                        if got != want {
                            assert!(
                                requested(uncovered, kind),
                                "checks={checks}: {kind:?} lost rows ({} of {}) without being uncovered",
                                got.len(),
                                want.len()
                            );
                        }
                        if !requested(uncovered, kind) {
                            assert_eq!(got, want, "checks={checks}: {kind:?}");
                        }
                    }
                }
                assert!(cut_in_derivation > 0, "no stop during derivation");
                assert!(cut_in_expansion > 0, "no stop during expansion");
                assert!(uncut > 0, "no uncancelled run");
            },
        );
    }

    #[test]
    fn lazy_expansion_reports_cancellation_and_deadline_after_complete_derivation() {
        with_rust_procedure(
            "fn subject(mut value: i32, flag: bool) -> i32 { if flag { value += 1; } while value < 10 { value += 1; } value }",
            |analyzer, semantic, procedure| {
                let mut cache = ControlRelationTraversalCache::default();
                for kind in ALL_CONTROL_RELATION_KINDS.iter().copied() {
                    let filter = ControlRelationFilter {
                        relations: vec![kind],
                        ..Default::default()
                    };
                    let derived =
                        cache.for_procedure(analyzer, semantic, &procedure, 0, &filter, None);
                    assert!(derived.completeness.reasons().is_empty());
                    for deadline in [false, true] {
                        let token = CancellationToken::new();
                        let mut rows = ControlRelationRows::new(
                            Arc::clone(&derived),
                            procedure.clone(),
                            token.clone(),
                        );
                        let artifact = Arc::downgrade(procedure.handle.artifact());
                        let retained_before_row = artifact.strong_count();
                        let first = rows
                            .next()
                            .expect("first positive row")
                            .unwrap()
                            .project(&procedure);
                        assert_eq!(
                            artifact.strong_count(),
                            retained_before_row,
                            "emitted rows and provenance must not retain the file artifact"
                        );
                        assert_eq!(public_control_relation(&first).completeness, "complete");
                        if deadline {
                            assert!(
                                token
                                    .clone()
                                    .with_deadline(std::time::Instant::now())
                                    .is_cancelled()
                            );
                        } else {
                            token.cancel();
                        }
                        let stop = rows
                            .next()
                            .expect("a typed stop is an iterator item")
                            .unwrap_err();
                        let ControlRelationIncompleteReason::Stopped {
                            cause,
                            relations,
                            rows_produced,
                            work,
                            ..
                        } = &stop.reason
                        else {
                            panic!("expected expansion stop")
                        };
                        assert_eq!(
                            *cause,
                            if deadline {
                                ControlRelationStop::Deadline
                            } else {
                                ControlRelationStop::Cancelled
                            }
                        );
                        assert_eq!(*relations, 1 << kind as u8);
                        assert_eq!(*rows_produced, Some(1));
                        assert!(work.node_visits >= 1);
                        // Serialize a value retained before the stop: both public
                        // coverage fields must now describe the truncated family.
                        let public = public_control_relation(&first);
                        assert_eq!(public_control_relation(&first).completeness, "partial");
                        assert_eq!(public.completeness, "partial");
                        assert_eq!(public.uncovered_relations, vec![kind.label()]);
                        let mut diagnostics = Vec::new();
                        cache.report_expansion_stop(
                            analyzer,
                            &procedure.wire_id(),
                            Language::Rust,
                            stop,
                            &mut diagnostics,
                        );
                        assert_eq!(diagnostics.len(), 1);
                        assert_eq!(
                            diagnostics[0].code,
                            CodeQueryDiagnosticCode::ControlRelationDerivationIncomplete
                        );
                        assert_eq!(
                            diagnostics[0].incompleteness,
                            brokk_bifrost_rql::Incompleteness::Operational(
                                DerivationExecutionCause::Cancelled
                            )
                        );
                        assert!(diagnostics[0].message.contains("expansion_rows=Some(1)"));
                        assert!(diagnostics[0].message.contains(if deadline {
                            "Deadline"
                        } else {
                            "Cancelled"
                        }));
                        assert!(rows.next().is_none());
                        drop(rows);
                        // The same cached facts get fresh expansion coverage;
                        // old rows retain their own stop even after that reuse.
                        assert!(derived.completeness.reasons().is_empty());
                        let fresh = ControlRelationRows::new(
                            Arc::clone(&derived),
                            procedure.clone(),
                            CancellationToken::new(),
                        )
                        .next()
                        .unwrap()
                        .unwrap()
                        .project(&procedure);
                        assert_eq!(public_control_relation(&fresh).completeness, "complete");
                        assert!(
                            public_control_relation(&fresh)
                                .uncovered_relations
                                .is_empty()
                        );
                        assert_eq!(public_control_relation(&first).completeness, "partial");
                    }
                }
                let filter = ControlRelationFilter {
                    relations: vec![ControlRelationKind::Reachable, ControlRelationKind::InLoop],
                    ..Default::default()
                };
                let derived = cache.for_procedure(analyzer, semantic, &procedure, 0, &filter, None);
                let token = CancellationToken::new();
                let mut rows = ControlRelationRows::new(derived, procedure.clone(), token.clone());
                let complete = rows.next().unwrap().unwrap().project(&procedure);
                assert_eq!(complete.row.relation, ControlRelationKind::Reachable);
                let unfinished = rows
                    .by_ref()
                    .map(Result::unwrap)
                    .find(|row| row.row.relation == ControlRelationKind::InLoop)
                    .unwrap()
                    .project(&procedure);
                token.cancel();
                assert!(rows.next().unwrap().is_err());
                assert_eq!(public_control_relation(&complete).completeness, "complete");
                assert_eq!(public_control_relation(&unfinished).completeness, "partial");
                assert_eq!(
                    public_control_relation(&unfinished).uncovered_relations,
                    vec!["in_loop"]
                );
            },
        );
    }

    #[test]
    fn control_relations_release_file_windows_under_a_shared_retained_allowance() {
        use super::super::{
            CodeQueryExecutionLimits, CodeQuerySemanticRowLimits, execute_workspace_with_limits,
        };
        use crate::analyzer::AnalyzerConfig;
        use crate::structural::search::tests::inline_project::InlineTestProject;
        let mut project = InlineTestProject::with_language(Language::Rust);
        for index in 0..64 {
            project = project.file(
                format!("file_{index:02}.rs"),
                "fn subject(mut value: i32) -> i32 { while value < 10 { value += 1; } value }",
            );
        }
        let project = project.build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let query = crate::structural::CodeQuery::from_source(
            "(limit 1000 (control-relations :relation [in-loop] (procedure-of (function :name \"subject\"))))",
        )
        .unwrap();
        let mut limits = CodeQueryExecutionLimits::default();
        // Each file fits; retaining all 64 procedures and compact loop families
        // at once does not. This uses the real query allowance, not a work cap.
        limits.semantic.max_retained_bytes = 64 * 1024;
        // Isolate actual retained bytes from the byte-derived row estimates.
        limits.semantic.rows_per_dimension =
            Some(CodeQuerySemanticRowLimits::from_rows(|_| 100_000));
        let result = execute_workspace_with_limits(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
            limits,
        );
        assert!(!result.truncated, "{}", result.render_text());
        assert!(result.diagnostics.is_empty(), "{}", result.render_text());
        let mut files = std::collections::BTreeSet::new();
        for item in &result.results {
            let super::super::CodeQueryResultValue::ControlRelation { value } = &item.value else {
                panic!("control row")
            };
            assert_eq!(value.completeness, "complete");
            assert!(value.uncovered_relations.is_empty());
            files.insert(value.path.as_str());
        }
        assert_eq!(files.len(), 64, "{}", result.render_text());
    }

    #[test]
    fn sparse_dominance_expansion_visits_only_real_pairs_in_canonical_order() {
        let points = 10_000;
        // A wide immediate-parent tree: root -> leaves. It has n-1 pairs,
        // not n squared; the production iterator must touch only those pairs.
        with_rust_procedure("fn subject() {}", |_analyzer, _semantic, procedure| {
            let root = ProgramPointId::try_from_index(0).unwrap();
            let live = (0..points)
                .map(|index| ProgramPointId::try_from_index(index).unwrap())
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let tree = AncestorTree::new(
                (0..points)
                    .map(|index| (index != 0).then_some(root))
                    .collect(),
            );
            let derived = Arc::new(ProcedureControlRelations {
                metadata: Arc::new(ControlRelationMetadata {
                    completeness: ControlRelationCompleteness::from_reasons(Vec::new()),
                    generation: 0,
                }),
                live,
                families: vec![CompactControlRelation::Ancestors {
                    relation: ControlRelationKind::Dominates,
                    tree,
                    certainty: FlowCertainty::Exact,
                }],
                ancestor_workspace: Mutex::new(Some(Vec::with_capacity(points))),
                resident_bytes: 0,
                reaches_allocations: 0,
                dependence_allocations: 0,
            });
            let mut rows = ControlRelationRows::new(
                Arc::clone(&derived),
                procedure.clone(),
                CancellationToken::new(),
            );
            let workspace = rows.ancestor_targets.as_ptr();
            for target in 1..points {
                let row = rows.next().unwrap().unwrap();
                assert_eq!(row.row.source, root);
                assert_eq!(row.row.target.index(), target);
            }
            assert!(rows.next().is_none());
            assert_eq!(rows.rows_produced, points - 1);
            assert_eq!(rows.expansion_visits, points - 1);
            drop(rows);
            let reused = ControlRelationRows::new(derived, procedure, CancellationToken::new());
            assert_eq!(
                reused.ancestor_targets.as_ptr(),
                workspace,
                "repeat expansions reuse the admitted buffer"
            );
        });
    }

    #[test]
    fn nested_dependence_capacity_is_refused_before_pair_allocation() {
        let nesting = 40;
        let source = format!(
            "fn subject(mut value: i32, flags: &[bool]) -> i32 {{ {} value += 1; {} value }}",
            (0..nesting)
                .map(|index| format!("if flags[{index}] {{ "))
                .collect::<String>(),
            "} ".repeat(nesting)
        );
        with_rust_procedure(&source, |analyzer, semantic, procedure| {
            let mut calibration = ControlRelationTraversalCache::default();
            let filter = ControlRelationFilter::default();
            let full = calibration.for_procedure(analyzer, semantic, &procedure, 0, &filter, None);
            let rows = full
                .families
                .iter()
                .find_map(|family| match family {
                    CompactControlRelation::Dependence { rows, .. } => Some(rows),
                    _ => None,
                })
                .expect("dependence fits normal allowance");
            assert!(rows.len() > 100);
            let pair_bytes = std::mem::size_of_val(rows.as_ref());
            let base_bytes = full.resident_bytes - pair_bytes;
            semantic.set_remaining_control_relation_bytes_for_test(base_bytes + pair_bytes / 2);
            let mut cache = ControlRelationTraversalCache::default();
            let refused = cache.for_procedure(analyzer, semantic, &procedure, 0, &filter, None);
            assert_eq!(refused.dependence_allocations, 0);
            assert!(
                !refused
                    .completeness
                    .covers(ControlRelationKind::ControlDependsOn)
            );
            for kind in ALL_CONTROL_RELATION_KINDS
                .iter()
                .copied()
                .filter(|kind| *kind != ControlRelationKind::ControlDependsOn)
            {
                assert!(refused.completeness.covers(kind), "{kind:?}");
            }
            assert_eq!(refused.families.len(), ALL_CONTROL_RELATION_KINDS.len() - 1);
            assert_eq!(
                uncovered_relations(&refused.completeness),
                vec!["control_depends_on"]
            );
            assert!(matches!(
                refused.completeness.reasons(),
                [ControlRelationIncompleteReason::Capacity {
                    relation: ControlRelationKind::ControlDependsOn,
                    ..
                }]
            ));
        });
    }

    /// The live-domain refusal withholds the families that read the live list,
    /// not control dependence, which expands only its precomputed pair rows.
    #[test]
    fn live_domain_refusal_keeps_control_dependence() {
        with_rust_procedure(
            "fn subject(flag: bool) -> i32 { if flag { 1 } else { 2 } }",
            |analyzer, semantic, procedure| {
                let filter = ControlRelationFilter {
                    relations: vec![
                        ControlRelationKind::Reaches,
                        ControlRelationKind::ControlDependsOn,
                    ],
                    ..Default::default()
                };
                let mut calibration = ControlRelationTraversalCache::default();
                let full =
                    calibration.for_procedure(analyzer, semantic, &procedure, 0, &filter, None);
                let dependence_bytes = full
                    .families
                    .iter()
                    .find_map(|family| match family {
                        CompactControlRelation::Dependence { rows, .. } => {
                            Some(std::mem::size_of_val(rows.as_ref()))
                        }
                        _ => None,
                    })
                    .expect("dependence rows");
                let live_bytes = full.live.len() * std::mem::size_of::<ProgramPointId>();
                let reaches_bytes =
                    full.live.len() * full.live.len().div_ceil(64) * std::mem::size_of::<u64>();
                assert!(dependence_bytes < live_bytes);
                let base_bytes =
                    full.resident_bytes - dependence_bytes - live_bytes - reaches_bytes;
                semantic
                    .set_remaining_control_relation_bytes_for_test(base_bytes + dependence_bytes);
                let mut cache = ControlRelationTraversalCache::default();
                let refused = cache.for_procedure(analyzer, semantic, &procedure, 0, &filter, None);
                assert!(!refused.completeness.covers(ControlRelationKind::Reaches));
                assert!(
                    refused
                        .completeness
                        .covers(ControlRelationKind::ControlDependsOn)
                );
                assert!(matches!(
                    refused.families.as_slice(),
                    [CompactControlRelation::Dependence { .. }]
                ));
            },
        );
    }

    #[test]
    fn shared_dependence_visitor_matches_wrapper_on_nested_branches_and_stops_in_both_passes() {
        use crate::analyzer::semantic::cfg_algorithms::control_dependence;
        for source in [
            "fn subject(mut x: i32, a: bool, b: bool) -> i32 { if a { if b { x += 1; } else { x += 2; } } x }",
            "fn subject(mut x: i32, a: bool, b: bool) -> i32 { while a { if b { break; } x += 1; } x }",
            "fn subject(x: i32, a: bool, b: bool) -> i32 { if a { if b { return x; } return 1; } 0 }",
        ] {
            with_rust_procedure(source, |_analyzer, _semantic, procedure| {
                let graph = procedure.handle.semantics();
                let token = CancellationToken::new();
                let mut budget = CfgAlgorithmBudget::default();
                let expected = control_dependence(
                    graph,
                    graph.entry_point(),
                    graph.normal_exit_point(),
                    graph.exceptional_exit_point(),
                    &mut CfgAlgorithmRequest::new(&mut budget, &token),
                )
                .unwrap();
                let mut budget = CfgAlgorithmBudget::default();
                let mut rows = Vec::new();
                let summary = visit_control_dependence(
                    graph,
                    graph.entry_point(),
                    graph.normal_exit_point(),
                    graph.exceptional_exit_point(),
                    &mut CfgAlgorithmRequest::new(&mut budget, &token),
                    |row| rows.push(row),
                )
                .unwrap();
                rows.sort_unstable();
                rows.dedup();
                assert_eq!(rows.as_slice(), expected.rows.as_ref());
                assert_eq!(summary.non_exiting_regions, expected.non_exiting_regions);
                assert_eq!(summary.unreachable_points, expected.unreachable_points);
                assert_eq!(summary.work, expected.work);
                assert!(!rows.is_empty());
                // Pass one can stop before it has allocated any pair storage.
                let cancelled = CancellationToken::cancel_after_checks_for_test(0);
                let mut budget = CfgAlgorithmBudget::default();
                assert!(matches!(
                    visit_control_dependence(
                        graph,
                        graph.entry_point(),
                        graph.normal_exit_point(),
                        graph.exceptional_exit_point(),
                        &mut CfgAlgorithmRequest::new(&mut budget, &cancelled),
                        |_| panic!("no pair before cancelled pass")
                    ),
                    Err(CfgAlgorithmError::Cancelled { .. })
                ));
                // Pass two can stop after a positive pair; it is an error,
                // never a successful summary with an incomplete rows Vec.
                let token = CancellationToken::new();
                let mut budget = CfgAlgorithmBudget::default();
                let mut produced = 0;
                let result = visit_control_dependence(
                    graph,
                    graph.entry_point(),
                    graph.normal_exit_point(),
                    graph.exceptional_exit_point(),
                    &mut CfgAlgorithmRequest::new(&mut budget, &token),
                    |_| {
                        produced += 1;
                        token.cancel();
                    },
                );
                assert!(matches!(result, Err(CfgAlgorithmError::Cancelled { .. })));
                assert_eq!(produced, 1);
            });
        }
    }

    #[test]
    #[ignore = "#13216: explicit 10k-point closure CPU and peak-RSS measurement"]
    fn measure_ten_thousand_live_point_control_relations() {
        let source = format!(
            "fn subject(mut value: i32) -> i32 {{\n{}\nvalue\n}}",
            "value += 1;\n".repeat(2500)
        );
        with_rust_procedure(&source, |analyzer, semantic, procedure| {
            let points = procedure.handle.semantics().points().len();
            assert!((10_000..11_000).contains(&points), "{points}");
            let mut cache = ControlRelationTraversalCache::default();
            let filter = ControlRelationFilter {
                relations: vec![ControlRelationKind::Reaches],
                ..Default::default()
            };
            let started = brokk_bifrost_core::profiling::thread_cpu_time();
            let derived = cache.for_procedure(analyzer, semantic, &procedure, 0, &filter, None);
            let cpu = brokk_bifrost_core::profiling::thread_cpu_time().saturating_sub(started);
            assert!(derived.completeness.reasons().is_empty());
            eprintln!(
                "CONTROL_RELATION_MEASUREMENT points={points} live_points={} retained_bytes={} reaches_allocations={} build_cpu_seconds={:.9}",
                derived.live.len(),
                derived.resident_bytes,
                derived.reaches_allocations,
                cpu.as_secs_f64()
            );
            assert_eq!(
                ControlRelationRows::new(derived, procedure, CancellationToken::new())
                    .take(1000)
                    .count(),
                1000
            );
        });
    }
}
