//! Demand-materialized, language-neutral interprocedural control flow.
//!
//! Callable CFGs remain immutable and procedure-local. This module stitches a
//! bounded, generation-local view on demand and never builds an eager
//! whole-workspace graph.

use std::collections::VecDeque;
use std::fmt;

use crate::analyzer::WorkspaceAnalyzer;
use crate::hash::{HashMap, HashSet};

use super::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, CfgAlgorithmWork,
    forward_reachability, reverse_reachability,
};
use super::workspace_oracle::{
    WorkspaceSemanticOracle, exact_source_for_procedure, semantic_locator_work,
};
use super::{
    CallContinuationKind, CallSiteHandle, CallSiteId, ControlContinuation, ControlEdgeKind,
    DeferredInvocationKind, DispatchBoundary, DispatchBoundaryKind, DispatchOracle, DispatchResult,
    EvidenceCompleteness, EvidenceHandle, OracleLimits, OracleRelationArena, OracleRelationHandle,
    OracleRelationId, OracleRelationKind, OracleRelationOwner, OracleRelationRecord,
    OracleRelationSubject, ProcedureHandle, ProcedureInvocationKind, ProgramPointHandle,
    ProgramPointId, ProofStatus, SemanticBudgetExceeded, SemanticCallSite, SemanticCapability,
    SemanticGap, SemanticGapImpact, SemanticGapKind, SemanticGapSubject, SemanticOutcome,
    SemanticProviderError, SemanticRequest, SemanticWork,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallTransfer {
    pub origin: CallSiteHandle,
    pub callee: ProcedureHandle,
    pub callee_entry: ProgramPointHandle,
    pub normal_continuation: ControlContinuation,
    pub exceptional_continuation: ControlContinuation,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallToReturnModel {
    Normal,
    Exceptional,
    NormalAndExceptional,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallBoundary {
    pub origin: CallSiteHandle,
    pub dispatch: DispatchBoundary,
    pub model: Option<CallToReturnModel>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallTransferSet {
    pub transfers: Box<[CallTransfer]>,
    pub boundaries: Box<[CallBoundary]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReturnTransferKind {
    Normal,
    Exceptional,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnTransfer {
    pub origin: CallSiteHandle,
    pub callee_exit: ProgramPointHandle,
    pub continuation: ProgramPointHandle,
    pub kind: ReturnTransferKind,
}

pub trait IcfgProvider: DispatchOracle {
    fn call_transfers(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError>;

    fn snapshot(
        &self,
        root: &ProcedureHandle,
        limits: IcfgSnapshotLimits,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgSnapshot>, SemanticProviderError>;
}

/// One provider is tied to one [`WorkspaceAnalyzer`] generation.
#[derive(Clone, Copy)]
pub struct WorkspaceIcfgProvider<'a> {
    oracle: WorkspaceSemanticOracle<'a>,
}

impl<'a> WorkspaceIcfgProvider<'a> {
    pub(crate) fn new(workspace: &'a WorkspaceAnalyzer) -> Self {
        Self {
            oracle: WorkspaceSemanticOracle::new(workspace),
        }
    }

    pub const fn workspace(&self) -> &'a WorkspaceAnalyzer {
        self.oracle.workspace()
    }

    pub const fn oracle(&self) -> &WorkspaceSemanticOracle<'a> {
        &self.oracle
    }
}

impl fmt::Debug for WorkspaceIcfgProvider<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspaceIcfgProvider")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcfgNodeKey {
    point: ProgramPointHandle,
    call_context: Box<[CallSiteHandle]>,
}

impl IcfgNodeKey {
    pub fn point(&self) -> &ProgramPointHandle {
        &self.point
    }

    pub fn call_context(&self) -> &[CallSiteHandle] {
        &self.call_context
    }
}

macro_rules! dense_icfg_id {
    ($name:ident) => {
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u32);

        impl $name {
            pub const fn new(raw: u32) -> Self {
                Self(raw)
            }

            pub const fn get(self) -> u32 {
                self.0
            }

            pub const fn index(self) -> usize {
                self.0 as usize
            }

            fn try_from_index(index: usize) -> Result<Self, SemanticProviderError> {
                u32::try_from(index).map(Self).map_err(|_| {
                    SemanticProviderError::internal(concat!(stringify!($name), " overflow"))
                })
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

dense_icfg_id!(IcfgNodeId);
dense_icfg_id!(IcfgEdgeId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IcfgEdgeKind {
    Intraprocedural(ControlEdgeKind),
    Call,
    NormalReturn,
    ExceptionalReturn,
    CallToNormalContinuation,
    CallToExceptionalContinuation,
}

impl IcfgEdgeKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Intraprocedural(kind) => kind.label(),
            Self::Call => "call_to_entry",
            Self::NormalReturn => "normal_return",
            Self::ExceptionalReturn => "exceptional_return",
            Self::CallToNormalContinuation => "call_to_normal_continuation",
            Self::CallToExceptionalContinuation => "call_to_exceptional_continuation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcfgEdge {
    pub source: IcfgNodeId,
    pub target: IcfgNodeId,
    pub kind: IcfgEdgeKind,
    pub origin: Option<CallSiteHandle>,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IcfgLimitKind {
    CallDepth,
    Nodes,
    Edges,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IcfgBoundaryKind {
    Dispatch(DispatchBoundaryKind),
    Limit(IcfgLimitKind),
    Continuation {
        kind: CallContinuationKind,
        state: ControlContinuation,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcfgBoundary {
    pub at: IcfgNodeId,
    pub origin: Option<CallSiteHandle>,
    pub kind: IcfgBoundaryKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcfgSnapshotLimits {
    pub max_call_depth: u32,
    pub max_nodes: usize,
    pub max_edges: usize,
}

impl IcfgSnapshotLimits {
    pub fn new(
        max_call_depth: u32,
        max_nodes: usize,
        max_edges: usize,
    ) -> Result<Self, InvalidIcfgSnapshotLimits> {
        let limits = Self {
            max_call_depth,
            max_nodes,
            max_edges,
        };
        limits.validate()?;
        Ok(limits)
    }

    fn validate(self) -> Result<(), InvalidIcfgSnapshotLimits> {
        if self.max_call_depth == 0 || self.max_nodes == 0 || self.max_edges == 0 {
            return Err(InvalidIcfgSnapshotLimits);
        }
        Ok(())
    }
}

impl Default for IcfgSnapshotLimits {
    fn default() -> Self {
        Self {
            max_call_depth: 8,
            max_nodes: 50_000,
            max_edges: 200_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidIcfgSnapshotLimits;

impl fmt::Display for InvalidIcfgSnapshotLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ICFG call-depth, node, and edge limits must be greater than zero")
    }
}

impl std::error::Error for InvalidIcfgSnapshotLimits {}

/// A bounded, dense, traversal-ready ICFG slice.
#[derive(Debug, Clone)]
pub struct IcfgSnapshot {
    nodes: Box<[IcfgNodeKey]>,
    edges: Box<[IcfgEdge]>,
    outgoing_offsets: Box<[u32]>,
    incoming_offsets: Box<[u32]>,
    incoming_edge_ids: Box<[IcfgEdgeId]>,
    boundaries: Box<[IcfgBoundary]>,
}

impl IcfgSnapshot {
    fn empty() -> Self {
        Self {
            nodes: Box::new([]),
            edges: Box::new([]),
            outgoing_offsets: Box::new([0]),
            incoming_offsets: Box::new([0]),
            incoming_edge_ids: Box::new([]),
            boundaries: Box::new([]),
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn node_ids(&self) -> impl ExactSizeIterator<Item = IcfgNodeId> + '_ {
        (0..self.nodes.len()).map(|index| {
            IcfgNodeId::try_from_index(index).expect("published ICFG node IDs fit in u32")
        })
    }

    pub fn nodes(&self) -> &[IcfgNodeKey] {
        &self.nodes
    }

    pub fn edges(&self) -> &[IcfgEdge] {
        &self.edges
    }

    pub fn boundaries(&self) -> &[IcfgBoundary] {
        &self.boundaries
    }

    pub fn node(&self, id: IcfgNodeId) -> Option<&IcfgNodeKey> {
        self.nodes.get(id.index())
    }

    pub fn edge(&self, id: IcfgEdgeId) -> Option<&IcfgEdge> {
        self.edges.get(id.index())
    }

    pub fn successor_edges(
        &self,
        node: IcfgNodeId,
    ) -> impl ExactSizeIterator<Item = (IcfgEdgeId, &IcfgEdge)> + '_ {
        let range = compact_row(&self.outgoing_offsets, node.index(), self.edges.len());
        range.map(|index| {
            let id = IcfgEdgeId::try_from_index(index).expect("published ICFG edge IDs fit in u32");
            (id, &self.edges[index])
        })
    }

    pub fn predecessor_edges(
        &self,
        node: IcfgNodeId,
    ) -> impl ExactSizeIterator<Item = (IcfgEdgeId, &IcfgEdge)> + '_ {
        let range = compact_row(
            &self.incoming_offsets,
            node.index(),
            self.incoming_edge_ids.len(),
        );
        range.map(|index| {
            let id = self.incoming_edge_ids[index];
            (id, &self.edges[id.index()])
        })
    }
}

fn compact_row(offsets: &[u32], row: usize, stored_len: usize) -> std::ops::Range<usize> {
    let Some((&start, &end)) = offsets.get(row).zip(offsets.get(row.saturating_add(1))) else {
        return stored_len..stored_len;
    };
    start as usize..end as usize
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CallFrame {
    origin: CallSiteHandle,
    callee: ProcedureHandle,
    proof: ProofStatus,
    completeness: EvidenceCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TraversalKey {
    point: ProgramPointHandle,
    frames: Box<[CallFrame]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotQuality {
    Complete,
    Ambiguous,
    Unproven,
    Unknown,
    Unsupported(SemanticCapability),
    Truncated,
    Cancelled,
}

struct SnapshotBuilder {
    limits: IcfgSnapshotLimits,
    interner: HashMap<TraversalKey, IcfgNodeId>,
    traversal: Vec<TraversalKey>,
    nodes: Vec<IcfgNodeKey>,
    edges: Vec<IcfgEdge>,
    edge_set: HashSet<IcfgEdge>,
    boundaries: Vec<IcfgBoundary>,
    queue: VecDeque<IcfgNodeId>,
    return_path_masks: HashMap<(ProcedureHandle, ProgramPointId), Box<[bool]>>,
    quality: SnapshotQuality,
    budget_exceeded: Option<SemanticBudgetExceeded>,
    work: SemanticWork,
}

impl SnapshotBuilder {
    fn new(limits: IcfgSnapshotLimits) -> Self {
        Self {
            limits,
            interner: HashMap::default(),
            traversal: Vec::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            edge_set: HashSet::default(),
            boundaries: Vec::new(),
            queue: VecDeque::new(),
            return_path_masks: HashMap::default(),
            quality: SnapshotQuality::Complete,
            budget_exceeded: None,
            work: SemanticWork::default(),
        }
    }

    fn intern(
        &mut self,
        key: TraversalKey,
        request: &mut SemanticRequest<'_>,
        boundary_at: Option<IcfgNodeId>,
        origin: Option<CallSiteHandle>,
    ) -> Result<Option<(IcfgNodeId, bool)>, SemanticProviderError> {
        if let Some(id) = self.interner.get(&key).copied() {
            return Ok(Some((id, false)));
        }
        if self.nodes.len() >= self.limits.max_nodes {
            self.quality = SnapshotQuality::Truncated;
            if let Some(at) = boundary_at {
                self.boundaries.push(IcfgBoundary {
                    at,
                    origin,
                    kind: IcfgBoundaryKind::Limit(IcfgLimitKind::Nodes),
                });
            }
            return Ok(None);
        }
        let work = node_work(&key);
        if let Err(exceeded) = request.budget.charge(work) {
            self.budget_exceeded = Some(exceeded);
            self.quality = SnapshotQuality::Truncated;
            return Ok(None);
        }
        self.work = self.work.conservative_add(work);
        self.publish_node(key).map(|id| Some((id, true)))
    }

    fn publish_node(&mut self, key: TraversalKey) -> Result<IcfgNodeId, SemanticProviderError> {
        let id = IcfgNodeId::try_from_index(self.nodes.len())?;
        let call_context = key
            .frames
            .iter()
            .map(|frame| frame.origin.clone())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        self.nodes.push(IcfgNodeKey {
            point: key.point.clone(),
            call_context,
        });
        self.traversal.push(key.clone());
        self.interner.insert(key, id);
        self.queue.push_back(id);
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    fn link(
        &mut self,
        source: IcfgNodeId,
        target_key: TraversalKey,
        kind: IcfgEdgeKind,
        origin: Option<CallSiteHandle>,
        proof: ProofStatus,
        completeness: EvidenceCompleteness,
        request: &mut SemanticRequest<'_>,
    ) -> Result<Option<IcfgNodeId>, SemanticProviderError> {
        let existing_target = self.interner.get(&target_key).copied();
        if existing_target.is_none() && self.nodes.len() >= self.limits.max_nodes {
            self.quality = SnapshotQuality::Truncated;
            self.boundaries.push(IcfgBoundary {
                at: source,
                origin,
                kind: IcfgBoundaryKind::Limit(IcfgLimitKind::Nodes),
            });
            return Ok(None);
        }
        if self.edges.len() >= self.limits.max_edges {
            self.quality = SnapshotQuality::Truncated;
            self.boundaries.push(IcfgBoundary {
                at: source,
                origin,
                kind: IcfgBoundaryKind::Limit(IcfgLimitKind::Edges),
            });
            return Ok(None);
        }
        let node_work = existing_target.is_none().then(|| node_work(&target_key));
        let edge_work = SemanticWork {
            control_edges: 1,
            nested_entries: 1,
            ..SemanticWork::default()
        };
        let mut staged_budget = request.budget.clone();
        if let Some(work) = node_work
            && let Err(exceeded) = staged_budget.charge(work)
        {
            self.budget_exceeded = Some(exceeded);
            self.quality = SnapshotQuality::Truncated;
            return Ok(None);
        }
        if let Err(exceeded) = staged_budget.charge(edge_work) {
            self.budget_exceeded = Some(exceeded);
            self.quality = SnapshotQuality::Truncated;
            return Ok(None);
        }
        let target = match existing_target {
            Some(target) => target,
            None => self.publish_node(target_key)?,
        };
        let edge = IcfgEdge {
            source,
            target,
            kind,
            origin,
            proof,
            completeness,
        };
        if self.edge_set.contains(&edge) {
            // A duplicate discovered after interning cannot own a new target.
            debug_assert!(existing_target.is_some());
            return Ok(Some(target));
        }
        *request.budget = staged_budget;
        let work = node_work.map_or(edge_work, |node| node.conservative_add(edge_work));
        self.work = self.work.conservative_add(work);
        self.edge_set.insert(edge.clone());
        self.edges.push(edge);
        Ok(Some(target))
    }

    fn record_dispatch_boundaries(&mut self, at: IcfgNodeId, boundaries: &[CallBoundary]) {
        for boundary in boundaries {
            self.boundaries.push(IcfgBoundary {
                at,
                origin: Some(boundary.origin.clone()),
                kind: IcfgBoundaryKind::Dispatch(boundary.dispatch.kind.clone()),
            });
        }
    }

    fn absorb_quality<T>(&mut self, outcome: &SemanticOutcome<T>) {
        let incoming = match outcome {
            SemanticOutcome::Complete { .. } => SnapshotQuality::Complete,
            SemanticOutcome::Ambiguous { .. } => SnapshotQuality::Ambiguous,
            SemanticOutcome::Unknown { .. } => SnapshotQuality::Unknown,
            SemanticOutcome::Unsupported { capability, .. } => {
                SnapshotQuality::Unsupported(*capability)
            }
            SemanticOutcome::Unproven { .. } => SnapshotQuality::Unproven,
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                self.budget_exceeded = Some(*exceeded);
                SnapshotQuality::Truncated
            }
            SemanticOutcome::Cancelled { .. } => SnapshotQuality::Cancelled,
        };
        self.quality = merge_quality(self.quality, incoming);
    }

    fn freeze(mut self) -> Result<IcfgSnapshot, SemanticProviderError> {
        self.edges.sort_by_key(icfg_edge_sort_key);
        let node_count = self.nodes.len();
        let mut incoming_counts = vec![0_u32; node_count];
        for edge in &self.edges {
            validate_frozen_edge(edge, node_count)?;
            let count = &mut incoming_counts[edge.target.index()];
            *count = count
                .checked_add(1)
                .ok_or_else(|| SemanticProviderError::internal("ICFG incoming row overflow"))?;
        }

        let mut outgoing_offsets = Vec::with_capacity(node_count.saturating_add(1));
        outgoing_offsets.push(0_u32);
        let mut cursor = 0usize;
        for source in 0..node_count {
            while cursor < self.edges.len() && self.edges[cursor].source.index() == source {
                cursor += 1;
            }
            outgoing_offsets.push(u32::try_from(cursor).map_err(|_| {
                SemanticProviderError::internal("ICFG outgoing offsets exceed u32")
            })?);
        }
        debug_assert_eq!(
            cursor,
            self.edges.len(),
            "frozen edge sources were validated"
        );

        let mut incoming_offsets = Vec::with_capacity(node_count.saturating_add(1));
        incoming_offsets.push(0_u32);
        for count in incoming_counts {
            let next = incoming_offsets
                .last()
                .copied()
                .unwrap_or_default()
                .checked_add(count)
                .ok_or_else(|| SemanticProviderError::internal("ICFG incoming offsets overflow"))?;
            incoming_offsets.push(next);
        }
        let mut incoming_edge_ids = vec![IcfgEdgeId::default(); self.edges.len()];
        let mut incoming_cursors = incoming_offsets[..node_count].to_vec();
        for (index, edge) in self.edges.iter().enumerate() {
            let target = edge.target.index();
            let destination = incoming_cursors[target] as usize;
            incoming_edge_ids[destination] = IcfgEdgeId::try_from_index(index)?;
            incoming_cursors[target] = incoming_cursors[target]
                .checked_add(1)
                .ok_or_else(|| SemanticProviderError::internal("ICFG incoming cursor overflow"))?;
        }

        self.boundaries.sort_by_key(icfg_boundary_sort_key);
        self.boundaries.dedup();
        Ok(IcfgSnapshot {
            nodes: self.nodes.into_boxed_slice(),
            edges: self.edges.into_boxed_slice(),
            outgoing_offsets: outgoing_offsets.into_boxed_slice(),
            incoming_offsets: incoming_offsets.into_boxed_slice(),
            incoming_edge_ids: incoming_edge_ids.into_boxed_slice(),
            boundaries: self.boundaries.into_boxed_slice(),
        })
    }
}

fn validate_frozen_edge(edge: &IcfgEdge, node_count: usize) -> Result<(), SemanticProviderError> {
    if edge.source.index() >= node_count {
        return Err(SemanticProviderError::internal(
            "ICFG edge has an out-of-range source",
        ));
    }
    if edge.target.index() >= node_count {
        return Err(SemanticProviderError::internal(
            "ICFG edge has an out-of-range target",
        ));
    }
    if !matches!(edge.kind, IcfgEdgeKind::Intraprocedural(_)) && edge.origin.is_none() {
        return Err(SemanticProviderError::internal(
            "interprocedural ICFG edge has no originating call site",
        ));
    }
    Ok(())
}

fn node_work(key: &TraversalKey) -> SemanticWork {
    SemanticWork {
        program_points: 1,
        nested_entries: key.frames.len().saturating_add(2),
        ..SemanticWork::default()
    }
}

fn merge_quality(current: SnapshotQuality, incoming: SnapshotQuality) -> SnapshotQuality {
    use SnapshotQuality::*;
    match (current, incoming) {
        (Cancelled, _) | (_, Cancelled) => Cancelled,
        (Truncated, _) | (_, Truncated) => Truncated,
        // The public outcome can carry only one unsupported capability. Use
        // stable capability order so aggregation is independent of traversal
        // and gap-emission order.
        (Unsupported(left), Unsupported(right)) => Unsupported(left.min(right)),
        (Unsupported(capability), _) | (_, Unsupported(capability)) => Unsupported(capability),
        (Unknown, _) | (_, Unknown) => Unknown,
        (Unproven, _) | (_, Unproven) => Unproven,
        (Ambiguous, _) | (_, Ambiguous) => Ambiguous,
        (Complete, Complete) => Complete,
    }
}

fn icfg_edge_sort_key(edge: &IcfgEdge) -> (usize, u8, usize, u32) {
    (
        edge.source.index(),
        icfg_edge_kind_rank(edge.kind),
        edge.target.index(),
        edge.origin
            .as_ref()
            .map_or(u32::MAX, |call| call.id().get()),
    )
}

fn icfg_edge_kind_rank(kind: IcfgEdgeKind) -> u8 {
    match kind {
        IcfgEdgeKind::Intraprocedural(control) => control_edge_kind_rank(control),
        IcfgEdgeKind::Call => 16,
        IcfgEdgeKind::NormalReturn => 17,
        IcfgEdgeKind::ExceptionalReturn => 18,
        IcfgEdgeKind::CallToNormalContinuation => 19,
        IcfgEdgeKind::CallToExceptionalContinuation => 20,
    }
}

fn control_edge_kind_rank(kind: ControlEdgeKind) -> u8 {
    match kind {
        ControlEdgeKind::Normal => 0,
        ControlEdgeKind::ConditionalTrue => 1,
        ControlEdgeKind::ConditionalFalse => 2,
        ControlEdgeKind::SwitchCase => 3,
        ControlEdgeKind::LoopBack => 4,
        ControlEdgeKind::Exceptional => 5,
        ControlEdgeKind::Cleanup => 6,
        ControlEdgeKind::AsyncNormal => 7,
        ControlEdgeKind::AsyncExceptional => 8,
    }
}

fn icfg_boundary_sort_key(boundary: &IcfgBoundary) -> (usize, u32, u8) {
    (
        boundary.at.index(),
        boundary
            .origin
            .as_ref()
            .map_or(u32::MAX, |origin| origin.id().get()),
        match boundary.kind {
            IcfgBoundaryKind::Dispatch(_) => 0,
            IcfgBoundaryKind::Limit(_) => 1,
            IcfgBoundaryKind::Continuation { .. } => 2,
        },
    )
}

impl DispatchOracle for WorkspaceIcfgProvider<'_> {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
        self.oracle.resolve_call(call, request)
    }
}
impl IcfgProvider for WorkspaceIcfgProvider<'_> {
    fn call_transfers(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        let semantic_call = caller
            .semantics()
            .call_site(call)
            .ok_or_else(|| SemanticProviderError::internal(format!("unknown call site {call}")))?
            .clone();
        let origin = caller
            .call_site_handle(call)
            .ok_or_else(|| SemanticProviderError::internal("failed to scope semantic call site"))?;
        let call_evaluation_gaps = scoped_call_evaluation_gaps(caller, &semantic_call);
        let mut staged_budget = request.budget.clone();
        let dispatch_outcome = self.resolve_call(
            &origin,
            &mut SemanticRequest::new(&mut staged_budget, request.cancellation),
        )?;
        let mapped = try_map_semantic_outcome(dispatch_outcome, |dispatch| {
            let mut transfers = Vec::new();
            let mut additional_work = SemanticWork::default();
            let (candidates, dispatch_boundaries, _) = dispatch.into_parts();
            let mut boundaries = dispatch_boundaries
                .into_vec()
                .into_iter()
                .map(|dispatch| CallBoundary {
                    origin: origin.clone(),
                    dispatch,
                    model: None,
                })
                .collect::<Vec<_>>();
            for candidate in candidates.into_vec() {
                let properties = candidate.target.semantics().properties();
                if properties.invocation == ProcedureInvocationKind::Deferred {
                    let previous_reason_bytes = completeness_reason_bytes(&candidate.completeness);
                    let completeness = EvidenceCompleteness::Partial(
                        "callee body execution requires a later resume transfer".into(),
                    );
                    let added_reason_bytes = completeness_reason_bytes(&completeness)
                        .saturating_sub(previous_reason_bytes);
                    let target = candidate.target.semantics().locator().clone();
                    let boundary_kind = DispatchBoundaryKind::Deferred {
                        target: target.clone(),
                        kind: deferred_invocation_kind(properties),
                    };
                    let (provenance, provenance_work) = deferred_boundary_provenance(
                        &origin,
                        &boundary_kind,
                        &candidate.provenance,
                        *self.oracle.limits(),
                    )?;
                    boundaries.push(CallBoundary {
                        origin: origin.clone(),
                        dispatch: DispatchBoundary {
                            kind: boundary_kind,
                            proof: candidate.proof,
                            completeness,
                            provenance,
                        },
                        // Creating the suspended object normally returns to the
                        // caller, while argument binding or language call
                        // mechanics can still fail synchronously.
                        model: Some(CallToReturnModel::NormalAndExceptional),
                    });
                    // The candidate row was already charged by dispatch. The
                    // transfer projection additionally owns its cloned locator,
                    // boundary-kind relation, and newly retained reason text.
                    additional_work = sum_semantic_work(
                        additional_work,
                        sum_semantic_work(
                            semantic_locator_work(&target),
                            sum_semantic_work(
                                provenance_work,
                                SemanticWork {
                                    owned_text_bytes: added_reason_bytes,
                                    ..SemanticWork::default()
                                },
                            ),
                        ),
                    );
                    continue;
                }
                let Some(entry) = candidate
                    .target
                    .point_handle(candidate.target.semantics().entry_point())
                else {
                    continue;
                };
                transfers.push(CallTransfer {
                    origin: origin.clone(),
                    callee: candidate.target,
                    callee_entry: entry,
                    normal_continuation: semantic_call.normal_continuation,
                    exceptional_continuation: semantic_call.exceptional_continuation,
                    proof: candidate.proof,
                    completeness: candidate.completeness,
                });
            }
            let mut transfer_set = CallTransferSet {
                transfers: transfers.into_boxed_slice(),
                boundaries: boundaries.into_boxed_slice(),
            };
            additional_work = sum_semantic_work(
                additional_work,
                SemanticWork {
                    owned_text_bytes: apply_call_evaluation_gaps(
                        &call_evaluation_gaps,
                        &mut transfer_set,
                    ),
                    ..SemanticWork::default()
                },
            );
            Ok((transfer_set, additional_work))
        })?;
        let additional_work = mapped
            .available_value()
            .map_or(SemanticWork::default(), |(_, work)| *work);
        let original_work = mapped.work();
        let total_work = sum_semantic_work(original_work, additional_work);
        if let Some(outcome) = charge_call_transfer_projection(
            &mapped,
            &mut staged_budget,
            additional_work,
            total_work,
            request.cancellation,
        ) {
            return Ok(outcome);
        }
        let mut outcome = weaken_call_transfer_outcome(
            mapped.map(|(transfer_set, _)| transfer_set),
            &call_evaluation_gaps,
            total_work,
        );
        if request.cancellation.is_cancelled()
            && !matches!(outcome, SemanticOutcome::Cancelled { .. })
        {
            outcome = cancelled_call_transfer_outcome(outcome, total_work);
        }
        if outcome.available_value().is_some() {
            *request.budget = staged_budget;
        }
        Ok(outcome)
    }

    fn snapshot(
        &self,
        root: &ProcedureHandle,
        limits: IcfgSnapshotLimits,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgSnapshot>, SemanticProviderError> {
        limits
            .validate()
            .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let max_source_bytes = request.budget.remaining().source_bytes;
        let Some((_, root_source)) =
            exact_source_for_procedure(self.workspace(), root, max_source_bytes)?
        else {
            let work = SemanticWork {
                source_bytes: max_source_bytes.saturating_add(1),
                ..SemanticWork::default()
            };
            let exceeded = request.budget.check(work).map_or_else(
                |exceeded| exceeded,
                |_| unreachable!("bounded root-source omission must exceed the remaining budget"),
            );
            return Ok(SemanticOutcome::ExceededBudget {
                partial: Some(IcfgSnapshot::empty()),
                exceeded,
                work,
            });
        };
        let root_entry = root
            .point_handle(root.semantics().entry_point())
            .ok_or_else(|| SemanticProviderError::internal("root procedure has no entry point"))?;
        let mut staged_budget = request.budget.clone();
        let root_work = SemanticWork {
            source_bytes: root_source.len(),
            ..SemanticWork::default()
        };
        if let Err(exceeded) = staged_budget.charge(root_work) {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: Some(IcfgSnapshot::empty()),
                exceeded,
                work: root_work,
            });
        }
        let mut staged_request = SemanticRequest::new(&mut staged_budget, request.cancellation);
        let mut builder = SnapshotBuilder::new(limits);
        let mut transfer_cache: HashMap<CallSiteHandle, SemanticOutcome<CallTransferSet>> =
            HashMap::default();
        builder.work = root_work;
        builder.intern(
            TraversalKey {
                point: root_entry,
                frames: Box::new([]),
            },
            &mut staged_request,
            None,
            None,
        )?;

        while let Some(node) = builder.queue.pop_front() {
            if request.cancellation.is_cancelled() {
                builder.quality = SnapshotQuality::Cancelled;
                break;
            }
            let key = builder.traversal[node.index()].clone();
            if expand_return(&mut builder, node, &key, &mut staged_request)? {
                continue;
            }
            let semantic_point = key
                .point
                .procedure()
                .semantics()
                .point(key.point.id())
                .ok_or_else(|| SemanticProviderError::internal("ICFG point handle is stale"))?;
            let call = semantic_point
                .events
                .iter()
                .find_map(|event| match event.effect {
                    super::SemanticEffect::Invoke { call_site } => Some(call_site),
                    _ => None,
                });

            if let Some(call) = call {
                let semantic_call = key
                    .point
                    .procedure()
                    .semantics()
                    .call_site(call)
                    .ok_or_else(|| SemanticProviderError::internal("invoke event has no call row"))?
                    .clone();
                let origin = key
                    .point
                    .procedure()
                    .call_site_handle(call)
                    .ok_or_else(|| {
                        SemanticProviderError::internal("failed to scope invoke call")
                    })?;

                if key.frames.len() >= limits.max_call_depth as usize {
                    builder.quality = merge_quality(builder.quality, SnapshotQuality::Truncated);
                    builder.boundaries.push(IcfgBoundary {
                        at: node,
                        origin: Some(origin.clone()),
                        kind: IcfgBoundaryKind::Limit(IcfgLimitKind::CallDepth),
                    });
                } else {
                    let (outcome, newly_resolved) = if let Some(cached) =
                        transfer_cache.get(&origin)
                    {
                        (cached.clone(), false)
                    } else {
                        let outcome =
                            self.call_transfers(key.point.procedure(), call, &mut staged_request)?;
                        transfer_cache.insert(origin.clone(), outcome.clone());
                        (outcome, true)
                    };
                    builder.absorb_quality(&outcome);
                    if newly_resolved {
                        builder.work = builder.work.conservative_add(outcome.work());
                    }
                    if let Some(transfers) = outcome.available_value().cloned() {
                        builder.record_dispatch_boundaries(node, &transfers.boundaries);
                        for boundary in &transfers.boundaries {
                            link_boundary_continuations(
                                &mut builder,
                                node,
                                &key,
                                &semantic_call,
                                boundary,
                                &mut staged_request,
                            )?;
                        }
                        for transfer in transfers.transfers.into_vec() {
                            let mut frames = key.frames.to_vec();
                            frames.push(CallFrame {
                                origin: transfer.origin.clone(),
                                callee: transfer.callee.clone(),
                                proof: transfer.proof.clone(),
                                completeness: transfer.completeness.clone(),
                            });
                            let target_key = TraversalKey {
                                point: transfer.callee_entry.clone(),
                                frames: frames.into_boxed_slice(),
                            };
                            builder.link(
                                node,
                                target_key,
                                IcfgEdgeKind::Call,
                                Some(origin.clone()),
                                transfer.proof,
                                transfer.completeness,
                                &mut staged_request,
                            )?;
                        }
                    }
                }

                // Preserve any unusual non-scaffolding local edges, while the
                // known normal/exceptional continuation rows are replaced by
                // call and matched-return transfers.
                for (_, edge) in key
                    .point
                    .procedure()
                    .semantics()
                    .successor_edges(key.point.id())
                {
                    if is_call_scaffolding(edge, &semantic_call) {
                        continue;
                    }
                    add_local_edge(&mut builder, node, &key, edge, &mut staged_request)?;
                }
            } else {
                for (_, edge) in key
                    .point
                    .procedure()
                    .semantics()
                    .successor_edges(key.point.id())
                {
                    add_local_edge(&mut builder, node, &key, edge, &mut staged_request)?;
                }
            }
        }

        let quality = builder.quality;
        let exceeded = builder.budget_exceeded;
        let work = builder.work;
        let snapshot = builder.freeze()?;
        *request.budget = staged_budget;
        Ok(finish_snapshot_outcome(snapshot, quality, exceeded, work))
    }
}

fn charge_call_transfer_projection(
    mapped: &SemanticOutcome<(CallTransferSet, SemanticWork)>,
    budget: &mut super::SemanticBudget,
    additional_work: SemanticWork,
    total_work: SemanticWork,
    cancellation: &crate::cancellation::CancellationToken,
) -> Option<SemanticOutcome<CallTransferSet>> {
    budget.charge(additional_work).err().map(|exceeded| {
        if matches!(mapped, SemanticOutcome::Cancelled { .. }) || cancellation.is_cancelled() {
            SemanticOutcome::Cancelled {
                // The projected payload cannot be published when its atomic
                // retained-work charge fails, but the operation-level
                // cancellation still takes precedence over that failure.
                partial: None,
                work: total_work,
            }
        } else {
            SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work: total_work,
            }
        }
    })
}

fn cancelled_call_transfer_outcome(
    outcome: SemanticOutcome<CallTransferSet>,
    work: SemanticWork,
) -> SemanticOutcome<CallTransferSet> {
    let partial = match outcome {
        SemanticOutcome::Complete { value, .. } => Some(value),
        SemanticOutcome::Ambiguous { candidates, .. } => Some(candidates),
        SemanticOutcome::Unproven { partial, .. } => Some(partial),
        SemanticOutcome::Unknown { partial, .. }
        | SemanticOutcome::Unsupported { partial, .. }
        | SemanticOutcome::ExceededBudget { partial, .. }
        | SemanticOutcome::Cancelled { partial, .. } => partial,
    };
    SemanticOutcome::Cancelled { partial, work }
}

fn finish_snapshot_outcome(
    snapshot: IcfgSnapshot,
    quality: SnapshotQuality,
    exceeded: Option<SemanticBudgetExceeded>,
    work: SemanticWork,
) -> SemanticOutcome<IcfgSnapshot> {
    if quality == SnapshotQuality::Cancelled {
        return SemanticOutcome::Cancelled {
            partial: Some(snapshot),
            work,
        };
    }
    if let Some(exceeded) = exceeded {
        return SemanticOutcome::ExceededBudget {
            partial: Some(snapshot),
            exceeded,
            work,
        };
    }
    match quality {
        SnapshotQuality::Complete => SemanticOutcome::Complete {
            value: snapshot,
            work,
        },
        SnapshotQuality::Ambiguous => SemanticOutcome::Ambiguous {
            candidates: snapshot,
            work,
        },
        SnapshotQuality::Unproven => SemanticOutcome::Unproven {
            partial: snapshot,
            work,
        },
        SnapshotQuality::Unknown | SnapshotQuality::Truncated => SemanticOutcome::Unknown {
            partial: Some(snapshot),
            work,
        },
        SnapshotQuality::Unsupported(capability) => SemanticOutcome::Unsupported {
            capability,
            partial: Some(snapshot),
            work,
        },
        SnapshotQuality::Cancelled => unreachable!("cancelled snapshots return above"),
    }
}

fn try_map_semantic_outcome<T, U>(
    outcome: SemanticOutcome<T>,
    mapper: impl FnOnce(T) -> Result<U, SemanticProviderError>,
) -> Result<SemanticOutcome<U>, SemanticProviderError> {
    Ok(match outcome {
        SemanticOutcome::Complete { value, work } => SemanticOutcome::Complete {
            value: mapper(value)?,
            work,
        },
        SemanticOutcome::Ambiguous { candidates, work } => SemanticOutcome::Ambiguous {
            candidates: mapper(candidates)?,
            work,
        },
        SemanticOutcome::Unknown { partial, work } => SemanticOutcome::Unknown {
            partial: partial.map(mapper).transpose()?,
            work,
        },
        SemanticOutcome::Unsupported {
            capability,
            partial,
            work,
        } => SemanticOutcome::Unsupported {
            capability,
            partial: partial.map(mapper).transpose()?,
            work,
        },
        SemanticOutcome::Unproven { partial, work } => SemanticOutcome::Unproven {
            partial: mapper(partial)?,
            work,
        },
        SemanticOutcome::ExceededBudget {
            partial,
            exceeded,
            work,
        } => SemanticOutcome::ExceededBudget {
            partial: partial.map(mapper).transpose()?,
            exceeded,
            work,
        },
        SemanticOutcome::Cancelled { partial, work } => SemanticOutcome::Cancelled {
            partial: partial.map(mapper).transpose()?,
            work,
        },
    })
}

fn deferred_boundary_provenance(
    origin: &CallSiteHandle,
    boundary: &DispatchBoundaryKind,
    candidate_provenance: &[OracleRelationHandle],
    limits: OracleLimits,
) -> Result<(Box<[OracleRelationHandle]>, SemanticWork), SemanticProviderError> {
    let DispatchBoundaryKind::Deferred { target, .. } = boundary else {
        return Err(SemanticProviderError::internal(
            "deferred boundary provenance requires a deferred boundary identity",
        ));
    };
    let expected_owner = OracleRelationOwner::Dispatch(origin.clone());
    let mut evidence = Vec::<EvidenceHandle>::new();
    for relation in candidate_provenance {
        if relation.owner() != &expected_owner
            || relation.record().kind() != OracleRelationKind::DispatchCandidate
            || !matches!(
                relation.record().subject(),
                Some(OracleRelationSubject::DispatchCandidate(candidate))
                    if candidate.semantics().locator() == target
            )
        {
            return Err(SemanticProviderError::internal(
                "deferred transfer candidate has invalid dispatch provenance",
            ));
        }
        for retained in relation.record().evidence() {
            if !evidence.contains(retained) {
                evidence.push(retained.clone());
            }
        }
    }
    if evidence.is_empty() {
        return Err(SemanticProviderError::internal(
            "deferred transfer candidate has no semantic evidence",
        ));
    }
    let evidence_entries = evidence.len();
    let record = OracleRelationRecord::dispatch_boundary(boundary.clone(), evidence, limits)
        .map_err(|error| {
            SemanticProviderError::internal(format!(
                "could not project deferred dispatch-boundary provenance: {error}"
            ))
        })?;
    let arena =
        OracleRelationArena::new(expected_owner, vec![record], limits).map_err(|error| {
            SemanticProviderError::internal(format!(
                "could not project deferred dispatch-boundary provenance: {error}"
            ))
        })?;
    let relation = arena
        .handle(OracleRelationId::new(0))
        .expect("deferred dispatch-boundary relation was inserted");
    let subject_work = semantic_locator_work(target);
    Ok((
        vec![relation].into_boxed_slice(),
        SemanticWork {
            // One payload handle, one arena record, and the record's evidence
            // array are retained independently by this projection. The exact
            // boundary subject additionally deep-clones its target locator.
            nested_entries: 2usize
                .saturating_add(evidence_entries)
                .saturating_add(subject_work.nested_entries),
            owned_text_bytes: subject_work.owned_text_bytes,
            ..subject_work
        },
    ))
}

fn scoped_call_evaluation_gaps<'a>(
    procedure: &'a ProcedureHandle,
    call: &SemanticCallSite,
) -> Vec<&'a SemanticGap> {
    procedure
        .semantics()
        .gaps()
        .iter()
        .filter(|gap| call_evaluation_gap_applies(gap, call))
        .collect()
}

fn call_evaluation_gap_applies(gap: &SemanticGap, call: &SemanticCallSite) -> bool {
    gap.impacts.contains(SemanticGapImpact::CallEvaluation)
        && match gap.subject {
            SemanticGapSubject::Procedure => true,
            SemanticGapSubject::Point => gap.point == call.point,
            SemanticGapSubject::CallSite(call_site) => {
                call_site == call.id && gap.point == call.point
            }
            SemanticGapSubject::Value(_)
            | SemanticGapSubject::MemoryLocation(_)
            | SemanticGapSubject::Capture(_)
            | SemanticGapSubject::CallContinuation { .. }
            | SemanticGapSubject::AsyncContinuation { .. } => false,
        }
}

fn apply_call_evaluation_gaps(gaps: &[&SemanticGap], transfers: &mut CallTransferSet) -> usize {
    if gaps.is_empty() {
        return 0;
    }
    let detail = gaps
        .iter()
        .map(|gap| {
            format!(
                "{} {}: {}",
                gap.kind.label(),
                gap.capability.label(),
                gap.detail
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    transfers
        .transfers
        .iter_mut()
        .map(|transfer| {
            let previous_reason_bytes = completeness_reason_bytes(&transfer.completeness);
            transfer.completeness = EvidenceCompleteness::Partial(match &transfer.completeness {
                EvidenceCompleteness::Complete => {
                    format!("caller-side call evaluation is incomplete: {detail}").into()
                }
                EvidenceCompleteness::Partial(existing) => {
                    format!("{existing}; caller-side call evaluation gaps: {detail}").into()
                }
            });
            completeness_reason_bytes(&transfer.completeness).saturating_sub(previous_reason_bytes)
        })
        .fold(0usize, usize::saturating_add)
}

fn weaken_call_transfer_outcome(
    outcome: SemanticOutcome<CallTransferSet>,
    gaps: &[&SemanticGap],
    work: SemanticWork,
) -> SemanticOutcome<CallTransferSet> {
    if gaps.is_empty() {
        return call_transfer_outcome_with_work(outcome, work);
    }
    let gap_quality = gaps.iter().fold(SnapshotQuality::Complete, |quality, gap| {
        merge_quality(quality, semantic_gap_quality(gap))
    });
    match outcome {
        SemanticOutcome::Complete { value, .. } => call_transfer_outcome(value, gap_quality, work),
        SemanticOutcome::Ambiguous { candidates, .. } => call_transfer_outcome(
            candidates,
            merge_quality(SnapshotQuality::Ambiguous, gap_quality),
            work,
        ),
        SemanticOutcome::Unproven { partial, .. } => call_transfer_outcome(
            partial,
            merge_quality(SnapshotQuality::Unproven, gap_quality),
            work,
        ),
        SemanticOutcome::Unknown {
            partial: Some(partial),
            ..
        } => call_transfer_outcome(
            partial,
            merge_quality(SnapshotQuality::Unknown, gap_quality),
            work,
        ),
        SemanticOutcome::Unknown { partial: None, .. } => SemanticOutcome::Unknown {
            partial: None,
            work,
        },
        SemanticOutcome::Unsupported {
            capability,
            partial: Some(partial),
            ..
        } => call_transfer_outcome(
            partial,
            merge_quality(SnapshotQuality::Unsupported(capability), gap_quality),
            work,
        ),
        SemanticOutcome::Unsupported {
            capability,
            partial: None,
            ..
        } => SemanticOutcome::Unsupported {
            capability,
            partial: None,
            work,
        },
        SemanticOutcome::ExceededBudget {
            partial, exceeded, ..
        } => SemanticOutcome::ExceededBudget {
            partial,
            exceeded,
            work,
        },
        SemanticOutcome::Cancelled { partial, .. } => SemanticOutcome::Cancelled { partial, work },
    }
}

fn call_transfer_outcome(
    transfers: CallTransferSet,
    quality: SnapshotQuality,
    work: SemanticWork,
) -> SemanticOutcome<CallTransferSet> {
    match quality {
        SnapshotQuality::Complete => SemanticOutcome::Complete {
            value: transfers,
            work,
        },
        SnapshotQuality::Ambiguous => SemanticOutcome::Ambiguous {
            candidates: transfers,
            work,
        },
        SnapshotQuality::Unproven | SnapshotQuality::Truncated => SemanticOutcome::Unproven {
            partial: transfers,
            work,
        },
        SnapshotQuality::Unknown => SemanticOutcome::Unknown {
            partial: Some(transfers),
            work,
        },
        SnapshotQuality::Unsupported(capability) => SemanticOutcome::Unsupported {
            capability,
            partial: Some(transfers),
            work,
        },
        SnapshotQuality::Cancelled => SemanticOutcome::Cancelled {
            partial: Some(transfers),
            work,
        },
    }
}

fn call_transfer_outcome_with_work(
    outcome: SemanticOutcome<CallTransferSet>,
    work: SemanticWork,
) -> SemanticOutcome<CallTransferSet> {
    match outcome {
        SemanticOutcome::Complete { value, .. } => SemanticOutcome::Complete { value, work },
        SemanticOutcome::Ambiguous { candidates, .. } => {
            SemanticOutcome::Ambiguous { candidates, work }
        }
        SemanticOutcome::Unknown { partial, .. } => SemanticOutcome::Unknown { partial, work },
        SemanticOutcome::Unsupported {
            capability,
            partial,
            ..
        } => SemanticOutcome::Unsupported {
            capability,
            partial,
            work,
        },
        SemanticOutcome::Unproven { partial, .. } => SemanticOutcome::Unproven { partial, work },
        SemanticOutcome::ExceededBudget {
            partial, exceeded, ..
        } => SemanticOutcome::ExceededBudget {
            partial,
            exceeded,
            work,
        },
        SemanticOutcome::Cancelled { partial, .. } => SemanticOutcome::Cancelled { partial, work },
    }
}

fn completeness_reason_bytes(completeness: &EvidenceCompleteness) -> usize {
    match completeness {
        EvidenceCompleteness::Complete => 0,
        EvidenceCompleteness::Partial(reason) => reason.len(),
    }
}

fn sum_semantic_work(left: SemanticWork, right: SemanticWork) -> SemanticWork {
    left.conservative_add(right)
}

fn scoped_return_affecting_gap_indices(
    builder: &mut SnapshotBuilder,
    procedure: &ProcedureHandle,
    exit: ProgramPointId,
) -> Vec<usize> {
    let semantics = procedure.semantics();
    let path_mask = builder
        .return_path_masks
        .get(&(procedure.clone(), exit))
        .expect("return path mask must be cached before gap selection");
    semantics
        .gaps()
        .iter()
        .enumerate()
        .filter_map(|(index, gap)| {
            let return_affecting = gap.impacts.contains(SemanticGapImpact::ReturnTransfer);
            let scoped_to_return_path = match gap.subject {
                SemanticGapSubject::Procedure => true,
                _ => path_mask.get(gap.point.index()).copied() == Some(true),
            };
            (return_affecting && scoped_to_return_path).then_some(index)
        })
        .collect()
}

fn cache_return_path_mask(
    builder: &mut SnapshotBuilder,
    procedure: &ProcedureHandle,
    exit: ProgramPointId,
    request: &mut SemanticRequest<'_>,
) -> bool {
    let cache_key = (procedure.clone(), exit);
    if builder.return_path_masks.contains_key(&cache_key) {
        return true;
    }

    let semantics = procedure.semantics();
    let point_count = semantics.points().len();
    let edge_count = semantics.control_edges().len();
    let gap_count = semantics.gaps().len();
    let scan_work = SemanticWork {
        program_points: point_count.saturating_mul(2),
        control_edges: edge_count.saturating_mul(2),
        gaps: gap_count,
        nested_entries: point_count
            .saturating_mul(2)
            .saturating_add(edge_count.saturating_mul(2))
            .saturating_add(gap_count),
        ..SemanticWork::default()
    };
    if let Err(exceeded) = request.budget.charge(scan_work) {
        builder.budget_exceeded = Some(exceeded);
        builder.quality = merge_quality(builder.quality, SnapshotQuality::Truncated);
        return false;
    }
    builder.work = builder.work.conservative_add(scan_work);

    let algorithm_limits = CfgAlgorithmWork {
        node_visits: point_count.saturating_mul(2),
        edge_visits: edge_count.saturating_mul(2),
    };
    let mut algorithm_budget = CfgAlgorithmBudget::new(algorithm_limits);
    let mut algorithm_request =
        CfgAlgorithmRequest::new(&mut algorithm_budget, request.cancellation);
    let from_entry =
        match forward_reachability(semantics, semantics.entry_point(), &mut algorithm_request) {
            Ok(reachable) => reachable,
            Err(CfgAlgorithmError::Cancelled { .. }) => {
                builder.quality = SnapshotQuality::Cancelled;
                return false;
            }
            Err(CfgAlgorithmError::ExceededBudget(exceeded)) => {
                unreachable!(
                    "precharged return-path traversal exceeded its complete-graph {:?} limit: \
                     attempted {}, limit {}, work {:?}",
                    exceeded.limit_kind, exceeded.attempted, exceeded.limit, exceeded.work
                );
            }
            Err(CfgAlgorithmError::InvalidNode(point)) => {
                unreachable!("validated procedure has an invalid entry point {point}");
            }
        };
    let to_exit = match reverse_reachability(semantics, exit, &mut algorithm_request) {
        Ok(reachable) => reachable,
        Err(CfgAlgorithmError::Cancelled { .. }) => {
            builder.quality = SnapshotQuality::Cancelled;
            return false;
        }
        Err(CfgAlgorithmError::ExceededBudget(exceeded)) => {
            unreachable!(
                "precharged return-path traversal exceeded its complete-graph {:?} limit: \
                 attempted {}, limit {}, work {:?}",
                exceeded.limit_kind, exceeded.attempted, exceeded.limit, exceeded.work
            );
        }
        Err(CfgAlgorithmError::InvalidNode(point)) => {
            unreachable!("validated procedure has an invalid exit point {point}");
        }
    };
    debug_assert_eq!(algorithm_budget.limits(), algorithm_limits);

    let path_mask = from_entry
        .membership()
        .iter()
        .copied()
        .zip(to_exit.membership().iter().copied())
        .map(|(reachable, reaches_exit)| reachable && reaches_exit)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    builder.return_path_masks.insert(cache_key, path_mask);
    true
}

fn semantic_gap_quality(gap: &SemanticGap) -> SnapshotQuality {
    match gap.kind {
        SemanticGapKind::Ambiguous => SnapshotQuality::Ambiguous,
        SemanticGapKind::Unsupported => SnapshotQuality::Unsupported(gap.capability),
        SemanticGapKind::ExceededBudget => SnapshotQuality::Truncated,
        SemanticGapKind::Unknown | SemanticGapKind::Unproven => SnapshotQuality::Unproven,
    }
}

fn deferred_invocation_kind(properties: super::ProcedureProperties) -> DeferredInvocationKind {
    match (properties.is_async, properties.is_generator) {
        (true, true) => DeferredInvocationKind::AsyncGenerator,
        (true, false) => DeferredInvocationKind::Async,
        (false, true) => DeferredInvocationKind::Generator,
        (false, false) => DeferredInvocationKind::LanguageDefined,
    }
}

fn link_boundary_continuations(
    builder: &mut SnapshotBuilder,
    source: IcfgNodeId,
    key: &TraversalKey,
    semantic_call: &super::SemanticCallSite,
    boundary: &CallBoundary,
    request: &mut SemanticRequest<'_>,
) -> Result<(), SemanticProviderError> {
    let Some(model) = boundary.model else {
        return Ok(());
    };
    let mut link = |kind: CallContinuationKind,
                    continuation: ControlContinuation,
                    edge_kind: IcfgEdgeKind|
     -> Result<(), SemanticProviderError> {
        match continuation {
            ControlContinuation::Target(point) => {
                let point = key.point.procedure().point_handle(point).ok_or_else(|| {
                    SemanticProviderError::internal("call boundary continuation is stale")
                })?;
                builder.link(
                    source,
                    TraversalKey {
                        point,
                        frames: key.frames.clone(),
                    },
                    edge_kind,
                    Some(boundary.origin.clone()),
                    boundary.dispatch.proof.clone(),
                    boundary.dispatch.completeness.clone(),
                    request,
                )?;
            }
            ControlContinuation::Absent => {}
            state => {
                builder.boundaries.push(IcfgBoundary {
                    at: source,
                    origin: Some(boundary.origin.clone()),
                    kind: IcfgBoundaryKind::Continuation { kind, state },
                });
                builder.quality = merge_quality(builder.quality, SnapshotQuality::Unknown);
            }
        }
        Ok(())
    };
    if matches!(
        model,
        CallToReturnModel::Normal | CallToReturnModel::NormalAndExceptional
    ) {
        link(
            CallContinuationKind::Normal,
            semantic_call.normal_continuation,
            IcfgEdgeKind::CallToNormalContinuation,
        )?;
    }
    if matches!(
        model,
        CallToReturnModel::Exceptional | CallToReturnModel::NormalAndExceptional
    ) {
        link(
            CallContinuationKind::Exceptional,
            semantic_call.exceptional_continuation,
            IcfgEdgeKind::CallToExceptionalContinuation,
        )?;
    }
    Ok(())
}

fn expand_return(
    builder: &mut SnapshotBuilder,
    node: IcfgNodeId,
    key: &TraversalKey,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, SemanticProviderError> {
    let semantics = key.point.procedure().semantics();
    let (kind, continuation_kind, continuation) = if key.point.id() == semantics.normal_exit_point()
    {
        (
            IcfgEdgeKind::NormalReturn,
            CallContinuationKind::Normal,
            ReturnTransferKind::Normal,
        )
    } else if key.point.id() == semantics.exceptional_exit_point() {
        (
            IcfgEdgeKind::ExceptionalReturn,
            CallContinuationKind::Exceptional,
            ReturnTransferKind::Exceptional,
        )
    } else {
        return Ok(false);
    };
    let Some(frame) = key.frames.last() else {
        return Ok(false);
    };
    if frame.callee != *key.point.procedure() {
        return Err(SemanticProviderError::internal(
            "ICFG return context does not match the exiting callee",
        ));
    }
    let semantic_call = frame
        .origin
        .procedure()
        .semantics()
        .call_site(frame.origin.id())
        .ok_or_else(|| SemanticProviderError::internal("return origin call handle is stale"))?;
    if !cache_return_path_mask(builder, key.point.procedure(), key.point.id(), request) {
        return Ok(true);
    }
    let return_gap_indices =
        scoped_return_affecting_gap_indices(builder, key.point.procedure(), key.point.id());
    let return_gaps = return_gap_indices
        .iter()
        .map(|index| &semantics.gaps()[*index])
        .collect::<Vec<_>>();
    let (return_proof, return_completeness) = if return_gaps.is_empty() {
        (frame.proof.clone(), frame.completeness.clone())
    } else {
        for gap in &return_gaps {
            builder.quality = merge_quality(builder.quality, semantic_gap_quality(gap));
        }
        let gap_reason = return_gaps
            .iter()
            .map(|gap| {
                format!(
                    "{} {}: {}",
                    gap.kind.label(),
                    gap.capability.label(),
                    gap.detail
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let proof_reason = match &frame.proof {
            ProofStatus::Proven => format!(
                "callee-exit evidence does not prove this {:?} completion returns to its caller: {gap_reason}",
                continuation
            ),
            ProofStatus::Unproven(existing) => format!("{existing}; {gap_reason}"),
        };
        let completeness_reason = match &frame.completeness {
            EvidenceCompleteness::Complete => {
                format!("the callee exit has exact return-affecting semantic gaps: {gap_reason}")
            }
            EvidenceCompleteness::Partial(existing) => {
                format!("{existing}; return-affecting gaps: {gap_reason}")
            }
        };
        (
            ProofStatus::Unproven(proof_reason.into()),
            EvidenceCompleteness::Partial(completeness_reason.into()),
        )
    };
    let destination = match continuation {
        ReturnTransferKind::Normal => semantic_call.normal_continuation,
        ReturnTransferKind::Exceptional => semantic_call.exceptional_continuation,
    };
    match destination {
        ControlContinuation::Target(point) => {
            let target_point = frame
                .origin
                .procedure()
                .point_handle(point)
                .ok_or_else(|| SemanticProviderError::internal("return continuation is stale"))?;
            let target_key = TraversalKey {
                point: target_point.clone(),
                frames: key.frames[..key.frames.len() - 1]
                    .to_vec()
                    .into_boxed_slice(),
            };
            let transfer = ReturnTransfer {
                origin: frame.origin.clone(),
                callee_exit: key.point.clone(),
                continuation: target_point,
                kind: continuation,
            };
            builder.link(
                node,
                target_key,
                kind,
                Some(transfer.origin),
                return_proof,
                return_completeness,
                request,
            )?;
        }
        ControlContinuation::Absent => {}
        state => {
            builder.boundaries.push(IcfgBoundary {
                at: node,
                origin: Some(frame.origin.clone()),
                kind: IcfgBoundaryKind::Continuation {
                    kind: continuation_kind,
                    state,
                },
            });
            builder.quality = merge_quality(builder.quality, SnapshotQuality::Unknown);
        }
    }
    Ok(true)
}

fn add_local_edge(
    builder: &mut SnapshotBuilder,
    source: IcfgNodeId,
    key: &TraversalKey,
    edge: &super::ControlEdge,
    request: &mut SemanticRequest<'_>,
) -> Result<(), SemanticProviderError> {
    let point = key
        .point
        .procedure()
        .point_handle(edge.target_point)
        .ok_or_else(|| SemanticProviderError::internal("local CFG edge target is stale"))?;
    let target_key = TraversalKey {
        point,
        frames: key.frames.clone(),
    };
    builder.link(
        source,
        target_key,
        IcfgEdgeKind::Intraprocedural(edge.kind),
        None,
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
        request,
    )?;
    Ok(())
}

fn is_call_scaffolding(edge: &super::ControlEdge, call: &super::SemanticCallSite) -> bool {
    matches!(
        (edge.kind, call.normal_continuation),
        (ControlEdgeKind::Normal, ControlContinuation::Target(target)) if edge.target_point == target
    ) || matches!(
        (edge.kind, call.exceptional_continuation),
        (ControlEdgeKind::Exceptional, ControlContinuation::Target(target)) if edge.target_point == target
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::workspace_oracle::{
        CallableDefinitionIdentity, retain_dispatch_candidate,
    };
    use crate::analyzer::semantic::{
        CandidateCoverage, DeclarationSegment, DispatchCandidate, ProcedureKind, SemanticBudget,
        SemanticGapId, SemanticGapImpacts,
    };
    use crate::analyzer::{CodeUnit, CodeUnitType, ProjectFile};
    use crate::cancellation::CancellationToken;
    use crate::test_support::AnalyzerFixture;

    fn test_edge(source: u32, target: u32, kind: IcfgEdgeKind) -> IcfgEdge {
        IcfgEdge {
            source: IcfgNodeId::new(source),
            target: IcfgNodeId::new(target),
            kind,
            origin: None,
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
        }
    }

    #[test]
    fn frozen_edge_validation_owns_snapshot_invariants() {
        let local = test_edge(0, 1, IcfgEdgeKind::Intraprocedural(ControlEdgeKind::Normal));
        assert!(validate_frozen_edge(&local, 2).is_ok());

        let invalid_source =
            test_edge(2, 1, IcfgEdgeKind::Intraprocedural(ControlEdgeKind::Normal));
        assert!(
            validate_frozen_edge(&invalid_source, 2)
                .unwrap_err()
                .to_string()
                .contains("out-of-range source")
        );

        let invalid_target =
            test_edge(0, 2, IcfgEdgeKind::Intraprocedural(ControlEdgeKind::Normal));
        assert!(
            validate_frozen_edge(&invalid_target, 2)
                .unwrap_err()
                .to_string()
                .contains("out-of-range target")
        );

        let missing_origin = test_edge(0, 1, IcfgEdgeKind::Call);
        assert!(
            validate_frozen_edge(&missing_origin, 2)
                .unwrap_err()
                .to_string()
                .contains("no originating call site")
        );
    }

    #[test]
    fn unsupported_snapshot_quality_uses_stable_capability_order() {
        let deferred = SnapshotQuality::Unsupported(SemanticCapability::DeferredExecution);
        let cleanup = SnapshotQuality::Unsupported(SemanticCapability::CleanupControlFlow);

        let expected = SnapshotQuality::Unsupported(SemanticCapability::CleanupControlFlow);
        assert_eq!(merge_quality(deferred, cleanup), expected);
        assert_eq!(merge_quality(cleanup, deferred), expected);
    }

    #[test]
    fn cancelled_dispatch_precedes_a_failed_call_transfer_projection_charge() {
        let cancellation = CancellationToken::default();
        let additional_work = SemanticWork {
            nested_entries: 2,
            ..SemanticWork::default()
        };
        let mapped = SemanticOutcome::Cancelled {
            partial: Some((CallTransferSet::default(), additional_work)),
            work: SemanticWork::default(),
        };
        let mut budget = SemanticBudget::uniform(1).expect("positive semantic budget");

        let outcome = charge_call_transfer_projection(
            &mapped,
            &mut budget,
            additional_work,
            additional_work,
            &cancellation,
        )
        .expect("projection work must exceed the nested-entry budget");

        assert!(matches!(
            outcome,
            SemanticOutcome::Cancelled {
                partial: None,
                work,
            } if work == additional_work
        ));
        assert_eq!(budget.used(), SemanticWork::default());
    }

    #[test]
    fn snapshot_cancellation_precedes_an_existing_budget_exhaustion() {
        let attempted_work = SemanticWork {
            nested_entries: 2,
            ..SemanticWork::default()
        };
        let exceeded = SemanticBudget::uniform(1)
            .expect("positive semantic budget")
            .check(attempted_work)
            .expect_err("snapshot work must exceed the nested-entry budget");

        let outcome = finish_snapshot_outcome(
            IcfgSnapshot::empty(),
            SnapshotQuality::Cancelled,
            Some(exceeded),
            attempted_work,
        );

        assert!(matches!(
            outcome,
            SemanticOutcome::Cancelled {
                partial: Some(_),
                work,
            } if work == attempted_work
        ));
    }

    #[test]
    fn call_evaluation_gap_scope_covers_procedure_point_and_call_site() {
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::TypeScript,
            &[(
                "scope.ts",
                "function target() {}\nexport function caller() { target(); }\n",
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "scope.ts");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("TypeScript semantic materialization")
            .available_value()
            .cloned()
            .expect("TypeScript semantic artifact");
        let call = artifact
            .procedures()
            .iter()
            .find_map(|procedure| procedure.call_sites().first().cloned())
            .expect("semantic call site");
        let different_point = ProgramPointId::new(call.point.get().saturating_add(1));
        let gap = |subject, point, impacts| SemanticGap {
            id: SemanticGapId::new(0),
            point,
            subject,
            capability: SemanticCapability::Calls,
            impacts,
            kind: SemanticGapKind::Unproven,
            budget: None,
            detail: "caller-side evaluation is incomplete".into(),
            source: call.source,
            evidence: call.evidence,
        };

        assert!(call_evaluation_gap_applies(
            &gap(
                SemanticGapSubject::Procedure,
                different_point,
                SemanticGapImpacts::single(SemanticGapImpact::CallEvaluation),
            ),
            &call,
        ));
        assert!(call_evaluation_gap_applies(
            &gap(
                SemanticGapSubject::Point,
                call.point,
                SemanticGapImpacts::single(SemanticGapImpact::CallEvaluation),
            ),
            &call,
        ));
        assert!(!call_evaluation_gap_applies(
            &gap(
                SemanticGapSubject::Point,
                different_point,
                SemanticGapImpacts::single(SemanticGapImpact::CallEvaluation),
            ),
            &call,
        ));
        assert!(call_evaluation_gap_applies(
            &gap(
                SemanticGapSubject::CallSite(call.id),
                call.point,
                SemanticGapImpacts::single(SemanticGapImpact::CallEvaluation),
            ),
            &call,
        ));
        assert!(!call_evaluation_gap_applies(
            &gap(
                SemanticGapSubject::CallSite(CallSiteId::new(call.id.get().saturating_add(1),)),
                call.point,
                SemanticGapImpacts::single(SemanticGapImpact::CallEvaluation),
            ),
            &call,
        ));
        assert!(!call_evaluation_gap_applies(
            &gap(
                SemanticGapSubject::Procedure,
                call.point,
                SemanticGapImpacts::NONE,
            ),
            &call,
        ));
    }

    #[test]
    fn return_path_masks_are_scoped_to_distinct_artifact_instances() {
        fn materialize_handle() -> ProcedureHandle {
            let fixture = AnalyzerFixture::new_for_language(
                crate::analyzer::Language::TypeScript,
                &[(
                    "artifact-scope.ts",
                    "export function target(flag: boolean) {\n\
                     if (flag) { return; }\n\
                     return;\n\
                     const unreachable = 1;\n\
                     }\n",
                )],
            );
            let file = ProjectFile::new(fixture.project_root(), "artifact-scope.ts");
            let cancellation = CancellationToken::default();
            let mut budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("TypeScript semantic materialization")
                .available_value()
                .cloned()
                .expect("complete TypeScript semantic artifact");
            let procedure = artifact
                .procedures()
                .first()
                .expect("one TypeScript procedure");
            artifact
                .procedure_handle(procedure.id())
                .expect("procedure handle")
        }

        let first = materialize_handle();
        let second = materialize_handle();
        assert_eq!(first.id(), second.id());
        assert!(!std::sync::Arc::ptr_eq(first.artifact(), second.artifact()));
        assert_ne!(first, second);

        let mut builder = SnapshotBuilder::new(IcfgSnapshotLimits::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let first_exit = first.semantics().normal_exit_point();
        let second_exit = second.semantics().normal_exit_point();

        assert!(cache_return_path_mask(
            &mut builder,
            &first,
            first_exit,
            &mut request
        ));
        assert!(cache_return_path_mask(
            &mut builder,
            &second,
            second_exit,
            &mut request
        ));
        assert_eq!(builder.return_path_masks.len(), 2);
        assert!(
            builder
                .return_path_masks
                .contains_key(&(first.clone(), first_exit))
        );
        assert!(
            builder
                .return_path_masks
                .contains_key(&(second.clone(), second_exit))
        );
    }

    #[test]
    fn procedure_deferred_scheduling_does_not_weaken_a_nested_call_transfer() {
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::Rust,
            &[(
                "lib.rs",
                "pub fn leaf() -> i32 { 7 }\npub async fn scheduled() -> i32 { leaf() }\n",
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Rust semantic materialization")
            .available_value()
            .cloned()
            .expect("Rust semantic artifact");
        let scheduled = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("scheduled")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("scheduled procedure");
        let scheduling_gap = scheduled
            .semantics()
            .gaps()
            .iter()
            .find(|gap| {
                gap.subject == SemanticGapSubject::Procedure
                    && gap.capability == SemanticCapability::DeferredExecution
            })
            .expect("async procedure scheduling gap");
        assert!(
            !scheduling_gap
                .impacts
                .contains(SemanticGapImpact::CallEvaluation),
            "procedure scheduling must not claim that every represented nested call is incomplete"
        );
        let call = scheduled
            .semantics()
            .call_sites()
            .first()
            .expect("nested leaf call");
        let mut transfer_budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .icfg_provider()
            .call_transfers(
                &scheduled,
                call.id,
                &mut SemanticRequest::new(&mut transfer_budget, &cancellation),
            )
            .expect("nested leaf call transfer");
        assert!(
            !matches!(
                &outcome,
                SemanticOutcome::Unsupported {
                    capability: SemanticCapability::DeferredExecution,
                    ..
                }
            ),
            "procedure scheduling uncertainty must not downgrade the nested call: {outcome:#?}"
        );
        let transfers = outcome
            .available_value()
            .expect("nested call transfer payload");
        assert_eq!(transfers.transfers.len(), 1, "{transfers:#?}");
        assert!(transfers.transfers.iter().all(|transfer| {
            !matches!(
                &transfer.completeness,
                EvidenceCompleteness::Partial(reason)
                    if reason.contains("caller-side call evaluation")
            )
        }));
    }

    #[test]
    fn deferred_call_transfer_reprojects_provenance_and_charges_payload_atomically() {
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::Rust,
            &[
                ("leaf.rs", "pub async fn async_leaf() -> i32 { 7 }\n"),
                (
                    "lib.rs",
                    "mod leaf;\nuse crate::leaf::async_leaf;\npub fn make_future() { let _pending = async_leaf(); }\n",
                ),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Rust caller materialization")
            .available_value()
            .cloned()
            .expect("Rust caller artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("make_future")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("make_future procedure");
        let call = caller
            .semantics()
            .call_sites()
            .first()
            .and_then(|call| caller.call_site_handle(call.id))
            .expect("async_leaf call site");
        let provider = fixture.analyzer.icfg_provider();

        let mut dispatch_budget = SemanticBudget::default();
        let dispatch_outcome = provider
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
            )
            .expect("Rust async dispatch");
        assert_eq!(
            dispatch_outcome
                .available_value()
                .unwrap()
                .candidates()
                .len(),
            1
        );

        let mut transfer_budget = SemanticBudget::default();
        let transfer_outcome = provider
            .call_transfers(
                &caller,
                call.id(),
                &mut SemanticRequest::new(&mut transfer_budget, &cancellation),
            )
            .expect("Rust async call transfer");
        let transfers = transfer_outcome
            .available_value()
            .expect("deferred transfer payload");
        let deferred = transfers
            .boundaries
            .iter()
            .find(|boundary| {
                matches!(
                    boundary.dispatch.kind,
                    DispatchBoundaryKind::Deferred { .. }
                )
            })
            .expect("deferred call boundary");
        assert_eq!(deferred.dispatch.provenance.len(), 1);
        assert_eq!(
            deferred.dispatch.provenance[0].owner(),
            &OracleRelationOwner::Dispatch(call.clone())
        );
        assert_eq!(
            deferred.dispatch.provenance[0].record().kind(),
            OracleRelationKind::DispatchBoundary
        );
        assert!(matches!(
            deferred.dispatch.provenance[0].record().subject(),
            Some(OracleRelationSubject::DispatchBoundary(subject))
                if subject == &deferred.dispatch.kind
        ));
        assert!(
            !deferred.dispatch.provenance[0]
                .record()
                .evidence()
                .is_empty()
        );
        let candidate = &dispatch_outcome.available_value().unwrap().candidates()[0];
        let (projected, projected_work) = deferred_boundary_provenance(
            &call,
            &deferred.dispatch.kind,
            &candidate.provenance,
            OracleLimits::default(),
        )
        .expect("direct deferred provenance projection");
        let DispatchBoundaryKind::Deferred { target, .. } = &deferred.dispatch.kind else {
            unreachable!("selected boundary is deferred")
        };
        let locator_work = semantic_locator_work(target);
        assert_eq!(
            projected_work.owned_text_bytes,
            locator_work.owned_text_bytes
        );
        assert_eq!(
            projected_work.nested_entries,
            2 + projected[0].record().evidence().len() + locator_work.nested_entries
        );
        assert!(
            transfer_outcome.work().nested_entries
                >= dispatch_outcome.work().nested_entries.saturating_add(3)
        );
        assert_eq!(transfer_budget.used(), transfer_outcome.work());

        let mut limited = SemanticBudget::default().limits();
        limited.nested_entries = transfer_outcome.work().nested_entries.saturating_sub(1);
        let mut limited_budget =
            SemanticBudget::new(limited).expect("positive deferred projection budget");
        let limited_outcome = provider
            .call_transfers(
                &caller,
                call.id(),
                &mut SemanticRequest::new(&mut limited_budget, &cancellation),
            )
            .expect("limited Rust async call transfer");
        assert!(matches!(
            limited_outcome,
            SemanticOutcome::ExceededBudget {
                partial: None,
                work,
                ..
            } if work == transfer_outcome.work()
        ));
        assert_eq!(limited_budget.used(), SemanticWork::default());
    }

    #[test]
    fn cpp_header_definition_coalescing_is_unproven_and_excludes_unrelated_link_unit() {
        let header = "#pragma once\nnamespace api { int target(int value); }\n";
        let definition = concat!(
            "#include \"target.h\"\n",
            "namespace api { int target(int value) { return value + 1; } }\n",
        );
        let unrelated_header = "#pragma once\nnamespace api { int target(int value); }\n";
        let unrelated = concat!(
            "#include \"target.h\"\n",
            "namespace api { int target(int value) { return value + 2; } }\n",
        );
        let caller = concat!(
            "#include \"target.h\"\n",
            "int caller() { return api::target(1); }\n",
        );
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::Cpp,
            &[
                ("target.h", header),
                ("target.cpp", definition),
                ("other/target.h", unrelated_header),
                ("other/target.cpp", unrelated),
                ("caller.cpp", caller),
            ],
        );
        let caller_file = ProjectFile::new(fixture.project_root(), "caller.cpp");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &caller_file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("C++ caller materialization")
            .available_value()
            .cloned()
            .expect("C++ caller artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("caller")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("caller procedure");
        let call = caller
            .semantics()
            .call_sites()
            .first()
            .and_then(|call| caller.call_site_handle(call.id))
            .expect("target call site");

        let mut dispatch_budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .icfg_provider()
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
            )
            .expect("C++ exact dispatch");
        let dispatch = outcome.available_value().expect("dispatch payload");

        assert!(matches!(&outcome, SemanticOutcome::Unproven { .. }));
        assert_eq!(dispatch.candidates().len(), 1, "{dispatch:#?}");
        assert!(matches!(
            &dispatch.candidates()[0].proof,
            ProofStatus::Unproven(_)
        ));
        assert!(matches!(
            &dispatch.candidates()[0].completeness,
            EvidenceCompleteness::Partial(_)
        ));
        assert_eq!(
            dispatch.candidates()[0]
                .target
                .artifact()
                .key()
                .path()
                .as_str(),
            "target.cpp"
        );
        assert!(dispatch.boundaries().iter().any(|boundary| {
            boundary.kind == DispatchBoundaryKind::Unresolved
                && matches!(&boundary.proof, ProofStatus::Unproven(_))
                && matches!(&boundary.completeness, EvidenceCompleteness::Partial(_))
        }));

        let pre_cancelled = CancellationToken::default();
        pre_cancelled.cancel();
        let mut cancelled_budget = SemanticBudget::default();
        let cancelled = fixture
            .analyzer
            .icfg_provider()
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut cancelled_budget, &pre_cancelled),
            )
            .expect("pre-cancelled dispatch");
        assert!(matches!(
            cancelled,
            SemanticOutcome::Cancelled {
                partial: None,
                work
            } if work == SemanticWork::default()
        ));
        assert_eq!(cancelled_budget.used(), SemanticWork::default());
    }

    #[test]
    fn cpp_preprocessor_call_gap_opens_the_set_without_weakening_retained_candidates() {
        let source = r#"
int enabled_target(int value) { return value + 1; }
int disabled_target(int value) { return value + 2; }

int configured_caller(int value) {
#if FEATURE_ENABLED
    return enabled_target(value);
#else
    return disabled_target(value);
#endif
}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::Cpp,
            &[("configured.cpp", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "configured.cpp");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("C++ preprocessor materialization")
            .available_value()
            .cloned()
            .expect("C++ preprocessor artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("configured_caller")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("configured caller procedure");
        assert!(caller.semantics().gaps().iter().any(|gap| {
            gap.subject == SemanticGapSubject::Procedure
                && gap.capability == SemanticCapability::Calls
                && gap.kind == SemanticGapKind::Unsupported
                && gap.impacts.contains(SemanticGapImpact::DispatchCoverage)
        }));
        let call = caller
            .semantics()
            .call_sites()
            .first()
            .and_then(|call| caller.call_site_handle(call.id))
            .expect("conditionally compiled call site");

        let mut dispatch_budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .icfg_provider()
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
            )
            .expect("preprocessor call dispatch");
        let dispatch = outcome.available_value().expect("dispatch payload");

        assert!(matches!(&outcome, SemanticOutcome::Unproven { .. }));
        assert_eq!(dispatch.coverage(), CandidateCoverage::Open);
        assert_eq!(dispatch.candidates().len(), 1, "{dispatch:#?}");
        assert!(matches!(
            &dispatch.candidates()[0].proof,
            ProofStatus::Proven
        ));
        assert!(matches!(
            &dispatch.candidates()[0].completeness,
            EvidenceCompleteness::Complete
        ));
        assert!(dispatch.boundaries().iter().any(|boundary| {
            boundary.kind == DispatchBoundaryKind::Unresolved
                && matches!(&boundary.proof, ProofStatus::Unproven(_))
                && matches!(&boundary.completeness, EvidenceCompleteness::Partial(_))
        }));
    }

    #[test]
    fn ruby_procedure_call_gap_is_not_a_cpp_configuration_gap() {
        let source = r#"
class Widget
  def initialize
    helper
  end

  def helper
    1
  end
end
"#;
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::Ruby,
            &[("widget.rb", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "widget.rb");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Ruby materialization")
            .available_value()
            .cloned()
            .expect("Ruby artifact");
        let constructor = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.kind() == ProcedureKind::Constructor)
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("Ruby initialize procedure");

        assert!(constructor.semantics().gaps().iter().any(|gap| {
            gap.subject == SemanticGapSubject::Procedure
                && gap.capability == SemanticCapability::Calls
                && gap.kind == SemanticGapKind::Unsupported
                && !gap.impacts.contains(SemanticGapImpact::DispatchCoverage)
        }));
        assert!(
            crate::analyzer::semantic::workspace_oracle::scoped_procedure_dispatch_gap(
                &constructor
            )
            .is_none()
        );
    }

    #[test]
    fn typescript_imported_target_does_not_admit_unrelated_same_name_body() {
        let target = "export function target(value: number) { return value + 1; }\n";
        let unrelated = "export function target(value: number) { return value + 2; }\n";
        let caller = concat!(
            "import { target } from './target';\n",
            "export function caller() { return target(1); }\n",
        );
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::TypeScript,
            &[
                ("target.ts", target),
                ("unrelated.ts", unrelated),
                ("caller.ts", caller),
            ],
        );
        let caller_file = ProjectFile::new(fixture.project_root(), "caller.ts");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &caller_file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("TypeScript caller materialization")
            .available_value()
            .cloned()
            .expect("TypeScript caller artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("caller")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("caller procedure");
        let call = caller
            .semantics()
            .call_sites()
            .first()
            .and_then(|call| caller.call_site_handle(call.id))
            .expect("target call site");

        let mut dispatch_budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .icfg_provider()
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
            )
            .expect("TypeScript exact dispatch");
        let dispatch = outcome.available_value().expect("dispatch payload");

        assert!(matches!(&outcome, SemanticOutcome::Unproven { .. }));
        assert_eq!(dispatch.coverage(), CandidateCoverage::Open);
        assert_eq!(dispatch.candidates().len(), 1, "{dispatch:#?}");
        assert!(matches!(
            &dispatch.candidates()[0].proof,
            ProofStatus::Proven
        ));
        assert!(matches!(
            &dispatch.candidates()[0].completeness,
            EvidenceCompleteness::Complete
        ));
        assert_eq!(
            dispatch.candidates()[0]
                .target
                .artifact()
                .key()
                .path()
                .as_str(),
            "target.ts"
        );
        assert!(dispatch.boundaries().iter().any(|boundary| {
            boundary.kind == DispatchBoundaryKind::Unresolved
                && matches!(&boundary.proof, ProofStatus::Unproven(_))
                && matches!(&boundary.completeness, EvidenceCompleteness::Partial(_))
        }));
    }

    #[test]
    fn cpp_dynamic_dispatch_gap_adds_an_open_target_arm_only_to_virtual_stitch() {
        let source = r#"
struct Base {
    virtual int dynamic_call(int value) { return value; }
    int direct_call(int value) { return value + 1; }
};

int invoke_dynamic(Base* receiver) {
    return receiver->dynamic_call(1);
}

int invoke_direct(Base* receiver) {
    return receiver->Base::direct_call(1);
}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::Cpp,
            &[("dispatch.cpp", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "dispatch.cpp");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("C++ dispatch materialization")
            .available_value()
            .cloned()
            .expect("C++ dispatch artifact");
        let procedure = |name: &str| {
            artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(DeclarationSegment::name)
                        == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .unwrap_or_else(|| panic!("missing {name} procedure"))
        };
        let dynamic_caller = procedure("invoke_dynamic");
        let direct_caller = procedure("invoke_direct");
        let dynamic_call = dynamic_caller
            .semantics()
            .call_sites()
            .first()
            .expect("dynamic call site");
        let direct_call = direct_caller
            .semantics()
            .call_sites()
            .first()
            .expect("direct call site");

        assert!(dynamic_caller.semantics().gaps().iter().any(|gap| {
            gap.point == dynamic_call.point
                && gap.capability == SemanticCapability::DynamicDispatch
                && gap.impacts.contains(SemanticGapImpact::DispatchCoverage)
                && (gap.subject == SemanticGapSubject::Point
                    || gap.subject == SemanticGapSubject::CallSite(dynamic_call.id))
        }));
        assert!(!direct_caller.semantics().gaps().iter().any(|gap| {
            gap.point == direct_call.point
                && gap.capability == SemanticCapability::DynamicDispatch
                && (gap.subject == SemanticGapSubject::Point
                    || gap.subject == SemanticGapSubject::CallSite(direct_call.id))
        }));
        assert!(direct_caller.semantics().gaps().iter().any(|gap| {
            gap.point == direct_call.point
                && gap.subject == SemanticGapSubject::CallSite(direct_call.id)
                && gap.impacts.contains(SemanticGapImpact::CallEvaluation)
                && !gap.impacts.contains(SemanticGapImpact::DispatchCoverage)
        }));

        let provider = fixture.analyzer.icfg_provider();
        let dynamic_call_handle = dynamic_caller
            .call_site_handle(dynamic_call.id)
            .expect("dynamic call handle");
        let direct_call_handle = direct_caller
            .call_site_handle(direct_call.id)
            .expect("direct call handle");
        let mut dynamic_dispatch_budget = SemanticBudget::default();
        let dynamic_dispatch = provider
            .resolve_call(
                &dynamic_call_handle,
                &mut SemanticRequest::new(&mut dynamic_dispatch_budget, &cancellation),
            )
            .expect("virtual C++ dispatch")
            .available_value()
            .cloned()
            .expect("virtual C++ dispatch payload");
        assert_eq!(dynamic_dispatch.coverage(), CandidateCoverage::Open);

        let mut direct_dispatch_budget = SemanticBudget::default();
        let direct_dispatch_outcome = provider
            .resolve_call(
                &direct_call_handle,
                &mut SemanticRequest::new(&mut direct_dispatch_budget, &cancellation),
            )
            .expect("qualified C++ dispatch");
        assert!(matches!(
            &direct_dispatch_outcome,
            SemanticOutcome::Complete { .. }
        ));
        let direct_dispatch = direct_dispatch_outcome
            .available_value()
            .cloned()
            .expect("qualified C++ dispatch payload");
        assert_eq!(direct_dispatch.coverage(), CandidateCoverage::Exhaustive);
        assert_eq!(
            direct_dispatch.candidates().len(),
            1,
            "{direct_dispatch:#?}"
        );
        assert!(matches!(
            direct_dispatch.candidates()[0].proof,
            ProofStatus::Proven
        ));
        assert!(matches!(
            direct_dispatch.candidates()[0].completeness,
            EvidenceCompleteness::Complete
        ));
        let direct_dispatch_work = direct_dispatch_outcome.work();
        let mut projection_limits = SemanticBudget::default().limits();
        projection_limits.nested_entries = direct_dispatch_work.nested_entries.saturating_sub(1);
        let mut projection_budget = SemanticBudget::new(projection_limits)
            .expect("dispatch projection limits remain positive");
        let projection_limited = provider
            .resolve_call(
                &direct_call_handle,
                &mut SemanticRequest::new(&mut projection_budget, &cancellation),
            )
            .expect("projection-limited dispatch");
        assert!(matches!(
            projection_limited,
            SemanticOutcome::ExceededBudget {
                partial: None,
                work,
                ..
            } if work.nested_entries == direct_dispatch_work.nested_entries
        ));
        assert_eq!(projection_budget.used(), SemanticWork::default());

        let mut dynamic_budget = SemanticBudget::default();
        let dynamic_outcome = provider
            .call_transfers(
                &dynamic_caller,
                dynamic_call.id,
                &mut SemanticRequest::new(&mut dynamic_budget, &cancellation),
            )
            .expect("virtual C++ call transfers");
        assert!(matches!(&dynamic_outcome, SemanticOutcome::Unproven { .. }));
        let dynamic = dynamic_outcome
            .available_value()
            .expect("virtual dispatch transfers");
        assert_eq!(dynamic.transfers.len(), 1, "{dynamic:#?}");
        assert!(matches!(&dynamic.transfers[0].proof, ProofStatus::Proven));
        assert!(matches!(
            &dynamic.transfers[0].completeness,
            // The open virtual target set does not weaken this retained
            // candidate's proof. Independent caller-side evaluation gaps do
            // still make the executable transfer incomplete.
            EvidenceCompleteness::Partial(_)
        ));
        assert!(dynamic.boundaries.iter().any(|boundary| {
            boundary.dispatch.kind == DispatchBoundaryKind::Unresolved
                && matches!(&boundary.dispatch.proof, ProofStatus::Unproven(_))
                && matches!(
                    &boundary.dispatch.completeness,
                    EvidenceCompleteness::Partial(_)
                )
        }));

        let mut direct_budget = SemanticBudget::default();
        let direct_outcome = provider
            .call_transfers(
                &direct_caller,
                direct_call.id,
                &mut SemanticRequest::new(&mut direct_budget, &cancellation),
            )
            .expect("explicitly qualified C++ call transfers");
        assert!(matches!(&direct_outcome, SemanticOutcome::Unproven { .. }));
        let direct = direct_outcome
            .available_value()
            .expect("non-virtual dispatch transfers");
        assert_eq!(direct.transfers.len(), 1, "{direct:#?}");
        assert!(matches!(&direct.transfers[0].proof, ProofStatus::Proven));
        assert!(matches!(
            &direct.transfers[0].completeness,
            EvidenceCompleteness::Partial(_)
        ));
        assert!(direct.boundaries.is_empty(), "{direct:#?}");
        assert!(
            direct_outcome.work().owned_text_bytes > direct_dispatch_work.owned_text_bytes,
            "call-evaluation reason text must be retained and charged only by call transfer"
        );
        assert_eq!(direct_budget.used(), direct_outcome.work());
    }

    #[test]
    fn cpp_syntax_error_elsewhere_does_not_weaken_an_exact_call_dispatch() {
        let source = r#"
int exact_target() { return 1; }

int caller_with_error() {
    int malformed = ;
    return exact_target();
}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::Cpp,
            &[("syntax_error.cpp", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "syntax_error.cpp");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("C++ syntax-error materialization")
            .available_value()
            .cloned()
            .expect("C++ syntax-error artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("caller_with_error")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("caller procedure");
        let call = caller
            .semantics()
            .call_sites()
            .first()
            .and_then(|call| caller.call_site_handle(call.id))
            .expect("exact target call site");

        assert!(caller.semantics().gaps().iter().any(|gap| {
            gap.subject == SemanticGapSubject::Procedure
                && gap.capability == SemanticCapability::Calls
                && gap.kind == SemanticGapKind::Unsupported
                && !gap.impacts.contains(SemanticGapImpact::DispatchCoverage)
        }));

        let mut dispatch_budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .icfg_provider()
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
            )
            .expect("exact C++ dispatch despite unrelated syntax error");
        assert!(matches!(&outcome, SemanticOutcome::Complete { .. }));
        let dispatch = outcome.available_value().expect("exact dispatch payload");
        assert_eq!(dispatch.coverage(), CandidateCoverage::Exhaustive);
        assert_eq!(dispatch.candidates().len(), 1, "{dispatch:#?}");
    }

    #[test]
    fn cpp_conditional_noexcept_gap_downgrades_exceptional_return() {
        let source = r#"
void conditional_target() noexcept(sizeof(int) == 4) {
    throw 1;
}

void conditional_caller() {
    conditional_target();
}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::Cpp,
            &[("conditional_noexcept.cpp", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "conditional_noexcept.cpp");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("conditional-noexcept materialization")
            .available_value()
            .cloned()
            .expect("conditional-noexcept artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("conditional_caller")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("conditional caller procedure");

        let mut snapshot_budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .icfg_provider()
            .snapshot(
                &caller,
                IcfgSnapshotLimits::default(),
                &mut SemanticRequest::new(&mut snapshot_budget, &cancellation),
            )
            .expect("conditional-noexcept ICFG snapshot");
        assert!(matches!(&outcome, SemanticOutcome::Unproven { .. }));
        let snapshot = outcome
            .available_value()
            .expect("conditional-noexcept partial snapshot");
        let exceptional_returns = snapshot
            .edges()
            .iter()
            .filter(|edge| edge.kind == IcfgEdgeKind::ExceptionalReturn)
            .collect::<Vec<_>>();
        assert_eq!(exceptional_returns.len(), 1, "{snapshot:#?}");
        assert!(matches!(
            exceptional_returns[0].proof,
            ProofStatus::Unproven(_)
        ));
        assert!(matches!(
            exceptional_returns[0].completeness,
            EvidenceCompleteness::Partial(_)
        ));
    }

    #[test]
    fn cpp_raii_exit_gap_downgrades_normal_return() {
        let source = r#"
struct Guard {
    Guard();
    ~Guard();
};

void raii_target() {
    Guard guard;
}

void raii_caller() {
    raii_target();
}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::Cpp,
            &[("raii_return.cpp", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "raii_return.cpp");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("RAII materialization")
            .available_value()
            .cloned()
            .expect("RAII artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("raii_caller")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("RAII caller procedure");

        let mut snapshot_budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .icfg_provider()
            .snapshot(
                &caller,
                IcfgSnapshotLimits::default(),
                &mut SemanticRequest::new(&mut snapshot_budget, &cancellation),
            )
            .expect("RAII ICFG snapshot");
        assert!(matches!(&outcome, SemanticOutcome::Unproven { .. }));
        let snapshot = outcome.available_value().expect("RAII partial snapshot");
        let normal_returns = snapshot
            .edges()
            .iter()
            .filter(|edge| edge.kind == IcfgEdgeKind::NormalReturn)
            .collect::<Vec<_>>();
        assert_eq!(normal_returns.len(), 1, "{snapshot:#?}");
        assert!(matches!(normal_returns[0].proof, ProofStatus::Unproven(_)));
        assert!(matches!(
            normal_returns[0].completeness,
            EvidenceCompleteness::Partial(_)
        ));
    }

    #[test]
    fn cpp_bodyless_callable_identity_emits_one_unmaterialized_boundary() {
        let header = "#pragma once\nint target(int value);\n";
        let caller = "#include \"target.h\"\nint caller() { return target(1); }\n";
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::Cpp,
            &[("target.h", header), ("caller.cpp", caller)],
        );
        let caller_file = ProjectFile::new(fixture.project_root(), "caller.cpp");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &caller_file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("C++ caller materialization")
            .available_value()
            .cloned()
            .expect("C++ caller artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("caller")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("caller procedure");
        let call = caller
            .semantics()
            .call_sites()
            .first()
            .and_then(|call| caller.call_site_handle(call.id))
            .expect("target call site");

        let mut dispatch_budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .icfg_provider()
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
            )
            .expect("C++ exact dispatch");
        let dispatch = outcome.available_value().expect("dispatch payload");

        assert!(dispatch.candidates().is_empty(), "{dispatch:#?}");
        assert_eq!(dispatch.boundaries().len(), 1, "{dispatch:#?}");
        assert!(matches!(
            dispatch.boundaries()[0].kind,
            DispatchBoundaryKind::Unmaterialized(_)
        ));
    }

    #[test]
    fn final_dispatch_limit_counts_unique_materialized_procedures() {
        let source = concat!(
            "export function first() { return 1; }\n",
            "export function second() { return 2; }\n",
        );
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::TypeScript,
            &[("targets.ts", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "targets.ts");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("TypeScript materialization")
            .available_value()
            .cloned()
            .expect("TypeScript artifact");
        let mut procedures = artifact
            .procedures()
            .iter()
            .filter_map(|procedure| artifact.procedure_handle(procedure.id()))
            .collect::<Vec<_>>();
        procedures
            .sort_by(|left, right| left.semantics().locator().cmp(right.semantics().locator()));
        assert_eq!(procedures.len(), 2);

        let candidate = |target: ProcedureHandle| {
            DispatchCandidate::new(
                target,
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                std::iter::empty(),
                OracleLimits::default(),
            )
            .expect("an empty dispatch draft fits every positive provenance limit")
        };
        let mut retained = Vec::new();
        let mut indexes = HashMap::default();
        assert!(!retain_dispatch_candidate(
            &mut retained,
            &mut indexes,
            candidate(procedures[0].clone()),
            1,
        ));
        assert!(!retain_dispatch_candidate(
            &mut retained,
            &mut indexes,
            candidate(procedures[0].clone()),
            1,
        ));
        assert!(retain_dispatch_candidate(
            &mut retained,
            &mut indexes,
            candidate(procedures[1].clone()),
            1,
        ));
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].target, procedures[0]);
    }

    #[test]
    fn workspace_icfg_provider_remains_copy() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<WorkspaceIcfgProvider<'static>>();
    }

    #[test]
    fn callable_definition_identity_keeps_cpp_sources_and_overloads_distinct() {
        let root = std::env::temp_dir();
        let header = ProjectFile::new(root.clone(), "target.h");
        let source = ProjectFile::new(root, "target.cpp");
        let declaration = CodeUnit::with_signature(
            header,
            CodeUnitType::Function,
            "",
            "target",
            Some("(int)".to_string()),
            false,
        );
        let definition = CodeUnit::with_signature(
            source.clone(),
            CodeUnitType::Function,
            "",
            "target",
            Some("(int)".to_string()),
            false,
        );
        let overload = CodeUnit::with_signature(
            source,
            CodeUnitType::Function,
            "",
            "target",
            Some("(double)".to_string()),
            false,
        );

        assert_ne!(
            CallableDefinitionIdentity::with_source_scope(
                &declaration,
                Some(declaration.source().clone())
            ),
            CallableDefinitionIdentity::with_source_scope(
                &definition,
                Some(definition.source().clone())
            )
        );
        assert_ne!(
            CallableDefinitionIdentity::with_source_scope(
                &definition,
                Some(definition.source().clone())
            ),
            CallableDefinitionIdentity::with_source_scope(
                &overload,
                Some(overload.source().clone())
            )
        );
    }
}
