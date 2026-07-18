//! Demand-materialized, language-neutral interprocedural control flow.
//!
//! Callable CFGs remain immutable and procedure-local. This module stitches a
//! bounded, generation-local view on demand and never builds an eager
//! whole-workspace graph.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;

use crate::analyzer::usages::get_definition::DefinitionLookupStatus;
use crate::analyzer::usages::{
    CallDispatchBoundaryKind, CallRelationLimits, CallRelationService, ExactCallLocation,
    UsageProof,
};
use crate::analyzer::{
    CodeUnit, CodeUnitType, IAnalyzer, LanguageDialect, ProjectFile, ProjectSourceOrigin, Range,
    WorkspaceAnalyzer,
};
use crate::hash::{HashMap, HashSet};

use super::{
    CallContinuationKind, CallSiteHandle, CallSiteId, ContentIdentity, ControlContinuation,
    ControlEdgeKind, DeclarationLocator, DeclarationSegment, DeclarationSegmentKind,
    EvidenceCompleteness, OverlaySnapshotId, ProcedureHandle, ProcedureInvocationKind,
    ProcedureKind, ProgramPointHandle, ProofStatus, SemanticBudgetExceeded, SemanticCapability,
    SemanticLocator, SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticRole,
    SemanticWork, SourceAnchor, SourcePosition, SourceRevision, SourceSpan, WorkspaceMountId,
    WorkspaceRelativePath,
};

const MAX_DISPATCH_TARGETS: usize = 1_024;

/// One materialized workspace target for an exact semantic call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchCandidate {
    pub target: ProcedureHandle,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

/// A dispatch arm that cannot enter a materialized workspace procedure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DispatchBoundaryKind {
    /// The resolver proved that the target crosses the indexed workspace
    /// boundary. Older resolver paths cannot always name that declaration.
    External(Option<SemanticLocator>),
    /// A declaration was resolved, but no callable body was published by the
    /// language adapter for this generation.
    Unmaterialized(SemanticLocator),
    /// Dispatch resolved a callable body, but invoking it only creates a
    /// suspended object. Entering that body requires a later language-level
    /// resume operation that this control-only ICFG does not yet model.
    Deferred {
        target: SemanticLocator,
        kind: DeferredInvocationKind,
    },
    Unresolved,
    Truncated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeferredInvocationKind {
    Async,
    Generator,
    AsyncGenerator,
    LanguageDefined,
}

impl DeferredInvocationKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Async => "async",
            Self::Generator => "generator",
            Self::AsyncGenerator => "async_generator",
            Self::LanguageDefined => "language_defined",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DispatchBoundary {
    pub kind: DispatchBoundaryKind,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DispatchResult {
    pub candidates: Box<[DispatchCandidate]>,
    pub boundaries: Box<[DispatchBoundary]>,
}

/// Location-first whole-program dispatch over one exact semantic call site.
pub trait DispatchOracle {
    fn resolve_call(
        &self,
        call: &CallSiteHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError>;
}

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
    workspace: &'a WorkspaceAnalyzer,
}

impl<'a> WorkspaceIcfgProvider<'a> {
    pub(crate) const fn new(workspace: &'a WorkspaceAnalyzer) -> Self {
        Self { workspace }
    }

    pub const fn workspace(&self) -> &'a WorkspaceAnalyzer {
        self.workspace
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
    Unsupported,
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
        self.work = self
            .work
            .checked_add(work)
            .unwrap_or_else(|| SemanticWork::uniform(usize::MAX));
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
        let work = node_work.map_or(edge_work, |node| {
            node.checked_add(edge_work)
                .unwrap_or_else(|| SemanticWork::uniform(usize::MAX))
        });
        self.work = self
            .work
            .checked_add(work)
            .unwrap_or_else(|| SemanticWork::uniform(usize::MAX));
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
            SemanticOutcome::Unsupported { .. } => SnapshotQuality::Unsupported,
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
        if cursor != self.edges.len() {
            return Err(SemanticProviderError::internal(
                "ICFG edge has an out-of-range source",
            ));
        }

        let mut incoming_counts = vec![0_u32; node_count];
        for edge in &self.edges {
            let Some(count) = incoming_counts.get_mut(edge.target.index()) else {
                return Err(SemanticProviderError::internal(
                    "ICFG edge has an out-of-range target",
                ));
            };
            *count = count
                .checked_add(1)
                .ok_or_else(|| SemanticProviderError::internal("ICFG incoming row overflow"))?;
        }
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
        (Unsupported, _) | (_, Unsupported) => Unsupported,
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
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }

        let max_source_bytes = request.budget.remaining().source_bytes;
        let Some((file, exact_source)) =
            exact_source_for_procedure(self.workspace, call.procedure(), max_source_bytes)?
        else {
            let work = SemanticWork {
                source_bytes: max_source_bytes.saturating_add(1),
                ..SemanticWork::default()
            };
            let exceeded = request.budget.check(work).map_or_else(
                |exceeded| exceeded,
                |_| unreachable!("bounded source omission must exceed the remaining budget"),
            );
            return Ok(SemanticOutcome::ExceededBudget {
                partial: Some(DispatchResult {
                    candidates: Box::new([]),
                    boundaries: Box::new([truncated_dispatch_boundary()]),
                }),
                exceeded,
                work,
            });
        };
        let semantic_call = call
            .procedure()
            .semantics()
            .call_site(call.id())
            .ok_or_else(|| SemanticProviderError::internal("semantic call-site handle is stale"))?;
        let mapping = call
            .procedure()
            .semantics()
            .source_mapping(semantic_call.source)
            .ok_or_else(|| {
                SemanticProviderError::internal("semantic call site has no source mapping")
            })?;
        let span = mapping.locator.anchor().span();
        let location = ExactCallLocation {
            file,
            call_span: Range {
                start_byte: span.start_byte() as usize,
                end_byte: span.end_byte() as usize,
                start_line: span.start().line() as usize,
                end_line: span.end().line() as usize,
            },
        };

        let mut staged_budget = request.budget.clone();
        let lookup = CallRelationService::dispatch_at_bounded(
            self.workspace.analyzer(),
            &location,
            Arc::clone(&exact_source),
            CallRelationLimits {
                max_files: 1,
                max_source_bytes,
                max_candidates: MAX_DISPATCH_TARGETS,
            },
            Some(request.cancellation),
        );
        if lookup.cancelled || request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }

        debug_assert!(lookup.work.scanned_files <= 1);
        debug_assert!(lookup.callee_range.is_some() || lookup.status.is_none());
        let dispatch_work = SemanticWork {
            source_bytes: lookup.work.scanned_source_bytes,
            call_sites: 1,
            nested_entries: lookup
                .targets
                .len()
                .saturating_add(lookup.boundaries.len())
                .saturating_add(lookup.work.examined_candidates),
            ..SemanticWork::default()
        };
        if let Err(exceeded) = staged_budget.charge(dispatch_work) {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: Some(DispatchResult {
                    candidates: Box::new([]),
                    boundaries: Box::new([truncated_dispatch_boundary()]),
                }),
                exceeded,
                work: dispatch_work,
            });
        }
        let mut reported_work = dispatch_work;
        if lookup.budget_exhausted {
            let attempted = SemanticWork {
                source_bytes: exact_source.len().max(1),
                call_sites: 1,
                ..SemanticWork::default()
            };
            if let Err(exceeded) = request.budget.check(attempted) {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: Some(DispatchResult {
                        candidates: Box::new([]),
                        boundaries: Box::new([truncated_dispatch_boundary()]),
                    }),
                    exceeded,
                    work: attempted,
                });
            }
        }

        let mut candidates = Vec::new();
        let mut boundaries = lookup
            .boundaries
            .iter()
            .map(low_level_boundary)
            .collect::<Vec<_>>();
        let mut seen = HashSet::default();
        let mut materialization_quality = SnapshotQuality::Complete;
        let mut materialization_exceeded = None;
        let mut materialized_files: HashMap<
            ProjectFile,
            SemanticOutcome<Arc<super::SemanticArtifact>>,
        > = HashMap::default();
        let mut staged_request = SemanticRequest::new(&mut staged_budget, request.cancellation);

        for target in lookup.targets {
            if request.cancellation.is_cancelled() {
                materialization_quality = SnapshotQuality::Cancelled;
                break;
            }
            let outcome = if let Some(outcome) = materialized_files.get(target.definition.source())
            {
                outcome.clone()
            } else {
                let outcome = self.workspace.materialize_program_semantics(
                    target.definition.source(),
                    &mut staged_request,
                )?;
                reported_work = reported_work
                    .checked_add(outcome.work())
                    .unwrap_or_else(|| SemanticWork::uniform(usize::MAX));
                materialized_files.insert(target.definition.source().clone(), outcome.clone());
                outcome
            };
            match outcome {
                SemanticOutcome::Complete { value, .. } => {
                    let matched = procedures_for_definition(
                        self.workspace.analyzer(),
                        &target.definition,
                        &value,
                    );
                    if matched.is_empty() {
                        boundaries.push(DispatchBoundary {
                            kind: DispatchBoundaryKind::Unmaterialized(locator_for_definition(
                                self.workspace.analyzer(),
                                &target.definition,
                            )?),
                            proof: proof_from_usage(target.proof),
                            completeness: EvidenceCompleteness::Partial(
                                "resolved declaration has no published callable body".into(),
                            ),
                        });
                        materialization_quality =
                            merge_quality(materialization_quality, SnapshotQuality::Unproven);
                    }
                    for procedure in matched {
                        if seen.insert(procedure.clone()) {
                            candidates.push(DispatchCandidate {
                                target: procedure,
                                proof: proof_from_usage(target.proof),
                                completeness: EvidenceCompleteness::Complete,
                            });
                        }
                    }
                }
                SemanticOutcome::Ambiguous {
                    candidates: value, ..
                }
                | SemanticOutcome::Unproven { partial: value, .. } => {
                    let matched = procedures_for_definition(
                        self.workspace.analyzer(),
                        &target.definition,
                        &value,
                    );
                    if matched.is_empty() {
                        boundaries.push(DispatchBoundary {
                            kind: DispatchBoundaryKind::Unmaterialized(locator_for_definition(
                                self.workspace.analyzer(),
                                &target.definition,
                            )?),
                            proof: ProofStatus::Unproven(
                                "target semantic materialization is not authoritative".into(),
                            ),
                            completeness: EvidenceCompleteness::Partial(
                                "resolved declaration has no generation-matched callable body"
                                    .into(),
                            ),
                        });
                    }
                    for procedure in matched {
                        if seen.insert(procedure.clone()) {
                            candidates.push(DispatchCandidate {
                                target: procedure,
                                proof: ProofStatus::Unproven(
                                    "target semantic materialization is not authoritative".into(),
                                ),
                                completeness: EvidenceCompleteness::Partial(
                                    "target semantic materialization is incomplete".into(),
                                ),
                            });
                        }
                    }
                    materialization_quality =
                        merge_quality(materialization_quality, SnapshotQuality::Unproven);
                }
                SemanticOutcome::Unknown { .. } => {
                    boundaries.push(DispatchBoundary {
                        kind: DispatchBoundaryKind::Unmaterialized(locator_for_definition(
                            self.workspace.analyzer(),
                            &target.definition,
                        )?),
                        proof: proof_from_usage(target.proof),
                        completeness: EvidenceCompleteness::Partial(
                            "target semantic materialization is unknown".into(),
                        ),
                    });
                    materialization_quality =
                        merge_quality(materialization_quality, SnapshotQuality::Unknown);
                }
                SemanticOutcome::Unsupported { .. } => {
                    boundaries.push(DispatchBoundary {
                        kind: DispatchBoundaryKind::Unmaterialized(locator_for_definition(
                            self.workspace.analyzer(),
                            &target.definition,
                        )?),
                        proof: proof_from_usage(target.proof),
                        completeness: EvidenceCompleteness::Partial(
                            "target language has no callable semantic adapter".into(),
                        ),
                    });
                    materialization_quality =
                        merge_quality(materialization_quality, SnapshotQuality::Unsupported);
                }
                SemanticOutcome::ExceededBudget { exceeded, .. } => {
                    boundaries.push(truncated_dispatch_boundary());
                    materialization_exceeded = Some(exceeded);
                    materialization_quality = SnapshotQuality::Truncated;
                    break;
                }
                SemanticOutcome::Cancelled { .. } => {
                    materialization_quality = SnapshotQuality::Cancelled;
                    break;
                }
            }
        }

        candidates.sort_by(|left, right| {
            left.target
                .semantics()
                .locator()
                .cmp(right.target.semantics().locator())
        });
        boundaries.sort_by(|left, right| {
            dispatch_boundary_sort_key(left).cmp(&dispatch_boundary_sort_key(right))
        });
        boundaries.dedup();
        if lookup.truncated
            && !boundaries
                .iter()
                .any(|boundary| boundary.kind == DispatchBoundaryKind::Truncated)
        {
            boundaries.push(truncated_dispatch_boundary());
            materialization_quality =
                merge_quality(materialization_quality, SnapshotQuality::Unproven);
        }
        let result = DispatchResult {
            candidates: candidates.into_boxed_slice(),
            boundaries: boundaries.into_boxed_slice(),
        };
        *request.budget = staged_budget;

        if let Some(exceeded) = materialization_exceeded {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: Some(result),
                exceeded,
                work: reported_work,
            });
        }
        if materialization_quality == SnapshotQuality::Cancelled {
            return Ok(SemanticOutcome::Cancelled {
                partial: Some(result),
                work: reported_work,
            });
        }
        let status_quality = match lookup.status {
            Some(DefinitionLookupStatus::Resolved) => SnapshotQuality::Complete,
            Some(DefinitionLookupStatus::Ambiguous) => SnapshotQuality::Ambiguous,
            Some(DefinitionLookupStatus::UnsupportedLanguage) => SnapshotQuality::Unsupported,
            Some(
                DefinitionLookupStatus::NoDefinition
                | DefinitionLookupStatus::InvalidLocation
                | DefinitionLookupStatus::NotFound,
            )
            | None => SnapshotQuality::Unknown,
            Some(DefinitionLookupStatus::UnresolvableImportBoundary) => SnapshotQuality::Complete,
        };
        dispatch_outcome(
            result,
            merge_quality(status_quality, materialization_quality),
            reported_work,
        )
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
        Ok(self.resolve_call(&origin, request)?.map(|dispatch| {
            let mut transfers = Vec::new();
            let mut boundaries = dispatch
                .boundaries
                .into_vec()
                .into_iter()
                .map(|dispatch| CallBoundary {
                    origin: origin.clone(),
                    dispatch,
                    model: None,
                })
                .collect::<Vec<_>>();
            for candidate in dispatch.candidates.into_vec() {
                let properties = candidate.target.semantics().properties();
                if properties.invocation == ProcedureInvocationKind::Deferred {
                    boundaries.push(CallBoundary {
                        origin: origin.clone(),
                        dispatch: DispatchBoundary {
                            kind: DispatchBoundaryKind::Deferred {
                                target: candidate.target.semantics().locator().clone(),
                                kind: deferred_invocation_kind(properties),
                            },
                            proof: candidate.proof,
                            completeness: EvidenceCompleteness::Partial(
                                "callee body execution requires a later resume transfer".into(),
                            ),
                        },
                        // Creating the suspended object normally returns to the
                        // caller, while argument binding or language call
                        // mechanics can still fail synchronously.
                        model: Some(CallToReturnModel::NormalAndExceptional),
                    });
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
            CallTransferSet {
                transfers: transfers.into_boxed_slice(),
                boundaries: boundaries.into_boxed_slice(),
            }
        }))
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
            exact_source_for_procedure(self.workspace, root, max_source_bytes)?
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
                        builder.work = builder
                            .work
                            .checked_add(outcome.work())
                            .unwrap_or_else(|| SemanticWork::uniform(usize::MAX));
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
        if let Some(exceeded) = exceeded {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: Some(snapshot),
                exceeded,
                work,
            });
        }
        match quality {
            SnapshotQuality::Complete => Ok(SemanticOutcome::Complete {
                value: snapshot,
                work,
            }),
            SnapshotQuality::Ambiguous => Ok(SemanticOutcome::Ambiguous {
                candidates: snapshot,
                work,
            }),
            SnapshotQuality::Unproven => Ok(SemanticOutcome::Unproven {
                partial: snapshot,
                work,
            }),
            SnapshotQuality::Unknown | SnapshotQuality::Truncated => Ok(SemanticOutcome::Unknown {
                partial: Some(snapshot),
                work,
            }),
            SnapshotQuality::Unsupported => Ok(SemanticOutcome::Unsupported {
                capability: SemanticCapability::Calls,
                partial: Some(snapshot),
                work,
            }),
            SnapshotQuality::Cancelled => Ok(SemanticOutcome::Cancelled {
                partial: Some(snapshot),
                work,
            }),
        }
    }
}

fn exact_source_for_procedure(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    max_source_bytes: usize,
) -> Result<Option<(ProjectFile, Arc<String>)>, SemanticProviderError> {
    let key = procedure.artifact().key();
    let project = workspace.analyzer().project();
    let root = project.root();
    if key.mount() != WorkspaceMountId::from_root(root) {
        return Err(SemanticProviderError::invalid_identity(
            "call-site artifact belongs to a different workspace mount",
        ));
    }
    let file = ProjectFile::new(root.to_path_buf(), key.path().as_path());
    let Some(snapshot) = project
        .read_source_snapshot_limited(&file, max_source_bytes)
        .map_err(|error| {
            SemanticProviderError::source_access(format!(
                "could not read exact semantic source: {error}"
            ))
        })?
    else {
        return Ok(None);
    };
    let source = Arc::new(snapshot.source().to_owned());
    let content = ContentIdentity::hash_bytes(source.as_bytes());
    let revision = match snapshot.origin() {
        ProjectSourceOrigin::Disk => SourceRevision::Disk { content },
        ProjectSourceOrigin::Overlay(revision) => SourceRevision::Overlay {
            content,
            snapshot: OverlaySnapshotId::hash_bytes(revision.get().to_le_bytes()),
        },
    };
    if revision != key.revision() {
        return Err(SemanticProviderError::invalid_identity(format!(
            "call-site artifact revision for `{file}` no longer matches the atomic project source snapshot"
        )));
    }
    Ok(Some((file, source)))
}

fn low_level_boundary(boundary: &CallDispatchBoundaryKind) -> DispatchBoundary {
    match boundary {
        CallDispatchBoundaryKind::External => DispatchBoundary {
            kind: DispatchBoundaryKind::External(None),
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Partial(
                "external declaration body is outside the indexed workspace".into(),
            ),
        },
        CallDispatchBoundaryKind::Unresolved(status) => DispatchBoundary {
            kind: DispatchBoundaryKind::Unresolved,
            proof: ProofStatus::Unproven(
                format!("exact dispatch status is {}", status.as_str()).into(),
            ),
            completeness: EvidenceCompleteness::Partial(
                "no materialized workspace target is available".into(),
            ),
        },
        CallDispatchBoundaryKind::Truncated => truncated_dispatch_boundary(),
    }
}

fn truncated_dispatch_boundary() -> DispatchBoundary {
    DispatchBoundary {
        kind: DispatchBoundaryKind::Truncated,
        proof: ProofStatus::Unproven("dispatch candidate set was truncated".into()),
        completeness: EvidenceCompleteness::Partial(
            "not every dispatch candidate was retained".into(),
        ),
    }
}

fn proof_from_usage(proof: UsageProof) -> ProofStatus {
    match proof {
        UsageProof::Proven => ProofStatus::Proven,
        UsageProof::Unproven => ProofStatus::Unproven("dispatch target is ambiguous".into()),
    }
}

fn dispatch_outcome(
    result: DispatchResult,
    quality: SnapshotQuality,
    work: SemanticWork,
) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError> {
    Ok(match quality {
        SnapshotQuality::Complete => SemanticOutcome::Complete {
            value: result,
            work,
        },
        SnapshotQuality::Ambiguous => SemanticOutcome::Ambiguous {
            candidates: result,
            work,
        },
        SnapshotQuality::Unproven | SnapshotQuality::Truncated => SemanticOutcome::Unproven {
            partial: result,
            work,
        },
        SnapshotQuality::Unknown => SemanticOutcome::Unknown {
            partial: Some(result),
            work,
        },
        SnapshotQuality::Unsupported => SemanticOutcome::Unsupported {
            capability: SemanticCapability::Calls,
            partial: Some(result),
            work,
        },
        SnapshotQuality::Cancelled => SemanticOutcome::Cancelled {
            partial: Some(result),
            work,
        },
    })
}

fn procedures_for_definition(
    analyzer: &dyn IAnalyzer,
    definition: &CodeUnit,
    artifact: &Arc<super::SemanticArtifact>,
) -> Vec<ProcedureHandle> {
    let Some(indexed_source) = analyzer.indexed_source(definition.source()) else {
        return Vec::new();
    };
    if ContentIdentity::hash_bytes(indexed_source.as_bytes()) != artifact.key().revision().content()
    {
        // Declaration ranges and target semantics came from different source
        // generations. Never attach the stale range to a current procedure.
        return Vec::new();
    }
    let mut ranges = analyzer.ranges_of(definition);
    ranges.sort_by_key(|range| (range.start_byte, range.end_byte));
    let compatible = artifact
        .procedures()
        .iter()
        .filter(|procedure| procedure_matches_definition(procedure, definition))
        .collect::<Vec<_>>();
    let mut exact = compatible
        .iter()
        .copied()
        .filter(|procedure| {
            let span = procedure.locator().anchor().span();
            ranges.iter().any(|range| {
                range.start_byte == span.start_byte() as usize
                    && range.end_byte == span.end_byte() as usize
            })
        })
        .collect::<Vec<_>>();
    if exact.is_empty() {
        exact = compatible
            .into_iter()
            .filter(|procedure| {
                let span = procedure.locator().anchor().span();
                ranges.iter().any(|range| {
                    (range.start_byte <= span.start_byte() as usize
                        && range.end_byte >= span.end_byte() as usize)
                        || (span.start_byte() as usize <= range.start_byte
                            && span.end_byte() as usize >= range.end_byte)
                })
            })
            .collect();
    }
    exact.sort_by(|left, right| left.locator().cmp(right.locator()));
    exact
        .into_iter()
        .filter_map(|procedure| artifact.procedure_handle(procedure.id()))
        .collect()
}

fn procedure_matches_definition(
    procedure: &super::ProcedureSemantics,
    definition: &CodeUnit,
) -> bool {
    if definition.is_class() {
        return procedure.kind() == ProcedureKind::Constructor;
    }
    if !definition.is_callable() {
        return false;
    }
    let Some(name) = procedure
        .locator()
        .declaration()
        .segments()
        .last()
        .and_then(DeclarationSegment::name)
    else {
        return definition.is_anonymous();
    };
    name == definition.identifier()
        || (procedure.kind() == ProcedureKind::Constructor && name == definition.short_name())
}

fn locator_for_definition(
    analyzer: &dyn IAnalyzer,
    definition: &CodeUnit,
) -> Result<SemanticLocator, SemanticProviderError> {
    let source = analyzer
        .indexed_source(definition.source())
        .ok_or_else(|| {
            SemanticProviderError::source_access(format!(
                "indexed source is unavailable for resolved declaration `{}`",
                definition.fq_name()
            ))
        })?;
    let mut ranges = analyzer.ranges_of(definition);
    ranges.sort_by_key(|range| (range.start_byte, range.end_byte));
    let range = ranges.into_iter().next().unwrap_or(Range {
        start_byte: 0,
        end_byte: source.len(),
        start_line: 0,
        end_line: source.lines().count().saturating_sub(1),
    });
    let anchor = source_anchor_for_range(&source, &range)?;
    let file_name = definition
        .source()
        .rel_path()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("source");
    let file_segment =
        DeclarationSegment::named(DeclarationSegmentKind::File, file_name, anchor, 0)
            .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    let kind = match definition.kind() {
        CodeUnitType::Class => DeclarationSegmentKind::Type,
        CodeUnitType::Function => DeclarationSegmentKind::Function,
        CodeUnitType::Field
        | CodeUnitType::Module
        | CodeUnitType::Macro
        | CodeUnitType::FileScope => DeclarationSegmentKind::AnonymousCallable,
    };
    let declaration_segment =
        DeclarationSegment::named(kind, definition.identifier(), anchor, 0)
            .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    let declaration = DeclarationLocator::new(vec![file_segment, declaration_segment])
        .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    let path = WorkspaceRelativePath::try_from_path(definition.source().rel_path())
        .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    Ok(SemanticLocator::new(
        WorkspaceMountId::from_root(definition.source().root()),
        path,
        LanguageDialect::for_path(
            crate::analyzer::common::language_for_file(definition.source()),
            definition.source().rel_path(),
        ),
        declaration,
        SemanticRole::Procedure,
        anchor,
    ))
}

fn source_anchor_for_range(
    source: &str,
    range: &Range,
) -> Result<SourceAnchor, SemanticProviderError> {
    let start = source_position(source, range.start_byte)?;
    let end = source_position(source, range.end_byte)?;
    let span = SourceSpan::new(start, end)
        .map_err(|error| SemanticProviderError::invalid_identity(error.to_string()))?;
    Ok(SourceAnchor::new(span, 0))
}

fn source_position(source: &str, offset: usize) -> Result<SourcePosition, SemanticProviderError> {
    if offset > source.len() || !source.is_char_boundary(offset) {
        return Err(SemanticProviderError::invalid_identity(
            "resolved declaration range is outside its UTF-8 source",
        ));
    }
    let bytes = source.as_bytes();
    let line_start = bytes[..offset]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |newline| newline.saturating_add(1));
    let line = bytes[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count();
    Ok(SourcePosition::new(
        u32::try_from(offset)
            .map_err(|_| SemanticProviderError::invalid_identity("source offset exceeds u32"))?,
        u32::try_from(line)
            .map_err(|_| SemanticProviderError::invalid_identity("source line exceeds u32"))?,
        u32::try_from(offset.saturating_sub(line_start))
            .map_err(|_| SemanticProviderError::invalid_identity("source column exceeds u32"))?,
    ))
}

fn dispatch_boundary_sort_key(boundary: &DispatchBoundary) -> (u8, String) {
    match &boundary.kind {
        DispatchBoundaryKind::External(locator) => (
            0,
            locator.as_ref().map_or_else(String::new, locator_sort_key),
        ),
        DispatchBoundaryKind::Unmaterialized(locator) => (1, locator_sort_key(locator)),
        DispatchBoundaryKind::Deferred { target, kind } => {
            (2, format!("{}:{}", kind.label(), locator_sort_key(target)))
        }
        DispatchBoundaryKind::Unresolved => (3, String::new()),
        DispatchBoundaryKind::Truncated => (4, String::new()),
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

fn locator_sort_key(locator: &SemanticLocator) -> String {
    let span = locator.anchor().span();
    format!(
        "{}:{}:{}:{}",
        locator.path(),
        span.start_byte(),
        span.end_byte(),
        locator.anchor().occurrence()
    )
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
                frame.proof.clone(),
                frame.completeness.clone(),
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
