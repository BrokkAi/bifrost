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
    CallDispatchBoundaryKind, CallDispatchTarget, CallRelationLimits, CallRelationService,
    ExactCallLocation, UsageProof, call_dispatch_equivalence_source,
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
    ProcedureKind, ProcedureSemantics, ProgramPointHandle, ProgramPointId, ProofStatus,
    SemanticBudgetExceeded, SemanticCallSite, SemanticCapability, SemanticGap, SemanticGapKind,
    SemanticGapSubject, SemanticLocator, SemanticOutcome, SemanticProviderError, SemanticRequest,
    SemanticRole, SemanticWork, SourceAnchor, SourcePosition, SourceRevision, SourceSpan,
    WorkspaceMountId, WorkspaceRelativePath,
};

const MAX_DISPATCH_TARGETS: usize = 1_024;

/// Source-scoped callable identity used only while stitching dispatch. The
/// location-first resolver may return both a C/C++ declaration and a related
/// body, but the ICFG never manufactures equivalents from a workspace-global
/// FQN: external linkage does not identify one link unit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CallableDefinitionIdentity {
    kind: CodeUnitType,
    fq_name: String,
    signature: Option<String>,
    source_scope: Option<ProjectFile>,
}

impl CallableDefinitionIdentity {
    fn of(analyzer: &dyn IAnalyzer, definition: &CodeUnit) -> Self {
        Self::with_source_scope(
            definition,
            call_dispatch_equivalence_source(analyzer, definition),
        )
    }

    fn with_source_scope(definition: &CodeUnit, source_scope: Option<ProjectFile>) -> Self {
        Self {
            kind: definition.kind(),
            fq_name: definition.fq_name(),
            signature: definition.signature().map(str::to_owned),
            source_scope,
        }
    }
}

#[derive(Debug)]
struct DispatchTargetGroup {
    representative: CodeUnit,
    proof: UsageProof,
}

fn dispatch_target_groups(
    analyzer: &dyn IAnalyzer,
    targets: Vec<CallDispatchTarget>,
) -> Vec<DispatchTargetGroup> {
    let mut groups = Vec::<DispatchTargetGroup>::new();
    let mut index = HashMap::<CallableDefinitionIdentity, usize>::default();
    for target in targets {
        let identity = CallableDefinitionIdentity::of(analyzer, &target.definition);
        if let Some(group) = index
            .get(&identity)
            .and_then(|group| groups.get_mut(*group))
        {
            if target.definition < group.representative {
                group.representative = target.definition;
            }
            if target.proof == UsageProof::Proven {
                group.proof = UsageProof::Proven;
            }
            continue;
        }
        index.insert(identity.clone(), groups.len());
        groups.push(DispatchTargetGroup {
            representative: target.definition,
            proof: target.proof,
        });
    }
    groups
}

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
        (Unsupported(capability), _) => Unsupported(capability),
        (_, Unsupported(capability)) => Unsupported(capability),
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
        let dynamic_dispatch_gap =
            scoped_dynamic_dispatch_gap(call.procedure().semantics(), semantic_call);
        let call_evaluation_gaps = scoped_cpp_call_evaluation_gaps(call.procedure(), semantic_call);
        let procedure_call_gap = scoped_cpp_preprocessor_call_gap(call.procedure());
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
        debug_assert!(
            lookup.status.is_none() || !lookup.targets.is_empty() || !lookup.boundaries.is_empty(),
            "every completed dispatch status must retain a target or typed boundary"
        );
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
        let target_groups = dispatch_target_groups(self.workspace.analyzer(), lookup.targets);
        let target_group_count = target_groups.len();
        let mut candidate_indexes = HashMap::<ProcedureHandle, usize>::default();
        let mut materialization_quality = SnapshotQuality::Complete;
        let mut materialization_exceeded = None;
        let mut remaining_definition_materializations = MAX_DISPATCH_TARGETS;
        let mut materialized_files: HashMap<
            ProjectFile,
            SemanticOutcome<Arc<super::SemanticArtifact>>,
        > = HashMap::default();
        let mut staged_request = SemanticRequest::new(&mut staged_budget, request.cancellation);

        for (group_index, group) in target_groups.into_iter().enumerate() {
            if request.cancellation.is_cancelled() {
                materialization_quality = SnapshotQuality::Cancelled;
                break;
            }
            // Exact dispatch already performed the structured, language-aware
            // declaration/body expansion. Do not repeat it by global FQN here:
            // that would cross C/C++ link units and bypass dispatch work bounds.
            let mut definitions = vec![group.representative.clone()];
            let definitions_truncated = definitions.len() > remaining_definition_materializations;
            definitions.truncate(remaining_definition_materializations);
            remaining_definition_materializations =
                remaining_definition_materializations.saturating_sub(definitions.len());
            if definitions_truncated {
                boundaries.push(truncated_dispatch_boundary());
                materialization_quality = SnapshotQuality::Truncated;
            }

            let mut matched_any = false;
            let mut matched_quality = match group.proof {
                UsageProof::Proven => SnapshotQuality::Complete,
                UsageProof::Unproven => SnapshotQuality::Unproven,
            };
            let mut failure_quality = SnapshotQuality::Complete;
            for definition in definitions {
                if request.cancellation.is_cancelled() {
                    materialization_quality = SnapshotQuality::Cancelled;
                    break;
                }
                let outcome = if let Some(outcome) = materialized_files.get(definition.source()) {
                    outcome.clone()
                } else {
                    let outcome = self
                        .workspace
                        .materialize_program_semantics(definition.source(), &mut staged_request)?;
                    reported_work = reported_work
                        .checked_add(outcome.work())
                        .unwrap_or_else(|| SemanticWork::uniform(usize::MAX));
                    materialized_files.insert(definition.source().clone(), outcome.clone());
                    outcome
                };
                match outcome {
                    SemanticOutcome::Complete { value, .. } => {
                        let matched = procedures_for_definition(
                            self.workspace.analyzer(),
                            &definition,
                            &value,
                        );
                        matched_any |= !matched.is_empty();
                        for procedure in matched {
                            retain_dispatch_candidate(
                                &mut candidates,
                                &mut candidate_indexes,
                                DispatchCandidate {
                                    target: procedure,
                                    proof: proof_from_usage(group.proof),
                                    completeness: completeness_from_usage(group.proof),
                                },
                            );
                        }
                    }
                    SemanticOutcome::Ambiguous {
                        candidates: value, ..
                    }
                    | SemanticOutcome::Unproven { partial: value, .. } => {
                        let matched = procedures_for_definition(
                            self.workspace.analyzer(),
                            &definition,
                            &value,
                        );
                        let has_match = !matched.is_empty();
                        matched_any |= has_match;
                        if has_match {
                            matched_quality =
                                merge_quality(matched_quality, SnapshotQuality::Unproven);
                        } else {
                            failure_quality =
                                merge_quality(failure_quality, SnapshotQuality::Unproven);
                        }
                        for procedure in matched {
                            retain_dispatch_candidate(
                                &mut candidates,
                                &mut candidate_indexes,
                                DispatchCandidate {
                                    target: procedure,
                                    proof: ProofStatus::Unproven(
                                        "target semantic materialization is not authoritative"
                                            .into(),
                                    ),
                                    completeness: EvidenceCompleteness::Partial(
                                        "target semantic materialization is incomplete".into(),
                                    ),
                                },
                            );
                        }
                    }
                    SemanticOutcome::Unknown { .. } => {
                        failure_quality = merge_quality(failure_quality, SnapshotQuality::Unknown);
                    }
                    SemanticOutcome::Unsupported { capability, .. } => {
                        failure_quality = merge_quality(
                            failure_quality,
                            SnapshotQuality::Unsupported(capability),
                        );
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

            let interrupted = materialization_exceeded.is_some()
                || materialization_quality == SnapshotQuality::Cancelled;
            if matched_any {
                materialization_quality = merge_quality(materialization_quality, matched_quality);
            } else if !definitions_truncated && !interrupted {
                boundaries.push(DispatchBoundary {
                    kind: DispatchBoundaryKind::Unmaterialized(locator_for_definition(
                        self.workspace.analyzer(),
                        &group.representative,
                    )?),
                    proof: proof_from_usage(group.proof),
                    completeness: EvidenceCompleteness::Partial(
                        "equivalent callable declarations have no published workspace body".into(),
                    ),
                });
                let missing_quality = if failure_quality == SnapshotQuality::Complete {
                    SnapshotQuality::Unproven
                } else {
                    failure_quality
                };
                materialization_quality = merge_quality(materialization_quality, missing_quality);
            }

            let omitted_later_groups = remaining_definition_materializations == 0
                && group_index.saturating_add(1) < target_group_count;
            if interrupted || definitions_truncated || omitted_later_groups {
                if omitted_later_groups
                    && !boundaries
                        .iter()
                        .any(|boundary| boundary.kind == DispatchBoundaryKind::Truncated)
                {
                    boundaries.push(truncated_dispatch_boundary());
                    materialization_quality = SnapshotQuality::Truncated;
                }
                break;
            }
        }

        if let Some(gap) = dynamic_dispatch_gap {
            materialization_quality = merge_quality(
                materialization_quality,
                apply_dynamic_dispatch_gap(gap, &mut candidates, &mut boundaries),
            );
        }
        if !call_evaluation_gaps.is_empty() {
            materialization_quality = merge_quality(
                materialization_quality,
                apply_call_evaluation_gaps(&call_evaluation_gaps, &mut candidates),
            );
        }
        if let Some(gap) = procedure_call_gap {
            materialization_quality = merge_quality(
                materialization_quality,
                apply_procedure_call_gap(gap, &mut candidates, &mut boundaries),
            );
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
        if boundaries
            .iter()
            .any(|boundary| boundary.kind == DispatchBoundaryKind::Unresolved)
        {
            // A typed unresolved arm is itself unproven, even when the
            // low-level location lookup reported `Resolved`. That status can
            // describe a lexical callable value (for example a function-typed
            // parameter) without publishing any callable body.
            materialization_quality =
                merge_quality(materialization_quality, SnapshotQuality::Unproven);
        }
        if lookup.truncated {
            if !boundaries
                .iter()
                .any(|boundary| boundary.kind == DispatchBoundaryKind::Truncated)
            {
                boundaries.push(truncated_dispatch_boundary());
            }
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
            Some(DefinitionLookupStatus::UnsupportedLanguage) => {
                SnapshotQuality::Unsupported(SemanticCapability::Calls)
            }
            Some(
                DefinitionLookupStatus::NoDefinition
                | DefinitionLookupStatus::InvalidLocation
                | DefinitionLookupStatus::NotFound,
            )
            | None => SnapshotQuality::Unknown,
            Some(DefinitionLookupStatus::UnresolvableImportBoundary) => SnapshotQuality::Complete,
        };
        let quality = if result.candidates.is_empty()
            && status_quality == SnapshotQuality::Ambiguous
            && matches!(
                materialization_quality,
                SnapshotQuality::Complete | SnapshotQuality::Ambiguous | SnapshotQuality::Unproven
            ) {
            // A zero-body ambiguous lookup still has a precise ambiguity
            // classification. Dynamic/open-world incompleteness must not
            // collapse that typed outcome into generic Unproven.
            SnapshotQuality::Ambiguous
        } else {
            merge_quality(status_quality, materialization_quality)
        };
        dispatch_outcome(result, quality, reported_work)
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
            SnapshotQuality::Unsupported(capability) => Ok(SemanticOutcome::Unsupported {
                capability,
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
        CallDispatchBoundaryKind::UnprovenTargetIdentity => DispatchBoundary {
            kind: DispatchBoundaryKind::Unresolved,
            proof: ProofStatus::Unproven(
                "C/C++ include evidence does not prove one link-unit target identity".into(),
            ),
            completeness: EvidenceCompleteness::Partial(
                "additional or alternative linked bodies may exist".into(),
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

fn completeness_from_usage(proof: UsageProof) -> EvidenceCompleteness {
    match proof {
        UsageProof::Proven => EvidenceCompleteness::Complete,
        UsageProof::Unproven => EvidenceCompleteness::Partial(
            "dispatch cannot prove one complete target identity".into(),
        ),
    }
}

fn scoped_dynamic_dispatch_gap<'a>(
    procedure: &'a ProcedureSemantics,
    call: &SemanticCallSite,
) -> Option<&'a SemanticGap> {
    procedure
        .gaps()
        .iter()
        .filter(|gap| {
            gap.point == call.point
                && gap.capability == SemanticCapability::DynamicDispatch
                && match gap.subject {
                    SemanticGapSubject::Point => true,
                    SemanticGapSubject::CallSite(call_site) => call_site == call.id,
                    _ => false,
                }
        })
        .max_by_key(|gap| dynamic_dispatch_gap_rank(gap.kind))
}

fn scoped_cpp_preprocessor_call_gap(procedure: &ProcedureHandle) -> Option<&SemanticGap> {
    if procedure.artifact().key().language()
        != LanguageDialect::Standard(crate::analyzer::Language::Cpp)
    {
        return None;
    }
    let semantics = procedure.semantics();
    let has_configuration_control_gap = semantics.gaps().iter().any(|gap| {
        gap.subject == SemanticGapSubject::Procedure
            && gap.capability == SemanticCapability::NormalControlFlow
            && gap.kind == SemanticGapKind::Unsupported
    });
    if !has_configuration_control_gap {
        return None;
    }
    semantics
        .gaps()
        .iter()
        .filter(|gap| {
            gap.subject == SemanticGapSubject::Procedure
                && matches!(
                    gap.capability,
                    SemanticCapability::Calls | SemanticCapability::CallableReferences
                )
        })
        .max_by_key(|gap| dynamic_dispatch_gap_rank(gap.kind))
}

fn scoped_cpp_call_evaluation_gaps<'a>(
    procedure: &'a ProcedureHandle,
    call: &SemanticCallSite,
) -> Vec<&'a SemanticGap> {
    if procedure.artifact().key().language()
        != LanguageDialect::Standard(crate::analyzer::Language::Cpp)
    {
        return Vec::new();
    }
    procedure
        .semantics()
        .gaps()
        .iter()
        .filter(|gap| {
            gap.point == call.point
                && gap.subject == SemanticGapSubject::CallSite(call.id)
                && matches!(
                    gap.capability,
                    SemanticCapability::CleanupControlFlow
                        | SemanticCapability::ExceptionalControlFlow
                )
        })
        .collect()
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
            let return_affecting = matches!(
                gap.capability,
                SemanticCapability::CleanupControlFlow
                    | SemanticCapability::ExceptionalControlFlow
                    | SemanticCapability::NonLocalControl
            );
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
    builder.work = builder
        .work
        .checked_add(scan_work)
        .unwrap_or_else(|| SemanticWork::uniform(usize::MAX));

    let mut from_entry = vec![false; point_count];
    let mut stack = vec![semantics.entry_point()];
    while let Some(point) = stack.pop() {
        if request.cancellation.is_cancelled() {
            builder.quality = SnapshotQuality::Cancelled;
            return false;
        }
        if std::mem::replace(&mut from_entry[point.index()], true) {
            continue;
        }
        stack.extend(
            semantics
                .successor_edges(point)
                .map(|(_, edge)| edge.target_point),
        );
    }

    let mut to_exit = vec![false; point_count];
    stack.push(exit);
    while let Some(point) = stack.pop() {
        if request.cancellation.is_cancelled() {
            builder.quality = SnapshotQuality::Cancelled;
            return false;
        }
        if std::mem::replace(&mut to_exit[point.index()], true) {
            continue;
        }
        stack.extend(
            semantics
                .predecessor_edges(point)
                .map(|(_, edge)| edge.source_point),
        );
    }

    let path_mask = from_entry
        .into_iter()
        .zip(to_exit)
        .map(|(reachable, reaches_exit)| reachable && reaches_exit)
        .collect::<Vec<_>>()
        .into_boxed_slice();
    builder.return_path_masks.insert(cache_key, path_mask);
    true
}

fn dynamic_dispatch_gap_rank(kind: SemanticGapKind) -> u8 {
    match kind {
        SemanticGapKind::Unproven => 0,
        SemanticGapKind::Ambiguous => 1,
        SemanticGapKind::Unknown => 2,
        SemanticGapKind::Unsupported => 3,
        SemanticGapKind::ExceededBudget => 4,
    }
}

fn semantic_gap_quality(gap: &SemanticGap) -> SnapshotQuality {
    match gap.kind {
        SemanticGapKind::Ambiguous => SnapshotQuality::Ambiguous,
        SemanticGapKind::Unsupported => SnapshotQuality::Unsupported(gap.capability),
        SemanticGapKind::ExceededBudget => SnapshotQuality::Truncated,
        SemanticGapKind::Unknown | SemanticGapKind::Unproven => SnapshotQuality::Unproven,
    }
}

fn apply_dynamic_dispatch_gap(
    gap: &SemanticGap,
    candidates: &mut [DispatchCandidate],
    boundaries: &mut Vec<DispatchBoundary>,
) -> SnapshotQuality {
    let proof_reason = format!(
        "{} dynamic-dispatch evidence does not prove the complete target set: {}",
        gap.kind.label(),
        gap.detail
    );
    let completeness_reason = format!(
        "dynamic-dispatch target coverage is incomplete: {}",
        gap.detail
    );
    if candidates.is_empty() {
        // Preserve the specific boundary (external, unmaterialized, or a
        // resolver-provided unresolved status), while retaining the distinct
        // open-world dynamic arm. A point-scoped dynamic-dispatch gap can
        // never yield a Complete outcome merely because no local body was
        // materialized.
        if !boundaries
            .iter()
            .any(|boundary| boundary.kind == DispatchBoundaryKind::Unresolved)
        {
            boundaries.push(DispatchBoundary {
                kind: DispatchBoundaryKind::Unresolved,
                proof: ProofStatus::Unproven(proof_reason.into()),
                completeness: EvidenceCompleteness::Partial(completeness_reason.into()),
            });
        }
        return semantic_gap_quality(gap);
    }
    for candidate in candidates.iter_mut() {
        candidate.proof = ProofStatus::Unproven(match &candidate.proof {
            ProofStatus::Proven => proof_reason.clone().into(),
            ProofStatus::Unproven(existing) => format!("{existing}; {proof_reason}").into(),
        });
        candidate.completeness = EvidenceCompleteness::Partial(match &candidate.completeness {
            EvidenceCompleteness::Complete => completeness_reason.clone().into(),
            EvidenceCompleteness::Partial(existing) => {
                format!("{existing}; {completeness_reason}").into()
            }
        });
    }
    if !boundaries
        .iter()
        .any(|boundary| boundary.kind == DispatchBoundaryKind::Unresolved)
    {
        boundaries.push(DispatchBoundary {
            kind: DispatchBoundaryKind::Unresolved,
            proof: ProofStatus::Unproven(proof_reason.into()),
            completeness: EvidenceCompleteness::Partial(completeness_reason.into()),
        });
    }
    semantic_gap_quality(gap)
}

fn apply_procedure_call_gap(
    gap: &SemanticGap,
    candidates: &mut [DispatchCandidate],
    boundaries: &mut Vec<DispatchBoundary>,
) -> SnapshotQuality {
    let proof_reason = format!(
        "procedure-wide {} evidence does not prove this complete call target set: {}",
        gap.capability.label(),
        gap.detail
    );
    let completeness_reason = format!(
        "procedure-wide {} coverage is incomplete: {}",
        gap.capability.label(),
        gap.detail
    );
    for candidate in candidates.iter_mut() {
        candidate.proof = ProofStatus::Unproven(match &candidate.proof {
            ProofStatus::Proven => proof_reason.clone().into(),
            ProofStatus::Unproven(existing) => format!("{existing}; {proof_reason}").into(),
        });
        candidate.completeness = EvidenceCompleteness::Partial(match &candidate.completeness {
            EvidenceCompleteness::Complete => completeness_reason.clone().into(),
            EvidenceCompleteness::Partial(existing) => {
                format!("{existing}; {completeness_reason}").into()
            }
        });
    }
    if !candidates.is_empty()
        && !boundaries
            .iter()
            .any(|boundary| boundary.kind == DispatchBoundaryKind::Unresolved)
    {
        boundaries.push(DispatchBoundary {
            kind: DispatchBoundaryKind::Unresolved,
            proof: ProofStatus::Unproven(proof_reason.into()),
            completeness: EvidenceCompleteness::Partial(completeness_reason.into()),
        });
    }
    SnapshotQuality::Unproven
}

fn apply_call_evaluation_gaps(
    gaps: &[&SemanticGap],
    candidates: &mut [DispatchCandidate],
) -> SnapshotQuality {
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
    for candidate in candidates {
        candidate.completeness = EvidenceCompleteness::Partial(match &candidate.completeness {
            EvidenceCompleteness::Complete => {
                format!("caller-side call evaluation is incomplete: {detail}").into()
            }
            EvidenceCompleteness::Partial(existing) => {
                format!("{existing}; caller-side call evaluation gaps: {detail}").into()
            }
        });
    }
    gaps.iter().fold(SnapshotQuality::Complete, |quality, gap| {
        merge_quality(quality, semantic_gap_quality(gap))
    })
}

fn retain_dispatch_candidate(
    candidates: &mut Vec<DispatchCandidate>,
    indexes: &mut HashMap<ProcedureHandle, usize>,
    candidate: DispatchCandidate,
) {
    if let Some(existing) = indexes
        .get(&candidate.target)
        .and_then(|index| candidates.get_mut(*index))
    {
        if matches!(candidate.proof, ProofStatus::Proven) {
            existing.proof = ProofStatus::Proven;
        }
        if matches!(candidate.completeness, EvidenceCompleteness::Complete) {
            existing.completeness = EvidenceCompleteness::Complete;
        }
        return;
    }
    indexes.insert(candidate.target.clone(), candidates.len());
    candidates.push(candidate);
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
        SnapshotQuality::Unsupported(capability) => SemanticOutcome::Unsupported {
            capability,
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
    use crate::analyzer::semantic::SemanticBudget;
    use crate::cancellation::CancellationToken;
    use crate::test_support::AnalyzerFixture;

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
        assert_eq!(dispatch.candidates.len(), 1, "{dispatch:#?}");
        assert!(matches!(
            &dispatch.candidates[0].proof,
            ProofStatus::Unproven(_)
        ));
        assert!(matches!(
            &dispatch.candidates[0].completeness,
            EvidenceCompleteness::Partial(_)
        ));
        assert_eq!(
            dispatch.candidates[0]
                .target
                .artifact()
                .key()
                .path()
                .as_str(),
            "target.cpp"
        );
        assert!(dispatch.boundaries.iter().any(|boundary| {
            boundary.kind == DispatchBoundaryKind::Unresolved
                && matches!(&boundary.proof, ProofStatus::Unproven(_))
                && matches!(&boundary.completeness, EvidenceCompleteness::Partial(_))
        }));
    }

    #[test]
    fn cpp_preprocessor_call_gap_downgrades_the_retained_target_set() {
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
        assert_eq!(dispatch.candidates.len(), 1, "{dispatch:#?}");
        assert!(matches!(
            &dispatch.candidates[0].proof,
            ProofStatus::Unproven(_)
        ));
        assert!(matches!(
            &dispatch.candidates[0].completeness,
            EvidenceCompleteness::Partial(_)
        ));
        assert!(dispatch.boundaries.iter().any(|boundary| {
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
        }));
        assert!(scoped_cpp_preprocessor_call_gap(&constructor).is_none());
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
        assert_eq!(dispatch.candidates.len(), 1, "{dispatch:#?}");
        assert!(matches!(
            &dispatch.candidates[0].proof,
            ProofStatus::Unproven(_)
        ));
        assert!(matches!(
            &dispatch.candidates[0].completeness,
            EvidenceCompleteness::Partial(_)
        ));
        assert_eq!(
            dispatch.candidates[0]
                .target
                .artifact()
                .key()
                .path()
                .as_str(),
            "target.ts"
        );
        assert!(dispatch.boundaries.iter().any(|boundary| {
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
                && (gap.subject == SemanticGapSubject::Point
                    || gap.subject == SemanticGapSubject::CallSite(dynamic_call.id))
        }));
        assert!(!direct_caller.semantics().gaps().iter().any(|gap| {
            gap.point == direct_call.point
                && gap.capability == SemanticCapability::DynamicDispatch
                && (gap.subject == SemanticGapSubject::Point
                    || gap.subject == SemanticGapSubject::CallSite(direct_call.id))
        }));

        let provider = fixture.analyzer.icfg_provider();
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
        assert!(matches!(
            &dynamic.transfers[0].proof,
            ProofStatus::Unproven(_)
        ));
        assert!(matches!(
            &dynamic.transfers[0].completeness,
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

        assert!(dispatch.candidates.is_empty(), "{dispatch:#?}");
        assert_eq!(dispatch.boundaries.len(), 1, "{dispatch:#?}");
        assert!(matches!(
            dispatch.boundaries[0].kind,
            DispatchBoundaryKind::Unmaterialized(_)
        ));
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
