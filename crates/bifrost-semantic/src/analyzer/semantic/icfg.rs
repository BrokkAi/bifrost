//! Demand-materialized, language-neutral interprocedural control flow.
//!
//! Callable CFGs remain immutable and procedure-local. This module stitches a
//! bounded, generation-local view on demand and never builds an eager
//! whole-workspace graph.

use std::fmt;
use std::sync::Arc;

use crate::analyzer::semantic::read_ledger::ReadKey;

use brokk_bifrost_core::analyzer::model::Language;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmBudget;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmRequest;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmWork;

use crate::analyzer::semantic::cfg_algorithms::forward_reachability;

use crate::analyzer::semantic::cfg_algorithms::reverse_reachability;

use crate::analyzer::semantic::completeness_reason_bytes;

use crate::analyzer::semantic::workspace_oracle::semantic_locator_work;

use crate::analyzer::semantic::ArgumentCallableProvenance;

use crate::analyzer::semantic::CallContinuationKind;

use crate::analyzer::semantic::CallInvocationMode;

use crate::analyzer::semantic::CallSiteHandle;

use crate::analyzer::semantic::CallSiteId;

use crate::analyzer::semantic::ControlContinuation;

use crate::analyzer::semantic::ControlEdgeKind;

use crate::analyzer::semantic::DeferredInvocationKind;

use crate::analyzer::semantic::DispatchBoundaryKind;

use crate::analyzer::semantic::EvidenceCompleteness;

use crate::analyzer::semantic::EvidenceHandle;

use crate::analyzer::semantic::FormalMultiplicity;

use crate::analyzer::semantic::OracleCallContext;

use crate::analyzer::semantic::OracleLimits;

use crate::analyzer::semantic::OracleRelationArena;

use crate::analyzer::semantic::OracleRelationHandle;

use crate::analyzer::semantic::OracleRelationId;

use crate::analyzer::semantic::OracleRelationKind;

use crate::analyzer::semantic::OracleRelationOwner;

use crate::analyzer::semantic::OracleRelationRecord;

use crate::analyzer::semantic::OracleRelationSubject;

use crate::analyzer::semantic::ProcedureHandle;

use crate::analyzer::semantic::ProgramPointHandle;

use crate::analyzer::semantic::ProofStatus;

use crate::analyzer::semantic::SemanticBudgetExceeded;

use crate::analyzer::semantic::SemanticCallSite;

use crate::analyzer::semantic::SemanticCapability;

use crate::analyzer::semantic::SemanticGap;

use crate::analyzer::semantic::SemanticGapDischarge;

use crate::analyzer::semantic::SemanticGapImpact;

use crate::analyzer::semantic::SemanticGapKind;

use crate::analyzer::semantic::SemanticGapSubject;

use brokk_bifrost_core::analyzer::model::LanguageDialect as SemanticLanguage;

use crate::analyzer::semantic::SemanticOutcome;

use crate::analyzer::semantic::SemanticProviderError;

use crate::analyzer::semantic::SemanticRequest;

use crate::analyzer::semantic::SemanticValue;

use crate::analyzer::semantic::SemanticValueKind;

use crate::analyzer::semantic::SemanticWork;

#[doc(hidden)]
pub const DEFAULT_ICFG_PROVIDER_BEHAVIOR_DOMAIN: &[u8] =
    b"bifrost-icfg-provider/default-behavior/v1";
// Shared copied-member and return-port transport changes provider answers even
// when a language artifact is unchanged. Rotate both persisted behavior halves
// so field surveys, class-set roots and read-verified summaries cannot reuse
// answers produced before that transport was represented (#2848), before
// construction results were separated from initializer returns (#3347), or
// before Python bound-method dispatch accounted for receiver lookup hooks.
// Module-qualified Python constructors now bind their allocated instance
// without treating the module namespace as a runtime receiver, including
// calls through repeated unaliased imports of one dotted package root,
// resolver-proven from-imported submodules, and their local aliases (#4492).
// Nested class attributes and module namespaces imported in conditional
// branches use the same constructor allocation result (#4564).
// A Go call through a package variable now dispatches to its function-literal
// initializer when a workspace usage census proves the variable is never
// written, escaped, or read as a value (#3787).
// Factory callback provenance, matched-return capture transport and captured
// formal cell initialization change the executable flow and heap semantics.
// Go handler dispatch accepts reference sites whose roots omit trivia (#4811).
// Structured callee spines reject calls of values instead of binding them to
// names inside the callee expression (#5019).
// Native Kotlin points change call/definition answers consumed by persisted
// field and class-set results, independently of graph backend authority.
#[doc(hidden)]
pub const WORKSPACE_ICFG_PROVIDER_BEHAVIOR_DOMAIN: &[u8] =
    b"bifrost-icfg-provider/workspace-behavior/v30";
/// The domain of the same behavior without the workspace's content identity.
///
/// Its own domain rather than a shorter message under the one above, so that
/// no read half can ever equal a full identity by accident.
#[doc(hidden)]
pub const WORKSPACE_ICFG_PROVIDER_READ_BEHAVIOR_DOMAIN: &[u8] =
    b"bifrost-icfg-provider/workspace-read-behavior/v29";

/// Why one dispatch lookup could not be named by a replayable read key.
///
/// A summary that observes this status must fail closed instead of publishing
/// an apparently complete read set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DispatchReadUnattributedReason {
    /// The semantic call site has no exact retained source range.
    SourceRangeUnavailable,
    /// More than one lowered call row has the same exact source range inside
    /// the owning procedure.
    SourceRangeAmbiguous,
    /// Contextual dispatch has no context-aware persisted replay question yet.
    CallContextUnavailable,
}

/// The replayable input read by one call-dispatch lookup, or the typed reason
/// that lookup cannot be attributed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchReadAttribution {
    Attributed(ReadKey),
    Unattributed(DispatchReadUnattributedReason),
}

/// Whether this first authored non-return consumer has an unambiguous call
/// identity and immediate-invocation contract for `language`.
///
/// The external member key intentionally collapses same-arity overloads, and
/// an unmaterialized boundary does not carry async/generator invocation
/// semantics. Go has neither overloads nor deferred callable invocation at an
/// ordinary emitted call site. A supported `defer` emits on its cleanup route,
/// while a spawned call carries `DifferentTask` timing and never becomes a
/// synchronous body transfer. Broaden this predicate only with an equally
/// structured proof.
#[doc(hidden)]
pub const fn supports_authored_normal_continuation_absence(language: SemanticLanguage) -> bool {
    matches!(language, SemanticLanguage::Standard(Language::Go))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallTransfer {
    pub origin: CallSiteHandle,
    pub callee: ProcedureHandle,
    pub callee_entry: ProgramPointHandle,
    /// Exact caller creation and captured slots for a during-call invocation.
    pub argument_callable: Option<Arc<ArgumentCallableProvenance>>,
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

#[doc(hidden)]
pub const fn boundary_call_to_return_model(
    invocation_mode: CallInvocationMode,
    normal_continuation_absent: bool,
) -> CallToReturnModel {
    match (invocation_mode, normal_continuation_absent) {
        (CallInvocationMode::Detached, _) => CallToReturnModel::Normal,
        (CallInvocationMode::Ordinary, true) => CallToReturnModel::Exceptional,
        (CallInvocationMode::Ordinary, false) => CallToReturnModel::NormalAndExceptional,
    }
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
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
}

/// One procedure-local ICFG edge before a bounded call context assigns dense
/// snapshot node IDs.
///
/// Summary tabulation and bounded snapshot stitching consume the same owned
/// projection so call/return evidence cannot drift between the two backends.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProcedureIcfgEdge {
    pub source: ProgramPointHandle,
    pub target: ProgramPointHandle,
    pub kind: IcfgEdgeKind,
    pub origin: Option<CallSiteHandle>,
    pub proof: ProofStatus,
    pub completeness: EvidenceCompleteness,
    pub boundary: Option<DispatchBoundaryKind>,
}

/// One procedure-local incomplete ICFG boundary before snapshot node
/// materialization.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProcedureIcfgBoundary {
    pub at: ProgramPointHandle,
    pub origin: Option<CallSiteHandle>,
    pub kind: IcfgBoundaryKind,
}

/// Callee-local evidence from one entry to one normal or exceptional exit.
///
/// The profile deliberately excludes the evidence of any incoming call.
/// [`IcfgExitProfile::project_matched_return`] composes that caller-specific
/// evidence only when replaying a summary for an exact incoming call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcfgExitProfile {
    #[doc(hidden)]
    pub callee_entry: ProgramPointHandle,
    #[doc(hidden)]
    pub callee_exit: ProgramPointHandle,
    #[doc(hidden)]
    pub kind: ReturnTransferKind,
    #[doc(hidden)]
    pub gap_reason: Option<Box<str>>,
    #[doc(hidden)]
    pub matched_return_has_gaps: bool,
    #[doc(hidden)]
    pub matched_return_gap_reason: Option<Box<str>>,
    #[doc(hidden)]
    pub matched_return_gaps_are_implicit_abort_only: bool,
    // `SemanticOutcome` has no representation for a retained payload whose
    // quality is specifically truncated without attributing that truncation
    // to the current request budget. Keep the exact local quality so the
    // bounded snapshot adapter preserves its pre-extraction precedence when
    // it combines this profile with other semantic evidence.
    #[doc(hidden)]
    pub quality: SnapshotQuality,
}

impl IcfgExitProfile {
    pub fn callee_entry(&self) -> &ProgramPointHandle {
        &self.callee_entry
    }

    pub fn callee_exit(&self) -> &ProgramPointHandle {
        &self.callee_exit
    }

    pub const fn kind(&self) -> ReturnTransferKind {
        self.kind
    }

    /// Whether this exit contributes any gaps to the aggregate profile outcome.
    pub const fn has_aggregate_return_affecting_gaps(&self) -> bool {
        self.gap_reason.is_some()
    }

    /// Whether gaps weaken this exit's concrete matched-return projection.
    pub const fn has_matched_return_affecting_gaps(&self) -> bool {
        self.matched_return_has_gaps
    }

    /// Exact structured gaps contributing to the aggregate profile outcome.
    pub fn aggregate_return_affecting_gap_reason(&self) -> Option<&str> {
        self.gap_reason.as_deref()
    }

    /// Exact structured reason this exit cannot prove a complete matched return.
    pub fn matched_return_affecting_gap_reason(&self) -> Option<&str> {
        if !self.matched_return_has_gaps {
            None
        } else {
            self.matched_return_gap_reason
                .as_deref()
                .or(self.gap_reason.as_deref())
        }
    }

    /// Whether every gap weakening this matched return is an unlowered
    /// implicit-abort edge that its producer marked non-rejoining, with at
    /// least one such gap.
    ///
    /// The profile retains this structured classification because its rendered
    /// reason is diagnostic text, not an analysis interface. A caller may
    /// discharge these gaps only after proving that no abort route in its
    /// analyzed region runs user code.
    pub const fn matched_return_gaps_are_implicit_abort_only(&self) -> bool {
        self.matched_return_gaps_are_implicit_abort_only
    }

    /// Project this callee-local exit through one exact incoming call.
    pub fn project_matched_return(
        &self,
        incoming: &CallTransfer,
    ) -> Result<MatchedReturnProjection, SemanticProviderError> {
        project_matched_return(self, incoming)
    }
}

/// Exact result of matching one profiled callee exit to one incoming call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchedReturnProjection {
    Edge {
        /// Exact return edge projected into the caller.
        edge: ProcedureIcfgEdge,
        /// Whether the exit profile is the only source weakening this edge,
        /// and all of its matched-return gaps are implicit aborts.
        implicit_abort_only: bool,
    },
    Absent,
    Boundary(ProcedureIcfgBoundary),
}

/// Procedure-local call-to-return edges and continuation boundaries projected
/// from one modeled dispatch boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallToReturnProjection {
    pub edges: Box<[ProcedureIcfgEdge]>,
    pub boundaries: Box<[ProcedureIcfgBoundary]>,
}

#[doc(hidden)]
pub type CallTransferCacheKey = (ProcedureHandle, CallSiteId, OracleCallContext);
#[doc(hidden)]
pub type ExitProfileCacheKey = (ProgramPointHandle, ProgramPointHandle);

/// One exact in-process semantic artifact allocation.
///
/// A validity key and materialization digest can describe independently
/// allocated identical rows, but prepared dispatch may return artifact-local
/// handles. Pointer identity keeps those handles inside their owner while the
/// strong reference prevents address reuse for the lifetime of the key.
#[derive(Clone)]
#[doc(hidden)]
pub struct ExactArtifactAllocation(
    #[doc(hidden)] pub Arc<crate::analyzer::semantic::SemanticArtifact>,
);

impl PartialEq for ExactArtifactAllocation {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ExactArtifactAllocation {}

impl std::hash::Hash for ExactArtifactAllocation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::ptr::hash(Arc::as_ptr(&self.0), state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcfgNodeKey {
    #[doc(hidden)]
    pub point: ProgramPointHandle,
    #[doc(hidden)]
    pub call_context: Box<[CallSiteHandle]>,
    #[doc(hidden)]
    pub argument_callable: Option<Arc<ArgumentCallableProvenance>>,
}

impl IcfgNodeKey {
    /// Construct one dense-snapshot node from a language-neutral program point
    /// and its exact outermost-to-innermost call context.
    pub fn new(point: ProgramPointHandle, call_context: Vec<CallSiteHandle>) -> Self {
        Self {
            point,
            call_context: call_context.into_boxed_slice(),
            argument_callable: None,
        }
    }

    /// Exact creation/capture association of the innermost argument closure
    /// whose body contains this node. Capture value transport remains a
    /// separate, explicitly incomplete consumer contract.
    pub fn argument_callable(&self) -> Option<&ArgumentCallableProvenance> {
        self.argument_callable.as_deref()
    }

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

            #[doc(hidden)]
            pub fn try_from_index(index: usize) -> Result<Self, SemanticProviderError> {
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

    pub const fn sort_key(self) -> (u8, u8) {
        match self {
            Self::Intraprocedural(kind) => (0, kind.sort_rank()),
            Self::Call => (1, 0),
            Self::NormalReturn => (2, 0),
            Self::ExceptionalReturn => (3, 0),
            Self::CallToNormalContinuation => (4, 0),
            Self::CallToExceptionalContinuation => (5, 0),
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
    pub boundary: Option<DispatchBoundaryKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IcfgLimitKind {
    CallDepth,
    Nodes,
    Edges,
}

impl IcfgLimitKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::CallDepth => "call_depth_limit",
            Self::Nodes => "node_limit",
            Self::Edges => "edge_limit",
        }
    }
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

    #[doc(hidden)]
    pub fn validate(self) -> Result<(), InvalidIcfgSnapshotLimits> {
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
    #[doc(hidden)]
    pub fn empty() -> Self {
        Self {
            nodes: Box::new([]),
            edges: Box::new([]),
            outgoing_offsets: Box::new([0]),
            incoming_offsets: Box::new([0]),
            incoming_edge_ids: Box::new([]),
            boundaries: Box::new([]),
        }
    }

    /// Validate and index an already bounded language-neutral ICFG projection.
    ///
    /// Edges are grouped stably by source node. Their caller-supplied order is
    /// preserved within each source row, which lets custom providers choose a
    /// deterministic traversal order without rebuilding compact adjacency
    /// indexes themselves.
    pub fn try_from_parts(
        nodes: Vec<IcfgNodeKey>,
        mut edges: Vec<IcfgEdge>,
        mut boundaries: Vec<IcfgBoundary>,
    ) -> Result<Self, SemanticProviderError> {
        edges.sort_by_key(|edge| edge.source);
        let node_count = nodes.len();
        let mut incoming_counts = vec![0_u32; node_count];
        for edge in &edges {
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
            while cursor < edges.len() && edges[cursor].source.index() == source {
                cursor += 1;
            }
            outgoing_offsets.push(u32::try_from(cursor).map_err(|_| {
                SemanticProviderError::internal("ICFG outgoing offsets exceed u32")
            })?);
        }
        debug_assert_eq!(cursor, edges.len(), "ICFG edges are grouped by source");

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
        let mut incoming_edge_ids = vec![IcfgEdgeId::default(); edges.len()];
        let mut incoming_cursors = incoming_offsets[..node_count].to_vec();
        for (index, edge) in edges.iter().enumerate() {
            let target = edge.target.index();
            let destination = incoming_cursors[target] as usize;
            incoming_edge_ids[destination] = IcfgEdgeId::try_from_index(index)?;
            incoming_cursors[target] = incoming_cursors[target]
                .checked_add(1)
                .ok_or_else(|| SemanticProviderError::internal("ICFG incoming cursor overflow"))?;
        }

        for boundary in &boundaries {
            if boundary.at.index() >= node_count {
                return Err(SemanticProviderError::internal(
                    "ICFG boundary has an out-of-range node",
                ));
            }
        }
        boundaries.sort_by_key(icfg_boundary_sort_key);
        boundaries.dedup();

        Ok(Self {
            nodes: nodes.into_boxed_slice(),
            edges: edges.into_boxed_slice(),
            outgoing_offsets: outgoing_offsets.into_boxed_slice(),
            incoming_offsets: incoming_offsets.into_boxed_slice(),
            incoming_edge_ids: incoming_edge_ids.into_boxed_slice(),
            boundaries: boundaries.into_boxed_slice(),
        })
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
#[doc(hidden)]
pub struct CallFrame {
    #[doc(hidden)]
    pub transfer: CallTransfer,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct TraversalKey {
    #[doc(hidden)]
    pub point: ProgramPointHandle,
    #[doc(hidden)]
    pub frames: Box<[CallFrame]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum SnapshotQuality {
    Complete,
    Ambiguous,
    Unproven,
    Unknown,
    Unsupported(SemanticCapability),
    Truncated,
    Cancelled,
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
    if edge.boundary.is_some()
        && !matches!(
            edge.kind,
            IcfgEdgeKind::CallToNormalContinuation | IcfgEdgeKind::CallToExceptionalContinuation
        )
    {
        return Err(SemanticProviderError::internal(
            "dispatch-boundary metadata is attached to a non-continuation ICFG edge",
        ));
    }
    Ok(())
}

#[doc(hidden)]
pub fn node_work(key: &TraversalKey) -> SemanticWork {
    SemanticWork {
        program_points: 1,
        nested_entries: key.frames.len().saturating_add(2),
        ..SemanticWork::default()
    }
}

#[doc(hidden)]
pub fn merge_quality(current: SnapshotQuality, incoming: SnapshotQuality) -> SnapshotQuality {
    use crate::analyzer::semantic::icfg::SnapshotQuality::*;
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

#[doc(hidden)]
pub fn icfg_edge_sort_key(edge: &IcfgEdge) -> (usize, (u8, u8), usize, u32) {
    (
        edge.source.index(),
        edge.kind.sort_key(),
        edge.target.index(),
        edge.origin
            .as_ref()
            .map_or(u32::MAX, |call| call.id().get()),
    )
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

#[doc(hidden)]
pub fn call_binding_completeness(
    call: &SemanticCallSite,
    callee_values: &[SemanticValue],
    completeness: EvidenceCompleteness,
) -> (EvidenceCompleteness, usize) {
    let mut fixed_formals = 0usize;
    let mut has_rest_formal = false;
    for value in callee_values {
        match &value.kind {
            SemanticValueKind::Parameter {
                multiplicity: FormalMultiplicity::One,
                ..
            } => fixed_formals = fixed_formals.saturating_add(1),
            SemanticValueKind::Parameter {
                multiplicity: FormalMultiplicity::Rest(_),
                ..
            } => has_rest_formal = true,
            _ => {}
        }
    }
    let bindings_complete = if has_rest_formal {
        call.arguments.len() >= fixed_formals
    } else {
        call.arguments.len() == fixed_formals
    };
    if bindings_complete {
        return (completeness, 0);
    }

    let previous_reason_bytes = completeness_reason_bytes(&completeness);
    let completeness = EvidenceCompleteness::Partial(match completeness {
        EvidenceCompleteness::Complete => format!(
            "caller supplies {} arguments for {fixed_formals} fixed formal parameters; omitted/default or variadic binding effects are incomplete",
            call.arguments.len()
        )
        .into(),
        EvidenceCompleteness::Partial(existing) => format!(
            "{existing}; caller supplies {} arguments for {fixed_formals} fixed formal parameters; omitted/default or variadic binding effects are incomplete",
            call.arguments.len()
        )
        .into(),
    });
    let added_reason_bytes =
        completeness_reason_bytes(&completeness).saturating_sub(previous_reason_bytes);
    (completeness, added_reason_bytes)
}

#[doc(hidden)]
pub fn finish_snapshot_outcome(
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
    snapshot_quality_outcome(snapshot, quality, work)
}

fn snapshot_quality_outcome<T>(
    value: T,
    quality: SnapshotQuality,
    work: SemanticWork,
) -> SemanticOutcome<T> {
    match quality {
        SnapshotQuality::Complete => SemanticOutcome::Complete { value, work },
        SnapshotQuality::Ambiguous => SemanticOutcome::Ambiguous {
            candidates: value,
            work,
        },
        SnapshotQuality::Unproven => SemanticOutcome::Unproven {
            partial: value,
            work,
        },
        SnapshotQuality::Unknown | SnapshotQuality::Truncated => SemanticOutcome::Unknown {
            partial: Some(value),
            work,
        },
        SnapshotQuality::Unsupported(capability) => SemanticOutcome::Unsupported {
            capability,
            partial: Some(value),
            work,
        },
        SnapshotQuality::Cancelled => SemanticOutcome::Cancelled {
            partial: Some(value),
            work,
        },
    }
}

#[doc(hidden)]
pub fn deferred_boundary_provenance(
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

#[doc(hidden)]
pub fn scoped_call_evaluation_gaps<'a>(
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

#[doc(hidden)]
pub fn call_evaluation_gap_applies(gap: &SemanticGap, call: &SemanticCallSite) -> bool {
    // A call-resolution gap asks a question this call's resolution and
    // binding answer, and those carry their own quality into the transfers
    // (#1989, #3757). It must not weaken the resolved transfers a second time.
    gap.impacts.contains(SemanticGapImpact::CallEvaluation)
        && gap.discharge != SemanticGapDischarge::CallResolution
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

#[doc(hidden)]
pub fn materialize_exit_profile(
    callee_entry: &ProgramPointHandle,
    callee_exit: &ProgramPointHandle,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<IcfgExitProfile>, SemanticProviderError> {
    materialize_exit_profile_with_runtime_reads(callee_entry, callee_exit, &[], &[], request)
}

/// `discharged` gaps are answered by a query-time proof (runtime reads,
/// inert drops) and are not return gaps; `non_rejoining` gaps are aborts a
/// query-time proof shows to be non-rejoining exceptional exits.
#[doc(hidden)]
pub fn materialize_exit_profile_with_runtime_reads(
    callee_entry: &ProgramPointHandle,
    callee_exit: &ProgramPointHandle,
    discharged_runtime_reads: &[crate::analyzer::semantic::SemanticGapId],
    non_rejoining: &[crate::analyzer::semantic::SemanticGapId],
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<IcfgExitProfile>, SemanticProviderError> {
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: SemanticWork::default(),
        });
    }

    if callee_entry.procedure() != callee_exit.procedure() {
        return Err(SemanticProviderError::internal(
            "ICFG exit profile entry and exit belong to different procedures",
        ));
    }
    let procedure = callee_exit.procedure();
    let semantics = procedure.semantics();
    let kind = if callee_exit.id() == semantics.normal_exit_point() {
        ReturnTransferKind::Normal
    } else if callee_exit.id() == semantics.exceptional_exit_point() {
        ReturnTransferKind::Exceptional
    } else {
        return Err(SemanticProviderError::internal(
            "ICFG exit profile requires a normal or exceptional procedure exit",
        ));
    };
    let point_count = semantics.points().len();
    let edge_count = semantics.control_edges().len();
    let gap_count = semantics.gaps().len();
    let traversal_steps = point_count
        .saturating_mul(2)
        .saturating_add(edge_count.saturating_mul(2))
        .saturating_add(gap_count);
    if !request.charge_execution_traversal(traversal_steps) {
        return Ok(SemanticOutcome::Unknown {
            partial: None,
            work: SemanticWork::default(),
        });
    }
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
    request.budget.charge_work(scan_work);

    let algorithm_limits = CfgAlgorithmWork {
        node_visits: point_count.saturating_mul(2),
        edge_visits: edge_count.saturating_mul(2),
    };
    let mut algorithm_budget = CfgAlgorithmBudget::new(algorithm_limits);
    let mut algorithm_request =
        CfgAlgorithmRequest::new(&mut algorithm_budget, request.cancellation);
    let from_entry =
        match forward_reachability(semantics, callee_entry.id(), &mut algorithm_request) {
            Ok(reachable) => reachable,
            Err(CfgAlgorithmError::Cancelled { .. }) => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: scan_work,
                });
            }
            Err(CfgAlgorithmError::ExceededBudget(exceeded)) => {
                unreachable!(
                    "precharged return-path traversal exceeded its complete-graph {} limit: \
                     attempted {}, limit {}, work {:?}",
                    exceeded.limit_kind.label(),
                    exceeded.attempted,
                    exceeded.limit,
                    exceeded.work
                );
            }
            Err(CfgAlgorithmError::InvalidNode(point)) => {
                unreachable!("validated procedure has an invalid entry point {point}");
            }
        };
    let to_exit = match reverse_reachability(semantics, callee_exit.id(), &mut algorithm_request) {
        Ok(reachable) => reachable,
        Err(CfgAlgorithmError::Cancelled { .. }) => {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: scan_work,
            });
        }
        Err(CfgAlgorithmError::ExceededBudget(exceeded)) => {
            unreachable!(
                "precharged return-path traversal exceeded its complete-graph {} limit: \
                 attempted {}, limit {}, work {:?}",
                exceeded.limit_kind.label(),
                exceeded.attempted,
                exceeded.limit,
                exceeded.work
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
    // An implicit-exception gap whose abort paths run no user code cannot
    // move a value into or past the NORMAL exit: the missing edges only
    // remove abort paths, so they cannot weaken the normal profile (#1952).
    // The exceptional profile always keeps the gap: whether this procedure
    // can reach its exceptional exit decides whether a caller's handler is
    // reachable at all, and the missing edges are exactly that reachability.
    let abort_user_code =
        crate::analyzer::semantic::workspace_oracle::abort_paths_run_user_code(semantics);
    let is_return_gap = |gap: &SemanticGap| {
        // A gap that declares a call-resolution discharge asks a question the
        // resolution and binding path always answers: an unresolved call
        // surfaces as a dispatch boundary, and a resolved callee that defers
        // evaluation carries its own procedure-level gap into its exit
        // profile and bindings (#1989). It must not weaken this caller's
        // exit profile a second time.
        if gap.discharge == SemanticGapDischarge::CallResolution
            || discharged_runtime_reads.contains(&gap.id)
        {
            return false;
        }
        let return_affecting = gap.impacts.contains(SemanticGapImpact::ReturnTransfer);
        let scoped_to_return_path = match gap.subject {
            SemanticGapSubject::Procedure => true,
            _ => path_mask.get(gap.point.index()).copied() == Some(true),
        };
        return_affecting
            && scoped_to_return_path
            && !(kind == ReturnTransferKind::Normal
                && crate::analyzer::semantic::workspace_oracle::implicit_abort_gap_is_discharged(
                    gap,
                    abort_user_code,
                ))
    };
    let is_matched_return_gap =
        |gap: &SemanticGap| is_return_gap(gap) && gap_affects_matched_return(gap, kind);
    let mut return_gap_count = 0usize;
    let mut matched_return_gap_count = 0usize;
    let mut quality = SnapshotQuality::Complete;
    let mut gap_reason_bytes = 0usize;
    let mut matched_return_gap_reason_bytes = 0usize;
    let mut matched_return_gaps_are_implicit_abort_only = true;
    for gap in semantics.gaps() {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: scan_work,
            });
        }
        if !is_return_gap(gap) {
            continue;
        }
        quality = merge_quality(quality, semantic_gap_quality(gap));
        gap_reason_bytes = gap_reason_bytes
            .saturating_add(semantic_gap_reason_entry_bytes(gap, return_gap_count > 0));
        return_gap_count = return_gap_count.saturating_add(1);
        if is_matched_return_gap(gap) {
            matched_return_gaps_are_implicit_abort_only &= (gap.discharge
                == SemanticGapDischarge::NonRejoiningExceptionalExit
                || non_rejoining.contains(&gap.id))
                && crate::analyzer::semantic::workspace_oracle::implicit_abort_gap_is_discharged(
                    gap, false,
                );
            matched_return_gap_reason_bytes = matched_return_gap_reason_bytes.saturating_add(
                semantic_gap_reason_entry_bytes(gap, matched_return_gap_count > 0),
            );
            matched_return_gap_count = matched_return_gap_count.saturating_add(1);
        }
    }
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: scan_work,
        });
    }
    let distinct_matched_reason_bytes =
        if matched_return_gap_count > 0 && matched_return_gap_count != return_gap_count {
            matched_return_gap_reason_bytes
        } else {
            0
        };
    let text_work = SemanticWork {
        owned_text_bytes: gap_reason_bytes.saturating_add(distinct_matched_reason_bytes),
        ..SemanticWork::default()
    };
    if let Err(exceeded) = request.budget.admit(text_work) {
        return Ok(SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: scan_work,
        });
    }
    let total_work = scan_work.conservative_add(text_work);
    let gap_reason = if return_gap_count == 0 {
        None
    } else {
        let mut reason = String::with_capacity(gap_reason_bytes);
        let mut written = 0usize;
        for gap in semantics.gaps() {
            if request.cancellation.is_cancelled() {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: total_work,
                });
            }
            if !is_return_gap(gap) {
                continue;
            }
            append_semantic_gap_reason_entry(&mut reason, gap, written > 0);
            written = written.saturating_add(1);
        }
        debug_assert_eq!(written, return_gap_count);
        debug_assert_eq!(reason.len(), gap_reason_bytes);
        Some(reason.into_boxed_str())
    };
    let matched_return_gap_reason =
        if matched_return_gap_count == 0 || matched_return_gap_count == return_gap_count {
            None
        } else {
            let mut reason = String::with_capacity(matched_return_gap_reason_bytes);
            let mut written = 0usize;
            for gap in semantics.gaps() {
                if request.cancellation.is_cancelled() {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work: total_work,
                    });
                }
                if !is_matched_return_gap(gap) {
                    continue;
                }
                append_semantic_gap_reason_entry(&mut reason, gap, written > 0);
                written = written.saturating_add(1);
            }
            debug_assert_eq!(written, matched_return_gap_count);
            debug_assert_eq!(reason.len(), matched_return_gap_reason_bytes);
            Some(reason.into_boxed_str())
        };
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: total_work,
        });
    }
    let profile = IcfgExitProfile {
        callee_entry: callee_entry.clone(),
        callee_exit: callee_exit.clone(),
        kind,
        gap_reason,
        matched_return_has_gaps: matched_return_gap_count > 0,
        matched_return_gap_reason,
        matched_return_gaps_are_implicit_abort_only: matched_return_gap_count > 0
            && matched_return_gaps_are_implicit_abort_only,
        quality,
    };
    Ok(exit_profile_outcome(profile, quality, total_work))
}

fn semantic_gap_reason_entry_bytes(gap: &SemanticGap, has_prior: bool) -> usize {
    usize::from(has_prior)
        .saturating_mul(2)
        .saturating_add(gap.kind.label().len())
        .saturating_add(1)
        .saturating_add(gap.capability.label().len())
        .saturating_add(2)
        .saturating_add(gap.detail.len())
}

fn append_semantic_gap_reason_entry(reason: &mut String, gap: &SemanticGap, has_prior: bool) {
    if has_prior {
        reason.push_str("; ");
    }
    reason.push_str(gap.kind.label());
    reason.push(' ');
    reason.push_str(gap.capability.label());
    reason.push_str(": ");
    reason.push_str(&gap.detail);
}

#[doc(hidden)]
pub fn gap_affects_matched_return(gap: &SemanticGap, kind: ReturnTransferKind) -> bool {
    // An unsupported exceptional alternative does not weaken the explicitly
    // represented normal route through the same operation. Unknown exceptional
    // behavior can still make that concrete route itself uncertain.
    kind != ReturnTransferKind::Normal
        || gap.capability != SemanticCapability::ExceptionalControlFlow
        || gap.kind != SemanticGapKind::Unsupported
}

fn exit_profile_outcome(
    profile: IcfgExitProfile,
    quality: SnapshotQuality,
    work: SemanticWork,
) -> SemanticOutcome<IcfgExitProfile> {
    snapshot_quality_outcome(profile, quality, work)
}

#[doc(hidden)]
pub fn semantic_gap_quality(gap: &SemanticGap) -> SnapshotQuality {
    match gap.kind {
        SemanticGapKind::Ambiguous => SnapshotQuality::Ambiguous,
        SemanticGapKind::Unsupported => SnapshotQuality::Unsupported(gap.capability),
        SemanticGapKind::ExceededBudget => SnapshotQuality::Truncated,
        SemanticGapKind::Unknown | SemanticGapKind::Unproven => SnapshotQuality::Unproven,
    }
}

#[doc(hidden)]
pub fn deferred_invocation_kind(
    properties: crate::analyzer::semantic::ProcedureProperties,
) -> DeferredInvocationKind {
    match (properties.is_async, properties.is_generator) {
        (true, true) => DeferredInvocationKind::AsyncGenerator,
        (true, false) => DeferredInvocationKind::Async,
        (false, true) => DeferredInvocationKind::Generator,
        (false, false) => DeferredInvocationKind::LanguageDefined,
    }
}

pub(crate) fn project_matched_return(
    exit: &IcfgExitProfile,
    incoming: &CallTransfer,
) -> Result<MatchedReturnProjection, SemanticProviderError> {
    if incoming.callee != *exit.callee_exit.procedure()
        || incoming.callee_entry != exit.callee_entry
    {
        return Err(SemanticProviderError::internal(
            "ICFG incoming call does not match the profiled callee entry",
        ));
    }

    let (continuation_kind, destination) = match exit.kind {
        ReturnTransferKind::Normal => (CallContinuationKind::Normal, incoming.normal_continuation),
        ReturnTransferKind::Exceptional => (
            CallContinuationKind::Exceptional,
            incoming.exceptional_continuation,
        ),
    };
    match destination {
        ControlContinuation::Target(point) => {
            let (proof, completeness) = return_evidence(exit, incoming);
            let implicit_abort_only = exit.matched_return_gaps_are_implicit_abort_only
                && matches!(&incoming.proof, ProofStatus::Proven)
                && matches!(&incoming.completeness, EvidenceCompleteness::Complete);
            let continuation = incoming
                .origin
                .procedure()
                .point_handle(point)
                .ok_or_else(|| SemanticProviderError::internal("return continuation is stale"))?;
            Ok(MatchedReturnProjection::Edge {
                edge: ProcedureIcfgEdge {
                    source: exit.callee_exit.clone(),
                    target: continuation,
                    kind: match exit.kind {
                        ReturnTransferKind::Normal => IcfgEdgeKind::NormalReturn,
                        ReturnTransferKind::Exceptional => IcfgEdgeKind::ExceptionalReturn,
                    },
                    origin: Some(incoming.origin.clone()),
                    proof,
                    completeness,
                    boundary: None,
                },
                implicit_abort_only,
            })
        }
        ControlContinuation::Absent => Ok(MatchedReturnProjection::Absent),
        state => Ok(MatchedReturnProjection::Boundary(ProcedureIcfgBoundary {
            at: exit.callee_exit.clone(),
            origin: Some(incoming.origin.clone()),
            kind: IcfgBoundaryKind::Continuation {
                kind: continuation_kind,
                state,
            },
        })),
    }
}

fn return_evidence(
    exit: &IcfgExitProfile,
    incoming: &CallTransfer,
) -> (ProofStatus, EvidenceCompleteness) {
    let Some(gap_reason) = exit.matched_return_affecting_gap_reason() else {
        return (incoming.proof.clone(), incoming.completeness.clone());
    };
    let proof = match &incoming.proof {
        ProofStatus::Proven => ProofStatus::Unproven(
            format!(
                "callee-exit evidence does not prove this {:?} completion returns to its caller: {gap_reason}",
                exit.kind
            )
            .into(),
        ),
        ProofStatus::Unproven(existing) => {
            ProofStatus::Unproven(format!("{existing}; {gap_reason}").into())
        }
    };
    let completeness = match &incoming.completeness {
        EvidenceCompleteness::Complete => EvidenceCompleteness::Partial(
            format!("the callee exit has exact return-affecting semantic gaps: {gap_reason}")
                .into(),
        ),
        EvidenceCompleteness::Partial(existing) => EvidenceCompleteness::Partial(
            format!("{existing}; return-affecting gaps: {gap_reason}").into(),
        ),
    };
    (proof, completeness)
}

pub fn invoked_call_at(
    point: &ProgramPointHandle,
) -> Result<Option<CallSiteId>, SemanticProviderError> {
    let semantic_point = point
        .procedure()
        .semantics()
        .point(point.id())
        .ok_or_else(|| SemanticProviderError::internal("ICFG point handle is stale"))?;
    Ok(semantic_point
        .events
        .iter()
        .find_map(|event| match event.effect {
            crate::analyzer::semantic::SemanticEffect::Invoke { call_site } => Some(call_site),
            _ => None,
        }))
}

/// Validate provider-owned exit evidence before either ICFG backend caches it.
pub fn validate_exit_profile(
    callee_entry: &ProgramPointHandle,
    callee_exit: &ProgramPointHandle,
    profile: &IcfgExitProfile,
) -> Result<(), SemanticProviderError> {
    if profile.callee_entry() != callee_entry {
        return Err(SemanticProviderError::internal(
            "ICFG exit profile entry does not match the requested entry",
        ));
    }
    if profile.callee_exit() != callee_exit {
        return Err(SemanticProviderError::internal(
            "ICFG exit profile exit does not match the requested exit",
        ));
    }
    Ok(())
}

pub fn is_call_scaffolding(
    edge: &crate::analyzer::semantic::ControlEdge,
    call: &crate::analyzer::semantic::SemanticCallSite,
) -> bool {
    matches!(
        (edge.kind, call.normal_continuation),
        (ControlEdgeKind::Normal, ControlContinuation::Target(target)) if edge.target_point == target
    ) || matches!(
        (edge.kind, call.exceptional_continuation),
        (ControlEdgeKind::Exceptional, ControlContinuation::Target(target)) if edge.target_point == target
    )
}
