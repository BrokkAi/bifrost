//! Demand-materialized, language-neutral interprocedural control flow.
//!
//! Callable CFGs remain immutable and procedure-local. This module stitches a
//! bounded, generation-local view on demand and never builds an eager
//! whole-workspace graph.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;

use crate::analyzer::semantic_model::{ActiveSemanticModelSnapshot, ProcedureSummaryMemberKey};
use crate::analyzer::{DispatchHierarchyExpansion, Language, WorkspaceAnalyzer};
use crate::hash::{HashMap, HashSet};

use super::cfg_algorithms::{
    CfgAlgorithmBudget, CfgAlgorithmError, CfgAlgorithmRequest, CfgAlgorithmWork,
    forward_reachability, reverse_reachability,
};
use super::workspace_oracle::{
    WorkspaceSemanticOracle, exact_source_for_procedure, semantic_locator_work,
};
use super::{
    CallContinuationKind, CallInvocationMode, CallSiteHandle, CallSiteId, CandidateCoverage,
    ControlContinuation, ControlEdgeKind, DeferredInvocationKind, DispatchBoundary,
    DispatchBoundaryKind, DispatchHints, DispatchOracle, DispatchResult, EvidenceCompleteness,
    EvidenceHandle, FormalMultiplicity, LengthDelimitedDigest, OracleLimits, OracleRelationArena,
    OracleRelationHandle, OracleRelationId, OracleRelationKind, OracleRelationOwner,
    OracleRelationRecord, OracleRelationSubject, ProcedureHandle, ProcedureInvocationKind,
    ProgramPointHandle, ProgramPointId, ProofStatus, SemanticBudgetExceeded, SemanticCallSite,
    SemanticCapability, SemanticGap, SemanticGapDischarge, SemanticGapImpact, SemanticGapKind,
    SemanticGapSubject, SemanticLanguage, SemanticOutcome, SemanticProviderError, SemanticRequest,
    SemanticValue, SemanticValueKind, SemanticWork, StableDigest,
};

const DEFAULT_ICFG_PROVIDER_BEHAVIOR_DOMAIN: &[u8] = b"bifrost-icfg-provider/default-behavior/v1";
const WORKSPACE_ICFG_PROVIDER_BEHAVIOR_DOMAIN: &[u8] =
    b"bifrost-icfg-provider/workspace-behavior/v4";
/// The domain of the same behavior without the workspace's content identity.
///
/// Its own domain rather than a shorter message under the one above, so that
/// no read half can ever equal a full identity by accident.
const WORKSPACE_ICFG_PROVIDER_READ_BEHAVIOR_DOMAIN: &[u8] =
    b"bifrost-icfg-provider/workspace-read-behavior/v2";

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
const fn supports_authored_normal_continuation_absence(language: SemanticLanguage) -> bool {
    matches!(language, SemanticLanguage::Standard(Language::Go))
}

/// Stable identity of every input that can change one provider's ICFG topology.
///
/// Providers whose behavior varies independently of their semantic artifacts
/// must override [`IcfgProvider::behavior_identity`]. The default preserves one
/// conservative identity for stateless providers and existing test fakes.
/// `read` is the same identity with the workspace's content identity left out,
/// for a record that must compare across two checkouts of the same content.
/// Everything else the digest folds -- the active model set, the semantic-model
/// overlay's presence, the dispatch hierarchy expansion -- is an engine input a
/// reader states independently, while the content identity rotates on every
/// edit anywhere in the workspace. A record keyed by the full digest could
/// therefore never be verified after any edit, however unrelated
/// (`.agents/plans/impact-sliced-diff-base.md`, Decision Log (5b)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IcfgProviderBehaviorIdentity {
    digest: StableDigest,
    read: StableDigest,
}

impl IcfgProviderBehaviorIdentity {
    /// One provider identity named by its own bytes.
    ///
    /// Both halves are the same digest: a provider that states its behavior as
    /// a fixed name folds no workspace content, so there is nothing to leave
    /// out.
    pub fn hash_bytes(bytes: impl AsRef<[u8]>) -> Self {
        let digest = StableDigest::sha256(bytes);
        Self {
            digest,
            read: digest,
        }
    }

    pub const fn digest(self) -> StableDigest {
        self.digest
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.digest.as_bytes()
    }

    /// This identity without the workspace's content identity.
    pub const fn read_digest(self) -> StableDigest {
        self.read
    }

    pub const fn read_bytes(&self) -> &[u8; 32] {
        self.read.as_bytes()
    }

    fn workspace(
        workspace: &WorkspaceAnalyzer,
        hierarchy_expansion: DispatchHierarchyExpansion,
        snapshot: Option<&ActiveSemanticModelSnapshot>,
        dispatch_hints: StableDigest,
    ) -> Self {
        let mut digest = LengthDelimitedDigest::new(WORKSPACE_ICFG_PROVIDER_BEHAVIOR_DOMAIN);
        let mut read = LengthDelimitedDigest::new(WORKSPACE_ICFG_PROVIDER_READ_BEHAVIOR_DOMAIN);
        // Every engine input except the workspace's own content identity, into
        // both halves: each of these is something a reader of a recorded read
        // states for itself, and none of them moves because an unrelated file
        // was edited.
        let push_engine_inputs = |digest: &mut LengthDelimitedDigest| {
            match snapshot {
                Some(snapshot) => {
                    digest.push(b"active-semantic-model-set");
                    digest.push(snapshot.active_models().active_model_set_hash().as_bytes());
                    if snapshot.semantic_model_overlay().is_some() {
                        digest.push(b"semantic-model-overlay-present");
                    } else {
                        digest.push(b"semantic-model-overlay-absent");
                    }
                }
                None => digest.push(b"no-active-semantic-model-set"),
            }
            digest.push(b"dispatch-hierarchy-expansion");
            digest.push(if hierarchy_expansion.concrete_overrides {
                b"concrete-overrides"
            } else {
                b"off"
            });
            match workspace.analyzer().external_dispatch_behavior_identity() {
                Some(identity) => {
                    digest.push(b"external-dispatch-surface");
                    digest.push(identity.as_bytes());
                }
                None => digest.push(b"no-external-dispatch-surface"),
            }
            digest.push(b"receiver-class-dispatch-hints");
            digest.push(dispatch_hints.as_bytes());
        };
        push_engine_inputs(&mut digest);
        push_engine_inputs(&mut read);
        // Dispatch can materialize any compatible declaration in the analyzer,
        // not only procedures from the root artifact. Bind the exact analyzed
        // file-set, language composition, epochs, and configuration through
        // their stable content identity. A pointer or generation would prevent
        // valid reuse across equivalent analyzer snapshots without proving the
        // target universes equal.
        //
        // The read half deliberately stops here: it names the same engine,
        // and which files that engine has is what a read set's own `File` and
        // `Artifact` keys state exactly.
        match workspace.analyzer().workspace_content_identity() {
            Some(identity) => {
                digest.push(b"workspace-dispatch-universe");
                digest.push(identity.digest().as_bytes());
            }
            None => {
                // Every production language analyzer publishes a content
                // identity. Only a workspace with no language delegates has a
                // genuinely empty dispatch universe that is safe to name with
                // one shared marker.
                assert!(
                    workspace.analyzer().languages().is_empty(),
                    "a nonempty workspace analyzer must state a content identity for ICFG caching"
                );
                digest.push(b"empty-workspace-dispatch-universe");
            }
        }
        Self {
            digest: digest.finish(),
            read: read.finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

const fn boundary_call_to_return_model(
    invocation_mode: CallInvocationMode,
    normal_continuation_absent: bool,
) -> CallToReturnModel {
    match (invocation_mode, normal_continuation_absent) {
        (CallInvocationMode::Detached, _) => CallToReturnModel::Normal,
        (CallInvocationMode::Ordinary, true) => CallToReturnModel::Exceptional,
        (CallInvocationMode::Ordinary, false) => CallToReturnModel::NormalAndExceptional,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallBoundary {
    pub origin: CallSiteHandle,
    pub dispatch: DispatchBoundary,
    pub model: CallToReturnModel,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallTransferSet {
    pub transfers: Box<[CallTransfer]>,
    pub boundaries: Box<[CallBoundary]>,
    pub coverage: CandidateCoverage,
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
    callee_entry: ProgramPointHandle,
    callee_exit: ProgramPointHandle,
    kind: ReturnTransferKind,
    gap_reason: Option<Box<str>>,
    matched_return_has_gaps: bool,
    matched_return_gap_reason: Option<Box<str>>,
    matched_return_gaps_are_implicit_abort_only: bool,
    // `SemanticOutcome` has no representation for a retained payload whose
    // quality is specifically truncated without attributing that truncation
    // to the current request budget. Keep the exact local quality so the
    // bounded snapshot adapter preserves its pre-extraction precedence when
    // it combines this profile with other semantic evidence.
    quality: SnapshotQuality,
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

pub trait IcfgProvider: DispatchOracle {
    /// Stable identity of provider state that can change emitted topology.
    fn behavior_identity(&self) -> IcfgProviderBehaviorIdentity {
        IcfgProviderBehaviorIdentity::hash_bytes(DEFAULT_ICFG_PROVIDER_BEHAVIOR_DOMAIN)
    }

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

    /// Materialize callee-local evidence from one procedure entry to one exit.
    ///
    /// Callers should cache the outcome query-locally by procedure, entry, and
    /// exit. A cache miss owns the bounded forward/reverse topology scan;
    /// replaying the returned profile for additional callers or facts owns no
    /// semantic work.
    fn exit_profile(
        &self,
        callee_entry: &ProgramPointHandle,
        callee_exit: &ProgramPointHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgExitProfile>, SemanticProviderError> {
        materialize_exit_profile(callee_entry, callee_exit, request)
    }
}

/// One provider is tied to one [`WorkspaceAnalyzer`] generation.
#[derive(Clone)]
pub struct WorkspaceIcfgProvider<'a> {
    oracle: WorkspaceSemanticOracle<'a>,
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    behavior_identity: IcfgProviderBehaviorIdentity,
}

impl<'a> WorkspaceIcfgProvider<'a> {
    pub fn new(workspace: &'a WorkspaceAnalyzer) -> Self {
        Self::with_active_semantic_model_snapshot(
            workspace,
            workspace.analyzer().active_semantic_model_snapshot(),
        )
    }

    /// Bind this provider to an active-model snapshot already captured by its
    /// request owner.
    ///
    /// This keeps several semantic consumers in one request on one model
    /// identity even if a later activation publishes a new analyzer overlay.
    pub fn with_active_semantic_model_snapshot(
        workspace: &'a WorkspaceAnalyzer,
        snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Self {
        Self::with_active_semantic_model_snapshot_and_hints(
            workspace,
            snapshot,
            DispatchHints::empty(),
        )
    }

    /// Bind this provider to one captured active-model snapshot and one
    /// immutable receiver-class dispatch overlay.
    pub fn with_active_semantic_model_snapshot_and_hints(
        workspace: &'a WorkspaceAnalyzer,
        snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
        dispatch_hints: DispatchHints,
    ) -> Self {
        let oracle = WorkspaceSemanticOracle::with_dispatch_hints(
            workspace,
            snapshot.as_deref(),
            dispatch_hints,
        );
        let behavior_identity = IcfgProviderBehaviorIdentity::workspace(
            workspace,
            oracle.hierarchy_expansion(),
            snapshot.as_deref(),
            oracle.dispatch_hints().digest(),
        );
        Self {
            oracle,
            active_semantic_model_snapshot: snapshot,
            behavior_identity,
        }
    }

    pub const fn workspace(&self) -> &'a WorkspaceAnalyzer {
        self.oracle.workspace()
    }

    pub const fn oracle(&self) -> &WorkspaceSemanticOracle<'a> {
        &self.oracle
    }

    /// Record that this provider read `procedure`'s owning semantic artifact
    /// (issue: impact-sliced `--diff-base`, Milestone 5).
    ///
    /// A snapshot, a call-transfer projection and an exit profile all read the
    /// procedure, point, edge and call-site rows of one immutable artifact, and
    /// the artifact is the unit derivation publishes, so the read is named
    /// exactly as `semantic::service::materialize_with_lowerer` names it: by
    /// the artifact's public fingerprint and its workspace-relative path,
    /// never by the mount-bearing `SemanticArtifactKey`. Recording the whole
    /// artifact rather than the rows actually touched is the over-recording
    /// direction the ledger requires.
    ///
    /// A run with no ledger attached pays one relaxed load and allocates
    /// nothing.
    fn record_artifact_read(&self, procedure: &ProcedureHandle) {
        let analyzer = self.workspace().analyzer();
        if !analyzer.read_ledger_attached() {
            return;
        }
        let key = procedure.artifact().key();
        analyzer.record_read(crate::analyzer::read_ledger::ReadKey::artifact(
            crate::analyzer::invalidation::DerivedArtifactId::semantic_artifact(
                key.public_fingerprint(),
            ),
            Some(key.path().as_str()),
        ));
    }

    /// Record one dispatch answer this provider read.
    ///
    /// Dispatch is the channel a typestate or taint solve composes callee
    /// bodies through, so which targets a call site resolved to -- and whether
    /// that set was exhaustive -- is itself an input the solve depended on. The
    /// question and the answer digest are built by the same helpers
    /// `WorkspaceSemanticOracle::dispatch_at_source_in_artifact` uses, so
    /// `read_verification::replay_lookup` replays this recording through the
    /// source-range entry point without a second rendering of the answer.
    ///
    /// A call site with no retained source mapping cannot be named in the
    /// source-range terms replay asks in. That is a funnel crossing this
    /// provider cannot attribute, and it says so rather than staying silent.
    fn record_dispatch_read(
        &self,
        call: &CallSiteHandle,
        outcome: &SemanticOutcome<DispatchResult>,
    ) {
        let analyzer = self.workspace().analyzer();
        if !analyzer.read_ledger_attached() {
            return;
        }
        let Ok(range) = super::workspace_oracle::exact_call_range(call) else {
            analyzer.record_unattributed_read();
            return;
        };
        analyzer.record_read(crate::analyzer::read_ledger::ReadKey::lookup(
            crate::analyzer::read_ledger::LookupKind::Dispatch,
            super::workspace_oracle::dispatch_question(call.procedure().artifact(), range),
            super::workspace_oracle::one_call_dispatch_answer_digest(call, outcome),
        ));
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
    /// Construct one dense-snapshot node from a language-neutral program point
    /// and its exact outermost-to-innermost call context.
    pub fn new(point: ProgramPointHandle, call_context: Vec<CallSiteHandle>) -> Self {
        Self {
            point,
            call_context: call_context.into_boxed_slice(),
        }
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
    pub boundary: Option<DispatchBoundaryKind>,
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
struct CallFrame {
    transfer: CallTransfer,
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
    /// Every caller-side continuation already published, whichever projection
    /// published it. A dispatch boundary and a matched return can name the
    /// same continuation of the same call, and the two rows differ only in the
    /// boundary they carry, so plain edge deduplication would keep both.
    call_to_return_edges: HashSet<(IcfgNodeId, IcfgNodeId, IcfgEdgeKind)>,
    boundaries: Vec<IcfgBoundary>,
    queue: VecDeque<IcfgNodeId>,
    exit_profiles: HashMap<
        (ProcedureHandle, ProgramPointId, ProgramPointId),
        SemanticOutcome<Arc<IcfgExitProfile>>,
    >,
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
            call_to_return_edges: HashSet::default(),
            boundaries: Vec::new(),
            queue: VecDeque::new(),
            exit_profiles: HashMap::default(),
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
            .map(|frame| frame.transfer.origin.clone())
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
        boundary: Option<DispatchBoundaryKind>,
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
            boundary,
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
        self.edges.sort_by(|left, right| {
            icfg_edge_sort_key(left)
                .cmp(&icfg_edge_sort_key(right))
                .then_with(|| left.boundary.cmp(&right.boundary))
        });
        IcfgSnapshot::try_from_parts(self.nodes, self.edges, self.boundaries)
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
        let outcome = self.oracle.resolve_call(call, request)?;
        self.record_artifact_read(call.procedure());
        self.record_dispatch_read(call, &outcome);
        Ok(outcome)
    }
}
impl IcfgProvider for WorkspaceIcfgProvider<'_> {
    fn behavior_identity(&self) -> IcfgProviderBehaviorIdentity {
        self.behavior_identity
    }

    /// The default profile projection, with the callee artifact it reads
    /// named.
    ///
    /// The entry and exit points scope one procedure of one artifact, and the
    /// profile is a bounded scan of that procedure's own topology, so the read
    /// is the artifact. The default implementation is otherwise unchanged.
    fn exit_profile(
        &self,
        callee_entry: &ProgramPointHandle,
        callee_exit: &ProgramPointHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<IcfgExitProfile>, SemanticProviderError> {
        self.record_artifact_read(callee_entry.procedure());
        materialize_exit_profile(callee_entry, callee_exit, request)
    }

    fn call_transfers(
        &self,
        caller: &ProcedureHandle,
        call: CallSiteId,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError> {
        self.record_artifact_read(caller);
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
        let dispatch_outcome =
            self.resolve_call(&origin, &mut request.staged(&mut staged_budget))?;
        let mapped = try_map_semantic_outcome(dispatch_outcome, |dispatch| {
            let mut transfers = Vec::new();
            let mut additional_work = SemanticWork::default();
            let (candidates, dispatch_boundaries, coverage) = dispatch.into_parts();
            let mut boundaries = dispatch_boundaries
                .into_vec()
                .into_iter()
                .map(|dispatch| {
                    let normal_continuation_absent = dispatch
                        .unmaterialized_external_target()
                        .is_some_and(|target| {
                            supports_authored_normal_continuation_absence(target.language())
                                && self.active_semantic_model_snapshot.as_deref().is_some_and(
                                    |snapshot| {
                                        snapshot.active_models().proves_normal_continuation_absent(
                                            ProcedureSummaryMemberKey::new(
                                                target.language().semantic_pack_label(),
                                                target.owner_fqn(),
                                                target.member(),
                                                target.has_receiver(),
                                                target.arity(),
                                            ),
                                        )
                                    },
                                )
                        });
                    CallBoundary {
                        origin: origin.clone(),
                        dispatch,
                        model: boundary_call_to_return_model(
                            semantic_call.invocation_mode,
                            normal_continuation_absent,
                        ),
                    }
                })
                .collect::<Vec<_>>();
            for candidate in candidates.into_vec() {
                let properties = candidate.target.semantics().properties();
                if semantic_call.invocation_mode == CallInvocationMode::Detached {
                    let previous_reason_bytes = completeness_reason_bytes(&candidate.completeness);
                    let completeness = EvidenceCompleteness::Partial(
                        "callee body executes in a different task".into(),
                    );
                    let added_reason_bytes = completeness_reason_bytes(&completeness)
                        .saturating_sub(previous_reason_bytes);
                    let target = candidate.target.semantics().locator().clone();
                    let boundary_kind = DispatchBoundaryKind::Deferred {
                        target: target.clone(),
                        kind: DeferredInvocationKind::Async,
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
                            external_callee_identity: None,
                            exact_external_target: None,
                            unmaterialized_external_target: None,
                            proof: candidate.proof,
                            completeness,
                            provenance,
                        },
                        // Starting the task returns normally to the registering
                        // procedure. The spawned body's exits never rejoin it.
                        model: CallToReturnModel::Normal,
                    });
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
                            external_callee_identity: None,
                            exact_external_target: None,
                            unmaterialized_external_target: None,
                            proof: candidate.proof,
                            completeness,
                            provenance,
                        },
                        // Creating the suspended object normally returns to the
                        // caller, while argument binding or language call
                        // mechanics can still fail synchronously.
                        model: CallToReturnModel::NormalAndExceptional,
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
                let (completeness, added_reason_bytes) = call_binding_completeness(
                    &semantic_call,
                    candidate.target.semantics().values(),
                    candidate.completeness,
                );
                additional_work = sum_semantic_work(
                    additional_work,
                    SemanticWork {
                        owned_text_bytes: added_reason_bytes,
                        ..SemanticWork::default()
                    },
                );
                transfers.push(CallTransfer {
                    origin: origin.clone(),
                    callee: candidate.target,
                    callee_entry: entry,
                    normal_continuation: semantic_call.normal_continuation,
                    exceptional_continuation: semantic_call.exceptional_continuation,
                    proof: candidate.proof,
                    completeness,
                });
            }
            let mut transfer_set = CallTransferSet {
                transfers: transfers.into_boxed_slice(),
                boundaries: boundaries.into_boxed_slice(),
                coverage,
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
        self.record_artifact_read(root);
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
        let mut staged_request = request.staged(&mut staged_budget);
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
            if !staged_request.charge_execution_traversal(1) {
                builder.quality = merge_quality(builder.quality, SnapshotQuality::Truncated);
                break;
            }
            let key = builder.traversal[node.index()].clone();
            if expand_return(self, &mut builder, node, &key, &mut staged_request)? {
                continue;
            }
            let call = invoked_call_at(&key.point)?;

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
                        validate_call_transfer_set(
                            key.point.procedure(),
                            &semantic_call,
                            &transfers,
                        )?;
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
                            let callee_entry = transfer.callee_entry.clone();
                            let proof = transfer.proof.clone();
                            let completeness = transfer.completeness.clone();
                            let mut frames = key.frames.to_vec();
                            frames.push(CallFrame { transfer });
                            let target_key = TraversalKey {
                                point: callee_entry,
                                frames: frames.into_boxed_slice(),
                            };
                            builder.link(
                                node,
                                target_key,
                                IcfgEdgeKind::Call,
                                Some(origin.clone()),
                                proof,
                                completeness,
                                None,
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

fn call_binding_completeness(
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

fn materialize_exit_profile(
    callee_entry: &ProgramPointHandle,
    callee_exit: &ProgramPointHandle,
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
    if let Err(exceeded) = request.budget.charge(scan_work) {
        return Ok(SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: SemanticWork::default(),
        });
    }

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
        if gap.discharge == SemanticGapDischarge::CallResolution {
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
            matched_return_gaps_are_implicit_abort_only &= gap.discharge
                == SemanticGapDischarge::NonRejoiningExceptionalExit
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
    if let Err(exceeded) = request.budget.charge(text_work) {
        return Ok(SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: scan_work,
        });
    }
    let total_work = sum_semantic_work(scan_work, text_work);
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

fn gap_affects_matched_return(gap: &SemanticGap, kind: ReturnTransferKind) -> bool {
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
    match quality {
        SnapshotQuality::Complete => SemanticOutcome::Complete {
            value: profile,
            work,
        },
        SnapshotQuality::Ambiguous => SemanticOutcome::Ambiguous {
            candidates: profile,
            work,
        },
        SnapshotQuality::Unproven => SemanticOutcome::Unproven {
            partial: profile,
            work,
        },
        SnapshotQuality::Unknown | SnapshotQuality::Truncated => SemanticOutcome::Unknown {
            partial: Some(profile),
            work,
        },
        SnapshotQuality::Unsupported(capability) => SemanticOutcome::Unsupported {
            capability,
            partial: Some(profile),
            work,
        },
        SnapshotQuality::Cancelled => SemanticOutcome::Cancelled {
            partial: Some(profile),
            work,
        },
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

fn deferred_invocation_kind(properties: super::ProcedureProperties) -> DeferredInvocationKind {
    match (properties.is_async, properties.is_generator) {
        (true, true) => DeferredInvocationKind::AsyncGenerator,
        (true, false) => DeferredInvocationKind::Async,
        (false, true) => DeferredInvocationKind::Generator,
        (false, false) => DeferredInvocationKind::LanguageDefined,
    }
}

pub fn project_call_boundary(
    caller: &ProcedureHandle,
    semantic_call: &SemanticCallSite,
    boundary: &CallBoundary,
) -> Result<CallToReturnProjection, SemanticProviderError> {
    let model = boundary.model;
    if boundary.origin.procedure() != caller {
        return Err(SemanticProviderError::internal(
            "call-to-return boundary belongs to a different caller",
        ));
    }
    if boundary.origin.id() != semantic_call.id {
        return Err(SemanticProviderError::internal(
            "call boundary origin does not match the projected call",
        ));
    }
    let at = caller
        .point_handle(semantic_call.point)
        .ok_or_else(|| SemanticProviderError::internal("call boundary point is stale"))?;

    let mut edges = Vec::new();
    let mut boundaries = Vec::new();
    let mut project = |kind: CallContinuationKind,
                       continuation: ControlContinuation,
                       edge_kind: IcfgEdgeKind|
     -> Result<(), SemanticProviderError> {
        match continuation {
            ControlContinuation::Target(point) => {
                let target = caller.point_handle(point).ok_or_else(|| {
                    SemanticProviderError::internal("call boundary continuation is stale")
                })?;
                edges.push(ProcedureIcfgEdge {
                    source: at.clone(),
                    target,
                    kind: edge_kind,
                    origin: Some(boundary.origin.clone()),
                    proof: boundary.dispatch.proof.clone(),
                    completeness: boundary.dispatch.completeness.clone(),
                    boundary: Some(boundary.dispatch.kind.clone()),
                });
            }
            ControlContinuation::Absent => {}
            state => {
                boundaries.push(ProcedureIcfgBoundary {
                    at: at.clone(),
                    origin: Some(boundary.origin.clone()),
                    kind: IcfgBoundaryKind::Continuation { kind, state },
                });
            }
        }
        Ok(())
    };
    if matches!(
        model,
        CallToReturnModel::Normal | CallToReturnModel::NormalAndExceptional
    ) {
        project(
            CallContinuationKind::Normal,
            semantic_call.normal_continuation,
            IcfgEdgeKind::CallToNormalContinuation,
        )?;
    }
    if matches!(
        model,
        CallToReturnModel::Exceptional | CallToReturnModel::NormalAndExceptional
    ) {
        project(
            CallContinuationKind::Exceptional,
            semantic_call.exceptional_continuation,
            IcfgEdgeKind::CallToExceptionalContinuation,
        )?;
    }
    Ok(CallToReturnProjection {
        edges: edges.into_boxed_slice(),
        boundaries: boundaries.into_boxed_slice(),
    })
}

fn link_boundary_continuations(
    builder: &mut SnapshotBuilder,
    source: IcfgNodeId,
    key: &TraversalKey,
    semantic_call: &SemanticCallSite,
    boundary: &CallBoundary,
    request: &mut SemanticRequest<'_>,
) -> Result<(), SemanticProviderError> {
    let projection = project_call_boundary(key.point.procedure(), semantic_call, boundary)?;
    for edge in projection.edges {
        debug_assert_eq!(edge.source, key.point);
        let kind = edge.kind;
        let linked = builder.link(
            source,
            TraversalKey {
                point: edge.target,
                frames: key.frames.clone(),
            },
            kind,
            edge.origin,
            edge.proof,
            edge.completeness,
            edge.boundary,
            request,
        )?;
        // A matched return through a resolved target of the same call must not
        // publish a second row for a continuation this boundary already owns.
        if let Some(target) = linked
            && matches!(
                kind,
                IcfgEdgeKind::CallToNormalContinuation
                    | IcfgEdgeKind::CallToExceptionalContinuation
            )
        {
            builder.call_to_return_edges.insert((source, target, kind));
        }
    }
    for boundary in projection.boundaries {
        debug_assert_eq!(boundary.at, key.point);
        builder.boundaries.push(IcfgBoundary {
            at: source,
            origin: boundary.origin,
            kind: boundary.kind,
        });
        builder.quality = merge_quality(builder.quality, SnapshotQuality::Unknown);
    }
    Ok(())
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

fn expand_return<P>(
    provider: &P,
    builder: &mut SnapshotBuilder,
    node: IcfgNodeId,
    key: &TraversalKey,
    request: &mut SemanticRequest<'_>,
) -> Result<bool, SemanticProviderError>
where
    P: IcfgProvider + ?Sized,
{
    let semantics = key.point.procedure().semantics();
    if key.point.id() != semantics.normal_exit_point()
        && key.point.id() != semantics.exceptional_exit_point()
    {
        return Ok(false);
    }
    let Some(frame) = key.frames.last() else {
        return Ok(false);
    };
    if frame.transfer.callee != *key.point.procedure() {
        return Err(SemanticProviderError::internal(
            "ICFG return context does not match the exiting callee",
        ));
    }

    let cache_key = (
        key.point.procedure().clone(),
        frame.transfer.callee_entry.id(),
        key.point.id(),
    );
    let (outcome, newly_materialized) = if let Some(cached) = builder.exit_profiles.get(&cache_key)
    {
        (cached.clone(), false)
    } else {
        let outcome = provider.exit_profile(&frame.transfer.callee_entry, &key.point, request)?;
        if let Some(profile) = outcome.available_value() {
            validate_exit_profile(&frame.transfer.callee_entry, &key.point, profile)?;
        }
        let outcome = outcome.map(Arc::new);
        builder.exit_profiles.insert(cache_key, outcome.clone());
        (outcome, true)
    };
    builder.absorb_quality(&outcome);
    if newly_materialized {
        builder.work = builder.work.conservative_add(outcome.work());
    }
    let Some(profile) = outcome.available_value() else {
        return Ok(true);
    };
    builder.quality = merge_quality(builder.quality, profile.quality);

    match profile.project_matched_return(&frame.transfer)? {
        MatchedReturnProjection::Edge { edge, .. } => {
            debug_assert_eq!(edge.source, key.point);
            let caller_frames: Box<[CallFrame]> = key.frames[..key.frames.len() - 1]
                .to_vec()
                .into_boxed_slice();
            let return_kind = edge.kind;
            let continuation_key = TraversalKey {
                point: edge.target,
                frames: caller_frames,
            };
            let continuation = builder.link(
                node,
                continuation_key.clone(),
                edge.kind,
                edge.origin,
                edge.proof,
                edge.completeness,
                edge.boundary,
                request,
            )?;
            if let Some(continuation) = continuation {
                link_caller_side_continuation(
                    builder,
                    &frame.transfer,
                    continuation_key,
                    continuation,
                    return_kind,
                    request,
                )?;
            }
        }
        MatchedReturnProjection::Absent => {}
        MatchedReturnProjection::Boundary(boundary) => {
            debug_assert_eq!(boundary.at, key.point);
            builder.boundaries.push(IcfgBoundary {
                at: node,
                origin: boundary.origin,
                kind: boundary.kind,
            });
            builder.quality = merge_quality(builder.quality, SnapshotQuality::Unknown);
        }
    }
    Ok(true)
}

/// Link the caller's own control continuation across a resolved call whose
/// matched return has just been projected (#1952, #2782).
///
/// A resolved call replaces the caller's scaffolding edge with call and
/// matched-return transfers, so nothing in the bounded graph otherwise lets a
/// caller-side value the callee neither receives nor returns survive the call.
/// Summary tabulation projects this row for itself; a solver reading this
/// snapshot had no way to, and its backward direction therefore lost every
/// value-flow pair that spans a call.
///
/// The row is projected here, beside the matched return, rather than at the
/// call, because the two must agree on when control resumes: a callee that
/// never returns normally reaches no normal exit, so it yields neither a
/// normal return nor a normal continuation.
///
/// The edge is the caller's own scaffolding, so its evidence is proven and
/// complete, and it carries no dispatch boundary. `resolved_call_to_return` is
/// what tells a solver whether to traverse it.
fn link_caller_side_continuation(
    builder: &mut SnapshotBuilder,
    transfer: &CallTransfer,
    continuation_key: TraversalKey,
    continuation: IcfgNodeId,
    return_kind: IcfgEdgeKind,
    request: &mut SemanticRequest<'_>,
) -> Result<(), SemanticProviderError> {
    let kind = match return_kind {
        IcfgEdgeKind::NormalReturn => IcfgEdgeKind::CallToNormalContinuation,
        IcfgEdgeKind::ExceptionalReturn => IcfgEdgeKind::CallToExceptionalContinuation,
        _ => return Ok(()),
    };
    let caller = transfer.origin.procedure();
    let call_site = caller
        .semantics()
        .call_site(transfer.origin.id())
        .ok_or_else(|| SemanticProviderError::internal("ICFG return origin call site is stale"))?;
    let call_point = caller
        .point_handle(call_site.point)
        .ok_or_else(|| SemanticProviderError::internal("ICFG return origin point is stale"))?;
    let call_key = TraversalKey {
        point: call_point,
        frames: continuation_key.frames.clone(),
    };
    // The callee was entered from this node, so it is already interned. An
    // absent caller would mean the return context does not match the call the
    // traversal came through, which `expand_return` has already rejected.
    let source = builder.interner.get(&call_key).copied().ok_or_else(|| {
        SemanticProviderError::internal("ICFG matched return has no calling node")
    })?;
    // A dispatch boundary at the same call already published this
    // continuation, and that row reaches every problem. A second,
    // boundary-free row for it would only duplicate the edge.
    if !builder
        .call_to_return_edges
        .insert((source, continuation, kind))
    {
        return Ok(());
    }
    builder.link(
        source,
        continuation_key,
        kind,
        Some(transfer.origin.clone()),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
        None,
        request,
    )?;
    Ok(())
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
        None,
        request,
    )?;
    Ok(())
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
            super::SemanticEffect::Invoke { call_site } => Some(call_site),
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

/// Validate provider-owned call projections before either ICFG backend
/// publishes them.
pub fn validate_call_transfer_set(
    caller: &ProcedureHandle,
    semantic_call: &SemanticCallSite,
    transfers: &CallTransferSet,
) -> Result<(), SemanticProviderError> {
    let Some(stored_call) = caller.semantics().call_site(semantic_call.id) else {
        return Err(SemanticProviderError::internal(
            "ICFG call transfer set refers to a call outside its caller",
        ));
    };
    if stored_call != semantic_call {
        return Err(SemanticProviderError::internal(
            "ICFG call transfer set refers to a mismatched semantic call",
        ));
    }
    let origin = caller
        .call_site_handle(semantic_call.id)
        .ok_or_else(|| SemanticProviderError::internal("failed to scope ICFG transfer call"))?;
    if semantic_call.invocation_mode == CallInvocationMode::Detached
        && !transfers.transfers.is_empty()
    {
        return Err(SemanticProviderError::internal(
            "detached call transfer set cannot enter a callee body synchronously",
        ));
    }
    for transfer in &transfers.transfers {
        if transfer.origin != origin {
            return Err(SemanticProviderError::internal(
                "ICFG call transfer origin does not match the requested call",
            ));
        }
        if transfer.callee_entry.procedure() != &transfer.callee {
            return Err(SemanticProviderError::internal(
                "ICFG call transfer entry belongs to a different callee",
            ));
        }
        if transfer.normal_continuation != semantic_call.normal_continuation {
            return Err(SemanticProviderError::internal(
                "ICFG call transfer has a mismatched normal continuation",
            ));
        }
        if transfer.exceptional_continuation != semantic_call.exceptional_continuation {
            return Err(SemanticProviderError::internal(
                "ICFG call transfer has a mismatched exceptional continuation",
            ));
        }
    }
    for boundary in &transfers.boundaries {
        if boundary.origin != origin {
            return Err(SemanticProviderError::internal(
                "ICFG call boundary origin does not match the requested call",
            ));
        }
        boundary
            .dispatch
            .validate_for_call(&origin)
            .map_err(|error| {
                SemanticProviderError::internal(format!(
                    "ICFG call boundary has invalid dispatch provenance: {error}"
                ))
            })?;
        if semantic_call.invocation_mode == CallInvocationMode::Detached
            && boundary.model != CallToReturnModel::Normal
        {
            return Err(SemanticProviderError::internal(
                "detached call boundary must retain only the caller's normal continuation",
            ));
        }
    }
    Ok(())
}

pub fn is_call_scaffolding(edge: &super::ControlEdge, call: &super::SemanticCallSite) -> bool {
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
        DeclarationSegment, DispatchCandidate, DispatchHintCallSiteKey, DispatchHintSet,
        ProcedureKind, SemanticBudget, SemanticGapId, SemanticGapImpacts,
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
            boundary: None,
        }
    }

    #[test]
    fn detached_external_call_keeps_parent_normal_continuation() {
        assert_eq!(
            boundary_call_to_return_model(CallInvocationMode::Detached, true),
            CallToReturnModel::Normal,
            "a nonreturning target summary describes the detached body, not spawn registration"
        );
        assert_eq!(
            boundary_call_to_return_model(CallInvocationMode::Detached, false),
            CallToReturnModel::Normal
        );
        assert_eq!(
            boundary_call_to_return_model(CallInvocationMode::Ordinary, true),
            CallToReturnModel::Exceptional
        );
        assert_eq!(
            boundary_call_to_return_model(CallInvocationMode::Ordinary, false),
            CallToReturnModel::NormalAndExceptional
        );
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
            discharge: SemanticGapDischarge::None,
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
    fn exit_profiles_are_scoped_to_distinct_artifact_instances() {
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
        for procedure in [&first, &second] {
            let entry = procedure
                .point_handle(procedure.semantics().entry_point())
                .expect("entry point handle");
            let exit = procedure
                .point_handle(procedure.semantics().normal_exit_point())
                .expect("normal exit point handle");
            let outcome = materialize_exit_profile(&entry, &exit, &mut request)
                .expect("exit profile")
                .map(Arc::new);
            assert!(
                builder
                    .exit_profiles
                    .insert((procedure.clone(), entry.id(), exit.id()), outcome,)
                    .is_none()
            );
        }

        assert_eq!(builder.exit_profiles.len(), 2);
        assert!(builder.exit_profiles.contains_key(&(
            first.clone(),
            first.semantics().entry_point(),
            first.semantics().normal_exit_point(),
        )));
        assert!(builder.exit_profiles.contains_key(&(
            second.clone(),
            second.semantics().entry_point(),
            second.semantics().normal_exit_point(),
        )));
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
        // Dispatch may materialize a cold target while call transfer reuses
        // that semantic artifact, so their total work is not directly
        // additive. The transfer must still retain at least the independently
        // measured deferred-boundary projection; the exact one-below budget
        // assertion below proves the complete payload is charged atomically.
        assert!(
            transfer_outcome.work().nested_entries >= projected_work.nested_entries,
            "deferred transfer must retain its projected nested rows"
        );
        assert!(
            transfer_outcome.work().owned_text_bytes >= projected_work.owned_text_bytes,
            "deferred transfer must retain its projected locator text"
        );
        assert_eq!(transfer_budget.used(), transfer_outcome.work());
        let semantic_call = caller
            .semantics()
            .call_site(call.id())
            .expect("deferred semantic call");
        let continuation_projection = project_call_boundary(&caller, semantic_call, deferred)
            .expect("modeled deferred continuations");
        let expected_projection_rows = [
            semantic_call.normal_continuation,
            semantic_call.exceptional_continuation,
        ]
        .into_iter()
        .filter(|continuation| !matches!(*continuation, ControlContinuation::Absent))
        .count();
        assert_eq!(
            continuation_projection
                .edges
                .len()
                .saturating_add(continuation_projection.boundaries.len()),
            expected_projection_rows
        );
        assert!(
            continuation_projection
                .edges
                .iter()
                .all(|edge| edge.origin.as_ref() == Some(&call)
                    && edge.proof == deferred.dispatch.proof
                    && edge.completeness == deferred.dispatch.completeness)
        );

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
    fn cpp_header_definition_coalescing_is_proven_and_excludes_unrelated_link_unit() {
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

        assert!(matches!(&outcome, SemanticOutcome::Complete { .. }));
        assert_eq!(dispatch.candidates().len(), 1, "{dispatch:#?}");
        assert_eq!(dispatch.candidates()[0].proof, ProofStatus::Proven);
        assert_eq!(
            dispatch.candidates()[0].completeness,
            EvidenceCompleteness::Complete
        );
        assert_eq!(
            dispatch.candidates()[0]
                .target
                .artifact()
                .key()
                .path()
                .as_str(),
            "target.cpp"
        );
        assert!(dispatch.boundaries().is_empty(), "{dispatch:#?}");

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

        // The resolver proved the imported target as the complete receiverless
        // target set, which discharges the adapter's blanket rebinding gap
        // (#1952): the outcome is complete, and no unresolved boundary remains.
        assert!(matches!(&outcome, SemanticOutcome::Complete { .. }));
        assert_eq!(dispatch.coverage(), CandidateCoverage::Exhaustive);
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
        assert!(dispatch.boundaries().is_empty(), "{dispatch:#?}");
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
        assert!(!direct_caller.semantics().gaps().iter().any(|gap| {
            gap.point == direct_call.point
                && gap.subject == SemanticGapSubject::CallSite(direct_call.id)
                && (gap.impacts.contains(SemanticGapImpact::CallEvaluation)
                    || gap.impacts.contains(SemanticGapImpact::DispatchCoverage))
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
        // The open virtual target set does not weaken this retained
        // candidate's proof or its represented normal call mechanics.
        assert_eq!(
            dynamic.transfers[0].completeness,
            EvidenceCompleteness::Complete
        );
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
        assert!(matches!(&direct_outcome, SemanticOutcome::Complete { .. }));
        let direct = direct_outcome
            .available_value()
            .expect("non-virtual dispatch transfers");
        assert_eq!(direct.transfers.len(), 1, "{direct:#?}");
        assert!(matches!(&direct.transfers[0].proof, ProofStatus::Proven));
        assert_eq!(
            direct.transfers[0].completeness,
            EvidenceCompleteness::Complete
        );
        assert!(direct.boundaries.is_empty(), "{direct:#?}");
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

Guard make_guard();

void temporary_target() {
    make_guard();
}

Guard *pointer_target(Guard *value) {
    Guard *copy = value;
    return copy;
}

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
        let caller = procedure("raii_caller");
        let temporary_target = procedure("temporary_target");
        let pointer_target = procedure("pointer_target");
        assert!(temporary_target.semantics().gaps().iter().any(|gap| {
            gap.point == temporary_target.semantics().normal_exit_point()
                && gap.capability == SemanticCapability::ResourceManagement
        }));
        assert!(!pointer_target.semantics().gaps().iter().any(|gap| {
            gap.point == pointer_target.semantics().normal_exit_point()
                && gap.capability == SemanticCapability::ResourceManagement
        }));

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
    fn cpp_bodyless_callable_identity_emits_one_unresolved_boundary() {
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

        assert!(!matches!(&outcome, SemanticOutcome::Complete { .. }));
        assert!(dispatch.candidates().is_empty(), "{dispatch:#?}");
        assert_eq!(dispatch.boundaries().len(), 1, "{dispatch:#?}");
        assert_eq!(
            dispatch.boundaries()[0].kind,
            DispatchBoundaryKind::Unresolved,
            "{dispatch:#?}"
        );
        assert!(matches!(
            dispatch.boundaries()[0].proof,
            ProofStatus::Unproven(_)
        ));
        assert!(matches!(
            dispatch.boundaries()[0].completeness,
            EvidenceCompleteness::Partial(_)
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
    fn workspace_icfg_provider_remains_clone() {
        fn assert_clone<T: Clone>() {}
        assert_clone::<WorkspaceIcfgProvider<'static>>();
    }

    #[test]
    fn dispatch_hint_order_is_canonical_and_separates_provider_behavior() {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[(
                "caller.py",
                "def caller(x):\n    x.first()\n    return x.second()\n",
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "caller.py");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("Python caller materialization")
            .available_value()
            .cloned()
            .expect("Python caller artifact");
        let procedure = artifact
            .procedures()
            .first()
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("caller procedure");
        let calls = procedure.semantics().call_sites();
        assert_eq!(calls.len(), 2);
        let first = DispatchHintSet::new(
            DispatchHintCallSiteKey::for_call(&procedure, calls[0].id),
            Vec::new(),
            true,
            true,
        );
        let second = DispatchHintSet::new(
            DispatchHintCallSiteKey::for_call(&procedure, calls[1].id),
            Vec::new(),
            true,
            true,
        );
        let forward = DispatchHints::new(vec![first.clone(), second.clone()]);
        let reverse = DispatchHints::new(vec![second, first]);
        assert_eq!(forward.digest(), reverse.digest());

        let open = DispatchHints::new(vec![DispatchHintSet::new(
            DispatchHintCallSiteKey::for_call(&procedure, calls[0].id),
            Vec::new(),
            false,
            true,
        )]);
        assert_ne!(forward.digest(), open.digest());

        let unhinted =
            WorkspaceIcfgProvider::with_active_semantic_model_snapshot(&fixture.analyzer, None);
        let hinted = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            &fixture.analyzer,
            None,
            forward,
        );
        assert_ne!(unhinted.behavior_identity(), hinted.behavior_identity());
        assert_ne!(
            unhinted.behavior_identity().read_digest(),
            hinted.behavior_identity().read_digest()
        );
    }

    #[test]
    fn authored_normal_continuation_absence_starts_with_unambiguous_go_calls() {
        assert!(supports_authored_normal_continuation_absence(
            SemanticLanguage::Standard(Language::Go)
        ));
        assert!(
            !supports_authored_normal_continuation_absence(SemanticLanguage::Standard(
                Language::Java
            )),
            "same-arity overloads need an exact signature and immediate-invocation proof first"
        );
    }

    #[test]
    fn exit_profile_projects_exact_returns_and_owns_one_topology_scan() {
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::TypeScript,
            &[(
                "returns.ts",
                concat!(
                    "function target(): number { return 1; }\n",
                    "function other(): number { return target(); }\n",
                    "export function caller(): number { return target(); }\n",
                ),
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "returns.ts");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("TypeScript materialization")
            .available_value()
            .cloned()
            .expect("TypeScript artifact");
        let find_procedure = |name| {
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
        let target = find_procedure("target");
        let other = find_procedure("other");
        let caller = find_procedure("caller");
        let semantic_call = caller
            .semantics()
            .call_sites()
            .first()
            .expect("target call");
        let call_point = caller
            .point_handle(semantic_call.point)
            .expect("target call point");
        let other_call = other
            .semantics()
            .call_sites()
            .first()
            .and_then(|call| other.call_site_handle(call.id))
            .expect("other target call");
        assert_eq!(
            invoked_call_at(&call_point).expect("valid invocation point"),
            Some(semantic_call.id)
        );
        assert!(
            caller
                .semantics()
                .successor_edges(semantic_call.point)
                .any(|(_, edge)| is_call_scaffolding(edge, semantic_call))
        );

        let provider = fixture.analyzer.icfg_provider();
        let mut transfer_budget = SemanticBudget::default();
        let transfer_outcome = provider
            .call_transfers(
                &caller,
                semantic_call.id,
                &mut SemanticRequest::new(&mut transfer_budget, &cancellation),
            )
            .expect("target call transfer");
        let transfer_set = transfer_outcome
            .available_value()
            .expect("target transfer payload");
        validate_call_transfer_set(&caller, semantic_call, transfer_set)
            .expect("valid target transfer set");
        let incoming = transfer_set
            .transfers
            .iter()
            .find(|transfer| transfer.callee == target)
            .expect("target transfer")
            .clone();
        let caller_entry = caller
            .point_handle(caller.semantics().entry_point())
            .expect("caller entry");
        let mut mismatched_origin = transfer_set.clone();
        mismatched_origin.transfers[0].origin = other_call.clone();
        assert!(
            validate_call_transfer_set(&caller, semantic_call, &mismatched_origin).is_err(),
            "transfer origins must identify the requested call"
        );
        let mut mismatched_entry_owner = transfer_set.clone();
        mismatched_entry_owner.transfers[0].callee_entry = caller_entry.clone();
        assert!(
            validate_call_transfer_set(&caller, semantic_call, &mismatched_entry_owner).is_err(),
            "callee entries must belong to their declared callees"
        );
        let mut mismatched_normal = transfer_set.clone();
        mismatched_normal.transfers[0].normal_continuation =
            if semantic_call.normal_continuation == ControlContinuation::Unknown {
                ControlContinuation::Absent
            } else {
                ControlContinuation::Unknown
            };
        assert!(
            validate_call_transfer_set(&caller, semantic_call, &mismatched_normal).is_err(),
            "normal continuations must match the semantic call"
        );
        let mut mismatched_exceptional = transfer_set.clone();
        mismatched_exceptional.transfers[0].exceptional_continuation =
            if semantic_call.exceptional_continuation == ControlContinuation::Unknown {
                ControlContinuation::Absent
            } else {
                ControlContinuation::Unknown
            };
        assert!(
            validate_call_transfer_set(&caller, semantic_call, &mismatched_exceptional).is_err(),
            "exceptional continuations must match the semantic call"
        );
        // The resolved receiverless call retains no boundary of its own since
        // the resolver-proven target set discharges the blanket rebinding gap
        // (#1952), so fabricate one with a foreign origin to prove the
        // validator still rejects boundary origins from another call.
        assert!(transfer_set.boundaries.is_empty(), "{transfer_set:#?}");
        let mut mismatched_boundary = transfer_set.clone();
        mismatched_boundary.boundaries = vec![CallBoundary {
            origin: other_call,
            dispatch: DispatchBoundary {
                kind: DispatchBoundaryKind::Unresolved,
                external_callee_identity: None,
                exact_external_target: None,
                unmaterialized_external_target: None,
                proof: ProofStatus::Unproven("fabricated foreign-origin boundary".into()),
                completeness: EvidenceCompleteness::Partial(
                    "fabricated foreign-origin boundary".into(),
                ),
                provenance: Box::new([]),
            },
            model: CallToReturnModel::NormalAndExceptional,
        }]
        .into_boxed_slice();
        assert!(
            validate_call_transfer_set(&caller, semantic_call, &mismatched_boundary).is_err(),
            "boundary origins must identify the requested call"
        );
        let exit = target
            .point_handle(target.semantics().normal_exit_point())
            .expect("target normal exit");
        let expected_work = SemanticWork {
            program_points: target.semantics().points().len().saturating_mul(2),
            control_edges: target.semantics().control_edges().len().saturating_mul(2),
            gaps: target.semantics().gaps().len(),
            nested_entries: target
                .semantics()
                .points()
                .len()
                .saturating_mul(2)
                .saturating_add(target.semantics().control_edges().len().saturating_mul(2))
                .saturating_add(target.semantics().gaps().len()),
            ..SemanticWork::default()
        };
        let mut exit_budget = SemanticBudget::default();
        let exit_outcome = provider
            .exit_profile(
                &incoming.callee_entry,
                &exit,
                &mut SemanticRequest::new(&mut exit_budget, &cancellation),
            )
            .expect("target exit profile");
        assert!(matches!(&exit_outcome, SemanticOutcome::Complete { .. }));
        assert_eq!(exit_outcome.work(), expected_work);
        assert_eq!(exit_budget.used(), expected_work);
        let profile = exit_outcome.available_value().expect("target exit payload");
        assert_eq!(profile.callee_entry(), &incoming.callee_entry);
        assert_eq!(profile.kind(), ReturnTransferKind::Normal);
        assert!(!profile.has_aggregate_return_affecting_gaps());

        let mut mismatched_profile_budget = SemanticBudget::default();
        assert!(
            provider
                .exit_profile(
                    &caller_entry,
                    &exit,
                    &mut SemanticRequest::new(&mut mismatched_profile_budget, &cancellation),
                )
                .is_err(),
            "profile entry and exit must belong to one procedure"
        );
        assert_eq!(
            mismatched_profile_budget.used(),
            SemanticWork::default(),
            "invalid profile topology must not own semantic work"
        );

        let MatchedReturnProjection::Edge {
            edge: return_edge, ..
        } = profile
            .project_matched_return(&incoming)
            .expect("matched target return")
        else {
            panic!("target normal exit must project a return edge");
        };
        assert_eq!(return_edge.source, exit);
        assert_eq!(return_edge.target.procedure(), &caller);
        assert_eq!(return_edge.kind, IcfgEdgeKind::NormalReturn);
        assert_eq!(return_edge.origin.as_ref(), Some(&incoming.origin));
        assert_eq!(return_edge.proof, incoming.proof);
        assert_eq!(return_edge.completeness, incoming.completeness);

        let exceptional_exit = target
            .point_handle(target.semantics().exceptional_exit_point())
            .expect("target exceptional exit");
        let abort_profile = IcfgExitProfile {
            callee_entry: incoming.callee_entry.clone(),
            callee_exit: exceptional_exit,
            kind: ReturnTransferKind::Exceptional,
            gap_reason: Some("unsupported exceptional_control_flow: implicit abort".into()),
            matched_return_has_gaps: true,
            matched_return_gap_reason: Some(
                "unsupported exceptional_control_flow: implicit abort".into(),
            ),
            matched_return_gaps_are_implicit_abort_only: true,
            quality: SnapshotQuality::Unsupported(SemanticCapability::ExceptionalControlFlow),
        };
        let projection_is_abort_only = |incoming: &CallTransfer| {
            let MatchedReturnProjection::Edge {
                implicit_abort_only,
                ..
            } = abort_profile
                .project_matched_return(incoming)
                .expect("implicit-abort exceptional return")
            else {
                panic!("target exceptional exit must project a return edge");
            };
            implicit_abort_only
        };
        assert!(
            projection_is_abort_only(&incoming),
            "a proven complete incoming transfer leaves only the implicit-abort weakening"
        );
        let mut unproven_incoming = incoming.clone();
        unproven_incoming.proof = ProofStatus::Unproven("independent dispatch uncertainty".into());
        assert!(
            !projection_is_abort_only(&unproven_incoming),
            "independently unproven incoming evidence must remain distinct"
        );
        let mut partial_incoming = incoming.clone();
        partial_incoming.completeness =
            EvidenceCompleteness::Partial("independent call-transfer gap".into());
        assert!(
            !projection_is_abort_only(&partial_incoming),
            "independently partial incoming evidence must remain distinct"
        );

        let mut mismatched_entry = incoming.clone();
        mismatched_entry.callee_entry = exit.clone();
        assert!(
            profile.project_matched_return(&mismatched_entry).is_err(),
            "matched returns require the exact profiled entry"
        );

        let mut unknown_continuation = incoming;
        unknown_continuation.normal_continuation = ControlContinuation::Unknown;
        let MatchedReturnProjection::Boundary(boundary) = profile
            .project_matched_return(&unknown_continuation)
            .expect("unknown return continuation")
        else {
            panic!("unknown continuation must remain a typed boundary");
        };
        assert_eq!(boundary.at, exit);
        assert_eq!(boundary.origin.as_ref(), Some(&unknown_continuation.origin));
        assert_eq!(
            boundary.kind,
            IcfgBoundaryKind::Continuation {
                kind: CallContinuationKind::Normal,
                state: ControlContinuation::Unknown,
            }
        );
    }

    #[test]
    fn go_implicit_abort_discharge_uses_the_gap_point_cleanup_scope() {
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::Go,
            &[(
                "defer_abort_scope.go",
                concat!(
                    "package sample\n",
                    "type resource struct{ value int }\n",
                    "func cleanup(int) {}\n",
                    "func first(resource *resource) { defer cleanup(resource.value) }\n",
                    "func later(resource *resource) {\n",
                    "    defer cleanup(0)\n",
                    "    defer cleanup(resource.value)\n",
                    "}\n",
                ),
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "defer_abort_scope.go");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Go materialization")
            .available_value()
            .cloned()
            .expect("Go artifact");
        let find_procedure = |name| {
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
        let selection_gap = |procedure: &ProcedureHandle| {
            procedure
                .semantics()
                .gaps()
                .iter()
                .find(|gap| gap.detail.as_ref() == "selection may panic on a nil operand")
                .cloned()
                .unwrap_or_else(|| panic!("missing selector abort gap in {procedure:#?}"))
        };
        let first = find_procedure("first");
        let later = find_procedure("later");
        let first_gap = selection_gap(&first);
        let later_gap = selection_gap(&later);
        assert_eq!(
            first_gap.discharge,
            SemanticGapDischarge::NonRejoiningExceptionalExit,
            "the first defer is not registered until after its field selection"
        );
        assert_eq!(
            later_gap.discharge,
            SemanticGapDischarge::ExitOnlyProcedureCompletion,
            "the earlier defer can run on panic, but cannot resume this procedure's normal body"
        );

        for procedure in [&first, &later] {
            assert!(
                crate::analyzer::semantic::workspace_oracle::abort_paths_run_user_code(
                    procedure.semantics()
                ),
                "the procedure-wide fallback sees deferred user code"
            );
        }
        assert!(
            crate::analyzer::semantic::workspace_oracle::implicit_abort_gap_is_discharged(
                &first_gap, true,
            ),
            "a later cleanup elsewhere in the procedure must not open the first selection"
        );
        assert!(
            !crate::analyzer::semantic::workspace_oracle::implicit_abort_gap_is_discharged(
                &later_gap, true,
            ),
            "an already-active cleanup must keep the later selection open"
        );

        let provider = fixture.analyzer.icfg_provider();
        let exit_profile = |procedure: &ProcedureHandle| {
            let entry = procedure
                .point_handle(procedure.semantics().entry_point())
                .expect("procedure entry");
            let exit = procedure
                .point_handle(procedure.semantics().normal_exit_point())
                .expect("procedure normal exit");
            let mut budget = SemanticBudget::default();
            provider
                .exit_profile(
                    &entry,
                    &exit,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("normal exit profile")
        };
        let first_outcome = exit_profile(&first);
        assert!(
            matches!(&first_outcome, SemanticOutcome::Complete { .. }),
            "the first deferred argument's pre-registration abort must discharge: {first_outcome:#?}"
        );
        let later_outcome = exit_profile(&later);
        assert!(
            matches!(&later_outcome, SemanticOutcome::Unsupported { .. }),
            "the later field selection can abort through the earlier cleanup: {later_outcome:#?}"
        );
        assert!(
            later_outcome
                .available_value()
                .and_then(IcfgExitProfile::aggregate_return_affecting_gap_reason)
                .is_some_and(|reason| reason.contains("selection may panic on a nil operand")),
            "the retained boundary must name the point-local selector gap: {later_outcome:#?}"
        );
    }

    #[test]
    fn python_mixed_return_gaps_retain_only_matched_normal_reason() {
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::Python,
            &[(
                "mixed_return_gaps.py",
                "async def target(value):\n    result = value\n    return result\n",
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "mixed_return_gaps.py");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Python materialization")
            .available_value()
            .cloned()
            .expect("Python artifact");
        let target = artifact
            .procedures()
            .first()
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("target procedure");
        let semantics = target.semantics();
        // The exit profile discharges implicit-abort gaps when no abort path
        // runs user code (#1952); the expected reasons below apply the same
        // rule. The raw gap set still retains the exceptional-flow gap, which
        // the direct assertions on `all_gaps` pin.
        let abort_user_code =
            crate::analyzer::semantic::workspace_oracle::abort_paths_run_user_code(semantics);
        let all_gaps = semantics
            .gaps()
            .iter()
            .filter(|gap| gap.impacts.contains(SemanticGapImpact::ReturnTransfer))
            .collect::<Vec<_>>();
        let return_gaps = all_gaps
            .iter()
            .copied()
            .filter(|gap| {
                !crate::analyzer::semantic::workspace_oracle::implicit_abort_gap_is_discharged(
                    gap,
                    abort_user_code,
                )
            })
            .collect::<Vec<_>>();
        assert!(
            return_gaps.iter().any(|gap| {
                gap.capability == SemanticCapability::AsyncSuspendResume
                    && gap.kind == SemanticGapKind::Unsupported
            }),
            "async lowering must retain its suspension gap: {return_gaps:#?}"
        );
        assert!(
            all_gaps.iter().any(|gap| {
                gap.capability == SemanticCapability::ExceptionalControlFlow
                    && gap.kind == SemanticGapKind::Unsupported
            }),
            "assignment must retain its exceptional-flow gap: {all_gaps:#?}"
        );
        let aggregate_reason = return_gaps
            .iter()
            .map(|gap| {
                format!(
                    "{} {}: {}",
                    gap.kind.label(),
                    gap.capability.label(),
                    gap.detail,
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let matched_reason = return_gaps
            .iter()
            .filter(|gap| gap_affects_matched_return(gap, ReturnTransferKind::Normal))
            .map(|gap| {
                format!(
                    "{} {}: {}",
                    gap.kind.label(),
                    gap.capability.label(),
                    gap.detail,
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        assert!(!matched_reason.is_empty());
        assert!(!matched_reason.contains(SemanticCapability::ExceptionalControlFlow.label()));

        let entry = target
            .point_handle(semantics.entry_point())
            .expect("target entry");
        let exit = target
            .point_handle(semantics.normal_exit_point())
            .expect("target normal exit");
        let provider = fixture.analyzer.icfg_provider();
        let mut budget = SemanticBudget::default();
        let outcome = provider
            .exit_profile(
                &entry,
                &exit,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("target exit profile");
        let profile = outcome.available_value().expect("retained profile");
        assert_eq!(
            profile.aggregate_return_affecting_gap_reason(),
            Some(aggregate_reason.as_str())
        );
        assert_eq!(
            profile.matched_return_affecting_gap_reason(),
            Some(matched_reason.as_str())
        );
        // The profile charges the matched reason only when it differs from the
        // aggregate; after the implicit-abort discharge (#1952) the two can
        // coincide.
        let expected_text_bytes =
            aggregate_reason
                .len()
                .saturating_add(if matched_reason == aggregate_reason {
                    0
                } else {
                    matched_reason.len()
                });
        assert_eq!(outcome.work().owned_text_bytes, expected_text_bytes);
        assert_eq!(budget.used(), outcome.work());

        let mut limited_work = SemanticBudget::default().limits();
        limited_work.owned_text_bytes = expected_text_bytes
            .checked_sub(1)
            .expect("mixed return-gap reasons are non-empty");
        let mut limited_budget =
            SemanticBudget::new(limited_work).expect("all semantic limits remain positive");
        let limited = provider
            .exit_profile(
                &entry,
                &exit,
                &mut SemanticRequest::new(&mut limited_budget, &cancellation),
            )
            .expect("owned-text boundary is a typed semantic outcome");
        assert!(matches!(
            limited,
            SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work,
            } if exceeded.dimension()
                == crate::analyzer::semantic::SemanticBudgetDimension::OwnedTextBytes
                && exceeded.limit() == expected_text_bytes - 1
                && exceeded.attempted() == expected_text_bytes
                && work.owned_text_bytes == 0
        ));
    }

    #[test]
    fn exit_profile_scopes_point_return_gaps_from_the_requested_entry() {
        let fixture = AnalyzerFixture::new_for_language(
            crate::analyzer::Language::Go,
            &[(
                "entry_scope.go",
                "package sample\nfunc target(callback func()) { defer callback() }\n",
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "entry_scope.go");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("Go materialization")
            .available_value()
            .cloned()
            .expect("Go artifact");
        let target = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("target")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("target procedure");
        let semantics = target.semantics();
        let return_gap = semantics
            .gaps()
            .iter()
            .find(|gap| {
                gap.subject == SemanticGapSubject::Point
                    && gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
            })
            .expect("point-scoped defer return gap");
        let canonical_entry = target
            .point_handle(semantics.entry_point())
            .expect("canonical target entry");
        let exit = target
            .point_handle(semantics.normal_exit_point())
            .expect("target normal exit");
        assert_ne!(
            return_gap.point,
            exit.id(),
            "alternate exit entry must begin after the defer gap"
        );

        let provider = fixture.analyzer.icfg_provider();
        let mut canonical_budget = SemanticBudget::default();
        let canonical_outcome = provider
            .exit_profile(
                &canonical_entry,
                &exit,
                &mut SemanticRequest::new(&mut canonical_budget, &cancellation),
            )
            .expect("canonical entry profile");
        let canonical_profile = canonical_outcome
            .available_value()
            .expect("canonical entry profile payload");
        assert_eq!(canonical_profile.callee_entry(), &canonical_entry);
        assert!(
            canonical_profile.has_aggregate_return_affecting_gaps(),
            "canonical entry-to-exit topology crosses the defer gap"
        );
        let expected_reason = semantics
            .gaps()
            .iter()
            .filter(|gap| gap.impacts.contains(SemanticGapImpact::ReturnTransfer))
            .map(|gap| {
                format!(
                    "{} {}: {}",
                    gap.kind.label(),
                    gap.capability.label(),
                    gap.detail,
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        assert_eq!(
            canonical_profile.gap_reason.as_deref(),
            Some(expected_reason.as_str()),
        );
        assert_eq!(
            canonical_outcome.work().owned_text_bytes,
            expected_reason.len(),
            "the exact retained return-gap text must be charged",
        );
        assert_eq!(canonical_budget.used(), canonical_outcome.work());

        let mut text_limited_work = SemanticBudget::default().limits();
        text_limited_work.owned_text_bytes = expected_reason
            .len()
            .checked_sub(1)
            .expect("return-gap reason is non-empty");
        let mut text_limited_budget =
            SemanticBudget::new(text_limited_work).expect("all semantic limits remain positive");
        let text_limited_outcome = provider
            .exit_profile(
                &canonical_entry,
                &exit,
                &mut SemanticRequest::new(&mut text_limited_budget, &cancellation),
            )
            .expect("owned-text boundary is a typed semantic outcome");
        let SemanticOutcome::ExceededBudget {
            partial,
            exceeded,
            work,
        } = text_limited_outcome
        else {
            panic!("the exact return-gap text must exceed the one-byte-short budget");
        };
        assert!(
            partial.is_none(),
            "a failed text charge publishes no profile"
        );
        assert_eq!(
            exceeded.dimension(),
            crate::analyzer::semantic::SemanticBudgetDimension::OwnedTextBytes,
        );
        assert_eq!(exceeded.limit(), expected_reason.len() - 1);
        assert_eq!(exceeded.attempted(), expected_reason.len());
        assert_eq!(work.owned_text_bytes, 0);
        assert_eq!(text_limited_budget.used(), work);

        let alternate_entry = exit.clone();
        let mut alternate_budget = SemanticBudget::default();
        let alternate_outcome = provider
            .exit_profile(
                &alternate_entry,
                &exit,
                &mut SemanticRequest::new(&mut alternate_budget, &cancellation),
            )
            .expect("alternate entry profile");
        let alternate_profile = alternate_outcome
            .available_value()
            .expect("alternate entry profile payload");
        assert_eq!(alternate_profile.callee_entry(), &alternate_entry);
        assert!(
            !alternate_profile.has_aggregate_return_affecting_gaps(),
            "starting at the exit must exclude the earlier point-scoped defer gap"
        );
        assert!(
            matches!(alternate_outcome, SemanticOutcome::Complete { .. }),
            "no other return gap should weaken the alternate entry profile"
        );
        assert_eq!(alternate_outcome.work().owned_text_bytes, 0);
        assert_eq!(alternate_budget.used(), alternate_outcome.work());
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
