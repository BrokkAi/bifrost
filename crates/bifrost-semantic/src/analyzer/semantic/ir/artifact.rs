use std::fmt;
use std::hash::{Hash, Hasher};
use std::mem::size_of;
use std::sync::Arc;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::compact_graph::CompactRows;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;

use crate::analyzer::semantic::capabilities::SemanticCapabilities;

use crate::analyzer::semantic::ids::AllocationId;

use crate::analyzer::semantic::ids::BlockId;

use crate::analyzer::semantic::ids::CallSiteId;
use crate::analyzer::semantic::ids::SourceAnchor;

use crate::analyzer::semantic::ids::CaptureId;

use crate::analyzer::semantic::ids::ControlEdgeId;

use crate::analyzer::semantic::ids::EvidenceId;

use crate::analyzer::semantic::ids::GuardId;

use crate::analyzer::semantic::ids::MemoryLocationId;

use crate::analyzer::semantic::ids::ProcedureId;

use crate::analyzer::semantic::ids::ProgramPointId;

use crate::analyzer::semantic::ids::SemanticArtifactKey;

use crate::analyzer::semantic::ids::SemanticDigestHasher as MaterializationFingerprintHasher;

use crate::analyzer::semantic::ids::SemanticGapId;

use crate::analyzer::semantic::ids::SemanticLocator;

use crate::analyzer::semantic::ids::SourceMappingId;

use crate::analyzer::semantic::ids::StableDigest;

use crate::analyzer::semantic::ids::SwitchFactId;

use crate::analyzer::semantic::ids::ValueId;

use crate::analyzer::semantic::provider::SemanticBudget;

use crate::analyzer::semantic::provider::SemanticBudgetExceeded;

use crate::analyzer::semantic::provider::SemanticWork;

use crate::analyzer::semantic::ir::model::*;

use crate::analyzer::semantic::ir::validation::find_boundaries;

use crate::analyzer::semantic::ir::validation::measure_artifact_work;

use crate::analyzer::semantic::ir::validation::validate_artifact;

/// Workspace-relative paths whose artifacts the validator rejects, for tests
/// that need a file-level rejection without relying on a lowering defect that
/// will later be fixed (#12571).
#[cfg(any(test, feature = "test-support"))]
static REJECTED_ARTIFACT_PATHS_FOR_TEST: std::sync::Mutex<Vec<String>> =
    std::sync::Mutex::new(Vec::new());

/// Keeps one path's artifacts rejected until it is dropped.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub struct ArtifactRejectionForTest(String);

#[cfg(any(test, feature = "test-support"))]
impl Drop for ArtifactRejectionForTest {
    fn drop(&mut self) {
        let mut paths = REJECTED_ARTIFACT_PATHS_FOR_TEST
            .lock()
            .expect("rejected artifact paths mutex poisoned");
        let index = paths
            .iter()
            .position(|path| path == &self.0)
            .expect("a registered rejection stays registered until dropped");
        paths.remove(index);
    }
}

/// Reject every artifact built for the workspace-relative `path` with a
/// `GapContract` error, as the validator rejects an artifact whose gap
/// records break the contract. Use a path no other test uses: the registry is
/// process-wide.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn reject_artifacts_at_path_for_test(path: &str) -> ArtifactRejectionForTest {
    REJECTED_ARTIFACT_PATHS_FOR_TEST
        .lock()
        .expect("rejected artifact paths mutex poisoned")
        .push(path.to_owned());
    ArtifactRejectionForTest(path.to_owned())
}

/// Failure to validate or fit a semantic artifact into its retained-work
/// budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticArtifactBuildError {
    Cancelled,
    Invalid(SemanticIrError),
    ExceededBudget(SemanticBudgetExceeded),
}

impl SemanticArtifactBuildError {
    pub const fn invalid_ir(&self) -> Option<&SemanticIrError> {
        match self {
            Self::Cancelled => None,
            Self::Invalid(error) => Some(error),
            Self::ExceededBudget(_) => None,
        }
    }

    pub const fn budget_exceeded(&self) -> Option<SemanticBudgetExceeded> {
        match self {
            Self::Invalid(_) | Self::Cancelled => None,
            Self::ExceededBudget(error) => Some(*error),
        }
    }
}

impl From<SemanticIrError> for SemanticArtifactBuildError {
    fn from(error: SemanticIrError) -> Self {
        if error.kind() == SemanticIrErrorKind::Cancelled {
            Self::Cancelled
        } else {
            Self::Invalid(error)
        }
    }
}

impl From<SemanticBudgetExceeded> for SemanticArtifactBuildError {
    fn from(error: SemanticBudgetExceeded) -> Self {
        Self::ExceededBudget(error)
    }
}

impl fmt::Display for SemanticArtifactBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("semantic publication cancelled"),
            Self::Invalid(error) => error.fmt(formatter),
            Self::ExceededBudget(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SemanticArtifactBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cancelled => None,
            Self::Invalid(error) => Some(error),
            Self::ExceededBudget(error) => Some(error),
        }
    }
}
/// Immutable intraprocedural control-flow topology.
///
/// Edge IDs are procedure-local indices into one canonical rich-edge table.
/// Outgoing rows are contiguous ranges in that source-sorted table, while
/// incoming rows retain edge IDs so both directions share the same payload.
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    edges: Box<[ControlEdge]>,
    outgoing_row_offsets: Box<[u32]>,
    incoming: CompactRows<ControlEdgeId>,
}

impl ControlFlowGraph {
    fn try_from_edges(
        procedure: ProcedureId,
        point_count: usize,
        mut edges: Vec<ControlEdge>,
    ) -> Result<Self, SemanticIrError> {
        let edge_count = u32::try_from(edges.len()).map_err(|_| {
            SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::ResourceLimit,
                format!(
                    "control-edge count {} cannot be represented by compact u32 row offsets",
                    edges.len()
                ),
            )
        })?;
        for edge in &edges {
            if edge.source_point.index() >= point_count || edge.target_point.index() >= point_count
            {
                return Err(SemanticIrError::procedure(
                    procedure,
                    SemanticIrErrorKind::ControlFlowContract,
                    format!(
                        "{} edge {} -> {} cannot be frozen for {point_count} program points",
                        edge.kind.label(),
                        edge.source_point,
                        edge.target_point
                    ),
                ));
            }
        }

        edges.sort_unstable_by_key(control_edge_sort_key);

        let row_capacity = point_count.checked_add(1).ok_or_else(|| {
            SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::ResourceLimit,
                "control-flow row count overflows usize",
            )
        })?;
        let mut outgoing_row_offsets = Vec::with_capacity(row_capacity);
        outgoing_row_offsets.push(0);
        let mut cursor = 0usize;
        for source in 0..point_count {
            while cursor < edges.len() && edges[cursor].source_point.index() == source {
                cursor += 1;
            }
            outgoing_row_offsets.push(u32::try_from(cursor).map_err(|_| {
                SemanticIrError::procedure(
                    procedure,
                    SemanticIrErrorKind::ResourceLimit,
                    "control-flow outgoing offset does not fit in u32",
                )
            })?);
        }
        if cursor != edges.len() {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::ControlFlowContract,
                "canonical control-edge table contains an out-of-range source row",
            ));
        }

        let mut incoming_counts = vec![0_u32; point_count];
        for edge in &edges {
            let count = &mut incoming_counts[edge.target_point.index()];
            *count = count.checked_add(1).ok_or_else(|| {
                SemanticIrError::procedure(
                    procedure,
                    SemanticIrErrorKind::ResourceLimit,
                    format!(
                        "incoming edge count for program point {} does not fit in u32",
                        edge.target_point
                    ),
                )
            })?;
        }
        let mut incoming_offsets = Vec::with_capacity(row_capacity);
        incoming_offsets.push(0);
        let mut incoming_total = 0_u32;
        for count in incoming_counts {
            incoming_total = incoming_total.checked_add(count).ok_or_else(|| {
                SemanticIrError::procedure(
                    procedure,
                    SemanticIrErrorKind::ResourceLimit,
                    "control-flow incoming offsets do not fit in u32",
                )
            })?;
            incoming_offsets.push(incoming_total);
        }
        debug_assert_eq!(incoming_total, edge_count);

        let mut incoming_cursors = incoming_offsets[..point_count].to_vec();
        let mut incoming_edge_ids = vec![ControlEdgeId::default(); edges.len()];
        for (index, edge) in edges.iter().enumerate() {
            let target = edge.target_point.index();
            let destination = incoming_cursors[target] as usize;
            incoming_edge_ids[destination] =
                ControlEdgeId::try_from_index(index).map_err(|error| {
                    SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::ResourceLimit,
                        error.to_string(),
                    )
                })?;
            incoming_cursors[target] = incoming_cursors[target]
                .checked_add(1)
                .expect("validated incoming edge count cannot overflow");
        }

        Self::try_from_parts(
            procedure,
            point_count,
            edges,
            outgoing_row_offsets,
            incoming_offsets,
            incoming_edge_ids,
        )
    }

    #[doc(hidden)]
    pub fn try_from_parts(
        procedure: ProcedureId,
        point_count: usize,
        edges: Vec<ControlEdge>,
        outgoing_row_offsets: Vec<u32>,
        incoming_offsets: Vec<u32>,
        incoming_edge_ids: Vec<ControlEdgeId>,
    ) -> Result<Self, SemanticIrError> {
        let incoming =
            CompactRows::try_from_parts(incoming_offsets, incoming_edge_ids).map_err(|detail| {
                SemanticIrError::procedure(
                    procedure,
                    SemanticIrErrorKind::ControlFlowContract,
                    format!("invalid incoming control-flow rows: {detail}"),
                )
            })?;
        let graph = Self {
            edges: edges.into_boxed_slice(),
            outgoing_row_offsets: outgoing_row_offsets.into_boxed_slice(),
            incoming,
        };
        graph.validate(procedure, point_count)?;
        Ok(graph)
    }

    fn validate(&self, procedure: ProcedureId, point_count: usize) -> Result<(), SemanticIrError> {
        let expected_offset_count = point_count.checked_add(1).ok_or_else(|| {
            SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::ResourceLimit,
                "control-flow row count overflows usize",
            )
        })?;
        if self.outgoing_row_offsets.len() != expected_offset_count
            || self.outgoing_row_offsets.first().copied() != Some(0)
            || self
                .outgoing_row_offsets
                .last()
                .copied()
                .map(|offset| offset as usize)
                != Some(self.edges.len())
            || !self
                .outgoing_row_offsets
                .windows(2)
                .all(|pair| pair[0] <= pair[1])
        {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::ControlFlowContract,
                "outgoing control-flow row offsets are not a complete monotonic edge partition",
            ));
        }
        if self.incoming.rows() != point_count {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::ControlFlowContract,
                format!(
                    "incoming control-flow row count {} does not match {point_count} program points",
                    self.incoming.rows()
                ),
            ));
        }
        if self
            .edges
            .windows(2)
            .any(|pair| control_edge_sort_key(&pair[0]) > control_edge_sort_key(&pair[1]))
        {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::ControlFlowContract,
                "control-edge table is not in canonical order",
            ));
        }
        if self.edges.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::DuplicateEdge,
                "control-edge table contains an exact duplicate rich edge",
            ));
        }

        for point in 0..point_count {
            let start = self.outgoing_row_offsets[point] as usize;
            let end = self.outgoing_row_offsets[point + 1] as usize;
            for edge in &self.edges[start..end] {
                if edge.source_point.index() != point {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::ControlFlowContract,
                        format!(
                            "outgoing row {point} contains edge {} -> {} owned by source row {}",
                            edge.source_point, edge.target_point, edge.source_point
                        ),
                    ));
                }
                if edge.target_point.index() >= point_count {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::ControlFlowContract,
                        format!(
                            "edge {} -> {} has an out-of-range target",
                            edge.source_point, edge.target_point
                        ),
                    ));
                }
            }
        }

        let mut incoming_seen = vec![false; self.edges.len()];
        for point in 0..point_count {
            let incoming_row = self.incoming.row(point);
            if incoming_row.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(SemanticIrError::procedure(
                    procedure,
                    SemanticIrErrorKind::ControlFlowContract,
                    format!(
                        "incoming row {point} is not in canonical increasing control-edge order"
                    ),
                ));
            }
            for edge_id in incoming_row {
                let Some(edge) = self.edges.get(edge_id.index()) else {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::ControlFlowContract,
                        format!("incoming row {point} references out-of-range edge {edge_id}"),
                    ));
                };
                if incoming_seen[edge_id.index()] {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::ControlFlowContract,
                        format!("incoming rows reference edge {edge_id} more than once"),
                    ));
                }
                incoming_seen[edge_id.index()] = true;
                if edge.target_point.index() != point {
                    return Err(SemanticIrError::procedure(
                        procedure,
                        SemanticIrErrorKind::ControlFlowContract,
                        format!(
                            "incoming row {point} references edge {edge_id} targeting {}",
                            edge.target_point
                        ),
                    ));
                }
            }
        }
        if let Some(missing) = incoming_seen.iter().position(|seen| !seen) {
            return Err(SemanticIrError::procedure(
                procedure,
                SemanticIrErrorKind::ControlFlowContract,
                format!("incoming rows do not reference edge {missing}"),
            ));
        }
        Ok(())
    }

    pub fn edges(&self) -> &[ControlEdge] {
        &self.edges
    }

    pub fn edge(&self, id: ControlEdgeId) -> Option<&ControlEdge> {
        self.edges.get(id.index())
    }

    pub fn successor_edges(
        &self,
        point: ProgramPointId,
    ) -> impl ExactSizeIterator<Item = (ControlEdgeId, &ControlEdge)> + '_ {
        self.successor_edges_bidirectional(point)
    }

    pub(crate) fn successor_edges_bidirectional(
        &self,
        point: ProgramPointId,
    ) -> impl DoubleEndedIterator<Item = (ControlEdgeId, &ControlEdge)> + ExactSizeIterator + '_
    {
        let point = point.index();
        assert!(
            point < self.incoming.rows(),
            "program point {point} is outside this control-flow graph"
        );
        let start = self.outgoing_row_offsets[point] as usize;
        let end = self.outgoing_row_offsets[point + 1] as usize;
        self.edges[start..end]
            .iter()
            .enumerate()
            .map(move |(offset, edge)| {
                let id = ControlEdgeId::try_from_index(start + offset)
                    .expect("validated control-edge index fits in u32");
                (id, edge)
            })
    }

    pub fn predecessor_edges(
        &self,
        point: ProgramPointId,
    ) -> impl ExactSizeIterator<Item = (ControlEdgeId, &ControlEdge)> + '_ {
        self.predecessor_edges_bidirectional(point)
    }

    pub(crate) fn predecessor_edges_bidirectional(
        &self,
        point: ProgramPointId,
    ) -> impl DoubleEndedIterator<Item = (ControlEdgeId, &ControlEdge)> + ExactSizeIterator + '_
    {
        let point = point.index();
        assert!(
            point < self.incoming.rows(),
            "program point {point} is outside this control-flow graph"
        );
        let edge_ids = self.incoming.row(point);
        edge_ids.iter().copied().map(|id| {
            let edge = &self.edges[id.index()];
            (id, edge)
        })
    }
}

fn control_edge_sort_key(
    edge: &ControlEdge,
) -> (
    ProgramPointId,
    &'static str,
    ProgramPointId,
    SourceMappingId,
    EvidenceId,
) {
    (
        edge.source_point,
        edge.kind.label(),
        edge.target_point,
        edge.source,
        edge.evidence,
    )
}
/// One normalized decision-point condition, frozen against its own procedure.
///
/// This is [`GuardFactParts`] after the canonical control-edge table exists:
/// each declared arm is resolved to the [`ControlEdgeId`] a `control_edge` row
/// publishes, so a consumer joins a guard to its successors by id equality. An
/// arm stays `None` when the lowerer emitted no edge for it, which is the
/// ordinary shape of a folded constant condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuardFact {
    pub id: GuardId,
    pub point: ProgramPointId,
    pub subject: Option<ValueId>,
    pub predicate: GuardPredicate,
    pub true_edge: Option<ControlEdgeId>,
    pub false_edge: Option<ControlEdgeId>,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

impl GuardFact {
    /// The arm the predicate proves cannot execute, when it proves one.
    ///
    /// A constant-true condition never takes its false arm and a constant-false
    /// one never takes its true arm. The answer is `None` both when the
    /// predicate proves no constant and when the infeasible arm carries no edge
    /// because lowering already folded it away -- in the second case there is
    /// nothing left to exclude.
    pub const fn infeasible_edge(&self) -> Option<ControlEdgeId> {
        match self.predicate.constant_value() {
            Some(true) => self.false_edge,
            Some(false) => self.true_edge,
            None => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwitchCaseFact {
    pub value: ValueId,
    pub edge: ControlEdgeId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SwitchFact {
    pub id: SwitchFactId,
    pub kind: SwitchFactKind,
    pub point: ProgramPointId,
    pub selector: Option<ValueId>,
    pub selector_domain: SwitchSelectorDomain,
    pub cases: Box<[SwitchCaseFact]>,
    pub default_edge: Option<ControlEdgeId>,
    pub default_present: bool,
    pub source: SourceMappingId,
    pub evidence: EvidenceId,
}

const PROCEDURE_MATERIALIZATION_ID_DOMAIN: &[u8] = b"bifrost-semantic-procedure-materialization-v1";
const ARTIFACT_MATERIALIZATION_ID_DOMAIN: &[u8] = b"bifrost-semantic-artifact-materialization-v1";

/// Process-stable identity for one exact frozen procedure row set.
///
/// This includes the owning procedure's artifact-local ID and all frozen row
/// fields, including cross-procedure references. It deliberately fails closed
/// when a partial artifact shifts dense IDs instead of claiming that those
/// references have been canonicalized. Derived indexes are excluded because
/// their complete inputs are included and their construction is deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ProcedureMaterializationId(StableDigest);

/// Identity for the complete proof-relevant contents of one semantic artifact.
///
/// [`SemanticArtifactKey`] identifies the source and lowering inputs, but one
/// key can still have multiple partial materializations. This digest adds the
/// exact capability table and ordered frozen procedure identities, so a dense
/// procedure-local row ID is used only after the complete materialization that
/// assigned it has been reconstructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemanticArtifactMaterializationId(StableDigest);

impl SemanticArtifactMaterializationId {
    /// The exact frozen artifact-content identity.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Display for SemanticArtifactMaterializationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

// A clone receives fresh derived state, even if a future owner changes its IR.
#[derive(Debug, Default)]
struct CallableSelectionDominance(
    std::sync::OnceLock<Option<crate::analyzer::semantic::cfg_algorithms::CompactDominators>>,
);

impl Clone for CallableSelectionDominance {
    fn clone(&self) -> Self {
        Self::default()
    }
}

// These cells live only as long as this immutable ProcedureSemantics value.
// There is no cross-request registry; clones start with empty derived state.
#[derive(Debug, Default)]
struct CallGapDerived {
    scopes: std::sync::OnceLock<CallGapScopes>,
    abort_user_code: std::sync::OnceLock<bool>,
}

impl Clone for CallGapDerived {
    fn clone(&self) -> Self {
        Self::default()
    }
}

#[derive(Debug)]
struct CallGapScopes {
    procedure: Box<[usize]>,
    points: Box<[(ProgramPointId, usize)]>,
    values: Box<[(ValueId, usize)]>,
    calls: Box<[(CallSiteId, usize)]>,
    /// Gaps whose subject is a cleanup-owner segment. Their members need a
    /// membership test, so they cannot sit in the value index.
    cleanup_owners: Box<[usize]>,
}

/// One isolated body and the authority its query owner must admit.
/// Executable evidence lives in the query receipt, never in the artifact.
#[derive(Debug, Clone)]
struct GuardedProcedureBody {
    semantics: ProcedureSemantics,
    authority: GuardedProcedureAuthority,
}

#[derive(Debug, Clone)]
enum GuardedProcedureAuthority {
    Macro(Box<[CandidateRecord]>),
    Executable,
}

/// One validated executable body.
#[derive(Debug, Clone)]
pub struct ProcedureSemantics {
    guarded_alternate: Option<Box<GuardedProcedureBody>>,
    callable_selection_dominance: CallableSelectionDominance,
    call_gap_derived: CallGapDerived,
    declared_result_classes: Option<Box<[StaticTypeClass]>>,
    id: ProcedureId,
    materialization_id: ProcedureMaterializationId,
    locator: SemanticLocator,
    source_range_holes: Box<[crate::analyzer::semantic::SourceSpan]>,
    lexical_parent: Option<ProcedureId>,
    kind: ProcedureKind,
    properties: ProcedureProperties,
    source: SourceMappingId,
    evidence: EvidenceId,
    values: Box<[SemanticValue]>,
    /// Structural ordinals for non-parameter values that share one source
    /// locator and semantic role. Most syntax sites mint one value per role,
    /// so the sparse payload is empty in the common case.
    value_identity_ordinals: Box<[(ValueId, u32)]>,
    allocations: Box<[AllocationSite]>,
    memory_locations: Box<[MemoryLocation]>,
    captures: Box<[CaptureBinding]>,
    call_sites: Box<[SemanticCallSite]>,
    call_phase_points: CallPhasePointIndex,
    call_result_sites: CallResultSiteIndex,
    source_mappings: Box<[SourceMapping]>,
    statement_entries: Box<[StatementEntrySite]>,
    loop_sites: Box<[LoopSite]>,
    cleanup_chains: super::CleanupChains,
    drops: Box<[DropFact]>,
    move_outs: Box<[MoveOutFact]>,
    scope_ends: Box<[ScopeEndFact]>,
    pointer_origins: Box<[PointerOrigin]>,
    pointer_aliases: Box<[PointerAlias]>,
    pointer_accesses: Box<[PointerAccess]>,
    pointer_invalidations: Box<[PointerInvalidation]>,
    incomplete_facts: Box<[SemanticIncompleteFact]>,
    receiver_type_facts: Box<[CallReceiverTypeFact]>,
    guarded_pattern_projections: Box<[GuardedPatternProjection]>,
    evidence_rows: Box<[Evidence]>,
    gaps: Box<[SemanticGap]>,
    blocks: Box<[BasicBlock]>,
    points: Box<[ProgramPoint]>,
    guard_facts: Box<[GuardFact]>,
    switch_facts: Box<[SwitchFact]>,
    cfg: ControlFlowGraph,
    entry_point: ProgramPointId,
    normal_exit_point: ProgramPointId,
    exceptional_exit_point: ProgramPointId,
}

impl ProcedureSemantics {
    /// Isolated candidate lowering; callers must never substitute it without admission.
    /// Dedicated alternate projection keeps this interpretation separate from base handles.
    pub fn candidate_macro_alternate(&self) -> Option<(&ProcedureSemantics, &[CandidateRecord])> {
        let alternate = self.guarded_alternate.as_deref()?;
        match &alternate.authority {
            GuardedProcedureAuthority::Macro(sites) => Some((&alternate.semantics, sites)),
            GuardedProcedureAuthority::Executable => None,
        }
    }

    /// Frozen guarded contents, for representation accounting only. This is
    /// not an executable selection and supplies no admission authority.
    #[doc(hidden)]
    pub fn guarded_alternate(&self) -> Option<&ProcedureSemantics> {
        self.guarded_alternate
            .as_deref()
            .map(|body| &body.semantics)
    }

    #[doc(hidden)]
    pub fn guarded_alternate_wrapper_bytes(&self) -> u64 {
        self.guarded_alternate
            .as_ref()
            .map_or(0, |_| size_of::<GuardedProcedureBody>() as u64)
    }

    /// An isolated body refined by executable refinement, requiring the owning
    /// query's recorded declaration proofs before it may execute.
    #[doc(hidden)]
    pub fn executable_alternate(&self) -> Option<&ProcedureSemantics> {
        let alternate = self.guarded_alternate.as_deref()?;
        match alternate.authority {
            GuardedProcedureAuthority::Executable => Some(&alternate.semantics),
            GuardedProcedureAuthority::Macro(_) => None,
        }
    }

    /// The source anchor that locates a candidate's invocation in this
    /// alternate, for refusal evidence: the realizing call when there is one,
    /// otherwise the alternate source mapping at the record's anchor.
    pub fn candidate_source_anchor(&self, record: &CandidateRecord) -> SourceAnchor {
        if let CandidateRealization::RuntimeCall(call) = record.realization {
            let call = self.call_site(call).expect("validated candidate call");
            return self
                .source_mapping(call.source)
                .expect("validated call mapping")
                .locator
                .anchor();
        }
        self.source_mappings
            .iter()
            .map(|mapping| mapping.locator.anchor())
            .find(|anchor| CandidateAnchor::of(anchor.span()) == record.anchor)
            .expect("validated candidate anchor has an alternate source mapping")
    }

    fn try_from_parts(
        mut parts: ProcedureSemanticsParts,
        entry_point: ProgramPointId,
        normal_exit_point: ProgramPointId,
        exceptional_exit_point: ProgramPointId,
    ) -> Result<Self, SemanticIrError> {
        let guarded_alternate = parts
            .candidate_alternate
            .take()
            .map(|alternate| {
                let CandidateMacroAlternateParts { parts, candidates } = *alternate;
                let boundaries = find_boundaries(&parts)?;
                Self::try_from_parts(
                    parts,
                    boundaries.entry,
                    boundaries.normal_exit,
                    boundaries.exceptional_exit,
                )
                .map(|semantics| {
                    Box::new(GuardedProcedureBody {
                        semantics,
                        authority: GuardedProcedureAuthority::Macro(candidates),
                    })
                })
            })
            .transpose()?;
        let cfg =
            ControlFlowGraph::try_from_edges(parts.id, parts.points.len(), parts.control_edges)?;
        let guard_facts = freeze_guard_facts(&cfg, &parts.guard_facts);
        let switch_facts = freeze_switch_facts(&cfg, &parts.switch_facts);
        let (call_phase_points, call_result_sites) = index_call_phases(&parts.call_sites);
        let value_identity_ordinals =
            duplicate_value_ordinals(&parts.values, &parts.source_mappings);
        let mut semantics = Self {
            guarded_alternate,
            callable_selection_dominance: CallableSelectionDominance::default(),
            call_gap_derived: CallGapDerived::default(),
            id: parts.id,
            materialization_id: ProcedureMaterializationId(StableDigest::from_array([0; 32])),
            locator: parts.locator,
            declared_result_classes: parts.declared_result_classes,
            source_range_holes: parts.source_range_holes.into_boxed_slice(),
            lexical_parent: parts.lexical_parent,
            kind: parts.kind,
            properties: parts.properties,
            source: parts.source,
            evidence: parts.evidence,
            values: parts.values.into_boxed_slice(),
            value_identity_ordinals,
            allocations: parts.allocations.into_boxed_slice(),
            memory_locations: parts.memory_locations.into_boxed_slice(),
            captures: parts.captures.into_boxed_slice(),
            call_sites: parts.call_sites.into_boxed_slice(),
            call_phase_points,
            call_result_sites,
            source_mappings: parts.source_mappings.into_boxed_slice(),
            statement_entries: parts.statement_entries.into_boxed_slice(),
            loop_sites: parts.loop_sites.into_boxed_slice(),
            cleanup_chains: parts.cleanup_chains,
            drops: parts.drops.into_boxed_slice(),
            move_outs: parts.move_outs.into_boxed_slice(),
            scope_ends: parts.scope_ends.into_boxed_slice(),
            pointer_origins: parts.pointer_origins.into_boxed_slice(),
            pointer_aliases: parts.pointer_aliases.into_boxed_slice(),
            pointer_accesses: parts.pointer_accesses.into_boxed_slice(),
            pointer_invalidations: parts.pointer_invalidations.into_boxed_slice(),
            incomplete_facts: parts.incomplete_facts.into_boxed_slice(),
            receiver_type_facts: parts.receiver_type_facts.into_boxed_slice(),
            guarded_pattern_projections: parts.guarded_pattern_projections.into_boxed_slice(),
            evidence_rows: parts.evidence_rows.into_boxed_slice(),
            gaps: parts.gaps.into_boxed_slice(),
            blocks: parts.blocks.into_boxed_slice(),
            points: parts.points.into_boxed_slice(),
            guard_facts,
            switch_facts,
            cfg,
            entry_point,
            normal_exit_point,
            exceptional_exit_point,
        };
        semantics.materialization_id = semantics.compute_materialization_id();
        Ok(semantics)
    }

    fn compute_materialization_id(&self) -> ProcedureMaterializationId {
        let mut digest = MaterializationFingerprintHasher::new(PROCEDURE_MATERIALIZATION_ID_DOMAIN);
        self.id.hash(&mut digest);
        self.locator.hash(&mut digest);
        // Empty holes preserve existing materialization identities for all
        // adapters that do not supply query-time ownership exclusions.
        if !self.source_range_holes.is_empty() {
            b"source-range-holes-v1".hash(&mut digest);
            self.source_range_holes.hash(&mut digest);
        }
        self.lexical_parent.hash(&mut digest);
        self.kind.hash(&mut digest);
        self.properties.hash(&mut digest);
        self.source.hash(&mut digest);
        self.evidence.hash(&mut digest);
        self.values.hash(&mut digest);
        self.value_identity_ordinals.hash(&mut digest);
        self.allocations.hash(&mut digest);
        self.memory_locations.hash(&mut digest);
        self.captures.hash(&mut digest);
        self.call_sites.hash(&mut digest);
        self.source_mappings.hash(&mut digest);
        self.statement_entries.hash(&mut digest);
        self.loop_sites.hash(&mut digest);
        self.cleanup_chains.nodes().hash(&mut digest);
        self.cleanup_chains.anchors().hash(&mut digest);
        self.cleanup_chains.projections().hash(&mut digest);
        self.drops.hash(&mut digest);
        self.move_outs.hash(&mut digest);
        self.scope_ends.hash(&mut digest);
        self.pointer_origins.hash(&mut digest);
        self.pointer_aliases.hash(&mut digest);
        self.pointer_accesses.hash(&mut digest);
        self.pointer_invalidations.hash(&mut digest);
        self.incomplete_facts.hash(&mut digest);
        self.declared_result_classes.hash(&mut digest);
        self.receiver_type_facts.hash(&mut digest);
        if !self.guarded_pattern_projections.is_empty() {
            b"guarded-pattern-projections-v1".hash(&mut digest);
            self.guarded_pattern_projections.hash(&mut digest);
        }
        self.evidence_rows.hash(&mut digest);
        self.gaps.hash(&mut digest);
        self.blocks.hash(&mut digest);
        self.points.hash(&mut digest);
        self.guard_facts.hash(&mut digest);
        self.switch_facts.hash(&mut digest);
        self.cfg.edges.hash(&mut digest);
        self.entry_point.hash(&mut digest);
        self.normal_exit_point.hash(&mut digest);
        self.exceptional_exit_point.hash(&mut digest);
        ProcedureMaterializationId(digest.finish_digest())
    }

    pub const fn id(&self) -> ProcedureId {
        self.id
    }

    /// Content identity of this procedure's parts, independent of its guarded alternative.
    #[doc(hidden)]
    pub const fn parts_materialization_id(&self) -> StableDigest {
        self.materialization_id.0
    }

    /// Identity of the isolated alternate parts; base-only changes do not affect it.
    #[doc(hidden)]
    pub fn candidate_macro_alternate_materialization_id(&self) -> Option<StableDigest> {
        self.candidate_macro_alternate()
            .map(|(alternate, _)| alternate.parts_materialization_id())
    }

    const fn materialization_id(&self) -> ProcedureMaterializationId {
        self.materialization_id
    }

    pub fn locator(&self) -> &SemanticLocator {
        &self.locator
    }

    pub fn source_range_holes(&self) -> &[crate::analyzer::semantic::SourceSpan] {
        &self.source_range_holes
    }

    pub const fn lexical_parent(&self) -> Option<ProcedureId> {
        self.lexical_parent
    }

    pub const fn kind(&self) -> ProcedureKind {
        self.kind
    }

    pub const fn properties(&self) -> ProcedureProperties {
        self.properties
    }

    pub const fn source(&self) -> SourceMappingId {
        self.source
    }

    pub const fn evidence(&self) -> EvidenceId {
        self.evidence
    }

    pub fn values(&self) -> &[SemanticValue] {
        &self.values
    }

    /// The structural disambiguator for a value-flow carrier at one source
    /// locator and semantic role.
    ///
    /// Parameter ordinals are authored semantics. Other values need an
    /// ordinal only when lowering legitimately specializes one syntax site
    /// into multiple values, as cleanup/finally CFG expansion does. The
    /// ordinal follows deterministic semantic row order and is stable across
    /// immutable artifact re-materializations.
    pub(crate) fn stable_value_ordinal(&self, id: ValueId) -> Option<u32> {
        let value = self.value(id)?;
        if let SemanticValueKind::Parameter { ordinal, .. } = value.kind {
            return Some(ordinal);
        }
        self.value_identity_ordinals
            .binary_search_by_key(&id, |(value, _)| *value)
            .ok()
            .map(|index| self.value_identity_ordinals[index].1)
    }

    /// Exact heap payload retained by the sparse value-identity index.
    #[doc(hidden)]
    pub fn value_identity_index_retained_bytes(&self) -> u64 {
        (self.value_identity_ordinals.len() as u64)
            .saturating_mul(std::mem::size_of::<(ValueId, u32)>() as u64)
    }

    pub fn allocations(&self) -> &[AllocationSite] {
        &self.allocations
    }

    pub fn memory_locations(&self) -> &[MemoryLocation] {
        &self.memory_locations
    }

    pub fn captures(&self) -> &[CaptureBinding] {
        &self.captures
    }

    pub fn call_sites(&self) -> &[SemanticCallSite] {
        &self.call_sites
    }

    /// Sorted call-phase points for logarithmic exact-membership checks.
    pub(crate) fn call_phase_points(&self, value: ValueId) -> Option<&[ProgramPointId]> {
        self.call_phase_points.get(&value).map(Box::as_ref)
    }

    #[doc(hidden)]
    pub fn call_result_site_ids(
        &self,
        value: ValueId,
        normal_point: ProgramPointId,
    ) -> Option<&[CallSiteId]> {
        self.call_result_sites
            .get(&(value, normal_point))
            .map(Box::as_ref)
    }

    /// Conservatively estimate heap storage retained by the derived call-phase
    /// indexes. The `HashMap` headers are inline in `ProcedureSemantics` and
    /// therefore covered by its row size; this accounts for retained bucket
    /// capacity, boxed-slice payloads, and allocator/control metadata.
    #[doc(hidden)]
    pub fn call_indexes_retained_bytes(&self) -> u64 {
        boxed_slice_index_retained_bytes(&self.call_phase_points)
            .saturating_add(boxed_slice_index_retained_bytes(&self.call_result_sites))
    }

    pub fn source_mappings(&self) -> &[SourceMapping] {
        &self.source_mappings
    }

    /// All producer-attested source statement entries, including distinct
    /// cleanup routes for one source statement.
    pub fn statement_entries(&self) -> &[StatementEntrySite] {
        &self.statement_entries
    }

    /// All producer-attested source loops with their iteration header and
    /// body entry.
    pub fn loop_sites(&self) -> &[LoopSite] {
        &self.loop_sites
    }

    /// Every explicit or implicit place destruction represented in this
    /// procedure artifact.
    pub fn cleanup_chains(&self) -> &super::CleanupChains {
        &self.cleanup_chains
    }

    /// Logical facts preserve direct/anchor publication order using direct-row offsets.
    /// No expanded cleanup rows are retained by the artifact.
    pub fn logical_drops(&self) -> impl Iterator<Item = super::LogicalDropFact<'_>> {
        logical_drops(&self.drops, &self.cleanup_chains)
    }

    pub fn logical_scope_ends(&self) -> impl Iterator<Item = super::LogicalScopeEndFact<'_>> {
        use crate::analyzer::semantic::cfg::ScopeCleanupAction;
        let direct = self
            .scope_ends
            .iter()
            .map(|fact| super::LogicalScopeEndFact {
                place: &fact.place,
                at: fact.at,
                source: fact.source,
                evidence: fact.evidence,
            });
        let anchored = self.cleanup_chains.anchors().iter().flat_map(|anchor| {
            let actions = self
                .cleanup_chains
                .anchor_actions(anchor)
                .filter_map(move |entry| {
                    if anchor.purpose != super::CleanupAnchorPurpose::Completion {
                        return None;
                    }
                    match &entry.action {
                        ScopeCleanupAction::ScopeEnd {
                            place,
                            source,
                            evidence,
                        } => Some(super::LogicalScopeEndFact {
                            place,
                            at: super::ScopeEndAt::Point(anchor.point),
                            source: *source,
                            evidence: *evidence,
                        }),
                        _ => None,
                    }
                });
            let owners = self
                .cleanup_chains
                .owners(anchor.segment)
                .filter_map(move |owner| {
                    (anchor.purpose == super::CleanupAnchorPurpose::LifetimeEnd
                        && owner.lifecycle == super::CleanupOwnerLifecycle::ScopeEnd)
                        .then_some(super::LogicalScopeEndFact {
                            place: &owner.place,
                            at: super::ScopeEndAt::Point(anchor.point),
                            source: owner.source,
                            evidence: owner.evidence,
                        })
                });
            actions
                .chain(owners)
                .map(move |fact| (anchor.scope_end_offset, fact))
        });
        merge_cleanup_facts(direct, anchored)
    }

    pub fn logical_incomplete_facts(
        &self,
    ) -> impl Iterator<Item = super::LogicalIncompleteFact<'_>> {
        use super::{LogicalIncompleteSubject as Subject, SemanticIncompleteSubject};
        use crate::analyzer::semantic::cfg::ScopeCleanupAction;
        let direct = self
            .incomplete_facts
            .iter()
            .map(|fact| super::LogicalIncompleteFact {
                point: fact.point,
                subject: match &fact.subject {
                    SemanticIncompleteSubject::Procedure => Subject::Procedure,
                    SemanticIncompleteSubject::Place(place) => Subject::Place(place),
                    SemanticIncompleteSubject::Value(value) => Subject::Value(*value),
                    SemanticIncompleteSubject::PointerOrigin(origin) => {
                        Subject::PointerOrigin(*origin)
                    }
                },
                reason: fact.reason,
                source: fact.source,
                evidence: fact.evidence,
            });
        let anchored = self
            .cleanup_chains
            .anchors()
            .iter()
            .filter(|a| a.purpose == super::CleanupAnchorPurpose::Completion)
            .flat_map(|anchor| {
                self.cleanup_chains
                    .anchor_actions(anchor)
                    .filter_map(move |entry| {
                        let incomplete = entry.incomplete.as_ref()?;
                        let (place, source) = match &entry.action {
                            ScopeCleanupAction::Drop { place, source, .. }
                            | ScopeCleanupAction::ScopeEnd { place, source, .. } => (place, source),
                        };
                        Some(super::LogicalIncompleteFact {
                            point: anchor.point,
                            subject: Subject::Place(place),
                            reason: super::SemanticIncompleteReason::Lifecycle(incomplete.reason),
                            source: *source,
                            evidence: incomplete.evidence,
                        })
                    })
                    .map(move |fact| (anchor.incomplete_offset, fact))
            });
        merge_cleanup_facts(direct, anchored)
    }

    pub fn logical_pointer_invalidations(&self) -> impl Iterator<Item = PointerInvalidation> + '_ {
        let direct = self.pointer_invalidations.iter().cloned();
        let anchored = self
            .cleanup_chains
            .anchors()
            .iter()
            .filter(|a| a.purpose == super::CleanupAnchorPurpose::LifetimeEnd)
            .flat_map(|anchor| {
                self.cleanup_chains
                    .owners(anchor.segment)
                    .filter_map(move |owner| {
                        let invalidation = owner.invalidation?;
                        Some(PointerInvalidation {
                            point: anchor.point,
                            target: invalidation.target,
                            cause: invalidation.cause,
                            strength: invalidation.strength,
                            source: owner.source,
                            evidence: owner.evidence,
                        })
                    })
                    .map(move |fact| (anchor.pointer_invalidation_offset, fact))
            });
        merge_cleanup_facts(direct, anchored)
    }

    /// Owners are queried from compact segments without a route-times-owner index.
    pub fn cleanup_anchors_for_owner(
        &self,
        value: ValueId,
    ) -> impl Iterator<Item = &super::CleanupAnchor> {
        self.cleanup_chains.anchors().iter().filter(move |anchor| {
            self.cleanup_chains
                .owners(anchor.segment)
                .any(|owner| owner.value == value)
        })
    }

    pub fn drops(&self) -> &[DropFact] {
        &self.drops
    }

    /// Place-level initialization transitions tied to move transfer events.
    pub fn move_outs(&self) -> &[MoveOutFact] {
        &self.move_outs
    }

    /// Exact local storage-lifetime end points or CFG edges.
    pub fn scope_ends(&self) -> &[ScopeEndFact] {
        &self.scope_ends
    }

    /// Procedure-local stack and allocation origins.
    pub fn pointer_origins(&self) -> &[PointerOrigin] {
        &self.pointer_origins
    }

    /// Pointer values and the origins they may designate.
    pub fn pointer_aliases(&self) -> &[PointerAlias] {
        &self.pointer_aliases
    }

    /// Source-mapped indirect operations through pointer values.
    pub fn pointer_accesses(&self) -> &[PointerAccess] {
        &self.pointer_accesses
    }

    /// Events that deallocate, transfer, drop, or may reallocate an origin.
    pub fn pointer_invalidations(&self) -> &[PointerInvalidation] {
        &self.pointer_invalidations
    }

    /// Machine-readable reasons that lifecycle or pointer support is partial.
    pub fn incomplete_facts(&self) -> &[SemanticIncompleteFact] {
        &self.incomplete_facts
    }

    /// Written receiver types of this procedure's method calls, in increasing
    /// call-site order, one fact per call site at most.
    pub fn declared_result_classes(&self) -> Option<&[StaticTypeClass]> {
        self.declared_result_classes.as_deref()
    }

    pub fn receiver_type_facts(&self) -> &[CallReceiverTypeFact] {
        &self.receiver_type_facts
    }

    pub fn guarded_pattern_projections(&self) -> &[GuardedPatternProjection] {
        &self.guarded_pattern_projections
    }

    /// The written receiver type fact for one call site, if the file proved one.
    pub fn receiver_type_fact(&self, call_site: CallSiteId) -> Option<&CallReceiverTypeFact> {
        self.receiver_type_facts
            .binary_search_by_key(&call_site, |fact| fact.call_site)
            .ok()
            .map(|index| &self.receiver_type_facts[index])
    }

    pub fn evidence_rows(&self) -> &[Evidence] {
        &self.evidence_rows
    }

    /// Expand only the requested logical view; compact storage stays unchanged.
    pub fn logical_gaps(&self) -> impl Iterator<Item = super::LogicalGapRef<'_>> {
        self.gaps
            .iter()
            .flat_map(move |gap| self.logical_gaps_of(gap))
    }

    /// The logical obligations of one gap of this procedure: the gap itself,
    /// or one member per owner of its cleanup-owner segment. A caller that
    /// holds one gap asks this instead of filtering [`Self::logical_gaps`],
    /// which would visit every gap of the procedure.
    pub fn logical_gaps_of<'a>(
        &'a self,
        gap: &'a SemanticGap,
    ) -> impl Iterator<Item = super::LogicalGapRef<'a>> + 'a {
        let segment = match gap.subject {
            SemanticGapSubject::CleanupOwners(segment) => Some(segment),
            _ => None,
        };
        segment
            .is_none()
            .then_some(super::LogicalGapRef {
                base: gap,
                member: None,
            })
            .into_iter()
            .chain(segment.into_iter().flat_map(move |segment| {
                self.cleanup_chains
                    .member_owners(segment)
                    .map(move |owner| super::LogicalGapRef {
                        base: gap,
                        member: Some(super::GapMemberRef {
                            base_gap_id: gap.id,
                            owner,
                        }),
                    })
            }))
    }

    /// Resolve a key only in its owning procedure, validating exact membership.
    pub fn logical_gap(&self, key: super::GapKey) -> Option<super::LogicalGapRef<'_>> {
        match key {
            super::GapKey::Gap(id) => {
                let base = self.gap(id)?;
                if matches!(base.subject, SemanticGapSubject::CleanupOwners(_)) {
                    return None;
                }
                Some(super::LogicalGapRef { base, member: None })
            }
            super::GapKey::Member(member) => {
                let base = self.gap(member.base_gap_id)?;
                let SemanticGapSubject::CleanupOwners(segment) = base.subject else {
                    return None;
                };
                self.value(member.owner)?;
                self.cleanup_chains
                    .contains_owner(segment, member.owner)
                    .then_some(super::LogicalGapRef {
                        base,
                        member: Some(member),
                    })
            }
        }
    }

    pub fn gaps(&self) -> &[SemanticGap] {
        &self.gaps
    }

    pub fn blocks(&self) -> &[BasicBlock] {
        &self.blocks
    }

    pub fn points(&self) -> &[ProgramPoint] {
        &self.points
    }

    /// Every normalized decision-point condition this procedure's lowerer could
    /// state, in dense id order (issue #2443).
    ///
    /// An empty table means one of two different things, and the adapter's
    /// [`crate::analyzer::semantic::capabilities::SemanticCapability::GuardFacts`]
    /// entry is what distinguishes them: `Unsupported` means the language
    /// publishes no guard facts at all, while an available capability means
    /// this procedure genuinely has no normalizable decision.
    pub fn guard_facts(&self) -> &[GuardFact] {
        &self.guard_facts
    }

    pub fn guard_fact(&self, id: GuardId) -> Option<&GuardFact> {
        self.guard_facts.get(id.index())
    }

    pub fn switch_facts(&self) -> &[SwitchFact] {
        &self.switch_facts
    }

    pub fn switch_fact(&self, id: SwitchFactId) -> Option<&SwitchFact> {
        self.switch_facts.get(id.index())
    }

    pub fn cfg(&self) -> &ControlFlowGraph {
        &self.cfg
    }

    /// Compatibility view over the canonical control-flow edge table.
    pub fn control_edges(&self) -> &[ControlEdge] {
        self.cfg.edges()
    }

    pub fn control_edge(&self, id: ControlEdgeId) -> Option<&ControlEdge> {
        self.cfg.edge(id)
    }

    pub fn successor_edges(
        &self,
        point: ProgramPointId,
    ) -> impl ExactSizeIterator<Item = (ControlEdgeId, &ControlEdge)> + '_ {
        self.cfg.successor_edges(point)
    }

    pub(crate) fn successor_edges_bidirectional(
        &self,
        point: ProgramPointId,
    ) -> impl DoubleEndedIterator<Item = (ControlEdgeId, &ControlEdge)> + ExactSizeIterator + '_
    {
        self.cfg.successor_edges_bidirectional(point)
    }

    pub fn predecessor_edges(
        &self,
        point: ProgramPointId,
    ) -> impl ExactSizeIterator<Item = (ControlEdgeId, &ControlEdge)> + '_ {
        self.cfg.predecessor_edges(point)
    }

    pub(crate) fn predecessor_edges_bidirectional(
        &self,
        point: ProgramPointId,
    ) -> impl DoubleEndedIterator<Item = (ControlEdgeId, &ControlEdge)> + ExactSizeIterator + '_
    {
        self.cfg.predecessor_edges_bidirectional(point)
    }

    pub const fn entry_point(&self) -> ProgramPointId {
        self.entry_point
    }

    pub const fn normal_exit_point(&self) -> ProgramPointId {
        self.normal_exit_point
    }

    pub const fn exceptional_exit_point(&self) -> ProgramPointId {
        self.exceptional_exit_point
    }

    pub fn value(&self, id: ValueId) -> Option<&SemanticValue> {
        self.values.get(id.index())
    }

    pub fn allocation(&self, id: AllocationId) -> Option<&AllocationSite> {
        self.allocations.get(id.index())
    }

    pub fn memory_location(&self, id: MemoryLocationId) -> Option<&MemoryLocation> {
        self.memory_locations.get(id.index())
    }

    /// An entry copy into a formal's own cell establishes private storage.
    /// It preserves the incoming value without writing the referenced object.
    /// Later stores and stores into capture or selected locations are accesses.
    pub fn is_formal_cell_initialization(
        &self,
        point: ProgramPointId,
        effect: &SemanticEffect,
    ) -> bool {
        let SemanticEffect::MemoryStore {
            location, value, ..
        } = *effect
        else {
            return false;
        };
        point == self.entry_point()
            && self.memory_location(location).is_some_and(|location| {
                matches!(location.kind, MemoryLocationKind::LexicalCell { binding } if binding == value)
            })
            && self.value(value).is_some_and(|value| {
                matches!(value.kind, SemanticValueKind::Parameter { .. } | SemanticValueKind::Receiver { .. })
            })
    }

    /// Return the unique local storage owned by one lexical binding.
    pub fn binding_memory_location(&self, binding: ValueId) -> Option<MemoryLocationId> {
        let mut matching = self.memory_locations.iter().filter_map(|location| {
            matches!(
                location.kind,
                MemoryLocationKind::LexicalCell { binding: candidate }
                    | MemoryLocationKind::Capture {
                        binding: Some(candidate),
                        ..
                    } if candidate == binding
            )
            .then_some(location.id)
        });
        let location = matching.next()?;
        assert!(
            matching.next().is_none(),
            "one semantic binding cannot own multiple local memory cells"
        );
        Some(location)
    }

    pub fn capture(&self, id: CaptureId) -> Option<&CaptureBinding> {
        self.captures.get(id.index())
    }

    pub fn call_site(&self, id: CallSiteId) -> Option<&SemanticCallSite> {
        self.call_sites.get(id.index())
    }

    /// The value an async suspend point awaits, when it names one.
    pub fn awaited_value(&self, suspend: ProgramPointId) -> Option<ValueId> {
        self.point(suspend)?
            .events
            .iter()
            .find_map(|event| match event.effect {
                SemanticEffect::AsyncSuspend { awaited, .. } => awaited,
                _ => None,
            })
    }

    fn same_source_occurrence(&self, left: SourceMappingId, right: SourceMappingId) -> bool {
        self.source_mapping(left)
            .zip(self.source_mapping(right))
            .is_some_and(|(left, right)| {
                left.kind == SourceMappingKind::Exact
                    && right.kind == SourceMappingKind::Exact
                    && left.locator == right.locator
                    && left.ast_identity == right.ast_identity
            })
    }

    /// Callable evaluations for this exact source occurrence that precede its
    /// invocation. A selector may be evaluated before arguments or retained
    /// until cleanup; its references need not live on the Invoke point.
    /// Keep all alternatives and their evidence for the consumer's proof.
    pub fn callable_selection_events(
        &self,
        id: CallSiteId,
    ) -> Vec<(ProgramPointId, usize, &SemanticEvent)> {
        let Some(call) = self.call_site(id) else {
            return Vec::new();
        };
        let Some(callee) = self.value(call.callee) else {
            return Vec::new();
        };
        let Some(callee_source) = self.source_mapping(callee.source) else {
            return Vec::new();
        };
        let Some(call_source) = self.source_mapping(call.source) else {
            return Vec::new();
        };
        let callee_span = callee_source.locator.anchor().span();
        let call_span = call_source.locator.anchor().span();
        let Some(dominance) = self.callable_selection_dominance() else {
            return Vec::new();
        };
        let invoke_index = self.point(call.point).and_then(|point| {
            point.events.iter().position(|event|
            matches!(event.effect, SemanticEffect::Invoke { call_site } if call_site == id))
        });
        self.points()
            .iter()
            .flat_map(|point| {
                point
                    .events
                    .iter()
                    .enumerate()
                    .map(move |(index, event)| (point.id, index, event))
            })
            .filter(|(point, index, event)| {
                if *point == call.point && invoke_index.is_none_or(|invoke| *index >= invoke) {
                    return false;
                }
                let result = match event.effect {
                    SemanticEffect::CallableReference { result, .. }
                    | SemanticEffect::CallableCreation { result, .. } => result,
                    _ => return false,
                };
                if result != call.callee || !dominance.dominates(self, *point, call.point) {
                    return false;
                }
                let Some(source) = self.source_mapping(event.source) else {
                    return false;
                };
                let span = source.locator.anchor().span();
                call_span.start_byte() <= span.start_byte()
                    && span.end_byte() <= call_span.end_byte()
                    && span.start_byte() <= callee_span.start_byte()
                    && callee_span.end_byte() <= span.end_byte()
            })
            .collect()
    }

    /// Match a selected receiver to the invocation's receiver, including an
    /// exact registration-time capture. Source identity and the ordered flow
    /// edge distinguish a capture from a later assignment or another selector.
    pub fn selected_receiver_matches(&self, id: CallSiteId, selected: ValueId) -> bool {
        let Some(call) = self.call_site(id) else {
            return false;
        };
        let Some(receiver) = call.receiver else {
            return false;
        };
        if receiver == selected {
            return true;
        }
        let (Some(source), Some(target)) = (self.value(selected), self.value(receiver)) else {
            return false;
        };
        if !self.same_source_occurrence(source.source, target.source) {
            return false;
        }
        let mut definitions = self.points().iter().flat_map(|point| {
            point
                .events
                .iter()
                .filter_map(move |event| match event.effect {
                    SemanticEffect::ValueFlow { source, target, .. } if target == receiver => {
                        Some((point.id, event, source))
                    }
                    _ => None,
                })
        });
        let Some((capture_point, event, source)) = definitions.next() else {
            return false;
        };
        if definitions.next().is_some() || source != selected {
            return false;
        }
        let Some(evidence) = self.evidence_row(event.evidence) else {
            return false;
        };
        if evidence.proof != ProofStatus::Proven
            || evidence.completeness != EvidenceCompleteness::Complete
        {
            return false;
        }
        let Some(dominance) = self.callable_selection_dominance() else {
            return false;
        };
        if !dominance.dominates(self, capture_point, call.point) {
            return false;
        }
        self.callable_selection_events(id)
            .iter()
            .any(|(point, index, _)| {
                dominance.dominates(self, *point, capture_point)
                    && (*point != capture_point
                        || self.point(capture_point).is_some_and(|point| {
                            point
                                .events
                                .iter()
                                .position(|candidate| std::ptr::eq(candidate, event))
                                .is_some_and(|capture| *index < capture)
                        }))
            })
    }

    fn callable_selection_dominance(
        &self,
    ) -> Option<&crate::analyzer::semantic::cfg_algorithms::CompactDominators> {
        self.callable_selection_dominance
            .0
            .get_or_init(|| {
                use crate::analyzer::semantic::cfg_algorithms::{
                    CfgAlgorithmBudget, CfgAlgorithmRequest, dominators,
                };
                // Fixed limits and a private uncancelled token make this outcome
                // a pure function of this immutable procedure. Never share this
                // result with callers whose CFG limits differ.
                let mut budget = CfgAlgorithmBudget::default();
                let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
                dominators(
                    self,
                    self.entry_point(),
                    &mut CfgAlgorithmRequest::new(&mut budget, &cancellation),
                )
                .ok()
                .map(|dominance| dominance.into_compact())
            })
            .as_ref()
    }

    /// Gaps whose subjects can affect this call, in original gap-id order.
    pub fn call_gap_candidates(&self, call: &SemanticCallSite) -> Vec<super::LogicalGapRef<'_>> {
        // A derived index of immutable IR is not charged: a fill charge lands on
        // whichever request fills it first, making persisted and rendered work
        // counters depend on request order.
        let scopes = self.call_gap_derived.scopes.get_or_init(|| {
            let mut procedure = Vec::new();
            let mut points = Vec::new();
            let mut values = Vec::new();
            let mut calls = Vec::new();
            let mut cleanup_owners = Vec::new();
            for (index, gap) in self.gaps.iter().enumerate() {
                match gap.subject {
                    SemanticGapSubject::Procedure
                    | SemanticGapSubject::FutureConstruction
                    | SemanticGapSubject::FutureActivation => procedure.push(index),
                    SemanticGapSubject::Point => points.push((gap.point, index)),
                    SemanticGapSubject::Value(value) => values.push((value, index)),
                    SemanticGapSubject::CallSite(call)
                    | SemanticGapSubject::CallContinuation {
                        call_site: call, ..
                    } => calls.push((call, index)),
                    SemanticGapSubject::CleanupOwners(_) => cleanup_owners.push(index),
                    SemanticGapSubject::MemoryLocation(_)
                    | SemanticGapSubject::Capture(_)
                    | SemanticGapSubject::AsyncContinuation { .. } => {}
                }
            }
            points.sort_unstable();
            values.sort_unstable();
            calls.sort_unstable();
            CallGapScopes {
                procedure: procedure.into_boxed_slice(),
                points: points.into_boxed_slice(),
                values: values.into_boxed_slice(),
                calls: calls.into_boxed_slice(),
                cleanup_owners: cleanup_owners.into_boxed_slice(),
            }
        });
        fn append<K: Ord>(rows: &[(K, usize)], key: K, candidates: &mut Vec<usize>) {
            let start = rows.partition_point(|(row, _)| row < &key);
            candidates.extend(
                rows[start..]
                    .iter()
                    .take_while(|(row, _)| row == &key)
                    .map(|(_, index)| *index),
            );
        }
        let mut candidates = scopes.procedure.to_vec();
        append(&scopes.points, call.point, &mut candidates);
        append(&scopes.calls, call.id, &mut candidates);
        let mut values = vec![call.callee];
        values.extend(call.receiver);
        values.extend(call.arguments.iter().map(|argument| argument.value));
        values.extend(call.normal_result_values());
        values.extend(call.thrown);
        values.sort_unstable();
        values.dedup();
        for &value in &values {
            append(&scopes.values, value, &mut candidates);
        }
        candidates.sort_unstable_by_key(|index| self.gaps[*index].id);
        let mut logical = candidates
            .into_iter()
            .map(|index| super::LogicalGapRef {
                base: &self.gaps[index],
                member: None,
            })
            .collect::<Vec<_>>();
        // Ordinary Value gaps came from the value index above. Only cleanup-owner
        // gaps need a membership test, so a procedure without them pays nothing.
        for &index in scopes.cleanup_owners.iter() {
            let gap = &self.gaps[index];
            let SemanticGapSubject::CleanupOwners(segment) = gap.subject else {
                unreachable!("the cleanup-owner index holds only cleanup-owner gaps");
            };
            for &owner in &values {
                if self.cleanup_chains.contains_owner(segment, owner) {
                    logical.push(super::LogicalGapRef {
                        base: gap,
                        member: Some(super::GapMemberRef {
                            base_gap_id: gap.id,
                            owner,
                        }),
                    });
                }
            }
        }
        logical.sort_unstable_by_key(|gap| {
            (
                gap.base.point,
                gap.base.capability,
                gap.member.map(|member| member.owner),
                gap.base.id,
            )
        });
        logical.dedup_by_key(|gap| gap.key());
        logical
    }

    /// Complete abort-path answer, derived without request reads or limits.
    pub(crate) fn memoized_abort_paths_run_user_code(
        &self,
        compute: impl FnOnce() -> bool,
    ) -> bool {
        *self.call_gap_derived.abort_user_code.get_or_init(compute)
    }

    /// Reserve all possible lazy gap-index rows before artifact admission.
    pub fn call_gap_index_reserved_bytes(&self) -> u64 {
        (self.gaps.len() as u64).saturating_mul(
            size_of::<(ProgramPointId, usize)>()
                .max(size_of::<(ValueId, usize)>())
                .max(size_of::<(CallSiteId, usize)>()) as u64,
        )
    }

    /// Reserve the largest lazy dominance payload before artifact admission.
    /// The inline cell is already included in size_of::<ProcedureSemantics>.
    pub fn callable_selection_dominance_reserved_bytes(&self) -> u64 {
        (self.points.len() as u64)
            .saturating_mul(size_of::<u32>() as u64)
            .saturating_add((size_of::<usize>() * 2) as u64)
    }

    /// Values introduced at a callable-selection boundary to prepare its
    /// receiver are not additional evaluations of the written operand. Follow
    /// their defining effects at that boundary, not their value kind or type.
    pub fn implicit_receiver_preparation_values(&self) -> HashSet<ValueId> {
        let mut prepared = self.receiver_preparation_values();
        for (point, index) in self.receiver_preparation_memory_events(&prepared) {
            match self.points()[point.index()].events[index].effect {
                SemanticEffect::MemoryLoad { result, .. } => {
                    prepared.insert(result);
                }
                SemanticEffect::MemoryStore { value, .. } => {
                    prepared.insert(value);
                }
                _ => unreachable!("preparation memory events are loads or stores"),
            }
        }
        prepared
    }

    /// Internal field snapshots of an implicit receiver copy, keyed by exact
    /// event occurrence. These remain heap/flow operations, but do not denote
    /// field accesses written in the source.
    pub fn implicit_receiver_preparation_memory_events(&self) -> HashSet<(ProgramPointId, usize)> {
        self.receiver_preparation_memory_events(&self.receiver_preparation_values())
    }

    fn receiver_preparation_memory_events(
        &self,
        prepared: &HashSet<ValueId>,
    ) -> HashSet<(ProgramPointId, usize)> {
        let mut snapshots = HashSet::default();
        for point in self.points() {
            for transfer in &point.events {
                let SemanticEffect::ValueFlow {
                    kind:
                        ValueFlowKind::Transfer(ValueTransfer {
                            kind: TransferKind::AggregateCopy,
                            ..
                        }),
                    source,
                    target,
                } = transfer.effect
                else {
                    continue;
                };
                if !prepared.contains(&target) {
                    continue;
                }
                for (store_index, store) in point.events.iter().enumerate() {
                    if store.source != transfer.source {
                        continue;
                    }
                    let SemanticEffect::MemoryStore {
                        location,
                        value: stored,
                        ..
                    } = store.effect
                    else {
                        continue;
                    };
                    let Some(MemoryLocationKind::Field { base, member }) =
                        self.memory_location(location).map(|row| &row.kind)
                    else {
                        continue;
                    };
                    if *base != target {
                        continue;
                    }
                    // The destination and source field must be the same exact
                    // declaration, and the stored value must come from that
                    // snapshot load through boundary-local copy effects.
                    let mut origins = HashSet::default();
                    let mut pending = vec![stored];
                    while let Some(value) = pending.pop() {
                        if !origins.insert(value) {
                            continue;
                        }
                        for definition in &point.events[..store_index] {
                            if definition.source != transfer.source {
                                continue;
                            }
                            match definition.effect {
                                SemanticEffect::Assignment {
                                    target,
                                    value: input,
                                } if target == value => pending.push(input),
                                SemanticEffect::ValueFlow {
                                    kind:
                                        ValueFlowKind::Transfer(ValueTransfer {
                                            kind: TransferKind::Copy | TransferKind::AggregateCopy,
                                            ..
                                        }),
                                    source: input,
                                    target,
                                } if target == value => pending.push(input),
                                _ => {}
                            }
                        }
                    }
                    for (load_index, load) in point.events[..store_index].iter().enumerate() {
                        if load.source != transfer.source {
                            continue;
                        }
                        let SemanticEffect::MemoryLoad {
                            location, result, ..
                        } = load.effect
                        else {
                            continue;
                        };
                        if origins.contains(&result) && self.memory_location(location).is_some_and(|row|
                            matches!(&row.kind, MemoryLocationKind::Field { base, member: selected } if *base == source && selected == member)) {
                            snapshots.insert((point.id, load_index));
                            snapshots.insert((point.id, store_index));
                        }
                    }
                }
            }
        }
        snapshots
    }

    fn receiver_preparation_values(&self) -> HashSet<ValueId> {
        let mut prepared = HashSet::default();
        for point in self.points() {
            for event in &point.events {
                let SemanticEffect::CallableReference { result, callable } = &event.effect else {
                    continue;
                };
                // The boundary must be the selected callable expression,
                // rather than a whole invocation that also evaluates operands.
                if self.value(*result).is_none_or(|callee| {
                    self.source_mapping(callee.source)
                        .zip(self.source_mapping(event.source))
                        .is_none_or(|(value, boundary)| {
                            value.kind != SourceMappingKind::Exact
                                || boundary.kind != SourceMappingKind::Exact
                                || value.locator.path() != boundary.locator.path()
                                || value.locator.declaration() != boundary.locator.declaration()
                                || value.locator.anchor().span() != boundary.locator.anchor().span()
                        })
                }) {
                    continue;
                }
                let Some(receiver) = callable.bound_receiver else {
                    continue;
                };
                let Some(receiver_value) = self.value(receiver) else {
                    continue;
                };
                let Some(operand) = self.source_mapping(receiver_value.source) else {
                    continue;
                };
                let Some(boundary) = self.source_mapping(event.source) else {
                    continue;
                };
                let operand_span = operand.locator.anchor().span();
                let boundary_span = boundary.locator.anchor().span();
                if !(boundary_span.start_byte() <= operand_span.start_byte()
                    && operand_span.end_byte() < boundary_span.end_byte())
                {
                    continue;
                }
                let mut pending = vec![receiver];
                while let Some(value) = pending.pop() {
                    if self
                        .pointer_aliases()
                        .iter()
                        .any(|alias| alias.point == point.id && alias.pointer == value)
                        && self.value(value).is_some_and(|value| {
                            self.same_source_occurrence(value.source, receiver_value.source)
                        })
                    {
                        prepared.insert(value);
                    }
                    if prepared.contains(&value)
                        || self.value(value).is_none_or(|value| {
                            !self.same_source_occurrence(value.source, receiver_value.source)
                        })
                    {
                        continue;
                    }
                    for definition in &point.events {
                        if definition.source != event.source {
                            continue;
                        }
                        let input = match definition.effect {
                            SemanticEffect::ValueFlow {
                                kind:
                                    ValueFlowKind::Transfer(ValueTransfer {
                                        kind: TransferKind::Copy | TransferKind::AggregateCopy,
                                        ..
                                    }),
                                source,
                                target,
                            } if target == value => Some(source),
                            SemanticEffect::MemoryLoad {
                                result, location, ..
                            } if result == value && value != receiver => {
                                match self
                                    .memory_location(location)
                                    .map(|location| &location.kind)
                                {
                                    Some(MemoryLocationKind::Dereference { address }) => {
                                        Some(*address)
                                    }
                                    _ => None,
                                }
                            }
                            _ => None,
                        };
                        if let Some(input) = input {
                            prepared.insert(value);
                            pending.push(input);
                        }
                    }
                }
            }
        }
        prepared
    }

    /// Return a receiver fact proved by the callable evaluation at this call.
    ///
    /// Target resolution is deliberately irrelevant: a language adapter can
    /// prove from local syntax that `package.Function(...)` evaluates a free
    /// function even when the external target remains open. Missing,
    /// incomplete, duplicate, or contradictory callable-reference evidence
    /// returns `None` instead of turning absent semantic support into a fact.
    pub fn proven_caller_receiver_binding(&self, id: CallSiteId) -> Option<CallerReceiverBinding> {
        let call = self.call_site(id)?;
        let call_evidence = self.evidence_row(call.evidence)?;
        if !matches!(call_evidence.proof, ProofStatus::Proven)
            || !matches!(call_evidence.completeness, EvidenceCompleteness::Complete)
        {
            return None;
        }

        let selections = self.callable_selection_events(id);
        let mut references = selections.iter().filter_map(|(_, _, event)| {
            let SemanticEffect::CallableReference { result, callable } = &event.effect else {
                return None;
            };
            (*result == call.callee).then_some((event, callable))
        });
        let (event, callable) = references.next()?;
        if references.next().is_some() {
            return None;
        }
        let event_evidence = self.evidence_row(event.evidence)?;
        if !matches!(event_evidence.proof, ProofStatus::Proven)
            || !matches!(event_evidence.completeness, EvidenceCompleteness::Complete)
        {
            return None;
        }

        match (call.receiver, callable.kind, callable.bound_receiver) {
            (Some(receiver), CallableReferenceKind::BoundMethod, Some(bound_receiver))
                if self.selected_receiver_matches(id, bound_receiver) =>
            {
                Some(CallerReceiverBinding::Bound(receiver))
            }
            (Some(receiver), CallableReferenceKind::ModuleQualified { qualifier }, None)
                if receiver == qualifier =>
            {
                Some(CallerReceiverBinding::ModuleQualified(qualifier))
            }
            (None, CallableReferenceKind::TypeQualifiedMethod { qualifier }, None) => {
                Some(CallerReceiverBinding::TypeQualified(qualifier))
            }
            (None, CallableReferenceKind::Function | CallableReferenceKind::StaticMethod, None) => {
                Some(CallerReceiverBinding::Absent)
            }
            _ => None,
        }
    }

    pub fn source_mapping(&self, id: SourceMappingId) -> Option<&SourceMapping> {
        self.source_mappings.get(id.index())
    }

    fn source_locator(&self, id: SourceMappingId) -> Option<&SemanticLocator> {
        self.source_mapping(id).map(|mapping| &mapping.locator)
    }

    pub fn evidence_row(&self, id: EvidenceId) -> Option<&Evidence> {
        self.evidence_rows.get(id.index())
    }

    pub fn gap(&self, id: SemanticGapId) -> Option<&SemanticGap> {
        self.gaps.get(id.index())
    }

    pub fn block(&self, id: BlockId) -> Option<&BasicBlock> {
        self.blocks.get(id.index())
    }

    pub fn point(&self, id: ProgramPointId) -> Option<&ProgramPoint> {
        self.points.get(id.index())
    }
}

/// Resolve every declared guard arm against the canonical control-edge table.
///
/// The lowerer names an arm by destination and edge kind because edge IDs only
/// exist once the table is sorted. Validation has already proved that a
/// declared arm names an edge leaving the guard's own point, so the lookup is a
/// scan of that point's outgoing row -- at most a handful of edges -- and never
/// fails for a declared arm.
fn freeze_guard_facts(cfg: &ControlFlowGraph, parts: &[GuardFactParts]) -> Box<[GuardFact]> {
    let resolve = |point: ProgramPointId, arm: Option<GuardArm>| {
        let arm = arm?;
        cfg.successor_edges(point)
            .find(|(_, edge)| edge.target_point == arm.target_point && edge.kind == arm.kind)
            .map(|(id, _)| id)
    };
    parts
        .iter()
        .map(|guard| GuardFact {
            id: guard.id,
            point: guard.point,
            subject: guard.subject,
            predicate: guard.predicate,
            true_edge: resolve(guard.point, guard.true_arm),
            false_edge: resolve(guard.point, guard.false_arm),
            source: guard.source,
            evidence: guard.evidence,
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn freeze_switch_facts(cfg: &ControlFlowGraph, parts: &[SwitchFactParts]) -> Box<[SwitchFact]> {
    let resolve = |edge: SwitchEdgeParts| {
        cfg.successor_edges(edge.source_point)
            .find(|(_, candidate)| {
                candidate.target_point == edge.arm.target_point && candidate.kind == edge.arm.kind
            })
            .map(|(id, _)| id)
            .expect("validated switch edge resolves in the frozen CFG")
    };
    parts
        .iter()
        .map(|fact| SwitchFact {
            id: fact.id,
            kind: fact.kind,
            point: fact.point,
            selector: fact.selector,
            selector_domain: fact.selector_domain,
            cases: fact
                .cases
                .iter()
                .map(|case| SwitchCaseFact {
                    value: case.value,
                    edge: resolve(case.edge),
                })
                .collect(),
            default_edge: fact.default_edge.map(resolve),
            default_present: fact.default_present,
            source: fact.source,
            evidence: fact.evidence,
        })
        .collect()
}

fn duplicate_value_ordinals(
    values: &[SemanticValue],
    source_mappings: &[SourceMapping],
) -> Box<[(ValueId, u32)]> {
    duplicate_value_ordinals_by(values, |source| {
        &source_mappings
            .get(source.index())
            .expect("validated semantic value source")
            .locator
    })
}

fn duplicate_value_ordinals_by<K>(
    values: &[SemanticValue],
    source_group: impl Fn(SourceMappingId) -> K,
) -> Box<[(ValueId, u32)]>
where
    K: Copy + Eq + Hash,
{
    let mut totals = HashMap::<(K, &'static str), usize>::default();
    for value in values {
        if matches!(value.kind, SemanticValueKind::Parameter { .. }) {
            continue;
        }
        *totals
            .entry((source_group(value.source), value.kind.label()))
            .or_default() += 1;
    }

    let mut seen = HashMap::<(K, &'static str), u32>::default();
    values
        .iter()
        .filter_map(|value| {
            if matches!(value.kind, SemanticValueKind::Parameter { .. }) {
                return None;
            }
            let key = (source_group(value.source), value.kind.label());
            if totals.get(&key).copied().unwrap_or_default() < 2 {
                return None;
            }
            let ordinal = seen.entry(key).or_default();
            let current = *ordinal;
            *ordinal = ordinal
                .checked_add(1)
                .expect("one source role cannot mint more than u32::MAX semantic values");
            Some((value.id, current))
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

#[cfg(test)]
mod value_identity_tests {

    use crate::analyzer::semantic::ir::artifact::*;

    fn value(id: u32, source: u32, kind: SemanticValueKind) -> SemanticValue {
        SemanticValue {
            actual_borrow: Default::default(),
            static_type_origin: None,
            static_type_class: Default::default(),
            id: ValueId::new(id),
            kind,
            source: SourceMappingId::new(source),
            evidence: EvidenceId::new(0),
        }
    }

    #[test]
    fn duplicate_non_parameter_values_receive_sparse_structural_ordinals() {
        let values = [
            value(0, 0, SemanticValueKind::Exception),
            value(1, 1, SemanticValueKind::Local),
            value(2, 0, SemanticValueKind::Exception),
            value(
                3,
                0,
                SemanticValueKind::Parameter {
                    ordinal: 7,
                    multiplicity: FormalMultiplicity::One,
                    name: None,
                    passing_mode: FormalParameterPassingMode::PositionalOrNamed,
                },
            ),
        ];

        assert_eq!(
            duplicate_value_ordinals_by(&values, |_| 0_u32).as_ref(),
            [(ValueId::new(0), 0), (ValueId::new(2), 1)]
        );
    }
}

type CallPhasePointIndex = HashMap<ValueId, Box<[ProgramPointId]>>;
type CallResultSiteIndex = HashMap<(ValueId, ProgramPointId), Box<[CallSiteId]>>;

fn index_call_phases(
    call_sites: &[SemanticCallSite],
) -> (CallPhasePointIndex, CallResultSiteIndex) {
    let mut indexed = HashMap::<ValueId, Vec<ProgramPointId>>::default();
    let mut indexed_pairs = HashSet::default();
    let mut result_sites = HashMap::<(ValueId, ProgramPointId), Vec<CallSiteId>>::default();
    let mut push = |value, point| {
        if indexed_pairs.insert((value, point)) {
            indexed.entry(value).or_default().push(point);
        }
    };
    for call in call_sites {
        push(call.callee, call.point);
        if let Some(point) = call.normal_continuation.target() {
            for result in call.normal_result_values() {
                push(result, point);
                result_sites
                    .entry((result, point))
                    .or_default()
                    .push(call.id);
            }
        }
        if let (Some(thrown), Some(point)) = (call.thrown, call.exceptional_continuation.target()) {
            push(thrown, point);
        }
    }
    let phase_points = indexed
        .into_iter()
        .map(|(value, mut points)| {
            points.sort_unstable();
            (value, points.into_boxed_slice())
        })
        .collect();
    let result_sites = result_sites
        .into_iter()
        .map(|(site, calls)| (site, calls.into_boxed_slice()))
        .collect();
    (phase_points, result_sites)
}

fn boxed_slice_index_retained_bytes<K, V>(index: &HashMap<K, Box<[V]>>) -> u64 {
    fn rows(count: usize, row_size: usize) -> u64 {
        (count as u64).saturating_mul(row_size as u64)
    }

    let bucket_size = size_of::<K>()
        .saturating_add(size_of::<Box<[V]>>())
        .saturating_add(size_of::<usize>().saturating_mul(2));
    index
        .values()
        .fold(rows(index.capacity(), bucket_size), |retained, payload| {
            retained
                .saturating_add(rows(payload.len(), size_of::<V>()))
                .saturating_add((size_of::<usize>().saturating_mul(2)) as u64)
        })
}

struct CandidateEvidence {
    value: Arc<dyn std::any::Any + Send + Sync>,
    bytes: usize,
}

impl std::fmt::Debug for CandidateEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CandidateEvidence")
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

/// One immutable interpretation of one mounted source snapshot.
#[derive(Debug)]
pub struct SemanticArtifact {
    /// Guarded IR shares the lifetime and allocation identity of this base.
    /// Flows and admission decisions remain per acquisition.
    candidate_arena: std::sync::OnceLock<std::sync::Mutex<CandidateArena>>,
    candidate_evidence: Option<CandidateEvidence>,
    pub(crate) charge: brokk_bifrost_core::retention_budget::AllocationCharge,
    pub(crate) cache_pins: Arc<ArtifactCachePins>,
    #[doc(hidden)]
    pub query_source: Option<Arc<str>>,
    key: SemanticArtifactKey,
    materialization_id: SemanticArtifactMaterializationId,
    capabilities: SemanticCapabilities,
    work: SemanticWork,
    base_work: SemanticWork,
    go_predeclared_builtin_assumptions: Box<[GoPredeclaredBuiltin]>,
    procedures: Box<[ProcedureSemantics]>,
    ownership_projection: Option<Box<OwnershipProjection>>,
    procedures_by_locator: HashMap<SemanticLocator, ProcedureId>,
    /// Procedures lexically enclosed by each procedure, built once from the
    /// validated parent links so a closure walk never rescans the procedure
    /// table per visited procedure (#2640, #2951).
    lexical_children: HashMap<ProcedureId, Box<[ProcedureId]>>,
    /// Source hull of each procedure's call-site mappings, sorted by start.
    /// Built once so a range lookup examines only procedures that can own a
    /// call site containing the range.
    call_source_extents: Box<[CallSourceExtent]>,
}

/// A demand view owns one target and shares every unrelated body and index.
#[derive(Debug)]
struct OwnershipProjection {
    base: Arc<SemanticArtifact>,
    target: ProcedureSemantics,
    owned_bytes: u64,
}

/// Dense logical procedure table backed by either an ordinary artifact or a
/// shared base plus one demand-local substitution. No table is copied.
#[derive(Clone, Copy)]
pub struct SemanticProcedures<'a>(&'a SemanticArtifact);

impl<'a> SemanticProcedures<'a> {
    pub fn len(self) -> usize {
        self.0
            .ownership_projection
            .as_ref()
            .map_or(self.0.procedures.len(), |view| view.base.procedures().len())
    }
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
    pub fn get(self, index: usize) -> Option<&'a ProcedureSemantics> {
        self.0
            .procedure(ProcedureId::new(u32::try_from(index).ok()?))
    }
    pub fn first(self) -> Option<&'a ProcedureSemantics> {
        self.get(0)
    }
    pub fn iter(self) -> SemanticProcedureIter<'a> {
        SemanticProcedureIter {
            table: self,
            indices: 0..self.len(),
        }
    }
}
#[derive(Clone)]
pub struct SemanticProcedureIter<'a> {
    table: SemanticProcedures<'a>,
    indices: std::ops::Range<usize>,
}
impl<'a> Iterator for SemanticProcedureIter<'a> {
    type Item = &'a ProcedureSemantics;
    fn next(&mut self) -> Option<Self::Item> {
        self.indices.next().and_then(|index| self.table.get(index))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.indices.size_hint()
    }
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.indices.nth(n).and_then(|index| self.table.get(index))
    }
}
impl ExactSizeIterator for SemanticProcedureIter<'_> {}
impl DoubleEndedIterator for SemanticProcedureIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.indices
            .next_back()
            .and_then(|index| self.table.get(index))
    }
}
impl<'a> IntoIterator for SemanticProcedures<'a> {
    type Item = &'a ProcedureSemantics;
    type IntoIter = SemanticProcedureIter<'a>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl std::fmt::Debug for SemanticProcedures<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}
impl std::ops::Index<usize> for SemanticProcedures<'_> {
    type Output = ProcedureSemantics;
    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("procedure index")
    }
}

/// The hull of one procedure's call-site source mappings. `max_end_byte` is
/// the largest `end_byte` of this entry and of every earlier entry in start
/// order, so a backward scan can stop once no earlier entry reaches a range.
#[derive(Debug, Clone, Copy)]
struct CallSourceExtent {
    procedure: ProcedureId,
    start_byte: usize,
    end_byte: usize,
    max_end_byte: usize,
}

#[derive(Debug, Default)]
struct CandidateArena {
    live: std::sync::Weak<SemanticArtifact>,
    retained: Option<Arc<SemanticArtifact>>,
}

impl SemanticArtifact {
    #[doc(hidden)]
    pub fn candidate_evidence(&self) -> Option<&Arc<dyn std::any::Any + Send + Sync>> {
        self.candidate_evidence
            .as_ref()
            .map(|evidence| &evidence.value)
    }

    #[doc(hidden)]
    pub fn attach_candidate_evidence(
        &mut self,
        evidence: Arc<dyn std::any::Any + Send + Sync>,
        bytes: usize,
    ) {
        assert!(self.candidate_evidence.is_none());
        self.work.owned_text_bytes = self.work.owned_text_bytes.saturating_add(bytes);
        self.candidate_evidence = Some(CandidateEvidence {
            value: evidence,
            bytes,
        });
    }

    /// Include retained projection rows in the complete-artifact census.
    #[doc(hidden)]
    pub fn include_candidate_census(&mut self, census: SemanticWork) {
        self.work = self.work.saturating_add(census);
    }

    #[doc(hidden)]
    pub fn candidate_evidence_retained_bytes(&self) -> usize {
        self.candidate_evidence
            .as_ref()
            .map_or(0, |evidence| evidence.bytes)
    }

    #[doc(hidden)]
    pub fn try_candidate_arena<E>(
        &self,
        build: impl FnOnce() -> Result<Option<Arc<Self>>, E>,
    ) -> Result<Option<Arc<Self>>, E> {
        assert!(
            !self.has_executable_projection(),
            "an executable body cannot acquire a macro arena"
        );
        let mut slot = self
            .candidate_arena
            .get_or_init(Default::default)
            .lock()
            .expect("candidate arena mutex poisoned");
        if let Some(live) = slot.live.upgrade() {
            return Ok(Some(live));
        }
        let Some(artifact) = build()? else {
            return Ok(None);
        };
        assert!(
            !artifact.has_executable_projection(),
            "a macro arena cannot retain an executable body"
        );
        slot.live = Arc::downgrade(&artifact);
        slot.retained = artifact.charge.is_charged().then(|| Arc::clone(&artifact));
        Ok(Some(artifact))
    }

    #[doc(hidden)]
    pub fn canonical_candidate_arena(&self, artifact: Arc<Self>) -> Arc<Self> {
        assert!(
            !self.has_executable_projection(),
            "an executable body cannot acquire a macro arena"
        );
        debug_assert_eq!(self.key(), artifact.key());
        debug_assert_eq!(self.capabilities(), artifact.capabilities());
        assert!(
            !artifact.has_executable_projection(),
            "a macro arena cannot canonicalize an executable body"
        );
        let mut slot = self
            .candidate_arena
            .get_or_init(Default::default)
            .lock()
            .expect("candidate arena mutex poisoned");
        if let Some(live) = slot.live.upgrade() {
            return live;
        }
        slot.live = Arc::downgrade(&artifact);
        slot.retained = artifact.charge.is_charged().then(|| Arc::clone(&artifact));
        artifact
    }

    #[doc(hidden)]
    pub fn candidate_arena_retained_bytes(&self) -> u64 {
        self.candidate_arena.get().map_or(0, |slot| {
            let slot = slot.lock().expect("candidate arena mutex poisoned");
            slot.retained.as_ref().map_or(0, |arena| {
                crate::analyzer::semantic::service::semantic_artifact_retained_bytes(arena)
            })
        })
    }

    /// Borrow the actual retained arena owner without building a census or
    /// copying its graph. The callback must not reenter this artifact's slot.
    #[doc(hidden)]
    pub fn for_each_retained_candidate_arena(&self, mut visit: impl FnMut(&Arc<Self>)) {
        if let Some(slot) = self.candidate_arena.get() {
            let slot = slot.lock().expect("candidate arena mutex poisoned");
            if let Some(arena) = &slot.retained {
                visit(arena);
            }
        }
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub(crate) fn retained_candidate_arena_for_test(&self) -> Option<Arc<Self>> {
        let slot = self.candidate_arena.get()?;
        {
            let slot = slot.lock().expect("candidate arena mutex poisoned");
            slot.retained.as_ref().map(Arc::clone)
        }
    }

    /// Attach decoded guarded parts before the ordinary full artifact validation.
    /// M4 uses this entry point to freeze alternatives in their base context.
    pub fn try_new_with_candidate_alternates(
        key: SemanticArtifactKey,
        capabilities: SemanticCapabilities,
        base_parts: Vec<ProcedureSemanticsParts>,
        alternates: impl IntoIterator<Item = (ProcedureSemanticsParts, Box<[CandidateRecord]>)>,
    ) -> Result<Self, SemanticIrError> {
        let mut budget = SemanticBudget::producer();
        Self::try_new_with_candidate_alternates_and_budget(
            key,
            capabilities,
            base_parts,
            alternates,
            &mut budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
        .map_err(|error| match error {
            SemanticArtifactBuildError::Invalid(error) => error,
            SemanticArtifactBuildError::Cancelled => SemanticIrError::artifact(
                SemanticIrErrorKind::Cancelled,
                "semantic validation cancelled",
            ),
            SemanticArtifactBuildError::ExceededBudget(error) => {
                SemanticIrError::artifact(SemanticIrErrorKind::ResourceLimit, error.to_string())
            }
        })
    }

    /// Attach guarded parts and charge their complete census to the caller.
    pub fn try_new_with_candidate_alternates_and_budget(
        key: SemanticArtifactKey,
        capabilities: SemanticCapabilities,
        mut base_parts: Vec<ProcedureSemanticsParts>,
        alternates: impl IntoIterator<Item = (ProcedureSemanticsParts, Box<[CandidateRecord]>)>,
        budget: &mut SemanticBudget,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<Self, SemanticArtifactBuildError> {
        for (alternate, candidates) in alternates {
            let id = alternate.id;
            let base = base_parts
                .get_mut(id.index())
                .filter(|base| base.id == id)
                .ok_or_else(|| {
                    SemanticIrError::procedure(
                        id,
                        SemanticIrErrorKind::OutOfBounds,
                        "unknown guarded procedure",
                    )
                })?;
            if base.candidate_alternate.is_some() || alternate.candidate_alternate.is_some() {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::CallContract,
                    "duplicate or nested guarded alternative",
                )
                .into());
            }
            if base.locator != alternate.locator {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::CallContract,
                    "invalid guarded locator",
                )
                .into());
            }
            if let Err(violation) = validate_candidate_records(base, &alternate, &candidates) {
                return Err(SemanticIrError::procedure(
                    id,
                    SemanticIrErrorKind::CallContract,
                    format!("invalid guarded candidate records: {violation}"),
                )
                .into());
            }
            base.candidate_alternate = Some(Box::new(CandidateMacroAlternateParts {
                parts: alternate,
                candidates,
            }));
        }
        Self::try_new_with_budget(key, capabilities, base_parts, budget, cancellation)
    }

    /// Validate all artifact, procedure, side-table, event, and topology
    /// invariants before exposing immutable semantics.
    pub fn try_new(
        key: SemanticArtifactKey,
        capabilities: SemanticCapabilities,
        procedure_parts: Vec<ProcedureSemanticsParts>,
    ) -> Result<Self, SemanticIrError> {
        let mut budget = SemanticBudget::producer();
        Self::try_new_with_budget(
            key,
            capabilities,
            procedure_parts,
            &mut budget,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
        .map_err(|error| match error {
            SemanticArtifactBuildError::Invalid(error) => error,
            SemanticArtifactBuildError::Cancelled => SemanticIrError::artifact(
                SemanticIrErrorKind::Cancelled,
                "semantic validation cancelled",
            ),
            SemanticArtifactBuildError::ExceededBudget(error) => {
                SemanticIrError::artifact(SemanticIrErrorKind::ResourceLimit, error.to_string())
            }
        })
    }

    /// Validate and publish an artifact while atomically charging every
    /// retained row, event, edge, nested entry, and owned string byte.
    /// Failed validation or charging leaves `budget` unchanged.
    pub fn try_new_with_budget(
        key: SemanticArtifactKey,
        capabilities: SemanticCapabilities,
        mut procedure_parts: Vec<ProcedureSemanticsParts>,
        budget: &mut SemanticBudget,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<Self, SemanticArtifactBuildError> {
        let mut go_predeclared_builtin_assumptions = Vec::new();
        for procedure in &mut procedure_parts {
            go_predeclared_builtin_assumptions
                .append(&mut procedure.go_predeclared_builtin_assumptions);
        }
        go_predeclared_builtin_assumptions.sort_unstable_by_key(|builtin| builtin.name());
        go_predeclared_builtin_assumptions.dedup();
        let (base_work, work) =
            measure_artifact_work(&key, &procedure_parts, &go_predeclared_builtin_assumptions);
        let mut charged_budget = budget.clone();
        charged_budget.admit_artifact_rows(work)?;
        #[cfg(any(test, feature = "test-support"))]
        if REJECTED_ARTIFACT_PATHS_FOR_TEST
            .lock()
            .expect("rejected artifact paths mutex poisoned")
            .iter()
            .any(|path| path == key.path().as_str())
        {
            return Err(SemanticArtifactBuildError::Invalid(
                SemanticIrError::artifact(
                    SemanticIrErrorKind::GapContract,
                    "artifact rejected by the test registry",
                ),
            ));
        }
        validate_artifact(&key, &capabilities, &procedure_parts, cancellation)?;

        let mut procedures_by_locator = HashMap::default();
        let mut procedures = Vec::with_capacity(procedure_parts.len());
        for parts in procedure_parts {
            let id = parts.id;
            let locator = parts.locator.clone();
            let boundaries = find_boundaries(&parts).map_err(|error| error.at_source(&locator))?;
            procedures.push(
                ProcedureSemantics::try_from_parts(
                    parts,
                    boundaries.entry,
                    boundaries.normal_exit,
                    boundaries.exceptional_exit,
                )
                .map_err(|error| error.at_source(&locator))?,
            );
            procedures_by_locator.insert(locator, id);
        }

        let procedures = procedures.into_boxed_slice();
        let mut lexical_children: HashMap<ProcedureId, Vec<ProcedureId>> = HashMap::default();
        for child in &procedures {
            if let Some(parent) = child.lexical_parent() {
                lexical_children.entry(parent).or_default().push(child.id());
            }
        }
        let lexical_children = lexical_children
            .into_iter()
            .map(|(parent, children)| (parent, children.into_boxed_slice()))
            .collect();
        let call_source_extents = call_source_extent_index(&procedures);
        let materialization_id = compute_artifact_materialization_id(
            &key,
            &capabilities,
            &procedures,
            &go_predeclared_builtin_assumptions,
        );
        let artifact = Self {
            candidate_arena: Default::default(),
            candidate_evidence: None,
            charge: Default::default(),
            cache_pins: Arc::new(ArtifactCachePins::default()),
            query_source: None,
            key,
            materialization_id,
            capabilities,
            work,
            base_work,
            go_predeclared_builtin_assumptions: go_predeclared_builtin_assumptions.into(),
            procedures,
            ownership_projection: None,
            procedures_by_locator,
            lexical_children,
            call_source_extents,
        };
        *budget = charged_budget;
        Ok(artifact)
    }

    /// Freeze one demand-local target in an already validated base context.
    /// The logical census and fingerprint equal a complete target-only rebuild.
    #[doc(hidden)]
    pub fn try_ownership_projection(
        base: Arc<Self>,
        alternate: ProcedureSemanticsParts,
        candidates: Box<[CandidateRecord]>,
        native_target_census: SemanticWork,
        budget: &mut SemanticBudget,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<Self, SemanticArtifactBuildError> {
        let original = Self::validate_ownership_target(&base, &alternate, cancellation)?;
        let id = alternate.id;
        if let Err(detail) = super::model::validate_candidate_records_with_anchor(
            |call| {
                original
                    .call_site(call)
                    .and_then(|call| original.source_mapping(call.source))
                    .map(|mapping| CandidateAnchor::of(mapping.locator.anchor().span()))
            },
            &alternate,
            &candidates,
        ) {
            return Err(
                SemanticIrError::procedure(id, SemanticIrErrorKind::CallContract, detail).into(),
            );
        }
        Self::freeze_ownership_projection(
            base,
            alternate,
            GuardedProcedureAuthority::Macro(candidates),
            native_target_census,
            budget,
        )
    }

    /// Freeze a demand-only body whose executable refinement evidence is owned
    /// by the acquiring query's receipt. This does not admit the body or put
    /// it in the native artifact cache. Legacy macro authority cannot share this executable slot.
    #[doc(hidden)]
    pub fn try_executable_projection(
        base: Arc<Self>,
        alternate: ProcedureSemanticsParts,
        native_target_census: SemanticWork,
        budget: &mut SemanticBudget,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<Self, SemanticArtifactBuildError> {
        Self::validate_ownership_target(&base, &alternate, cancellation)?;
        Self::freeze_ownership_projection(
            base,
            alternate,
            GuardedProcedureAuthority::Executable,
            native_target_census,
            budget,
        )
    }

    fn validate_ownership_target<'a>(
        base: &'a Self,
        alternate: &ProcedureSemanticsParts,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<&'a ProcedureSemantics, SemanticArtifactBuildError> {
        super::validation::validate_ownership_projection(base, alternate, cancellation)?;
        let original = base
            .procedure(alternate.id)
            .expect("validated ownership target");
        if original.guarded_alternate().is_some()
            || alternate.candidate_macro_alternate_parts().is_some()
        {
            return Err(SemanticIrError::procedure(
                alternate.id,
                SemanticIrErrorKind::CallContract,
                "duplicate or mixed ownership alternative",
            )
            .into());
        }
        Ok(original)
    }

    fn freeze_ownership_projection(
        base: Arc<Self>,
        alternate: ProcedureSemanticsParts,
        authority: GuardedProcedureAuthority,
        native_target_census: SemanticWork,
        budget: &mut SemanticBudget,
    ) -> Result<Self, SemanticArtifactBuildError> {
        let original = base
            .procedure(alternate.id)
            .expect("validated ownership target");
        let candidate_count = match &authority {
            GuardedProcedureAuthority::Macro(candidates) => candidates.len(),
            GuardedProcedureAuthority::Executable => 0,
        };
        let mut extra = super::validation::measure_procedure_work(&alternate);
        extra.procedures = 0;
        extra.nested_entries = extra.nested_entries.saturating_add(candidate_count);
        let work = base.work.conservative_add(extra);
        let mut staged = budget.clone();
        staged.admit_artifact_rows(work)?;
        let owned_bytes =
            crate::analyzer::semantic::service::procedure_parts_retained_bytes(&alternate) as u64
                + crate::analyzer::semantic::service::frozen_procedure_row_bytes(
                    original,
                    native_target_census,
                )
                + (candidate_count * size_of::<CandidateRecord>()) as u64;
        let boundaries = find_boundaries(&alternate)?;
        let alternate = ProcedureSemantics::try_from_parts(
            alternate,
            boundaries.entry,
            boundaries.normal_exit,
            boundaries.exceptional_exit,
        )?;
        let mut target = original.clone();
        target.guarded_alternate = Some(Box::new(GuardedProcedureBody {
            semantics: alternate,
            authority,
        }));
        let mut view = Self {
            candidate_arena: Default::default(),
            candidate_evidence: None,
            charge: Default::default(),
            cache_pins: Arc::new(ArtifactCachePins::default()),
            query_source: base.query_source.clone(),
            key: base.key.clone(),
            materialization_id: base.materialization_id,
            capabilities: base.capabilities.clone(),
            work,
            base_work: base.base_work,
            go_predeclared_builtin_assumptions: Box::default(),
            procedures: Box::default(),
            procedures_by_locator: HashMap::default(),
            lexical_children: HashMap::default(),
            call_source_extents: Box::default(),
            ownership_projection: Some(Box::new(OwnershipProjection {
                base,
                target,
                owned_bytes,
            })),
        };
        view.materialization_id = compute_artifact_materialization_id(
            &view.key,
            &view.capabilities,
            view.procedures().iter(),
            view.go_predeclared_builtin_assumptions(),
        );
        *budget = staged;
        Ok(view)
    }

    #[doc(hidden)]
    pub fn shared_ownership_base(&self) -> Option<&Arc<Self>> {
        self.ownership_projection.as_ref().map(|view| &view.base)
    }

    fn has_executable_projection(&self) -> bool {
        self.ownership_projection
            .as_ref()
            .is_some_and(|view| view.target.executable_alternate().is_some())
    }

    #[doc(hidden)]
    pub fn ownership_projection_retained_bytes(&self) -> Option<u64> {
        self.ownership_projection.as_ref().map(|view| {
            // Shared base/index/source storage has its own allocation charge.
            view.owned_bytes
                .saturating_add(size_of::<Self>() as u64)
                .saturating_add(size_of::<OwnershipProjection>() as u64)
                .saturating_add(view.target.call_indexes_retained_bytes())
                .saturating_add(view.target.cleanup_chains().index_retained_bytes() as u64)
                .saturating_add(view.target.callable_selection_dominance_reserved_bytes())
                .saturating_add(view.target.call_gap_index_reserved_bytes())
                .saturating_add(view.target.value_identity_index_retained_bytes())
                .saturating_add(view.target.guarded_alternate().map_or(0, |alternate| {
                    alternate
                        .call_indexes_retained_bytes()
                        .saturating_add(alternate.cleanup_chains().index_retained_bytes() as u64)
                        .saturating_add(alternate.callable_selection_dominance_reserved_bytes())
                        .saturating_add(alternate.call_gap_index_reserved_bytes())
                        .saturating_add(alternate.value_identity_index_retained_bytes())
                }))
        })
    }

    /// Retain one selected source file only for this demand materialization.
    /// Its bytes must be the exact revision already validated by the lowerer.
    #[doc(hidden)]
    pub fn with_query_source(mut self, source: Arc<str>) -> Self {
        assert_eq!(
            self.key.revision().content(),
            super::super::ids::ContentIdentity::hash_bytes(source.as_bytes()),
            "query source must match its semantic artifact revision"
        );
        assert!(self.query_source.is_none(), "query source is attached once");
        self.work.source_bytes = source.len();
        self.query_source = Some(source);
        self
    }

    #[doc(hidden)]
    pub fn query_source(&self) -> Option<&Arc<str>> {
        self.query_source.as_ref()
    }

    pub fn key(&self) -> &SemanticArtifactKey {
        &self.key
    }

    pub const fn materialization_id(&self) -> SemanticArtifactMaterializationId {
        self.materialization_id
    }

    pub fn capabilities(&self) -> &SemanticCapabilities {
        &self.capabilities
    }

    /// Retained row census of the ordinary IR, excluding isolated guarded rows.
    #[doc(hidden)]
    pub const fn base_work(&self) -> SemanticWork {
        self.base_work
    }

    pub const fn work(&self) -> SemanticWork {
        self.work
    }

    pub fn go_predeclared_builtin_assumptions(&self) -> &[GoPredeclaredBuiltin] {
        self.ownership_projection
            .as_ref()
            .map_or(self.go_predeclared_builtin_assumptions.as_ref(), |view| {
                view.base.go_predeclared_builtin_assumptions()
            })
    }

    pub fn procedures(&self) -> SemanticProcedures<'_> {
        SemanticProcedures(self)
    }

    pub fn procedure(&self, id: ProcedureId) -> Option<&ProcedureSemantics> {
        match &self.ownership_projection {
            Some(view) if view.target.id == id => Some(&view.target),
            Some(view) => view.base.procedure(id),
            None => self.procedures.get(id.index()),
        }
    }

    pub fn procedure_id(&self, locator: &SemanticLocator) -> Option<ProcedureId> {
        self.ownership_projection.as_ref().map_or_else(
            || self.procedures_by_locator.get(locator).copied(),
            |view| view.base.procedure_id(locator),
        )
    }

    /// Procedures lexically enclosed by `procedure`, in procedure-table
    /// order. The index is built once at construction from the validated
    /// parent links; a childless procedure returns an empty slice.
    pub fn lexical_children(&self, procedure: ProcedureId) -> &[ProcedureId] {
        if let Some(view) = &self.ownership_projection {
            return view.base.lexical_children(procedure);
        }
        self.lexical_children
            .get(&procedure)
            .map_or(&[][..], Box::as_ref)
    }

    /// Conservative heap storage retained by the derived lexical-child
    /// index. The complete-artifact cache includes this alongside the
    /// procedure-local derived indexes.
    #[doc(hidden)]
    pub fn lexical_children_index_retained_bytes(&self) -> u64 {
        boxed_slice_index_retained_bytes(&self.lexical_children)
    }

    /// Procedures, in procedure-table order, that own a call site whose source
    /// mapping can contain `range`. Each procedure is filtered by the hull of
    /// its call-site mappings, not by its own anchor: a Ruby procedure anchors
    /// only its `def` header, so its body call sites lie outside the anchor.
    /// Every returned procedure is a candidate; the caller still checks each
    /// call site's own mapping.
    pub(crate) fn procedures_with_call_source_containing(&self, range: Range) -> Vec<ProcedureId> {
        if let Some(view) = &self.ownership_projection {
            return view.base.procedures_with_call_source_containing(range);
        }
        let candidates = self
            .call_source_extents
            .partition_point(|extent| extent.start_byte <= range.start_byte);
        let mut found = Vec::new();
        for extent in self.call_source_extents[..candidates].iter().rev() {
            if extent.max_end_byte < range.end_byte {
                break;
            }
            if extent.end_byte >= range.end_byte {
                found.push(extent.procedure);
            }
        }
        found.sort_unstable();
        found
    }

    /// Conservative heap storage retained by the call-source extent index.
    #[doc(hidden)]
    pub fn call_source_extents_retained_bytes(&self) -> u64 {
        (self.call_source_extents.len() as u64).saturating_mul(size_of::<CallSourceExtent>() as u64)
    }

    pub fn procedure_by_locator(&self, locator: &SemanticLocator) -> Option<&ProcedureSemantics> {
        self.procedure(self.procedure_id(locator)?)
    }

    pub fn procedure_handle(self: &Arc<Self>, id: ProcedureId) -> Option<ProcedureHandle> {
        self.procedure(id)?;
        Some(ProcedureHandle {
            artifact: Arc::clone(self),
            id,
            interpretation: ProcedureInterpretation::Base,
        })
    }

    #[doc(hidden)]
    pub fn candidate_alternate_handle(
        self: &Arc<Self>,
        id: ProcedureId,
    ) -> Option<ProcedureHandle> {
        if self.procedure(id)?.executable_alternate().is_some() {
            return None;
        }
        Some(ProcedureHandle {
            artifact: Arc::clone(self),
            id,
            interpretation: ProcedureInterpretation::CandidateAlternate,
        })
    }

    /// Mint only an actually present executable body. Admission belongs to its
    /// owning query and must be replayed before this handle executes.
    #[doc(hidden)]
    pub fn executable_alternate_handle(
        self: &Arc<Self>,
        id: ProcedureId,
    ) -> Option<ProcedureHandle> {
        self.procedure(id)?.executable_alternate()?;
        Some(ProcedureHandle {
            artifact: Arc::clone(self),
            id,
            interpretation: ProcedureInterpretation::ExecutableAlternate,
        })
    }
}

/// Build the call-source extent index. A procedure contributes the hull of
/// every call-site mapping it owns, so the hull contains each of its call
/// sites regardless of what the procedure's own anchor covers.
fn call_source_extent_index(procedures: &[ProcedureSemantics]) -> Box<[CallSourceExtent]> {
    let mut extents = Vec::new();
    for procedure in procedures {
        let mut hull: Option<(usize, usize)> = None;
        for call in procedure.call_sites() {
            let Some(mapping) = procedure.source_mapping(call.source) else {
                continue;
            };
            let span = mapping.locator.anchor().span();
            let start = span.start_byte() as usize;
            let end = span.end_byte() as usize;
            hull = Some(match hull {
                None => (start, end),
                Some((hull_start, hull_end)) => (hull_start.min(start), hull_end.max(end)),
            });
        }
        if let Some((start_byte, end_byte)) = hull {
            extents.push(CallSourceExtent {
                procedure: procedure.id(),
                start_byte,
                end_byte,
                max_end_byte: end_byte,
            });
        }
    }
    extents.sort_unstable_by_key(|extent| extent.start_byte);
    let mut running_max = 0;
    for extent in &mut extents {
        running_max = running_max.max(extent.end_byte);
        extent.max_end_byte = running_max;
    }
    extents.into_boxed_slice()
}

fn compute_artifact_materialization_id<'a>(
    key: &SemanticArtifactKey,
    capabilities: &SemanticCapabilities,
    procedures: impl IntoIterator<Item = &'a ProcedureSemantics, IntoIter: ExactSizeIterator + Clone>,
    go_predeclared_builtin_assumptions: &[GoPredeclaredBuiltin],
) -> SemanticArtifactMaterializationId {
    let procedures = procedures.into_iter();
    let mut digest = MaterializationFingerprintHasher::new(ARTIFACT_MATERIALIZATION_ID_DOMAIN);
    key.fingerprint().hash(&mut digest);
    capabilities.iter().for_each(|(capability, support)| {
        capability.hash(&mut digest);
        support.hash(&mut digest);
    });
    procedures.len().hash(&mut digest);
    go_predeclared_builtin_assumptions.hash(&mut digest);
    for procedure in procedures.clone() {
        procedure.id().hash(&mut digest);
        procedure.materialization_id().hash(&mut digest);
    }
    // Preserve base-only identities. Once an artifact has an alternate, bind
    // every procedure's presence tag, alternate rows and candidate metadata.
    // The base row digest deliberately excludes these guarded contents.
    if procedures
        .clone()
        .any(|procedure| procedure.candidate_macro_alternate().is_some())
    {
        b"candidate-alternate-materializations-v1".hash(&mut digest);
        procedures.len().hash(&mut digest);
        for procedure in procedures.clone() {
            procedure.id().hash(&mut digest);
            match procedure.candidate_macro_alternate() {
                None => 0_u8.hash(&mut digest),
                Some((alternate, candidates)) => {
                    1_u8.hash(&mut digest);
                    alternate.materialization_id().hash(&mut digest);
                    candidates.hash(&mut digest);
                }
            }
        }
    }
    // An executable alternative has no legacy macro records. Preserve the existing base
    // and macro encodings and bind its presence and rows in its own section.
    if procedures
        .clone()
        .any(|procedure| procedure.executable_alternate().is_some())
    {
        b"executable-alternate-materializations-v1".hash(&mut digest);
        procedures.len().hash(&mut digest);
        for procedure in procedures {
            procedure.id().hash(&mut digest);
            match procedure.executable_alternate() {
                None => 0_u8.hash(&mut digest),
                Some(alternate) => {
                    1_u8.hash(&mut digest);
                    alternate.materialization_id().hash(&mut digest);
                }
            }
        }
    }
    SemanticArtifactMaterializationId(digest.finish_digest())
}

/// An artifact-instance-scoped procedure identity safe for provider/oracle
/// boundaries.  Two materializations may share a durable artifact key while
/// retaining different partial rows, so equality includes `Arc` identity.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureInterpretation {
    Base,
    CandidateAlternate,
    ExecutableAlternate,
}

/// Artifact, procedure and executable body interpretation.
pub type DurableProcedureKey = (SemanticArtifactKey, ProcedureId, ProcedureInterpretation);

/// Exact frozen contents and executable interpretation of one procedure.
/// A value identity; unlike handle equality it does not retain an allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExactProcedureIdentity {
    materialization: SemanticArtifactMaterializationId,
    procedure: ProcedureId,
    interpretation: ProcedureInterpretation,
}

/// A call's dense ID is scoped to the exact selected procedure contents.
pub type ExactCallSiteKey = (ExactProcedureIdentity, CallSiteId);

/// A dense locator cannot cross executable interpretations until translated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateLocatorRefusal {
    CandidateAlternateLocatorUntranslated {
        procedure: ProcedureId,
        minted: ProcedureInterpretation,
        selected: ProcedureInterpretation,
    },
}

impl CandidateLocatorRefusal {
    pub const fn label(&self) -> &'static str {
        "candidate_alternate_locator_untranslated"
    }
}

impl std::fmt::Display for CandidateLocatorRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {:?}", self.label(), self)
    }
}

impl std::error::Error for CandidateLocatorRefusal {}

#[derive(Clone)]
pub struct ProcedureHandle {
    artifact: Arc<SemanticArtifact>,
    id: ProcedureId,
    interpretation: ProcedureInterpretation,
}

impl brokk_bifrost_core::retention_budget::RetainedBytes for ProcedureHandle {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

impl ProcedureHandle {
    pub fn exact_identity(&self) -> ExactProcedureIdentity {
        ExactProcedureIdentity {
            materialization: self.artifact.materialization_id(),
            procedure: self.id,
            interpretation: self.interpretation,
        }
    }

    pub fn artifact(&self) -> &Arc<SemanticArtifact> {
        &self.artifact
    }

    pub const fn id(&self) -> ProcedureId {
        self.id
    }

    /// The procedure's durable identity: the owning artifact's validity key and
    /// this procedure's dense ID and executable interpretation.
    ///
    /// Handle equality is materialization-scoped, so a handle minted from a
    /// second materialization of one immutable artifact is unequal to the
    /// first even when both contain the same procedure rows. This compact key
    /// is suitable for deduplication within a materialization shape already
    /// established by the caller. It is not sufficient to reconstruct a row
    /// across arbitrary same-key partial artifacts; use
    /// [`ProcedureLocalLocator`] for that boundary.
    ///
    /// This is the owned, hashable form of the comparison
    /// `value_flow::model` uses for carriers.
    pub fn durable_key(&self) -> DurableProcedureKey {
        (self.artifact.key().clone(), self.id, self.interpretation)
    }

    pub fn interpretation(&self) -> ProcedureInterpretation {
        self.interpretation
    }

    /// Recover the opaque interpretation from this handle's owning allocation.
    pub fn base_interpretation(&self) -> Self {
        let base = self
            .artifact
            .procedure_handle(self.id)
            .expect("owned procedure");
        debug_assert_eq!(base.interpretation(), ProcedureInterpretation::Base);
        base
    }

    /// Whether this handle names the guarded executable interpretation.
    pub fn is_candidate_alternate(&self) -> bool {
        self.interpretation == ProcedureInterpretation::CandidateAlternate
    }

    /// Whether this handle requires an owning query's guarded-body receipt.
    pub fn is_guarded_alternate(&self) -> bool {
        match self.interpretation {
            ProcedureInterpretation::Base => false,
            ProcedureInterpretation::CandidateAlternate
            | ProcedureInterpretation::ExecutableAlternate => true,
        }
    }

    /// Check interpretation before inspecting any procedure-local dense ID.
    pub fn validate_durable_locator(
        &self,
        key: &DurableProcedureKey,
    ) -> Result<(), CandidateLocatorRefusal> {
        debug_assert_eq!(&key.0, self.artifact.key());
        debug_assert_eq!(key.1, self.id);
        if key.2 != self.interpretation {
            return Err(
                CandidateLocatorRefusal::CandidateAlternateLocatorUntranslated {
                    procedure: self.id,
                    minted: key.2,
                    selected: self.interpretation,
                },
            );
        }
        Ok(())
    }

    pub fn resolve_durable_call(
        &self,
        key: &(DurableProcedureKey, CallSiteId),
    ) -> Result<Option<CallSiteHandle>, CandidateLocatorRefusal> {
        self.validate_durable_locator(&key.0)?;
        Ok(self.call_site_handle(key.1))
    }

    pub fn resolve_durable_value(
        &self,
        key: &(DurableProcedureKey, ValueId),
    ) -> Result<Option<ValueHandle>, CandidateLocatorRefusal> {
        self.validate_durable_locator(&key.0)?;
        Ok(self.value_handle(key.1))
    }

    pub fn resolve_durable_point(
        &self,
        key: &(DurableProcedureKey, ProgramPointId),
    ) -> Result<Option<ProgramPointHandle>, CandidateLocatorRefusal> {
        self.validate_durable_locator(&key.0)?;
        Ok(self.point_handle(key.1))
    }

    pub fn semantics(&self) -> &ProcedureSemantics {
        let base = self
            .artifact
            .procedure(self.id)
            .expect("validated procedure");
        match self.interpretation {
            ProcedureInterpretation::Base => base,
            ProcedureInterpretation::CandidateAlternate => base
                .candidate_macro_alternate()
                .map_or(base, |(alternate, _)| alternate),
            ProcedureInterpretation::ExecutableAlternate => base
                .executable_alternate()
                .expect("an executable interpretation is minted only for its present body"),
        }
    }

    // Admission belongs to the query owner, independently for each procedure.
    // File-local projections have no proof for the target, so use its opaque base.
    pub(crate) fn local_procedure_handle(&self, id: ProcedureId) -> Option<Self> {
        self.artifact.procedure_handle(id)
    }

    fn scoped<I>(&self, id: I) -> ProcedureLocalHandle<I> {
        ProcedureLocalHandle {
            procedure: self.clone(),
            id,
        }
    }

    pub fn value_handle(&self, id: ValueId) -> Option<ValueHandle> {
        self.semantics().value(id)?;
        Some(self.scoped(id))
    }

    pub fn block_handle(&self, id: BlockId) -> Option<BlockHandle> {
        self.semantics().block(id)?;
        Some(self.scoped(id))
    }

    pub fn allocation_handle(&self, id: AllocationId) -> Option<AllocationHandle> {
        self.semantics().allocation(id)?;
        Some(self.scoped(id))
    }

    pub fn point_handle(&self, id: ProgramPointId) -> Option<ProgramPointHandle> {
        self.semantics().point(id)?;
        Some(self.scoped(id))
    }

    pub fn control_edge_handle(&self, id: ControlEdgeId) -> Option<ControlEdgeHandle> {
        self.semantics().control_edge(id)?;
        Some(self.scoped(id))
    }

    pub fn call_site_handle(&self, id: CallSiteId) -> Option<CallSiteHandle> {
        self.semantics().call_site(id)?;
        Some(self.scoped(id))
    }

    pub fn memory_location_handle(&self, id: MemoryLocationId) -> Option<MemoryLocationHandle> {
        self.semantics().memory_location(id)?;
        Some(self.scoped(id))
    }

    pub fn capture_handle(&self, id: CaptureId) -> Option<CaptureHandle> {
        self.semantics().capture(id)?;
        Some(self.scoped(id))
    }

    pub fn source_mapping_handle(&self, id: SourceMappingId) -> Option<SourceMappingHandle> {
        self.semantics().source_mapping(id)?;
        Some(self.scoped(id))
    }

    pub fn source_locator(&self, id: SourceMappingId) -> Option<&SemanticLocator> {
        self.semantics().source_locator(id)
    }

    pub fn evidence_handle(&self, id: EvidenceId) -> Option<EvidenceHandle> {
        self.semantics().evidence_row(id)?;
        Some(self.scoped(id))
    }

    pub fn logical_gap_handle(&self, key: super::GapKey) -> Option<LogicalGapHandle> {
        self.semantics().logical_gap(key)?;
        Some(self.scoped(key))
    }

    pub fn gap_handle(&self, id: SemanticGapId) -> Option<SemanticGapHandle> {
        self.semantics().gap(id)?;
        Some(self.scoped(id))
    }
}

impl fmt::Debug for ProcedureHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcedureHandle")
            .field("artifact_key", self.artifact.key())
            .field("id", &self.id)
            .finish()
    }
}

impl PartialEq for ProcedureHandle {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.interpretation == other.interpretation
            && Arc::ptr_eq(&self.artifact, &other.artifact)
    }
}

impl Eq for ProcedureHandle {}

impl Hash for ProcedureHandle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        crate::analyzer::semantic::hash_arc_key(&self.artifact, &self.id, state);
        self.interpretation.hash(state);
    }
}

/// A durable procedure-local row identity that does not retain a semantic
/// artifact materialization.
///
/// The artifact validity key, exact artifact materialization identity, and
/// stable procedure locator make the dense row ID meaningful after the
/// materialization that produced it has been released. A consumer must resolve
/// the locator against the same exact frozen artifact contents before using the
/// dense ID. An independently allocated artifact with identical capabilities
/// and rows is compatible; a same-key artifact whose contents differ fails
/// closed even when its dense IDs collide.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProcedureLocalLocator<I> {
    artifact_key: SemanticArtifactKey,
    artifact_materialization_id: SemanticArtifactMaterializationId,
    procedure_locator: SemanticLocator,
    interpretation: ProcedureInterpretation,
    id: I,
}

impl<I: Copy> ProcedureLocalLocator<I> {
    pub fn artifact_key(&self) -> &SemanticArtifactKey {
        &self.artifact_key
    }

    pub fn procedure_locator(&self) -> &SemanticLocator {
        &self.procedure_locator
    }

    pub const fn artifact_materialization_id(&self) -> SemanticArtifactMaterializationId {
        self.artifact_materialization_id
    }

    pub const fn id(&self) -> I {
        self.id
    }

    pub fn validate_owner(
        &self,
        procedure: &ProcedureHandle,
    ) -> Result<(), ProcedureLocalLocatorError> {
        if &self.artifact_key != procedure.artifact().key() {
            return Err(ProcedureLocalLocatorError::ArtifactKeyMismatch);
        }
        if self.interpretation != procedure.interpretation {
            return Err(
                ProcedureLocalLocatorError::CandidateAlternateLocatorUntranslated {
                    procedure: procedure.id(),
                    minted: self.interpretation,
                    selected: procedure.interpretation,
                },
            );
        }
        if self.artifact_materialization_id != procedure.artifact().materialization_id() {
            return Err(ProcedureLocalLocatorError::ArtifactMaterializationMismatch);
        }
        if &self.procedure_locator != procedure.semantics().locator() {
            return Err(ProcedureLocalLocatorError::ProcedureLocatorMismatch);
        }
        Ok(())
    }
}

/// Why a durable procedure-local row could not be reconstructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProcedureLocalLocatorError {
    CandidateAlternateLocatorUntranslated {
        procedure: ProcedureId,
        minted: ProcedureInterpretation,
        selected: ProcedureInterpretation,
    },
    ArtifactKeyMismatch,
    ArtifactMaterializationMismatch,
    ProcedureLocatorMismatch,
    RowMissing,
}

impl fmt::Display for ProcedureLocalLocatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Self::CandidateAlternateLocatorUntranslated {
            procedure,
            minted,
            selected,
        } = self
        {
            return write!(
                formatter,
                "candidate_alternate_locator_untranslated: procedure {procedure:?}, minted {minted:?}, selected {selected:?}"
            );
        }
        formatter.write_str(match self {
            Self::CandidateAlternateLocatorUntranslated { .. } => unreachable!("handled above"),
            Self::ArtifactKeyMismatch => "semantic artifact validity key changed",
            Self::ArtifactMaterializationMismatch => {
                "semantic artifact capabilities or frozen rows changed beneath their validity key"
            }
            Self::ProcedureLocatorMismatch => "stable semantic procedure identity changed",
            Self::RowMissing => "semantic procedure no longer contains the located row",
        })
    }
}

impl std::error::Error for ProcedureLocalLocatorError {}

/// A local ID paired with its owning artifact and procedure.  Type aliases
/// below keep APIs readable without duplicating wrapper implementations.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProcedureLocalHandle<I> {
    procedure: ProcedureHandle,
    id: I,
}

impl<I: Copy> ProcedureLocalHandle<I> {
    pub fn procedure(&self) -> &ProcedureHandle {
        &self.procedure
    }

    pub const fn id(&self) -> I {
        self.id
    }

    /// The scoped row's durable identity: the owning procedure's durable key
    /// and this row's dense ID.
    ///
    /// Every dense ID in this family is procedure-local -- a `CallSiteId`
    /// indexes `ProcedureSemantics::call_sites`, a `ValueId` indexes
    /// `ProcedureSemantics::values`, and so on -- so the owning procedure's
    /// durable key is the scope that makes the pair unique.
    ///
    /// This mirrors [`ProcedureHandle::durable_key`] and shares its
    /// materialization-shape precondition. Use [`Self::durable_locator`] when a
    /// row must survive release and exact re-materialization of its artifact.
    pub fn durable_key(&self) -> (DurableProcedureKey, I) {
        (self.procedure.durable_key(), self.id)
    }

    pub fn exact_key(&self) -> (ExactProcedureIdentity, I) {
        (self.procedure.exact_identity(), self.id)
    }

    /// Convert this artifact-retaining handle into a durable locator.
    pub fn durable_locator(&self) -> ProcedureLocalLocator<I> {
        ProcedureLocalLocator {
            interpretation: self.procedure.interpretation,
            artifact_key: self.procedure.artifact().key().clone(),
            artifact_materialization_id: self.procedure.artifact().materialization_id(),
            procedure_locator: self.procedure.semantics().locator().clone(),
            id: self.id,
        }
    }
}

impl ProcedureLocalHandle<ProgramPointId> {
    /// Resolve this program point's source mapping to its semantic locator.
    pub fn locator(&self) -> Option<&SemanticLocator> {
        let semantics = self.procedure.semantics();
        let point = semantics.point(self.id)?;
        semantics.source_locator(point.source)
    }
}

impl ProcedureLocalHandle<CallSiteId> {
    /// Bind the first ordinary actual to an instance receiver only after the
    /// selected target establishes that receiver contract. Rust path calls
    /// and type-selected instance calls share this rule; method syntax already
    /// carries its bound receiver and leaves the ordinary actuals untouched.
    pub fn receiver_argument_index(&self, target_has_receiver: bool) -> Option<usize> {
        let semantics = self.procedure().semantics();
        let call = semantics.call_site(self.id())?;
        if !target_has_receiver || call.receiver.is_some() {
            return None;
        }
        match semantics.proven_caller_receiver_binding(self.id()) {
            Some(crate::analyzer::semantic::ir::CallerReceiverBinding::TypeQualified(_)) => Some(0),
            Some(crate::analyzer::semantic::ir::CallerReceiverBinding::Absent) => {
                crate::analyzer::semantic::languages::language_knowledge(
                    self.procedure().artifact().key().language().language(),
                )
                .filter(|support| support.unbound_call_passes_receiver_as_argument())
                .map(|_| 0)
            }
            _ => None,
        }
    }

    /// Receiver-argument binding for a source target with an instance receiver.
    pub fn source_receiver_argument_index(
        &self,
        callee: &crate::analyzer::semantic::ir::ProcedureSemantics,
    ) -> Option<usize> {
        self.receiver_argument_index(
            callee.properties().receiver_binding
                == crate::analyzer::semantic::ir::ProcedureReceiverBinding::Instance
                && matches!(
                    callee.kind(),
                    crate::analyzer::semantic::ir::ProcedureKind::Method
                        | crate::analyzer::semantic::ir::ProcedureKind::Constructor
                )
                && callee.values().iter().any(|value| {
                    matches!(
                        value.kind,
                        crate::analyzer::semantic::ir::SemanticValueKind::Receiver { .. }
                    )
                }),
        )
    }

    /// The caller value bound to a selected instance receiver.
    pub fn target_receiver_value(&self, target_has_receiver: bool) -> Option<ValueId> {
        if !target_has_receiver {
            return None;
        }
        let row = self.procedure().semantics().call_site(self.id())?;
        row.receiver.or_else(|| {
            self.receiver_argument_index(target_has_receiver)
                .and_then(|index| row.arguments.get(index))
                .map(|argument| argument.value)
        })
    }

    /// Translate an ordinary actual position after any explicit self actual.
    pub fn target_argument_index(
        &self,
        target_has_receiver: bool,
        ordinary: usize,
    ) -> Option<usize> {
        ordinary.checked_add(usize::from(
            self.receiver_argument_index(target_has_receiver).is_some(),
        ))
    }

    /// Resolve this call site's source mapping to its semantic locator.
    pub fn locator(&self) -> Option<&SemanticLocator> {
        let semantics = self.procedure.semantics();
        let call = semantics.call_site(self.id)?;
        semantics.source_locator(call.source)
    }
}

pub type BlockHandle = ProcedureLocalHandle<BlockId>;
pub type ProgramPointHandle = ProcedureLocalHandle<ProgramPointId>;
pub type ControlEdgeHandle = ProcedureLocalHandle<ControlEdgeId>;
pub type ControlEdgeLocator = ProcedureLocalLocator<ControlEdgeId>;
pub type ValueHandle = ProcedureLocalHandle<ValueId>;
pub type AllocationHandle = ProcedureLocalHandle<AllocationId>;
pub type CallSiteHandle = ProcedureLocalHandle<CallSiteId>;
pub type MemoryLocationHandle = ProcedureLocalHandle<MemoryLocationId>;
pub type CaptureHandle = ProcedureLocalHandle<CaptureId>;
pub type SourceMappingHandle = ProcedureLocalHandle<SourceMappingId>;
pub type EvidenceHandle = ProcedureLocalHandle<EvidenceId>;
pub type SemanticGapHandle = ProcedureLocalHandle<SemanticGapId>;
pub type LogicalGapHandle = ProcedureLocalHandle<super::GapKey>;

impl ProcedureLocalLocator<ControlEdgeId> {
    /// Resolve this durable edge identity within a matching materialized
    /// procedure. A different artifact key, exact materialization contents, or
    /// stable procedure is not a compatible owner, even if it contains the same
    /// dense edge ID.
    pub fn resolve(
        &self,
        procedure: &ProcedureHandle,
    ) -> Result<ControlEdgeHandle, ProcedureLocalLocatorError> {
        self.validate_owner(procedure)?;
        procedure
            .control_edge_handle(self.id)
            .ok_or(ProcedureLocalLocatorError::RowMissing)
    }
}

#[cfg(test)]
mod tests {

    use crate::analyzer::semantic::ir::artifact::*;

    #[test]
    fn base_only_materialization_identity_pin() {
        use crate::analyzer::semantic::*;
        let key = SemanticArtifactKey::new(
            WorkspaceMountId::hash_bytes(b"materialization-pin"),
            WorkspaceRelativePath::try_from_path(std::path::Path::new("pin.rs")).unwrap(),
            SemanticLanguage::Standard(brokk_bifrost_core::analyzer::model::Language::Rust),
            SourceRevision::Disk {
                content: ContentIdentity::hash_bytes(b"pin"),
            },
            AdapterSemanticsVersion::new("pin", StableDigest::sha256(b"pin")).unwrap(),
            SemanticIrVersion::from_digest(StableDigest::sha256(b"fixed-pin-schema")),
            ConfigurationFingerprint::hash_bytes(b"pin"),
            DependencyFingerprint::hash_bytes(b"pin"),
        );
        let artifact = SemanticArtifact::try_new(key, Default::default(), vec![]).unwrap();
        assert_eq!(
            artifact.materialization_id().to_string(),
            "5677f2e1c18b1da5bdd93a3c9413e7276eb8c1849aa594583cdc65448c931b83"
        );
    }

    #[test]
    fn cloned_procedure_dominance_starts_uninitialized() {
        let cell = CallableSelectionDominance::default();
        cell.0
            .set(None)
            .expect("fresh cell accepts the deterministic outcome");
        assert!(cell.0.get().is_some());
        assert!(cell.clone().0.get().is_none());
    }

    fn call_with_shared_result(id: u32) -> SemanticCallSite {
        SemanticCallSite {
            id: CallSiteId::new(id),
            point: ProgramPointId::new(id),
            invocation_mode: CallInvocationMode::Ordinary,
            execution_timing: ExecutionTiming::SameEvaluation,
            callee: ValueId::new(id),
            receiver: None,
            member_selection: None,
            arguments: Box::new([]),
            normal_results: Box::new([]),
            result: Some(ValueId::new(7)),
            thrown: None,
            declared_targets: CallableTargetResolution::Unknown,
            target_evidence: EvidenceId::new(0),
            normal_continuation: ControlContinuation::Target(ProgramPointId::new(11)),
            exceptional_continuation: ControlContinuation::Absent,
            source: SourceMappingId::new(0),
            evidence: EvidenceId::new(0),
        }
    }

    #[test]
    fn call_result_index_retains_every_call_at_a_shared_value_and_point() {
        let calls = [call_with_shared_result(0), call_with_shared_result(1)];

        let (_, result_sites) = index_call_phases(&calls);

        assert_eq!(
            result_sites
                .get(&(ValueId::new(7), ProgramPointId::new(11)))
                .map(Box::as_ref),
            Some([CallSiteId::new(0), CallSiteId::new(1)].as_slice())
        );
    }
}

/// Cache ownership telemetry, excluded from semantic-handle equality and hash.
/// Keep this separate so Clippy's exemption covers only this counter.
#[derive(Debug, Default)]
pub(crate) struct ArtifactCachePins(std::sync::Mutex<usize>);

impl ArtifactCachePins {
    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, usize> {
        self.0.lock().expect("artifact cache pins")
    }
}

/// A stable procedure address that does not keep its artifact resident.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemanticProcedureReference {
    pub key: SemanticArtifactKey,
    pub locator: SemanticLocator,
}

impl SemanticProcedureReference {
    pub fn of(handle: &ProcedureHandle) -> Self {
        Self {
            key: handle.artifact().key().clone(),
            locator: handle.semantics().locator().clone(),
        }
    }

    pub fn public_digest(&self) -> crate::analyzer::semantic::StableDigest {
        Self::public_digest_for(&self.key, &self.locator)
    }

    pub fn public_digest_for(
        key: &SemanticArtifactKey,
        locator: &SemanticLocator,
    ) -> crate::analyzer::semantic::StableDigest {
        let mut digest = crate::analyzer::semantic::LengthDelimitedDigest::new(
            b"bifrost-code-query-semantic-wire-id-v2",
        );
        digest.push(key.public_fingerprint().as_bytes());
        digest.push(b"procedure");
        locator.push_stable_identity(&mut digest);
        digest.finish()
    }
}

/// Merge one domain's direct facts with its lazy anchored stream. Anchor offsets
/// count only direct rows; facts from equal-offset anchors keep anchor order.
fn merge_cleanup_facts<T>(
    direct: impl Iterator<Item = T>,
    anchored: impl Iterator<Item = (u32, T)>,
) -> impl Iterator<Item = T> {
    let mut direct = direct.peekable();
    let mut anchored = anchored.peekable();
    let mut direct_index = 0usize;
    std::iter::from_fn(move || {
        if anchored
            .peek()
            .is_some_and(|(offset, _)| *offset as usize <= direct_index)
        {
            return anchored.next().map(|(_, fact)| fact);
        }
        if let Some(fact) = direct.next() {
            direct_index += 1;
            return Some(fact);
        }
        assert!(
            anchored.peek().is_none(),
            "anchor offset exceeds direct fact count"
        );
        None
    })
}

/// Shared logical drop projection for frozen artifacts and decoded parts.
pub(super) fn logical_drops<'a>(
    drops: &'a [DropFact],
    cleanup_chains: &'a super::CleanupChains,
) -> impl Iterator<Item = super::LogicalDropFact<'a>> {
    use crate::analyzer::semantic::cfg::ScopeCleanupAction;
    let direct = drops.iter().map(|fact| super::LogicalDropFact {
        place: &fact.place,
        point: fact.point,
        behavior: &fact.behavior,
        source: fact.source,
        evidence: fact.evidence,
    });
    let anchored = cleanup_chains
        .anchors()
        .iter()
        .filter(|a| a.purpose == super::CleanupAnchorPurpose::Completion)
        .flat_map(|anchor| {
            cleanup_chains
                .anchor_actions(anchor)
                .filter_map(move |entry| match &entry.action {
                    ScopeCleanupAction::Drop {
                        place,
                        behavior,
                        source,
                        evidence,
                    } => Some(super::LogicalDropFact {
                        place,
                        behavior,
                        point: anchor.point,
                        source: *source,
                        evidence: *evidence,
                    }),
                    _ => None,
                })
                .map(move |fact| (anchor.drop_offset, fact))
        });
    merge_cleanup_facts(direct, anchored)
}
