use std::fmt;
use std::hash::{Hash, Hasher};
use std::mem::size_of;
use std::sync::Arc;

use crate::compact_graph::CompactRows;
use crate::hash::{HashMap, HashSet};

use super::super::capabilities::SemanticCapabilities;
use super::super::ids::{
    AllocationId, BlockId, CallSiteId, CaptureId, ControlEdgeId, EvidenceId, GuardId,
    LengthDelimitedDigest, MemoryLocationId, ProcedureId, ProgramPointId, SemanticArtifactKey,
    SemanticGapId, SemanticLocator, SourceMappingId, StableDigest, SwitchFactId, ValueId,
};
use super::super::provider::{SemanticBudget, SemanticBudgetExceeded, SemanticWork};
use super::model::*;
use super::validation::{find_boundaries, measure_artifact_work, validate_artifact};

/// Failure to validate or fit a semantic artifact into its retained-work
/// budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticArtifactBuildError {
    Invalid(SemanticIrError),
    ExceededBudget(SemanticBudgetExceeded),
}

impl SemanticArtifactBuildError {
    pub const fn invalid_ir(&self) -> Option<&SemanticIrError> {
        match self {
            Self::Invalid(error) => Some(error),
            Self::ExceededBudget(_) => None,
        }
    }

    pub const fn budget_exceeded(&self) -> Option<SemanticBudgetExceeded> {
        match self {
            Self::Invalid(_) => None,
            Self::ExceededBudget(error) => Some(*error),
        }
    }
}

impl From<SemanticIrError> for SemanticArtifactBuildError {
    fn from(error: SemanticIrError) -> Self {
        Self::Invalid(error)
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
            Self::Invalid(error) => error.fmt(formatter),
            Self::ExceededBudget(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SemanticArtifactBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
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

    pub(super) fn try_from_parts(
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

impl fmt::Display for SemanticArtifactMaterializationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

struct MaterializationFingerprintHasher(LengthDelimitedDigest);

impl MaterializationFingerprintHasher {
    fn new(domain: &[u8]) -> Self {
        Self(LengthDelimitedDigest::new(domain))
    }

    fn finish_digest(self) -> StableDigest {
        self.0.finish()
    }
}

impl Hasher for MaterializationFingerprintHasher {
    fn finish(&self) -> u64 {
        let digest = self.0.clone().finish();
        let mut head = [0_u8; 8];
        head.copy_from_slice(&digest.as_bytes()[..8]);
        u64::from_le_bytes(head)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.push(bytes);
    }

    fn write_u8(&mut self, value: u8) {
        self.0.push(&value.to_le_bytes());
    }

    fn write_u16(&mut self, value: u16) {
        self.0.push(&value.to_le_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.0.push(&value.to_le_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.0.push(&value.to_le_bytes());
    }

    fn write_u128(&mut self, value: u128) {
        self.0.push(&value.to_le_bytes());
    }

    fn write_usize(&mut self, value: usize) {
        self.write_u64(u64::try_from(value).expect("usize fits u64 on supported targets"));
    }

    fn write_i8(&mut self, value: i8) {
        self.0.push(&value.to_le_bytes());
    }

    fn write_i16(&mut self, value: i16) {
        self.0.push(&value.to_le_bytes());
    }

    fn write_i32(&mut self, value: i32) {
        self.0.push(&value.to_le_bytes());
    }

    fn write_i64(&mut self, value: i64) {
        self.0.push(&value.to_le_bytes());
    }

    fn write_i128(&mut self, value: i128) {
        self.0.push(&value.to_le_bytes());
    }

    fn write_isize(&mut self, value: isize) {
        self.write_i64(i64::try_from(value).expect("isize fits i64 on supported targets"));
    }
}

/// One validated executable body.
#[derive(Debug, Clone)]
pub struct ProcedureSemantics {
    id: ProcedureId,
    materialization_id: ProcedureMaterializationId,
    locator: SemanticLocator,
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
    fn try_from_parts(
        parts: ProcedureSemanticsParts,
        entry_point: ProgramPointId,
        normal_exit_point: ProgramPointId,
        exceptional_exit_point: ProgramPointId,
    ) -> Result<Self, SemanticIrError> {
        let cfg =
            ControlFlowGraph::try_from_edges(parts.id, parts.points.len(), parts.control_edges)?;
        let guard_facts = freeze_guard_facts(&cfg, &parts.guard_facts);
        let switch_facts = freeze_switch_facts(&cfg, &parts.switch_facts);
        let (call_phase_points, call_result_sites) = index_call_phases(&parts.call_sites);
        let value_identity_ordinals =
            duplicate_value_ordinals(&parts.values, &parts.source_mappings);
        let mut semantics = Self {
            id: parts.id,
            materialization_id: ProcedureMaterializationId(StableDigest::from_array([0; 32])),
            locator: parts.locator,
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

    const fn materialization_id(&self) -> ProcedureMaterializationId {
        self.materialization_id
    }

    pub fn locator(&self) -> &SemanticLocator {
        &self.locator
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
    pub(crate) fn value_identity_index_retained_bytes(&self) -> u64 {
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

    pub(crate) fn call_result_site_ids(
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
    pub(crate) fn call_indexes_retained_bytes(&self) -> u64 {
        boxed_slice_index_retained_bytes(&self.call_phase_points)
            .saturating_add(boxed_slice_index_retained_bytes(&self.call_result_sites))
    }

    pub fn source_mappings(&self) -> &[SourceMapping] {
        &self.source_mappings
    }

    pub fn evidence_rows(&self) -> &[Evidence] {
        &self.evidence_rows
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

    pub fn capture(&self, id: CaptureId) -> Option<&CaptureBinding> {
        self.captures.get(id.index())
    }

    pub fn call_site(&self, id: CallSiteId) -> Option<&SemanticCallSite> {
        self.call_sites.get(id.index())
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

        let point = self.point(call.point)?;
        let mut references = point.events.iter().filter_map(|event| {
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
                if receiver == bound_receiver =>
            {
                Some(CallerReceiverBinding::Bound(receiver))
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
    use super::*;

    fn value(id: u32, source: u32, kind: SemanticValueKind) -> SemanticValue {
        SemanticValue {
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

/// One immutable interpretation of one mounted source snapshot.
#[derive(Debug)]
pub struct SemanticArtifact {
    key: SemanticArtifactKey,
    materialization_id: SemanticArtifactMaterializationId,
    capabilities: SemanticCapabilities,
    work: SemanticWork,
    procedures: Box<[ProcedureSemantics]>,
    procedures_by_locator: HashMap<SemanticLocator, ProcedureId>,
}

impl SemanticArtifact {
    /// Validate all artifact, procedure, side-table, event, and topology
    /// invariants before exposing immutable semantics.
    pub fn try_new(
        key: SemanticArtifactKey,
        capabilities: SemanticCapabilities,
        procedure_parts: Vec<ProcedureSemanticsParts>,
    ) -> Result<Self, SemanticIrError> {
        let mut budget = SemanticBudget::default();
        Self::try_new_with_budget(key, capabilities, procedure_parts, &mut budget).map_err(
            |error| match error {
                SemanticArtifactBuildError::Invalid(error) => error,
                SemanticArtifactBuildError::ExceededBudget(error) => {
                    SemanticIrError::artifact(SemanticIrErrorKind::ResourceLimit, error.to_string())
                }
            },
        )
    }

    /// Validate and publish an artifact while atomically charging every
    /// retained row, event, edge, nested entry, and owned string byte.
    /// Failed validation or charging leaves `budget` unchanged.
    pub fn try_new_with_budget(
        key: SemanticArtifactKey,
        capabilities: SemanticCapabilities,
        procedure_parts: Vec<ProcedureSemanticsParts>,
        budget: &mut SemanticBudget,
    ) -> Result<Self, SemanticArtifactBuildError> {
        let work = measure_artifact_work(&key, &procedure_parts);
        let mut charged_budget = budget.clone();
        charged_budget.charge(work)?;
        validate_artifact(&key, &capabilities, &procedure_parts)?;

        let mut procedures_by_locator = HashMap::default();
        let mut procedures = Vec::with_capacity(procedure_parts.len());
        for parts in procedure_parts {
            let boundaries = find_boundaries(&parts)?;
            procedures_by_locator.insert(parts.locator.clone(), parts.id);
            procedures.push(ProcedureSemantics::try_from_parts(
                parts,
                boundaries.entry,
                boundaries.normal_exit,
                boundaries.exceptional_exit,
            )?);
        }

        let procedures = procedures.into_boxed_slice();
        let materialization_id =
            compute_artifact_materialization_id(&key, &capabilities, &procedures);
        let artifact = Self {
            key,
            materialization_id,
            capabilities,
            work,
            procedures,
            procedures_by_locator,
        };
        *budget = charged_budget;
        Ok(artifact)
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

    pub const fn work(&self) -> SemanticWork {
        self.work
    }

    pub fn procedures(&self) -> &[ProcedureSemantics] {
        &self.procedures
    }

    pub fn procedure(&self, id: ProcedureId) -> Option<&ProcedureSemantics> {
        self.procedures.get(id.index())
    }

    pub fn procedure_id(&self, locator: &SemanticLocator) -> Option<ProcedureId> {
        self.procedures_by_locator.get(locator).copied()
    }

    pub fn procedure_by_locator(&self, locator: &SemanticLocator) -> Option<&ProcedureSemantics> {
        self.procedure(self.procedure_id(locator)?)
    }

    pub fn procedure_handle(self: &Arc<Self>, id: ProcedureId) -> Option<ProcedureHandle> {
        self.procedure(id)?;
        Some(ProcedureHandle {
            artifact: Arc::clone(self),
            id,
        })
    }
}

fn compute_artifact_materialization_id(
    key: &SemanticArtifactKey,
    capabilities: &SemanticCapabilities,
    procedures: &[ProcedureSemantics],
) -> SemanticArtifactMaterializationId {
    let mut digest = MaterializationFingerprintHasher::new(ARTIFACT_MATERIALIZATION_ID_DOMAIN);
    key.fingerprint().hash(&mut digest);
    capabilities.iter().for_each(|(capability, support)| {
        capability.hash(&mut digest);
        support.hash(&mut digest);
    });
    procedures.len().hash(&mut digest);
    for procedure in procedures {
        procedure.id().hash(&mut digest);
        procedure.materialization_id().hash(&mut digest);
    }
    SemanticArtifactMaterializationId(digest.finish_digest())
}

/// An artifact-instance-scoped procedure identity safe for provider/oracle
/// boundaries.  Two materializations may share a durable artifact key while
/// retaining different partial rows, so equality includes `Arc` identity.
#[derive(Clone)]
pub struct ProcedureHandle {
    artifact: Arc<SemanticArtifact>,
    id: ProcedureId,
}

impl ProcedureHandle {
    pub fn artifact(&self) -> &Arc<SemanticArtifact> {
        &self.artifact
    }

    pub const fn id(&self) -> ProcedureId {
        self.id
    }

    /// The procedure's durable identity: the owning artifact's validity key and
    /// this procedure's dense ID.
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
    pub fn durable_key(&self) -> (SemanticArtifactKey, ProcedureId) {
        (self.artifact.key().clone(), self.id)
    }

    pub fn semantics(&self) -> &ProcedureSemantics {
        // Construction is private and checked by SemanticArtifact::procedure_handle.
        &self.artifact.procedures[self.id.index()]
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

    pub fn evidence_handle(&self, id: EvidenceId) -> Option<EvidenceHandle> {
        self.semantics().evidence_row(id)?;
        Some(self.scoped(id))
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
        self.id == other.id && Arc::ptr_eq(&self.artifact, &other.artifact)
    }
}

impl Eq for ProcedureHandle {}

impl Hash for ProcedureHandle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::ptr::hash(Arc::as_ptr(&self.artifact), state);
        self.id.hash(state);
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
    ArtifactKeyMismatch,
    ArtifactMaterializationMismatch,
    ProcedureLocatorMismatch,
    RowMissing,
}

impl fmt::Display for ProcedureLocalLocatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
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
    pub fn durable_key(&self) -> ((SemanticArtifactKey, ProcedureId), I) {
        (self.procedure.durable_key(), self.id)
    }

    /// Convert this artifact-retaining handle into a durable locator.
    pub fn durable_locator(&self) -> ProcedureLocalLocator<I> {
        ProcedureLocalLocator {
            artifact_key: self.procedure.artifact().key().clone(),
            artifact_materialization_id: self.procedure.artifact().materialization_id(),
            procedure_locator: self.procedure.semantics().locator().clone(),
            id: self.id,
        }
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
    use super::*;

    fn call_with_shared_result(id: u32) -> SemanticCallSite {
        SemanticCallSite {
            id: CallSiteId::new(id),
            point: ProgramPointId::new(id),
            invocation_mode: CallInvocationMode::Ordinary,
            execution_timing: ExecutionTiming::SameEvaluation,
            callee: ValueId::new(id),
            receiver: None,
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

    #[test]
    fn call_phase_index_sorts_shared_value_points_for_bounded_membership() {
        let mut later = call_with_shared_result(12);
        later.callee = ValueId::new(9);
        let mut earlier = call_with_shared_result(3);
        earlier.callee = ValueId::new(9);

        let (phase_points, _) = index_call_phases(&[later, earlier]);

        assert_eq!(
            phase_points.get(&ValueId::new(9)).map(Box::as_ref),
            Some([ProgramPointId::new(3), ProgramPointId::new(12)].as_slice())
        );
    }
}
