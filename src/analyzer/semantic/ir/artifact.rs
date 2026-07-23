use std::fmt;
use std::hash::{Hash, Hasher};
use std::mem::size_of;
use std::sync::Arc;

use crate::compact_graph::CompactRows;
use crate::hash::{HashMap, HashSet};

use super::super::capabilities::SemanticCapabilities;
use super::super::ids::{
    AllocationId, BlockId, CallSiteId, CaptureId, ControlEdgeId, EvidenceId, MemoryLocationId,
    ProcedureId, ProgramPointId, SemanticArtifactKey, SemanticGapId, SemanticLocator,
    SourceMappingId, ValueId,
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
/// One validated executable body.
#[derive(Debug, Clone)]
pub struct ProcedureSemantics {
    id: ProcedureId,
    locator: SemanticLocator,
    lexical_parent: Option<ProcedureId>,
    kind: ProcedureKind,
    properties: ProcedureProperties,
    source: SourceMappingId,
    evidence: EvidenceId,
    values: Box<[SemanticValue]>,
    allocations: Box<[AllocationSite]>,
    memory_locations: Box<[MemoryLocation]>,
    captures: Box<[CaptureBinding]>,
    call_sites: Box<[SemanticCallSite]>,
    call_phase_points: HashMap<ValueId, Box<[ProgramPointId]>>,
    call_result_sites: HashMap<(ValueId, ProgramPointId), Box<[CallSiteId]>>,
    source_mappings: Box<[SourceMapping]>,
    evidence_rows: Box<[Evidence]>,
    gaps: Box<[SemanticGap]>,
    blocks: Box<[BasicBlock]>,
    points: Box<[ProgramPoint]>,
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
        let (call_phase_points, call_result_sites) = index_call_phases(&parts.call_sites);
        Ok(Self {
            id: parts.id,
            locator: parts.locator,
            lexical_parent: parts.lexical_parent,
            kind: parts.kind,
            properties: parts.properties,
            source: parts.source,
            evidence: parts.evidence,
            values: parts.values.into_boxed_slice(),
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
            cfg,
            entry_point,
            normal_exit_point,
            exceptional_exit_point,
        })
    }

    pub const fn id(&self) -> ProcedureId {
        self.id
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

    pub fn predecessor_edges(
        &self,
        point: ProgramPointId,
    ) -> impl ExactSizeIterator<Item = (ControlEdgeId, &ControlEdge)> + '_ {
        self.cfg.predecessor_edges(point)
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

fn index_call_phases(
    call_sites: &[SemanticCallSite],
) -> (
    HashMap<ValueId, Box<[ProgramPointId]>>,
    HashMap<(ValueId, ProgramPointId), Box<[CallSiteId]>>,
) {
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
        if let (Some(result), Some(point)) = (call.result, call.normal_continuation.target()) {
            push(result, point);
            result_sites
                .entry((result, point))
                .or_default()
                .push(call.id);
        }
        if let (Some(thrown), Some(point)) = (call.thrown, call.exceptional_continuation.target()) {
            push(thrown, point);
        }
    }
    let phase_points = indexed
        .into_iter()
        .map(|(value, points)| (value, points.into_boxed_slice()))
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

        let artifact = Self {
            key,
            capabilities,
            work,
            procedures: procedures.into_boxed_slice(),
            procedures_by_locator,
        };
        *budget = charged_budget;
        Ok(artifact)
    }

    pub fn key(&self) -> &SemanticArtifactKey {
        &self.key
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
}

pub type BlockHandle = ProcedureLocalHandle<BlockId>;
pub type ProgramPointHandle = ProcedureLocalHandle<ProgramPointId>;
pub type ControlEdgeHandle = ProcedureLocalHandle<ControlEdgeId>;
pub type ValueHandle = ProcedureLocalHandle<ValueId>;
pub type AllocationHandle = ProcedureLocalHandle<AllocationId>;
pub type CallSiteHandle = ProcedureLocalHandle<CallSiteId>;
pub type MemoryLocationHandle = ProcedureLocalHandle<MemoryLocationId>;
pub type CaptureHandle = ProcedureLocalHandle<CaptureId>;
pub type SourceMappingHandle = ProcedureLocalHandle<SourceMappingId>;
pub type EvidenceHandle = ProcedureLocalHandle<EvidenceId>;
pub type SemanticGapHandle = ProcedureLocalHandle<SemanticGapId>;

#[cfg(test)]
mod tests {
    use super::*;

    fn call_with_shared_result(id: u32) -> SemanticCallSite {
        SemanticCallSite {
            id: CallSiteId::new(id),
            point: ProgramPointId::new(id),
            callee: ValueId::new(id),
            receiver: None,
            arguments: Box::new([]),
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
