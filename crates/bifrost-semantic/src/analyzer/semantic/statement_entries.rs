//! Exact source statement entries from one immutable procedure artifact.
//!
//! A query must enumerate executable syntax from a prepared tree before asking
//! for an entry. A missing producer site for such syntax is open coverage, not
//! evidence that the statement is unreachable.

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError;

use crate::analyzer::semantic::cfg_algorithms::{CfgAlgorithmRequest, forward_reachability};

use crate::analyzer::semantic::cfg_algorithms::Reachability;

use crate::analyzer::semantic::ContentIdentity;

use crate::analyzer::semantic::EvidenceCompleteness;
use crate::analyzer::semantic::EvidenceId;

use crate::analyzer::semantic::OverlaySnapshotId;

use crate::analyzer::semantic::ProcedureHandle;

use crate::analyzer::semantic::ProcedureSemantics;

use crate::analyzer::semantic::ProgramPointId;

use crate::analyzer::semantic::ProofStatus;

use crate::analyzer::semantic::SemanticCapability;

use crate::analyzer::semantic::SemanticGapDischarge;

use crate::analyzer::semantic::SemanticGapSubject;

use crate::analyzer::semantic::SourceRevision;

use crate::analyzer::semantic::SourceSpan;

use crate::analyzer::semantic::StableDigest;

use crate::analyzer::semantic::WorkspaceMountId;

use crate::analyzer::semantic::WorkspaceRelativePath;

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSourceOrigin;

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_core::hash::HashSet;
use std::collections::VecDeque;
use std::mem::size_of;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementEntryOpen {
    SourceSnapshotMismatch,
    MissingProducerSite,
}

/// An exact span-to-entry index for one procedure and one prepared source.
///
/// Several points may enter the same statement (for example, distinct finally
/// routes), so callers must inspect every returned point. An entry point may
/// also be shared with an enclosing statement; the producer's source mapping
/// identifies which statement each row describes.
pub struct StatementEntryIndex {
    by_span: HashMap<SourceSpan, Vec<ProgramPointId>>,
}

impl StatementEntryIndex {
    pub fn new(
        procedure: &ProcedureHandle,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
    ) -> Result<Self, StatementEntryOpen> {
        let key = procedure.artifact().key();
        let path = WorkspaceRelativePath::try_from_path(file.rel_path()).map_err(|_| {
            brokk_bifrost_core::analyzer::carried_context::mark_execution_dependent();
            StatementEntryOpen::SourceSnapshotMismatch
        })?;
        let content = ContentIdentity::from_source_digest(
            StableDigest::from_array(prepared.source_sha256()),
            prepared.dialect().language(),
            prepared.parse_variant(),
        );
        let revision_matches = match (key.revision(), prepared.origin()) {
            (SourceRevision::Disk { content: expected }, PreparedSourceOrigin::Disk) => {
                content == expected
            }
            (
                SourceRevision::Overlay {
                    content: expected,
                    snapshot,
                },
                PreparedSourceOrigin::Overlay,
            ) => {
                content == expected
                    && prepared.overlay_revision().is_some_and(|overlay| {
                        OverlaySnapshotId::hash_bytes(overlay.get().to_le_bytes()) == snapshot
                    })
            }
            _ => false,
        };
        if key.mount() != WorkspaceMountId::from_root(file.root())
            || key.path() != &path
            || key.language() != prepared.dialect()
            || !revision_matches
        {
            brokk_bifrost_core::analyzer::carried_context::mark_execution_dependent();
            return Err(StatementEntryOpen::SourceSnapshotMismatch);
        }

        let semantics = procedure.semantics();
        let mut by_span = HashMap::default();
        for site in semantics.statement_entries() {
            let source = semantics
                .source_mapping(site.source)
                .expect("validated statement entry has an exact source mapping");
            by_span
                .entry(source.locator.anchor().span())
                .or_insert_with(Vec::new)
                .push(site.point);
        }
        Ok(Self { by_span })
    }

    /// Look up one independently enumerated executable statement node.
    ///
    /// The caller is responsible for proving that only one candidate syntax
    /// node of the relevant statement role owns this exact span. A missing
    /// site is explicitly open; it must not be treated as a dead statement.
    pub fn at_span(&self, span: SourceSpan) -> Result<&[ProgramPointId], StatementEntryOpen> {
        self.by_span
            .get(&span)
            .map(Vec::as_slice)
            .ok_or(StatementEntryOpen::MissingProducerSite)
    }
}

#[doc(hidden)]
pub const MAX_STATEMENT_SOURCE_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementVerdict {
    Reachable,
    Unreachable,
    Open(&'static str),
}

/// CodeQL-style first visible node of an unreachable control-flow region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionFirstVerdict {
    First,
    NotFirst,
    Open,
}

#[derive(Debug, Clone, Copy)]
pub struct StatementCoordinates {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone)]
pub struct StatementAssessment {
    pub range: Range,
    pub coordinates: StatementCoordinates,
    pub kind: &'static str,
    pub verdict: StatementVerdict,
    pub region_first: Option<RegionFirstVerdict>,
}

#[derive(Debug, Clone)]
pub struct StatementAssessments {
    pub rows: Vec<StatementAssessment>,
    pub complete: bool,
    pub reason: Option<&'static str>,
}

#[doc(hidden)]
pub fn unavailable(reason: &'static str) -> StatementAssessments {
    StatementAssessments {
        rows: Vec::new(),
        complete: false,
        reason: Some(reason),
    }
}

/// Stable labels shared with the analyzer's literal classifier inventory.
pub mod reason {
    pub const CANCELLED: &str = "cancelled";
    pub const CONTROL_BUDGET_EXHAUSTED: &str = "control_budget_exhausted";
    pub const CONTROL_EVIDENCE_INCOMPLETE: &str = "control_evidence_incomplete";
    pub const CONTROL_FRONTIER_INCOMPLETE: &str = "control_frontier_incomplete";
}

/// Points reachable from entry using only proven control edges. Candidate
/// routes still participate in value propagation, but do
/// not establish that their destination executes.
pub fn proven_control_reachable_points(semantics: &ProcedureSemantics) -> HashSet<ProgramPointId> {
    let mut reached = HashSet::default();
    let mut pending = VecDeque::from([semantics.entry_point()]);
    while let Some(point) = pending.pop_front() {
        if !reached.insert(point) {
            continue;
        }
        pending.extend(semantics.successor_edges(point).filter_map(|(_, edge)| {
            control_edge_proves_route(semantics, edge.evidence).then_some(edge.target_point)
        }));
    }
    reached
}

/// Edge completeness describes inherited point facts; only proof says whether
/// the edge establishes a route.
pub fn control_edge_proves_route(semantics: &ProcedureSemantics, evidence: EvidenceId) -> bool {
    semantics
        .evidence_row(evidence)
        .expect("validated control evidence")
        .proof
        == ProofStatus::Proven
}

/// Candidate routes indexed by the points they can reach. Construction charges
/// the caller's CFG budget once per candidate edge, never per queried anchor.
#[derive(Debug)]
pub struct CandidateControlRouteIndex {
    by_evidence: HashMap<EvidenceId, HashSet<ProgramPointId>>,
    candidate_evidence: HashSet<EvidenceId>,
}

impl CandidateControlRouteIndex {
    pub fn build_empty() -> Self {
        Self {
            by_evidence: HashMap::default(),
            candidate_evidence: HashSet::default(),
        }
    }
    pub fn build(
        semantics: &ProcedureSemantics,
        request: &mut CfgAlgorithmRequest<'_>,
    ) -> Result<Self, CfgAlgorithmError<ProgramPointId>> {
        let candidates = semantics
            .control_edges()
            .iter()
            .filter(|edge| !control_edge_proves_route(semantics, edge.evidence))
            .collect::<Vec<_>>();
        let candidate_evidence = candidates.iter().map(|edge| edge.evidence).collect();
        if candidates.is_empty() {
            return Ok(Self {
                by_evidence: HashMap::default(),
                candidate_evidence,
            });
        }
        let from_entry = forward_reachability(semantics, semantics.entry_point(), request)?;
        let mut by_evidence = HashMap::<EvidenceId, HashSet<ProgramPointId>>::default();
        for edge in candidates {
            request.visit_edge::<ProgramPointId>()?;
            if !from_entry.contains(semantics, edge.source_point) {
                continue;
            }
            let reached = forward_reachability(semantics, edge.target_point, request)?;
            let points = by_evidence.entry(edge.evidence).or_default();
            for point in semantics.points() {
                request.visit_node::<ProgramPointId>()?;
                if reached.contains(semantics, point.id) {
                    points.insert(point.id);
                }
            }
        }
        Ok(Self {
            by_evidence,
            candidate_evidence,
        })
    }

    pub fn has_candidate_edge(&self, evidence: EvidenceId) -> bool {
        self.candidate_evidence.contains(&evidence)
    }

    pub fn has_candidates(&self) -> bool {
        !self.candidate_evidence.is_empty()
    }

    pub fn contains(&self, evidence: EvidenceId, anchor: ProgramPointId) -> bool {
        self.by_evidence
            .get(&evidence)
            .is_some_and(|points| points.contains(&anchor))
    }

    pub fn any_at(&self, anchor: ProgramPointId) -> bool {
        self.by_evidence
            .values()
            .any(|points| points.contains(&anchor))
    }
}

#[doc(hidden)]
pub fn algorithm_open_reason(error: CfgAlgorithmError<ProgramPointId>) -> &'static str {
    match error {
        CfgAlgorithmError::Cancelled { .. } => reason::CANCELLED,
        CfgAlgorithmError::ExceededBudget(_) => reason::CONTROL_BUDGET_EXHAUSTED,
        CfgAlgorithmError::InvalidNode(point) => {
            panic!("validated procedure has an invalid CFG point {point:?}")
        }
    }
}

#[doc(hidden)]
pub fn scan_control_evidence(
    semantics: &ProcedureSemantics,
    reachable: &Reachability<ProgramPointId>,
    request: &mut CfgAlgorithmRequest<'_>,
) -> Result<Option<&'static str>, CfgAlgorithmError<ProgramPointId>> {
    let candidate_evidence = semantics
        .control_edges()
        .iter()
        .filter(|edge| !control_edge_proves_route(semantics, edge.evidence))
        .map(|edge| edge.evidence)
        .collect::<HashSet<_>>();
    let complete_evidence = |id| {
        let evidence = semantics
            .evidence_row(id)
            .expect("validated control row has evidence");
        evidence.proof == ProofStatus::Proven
            && evidence.completeness == EvidenceCompleteness::Complete
    };
    for gap in semantics.gaps() {
        request.visit_node::<ProgramPointId>()?;
        if candidate_evidence.contains(&gap.evidence) {
            continue;
        }
        // Reachability depends only on the retained successor topology. A
        // retained-topology gap keeps every successor, and a non-rejoining
        // exceptional exit omits only a route that enters no handler or
        // cleanup code and never resumes this procedure, so neither can make
        // a statement reachable.
        if matches!(
            gap.discharge,
            SemanticGapDischarge::RetainedControlTopology
                | SemanticGapDischarge::NonRejoiningExceptionalExit
        ) {
            continue;
        }
        if matches!(
            gap.capability,
            SemanticCapability::NormalControlFlow
                | SemanticCapability::ExceptionalControlFlow
                | SemanticCapability::CleanupControlFlow
                | SemanticCapability::NonLocalControl
                | SemanticCapability::GuardFacts
                | SemanticCapability::SwitchFacts
        ) && (gap.subject == SemanticGapSubject::Procedure
            || reachable.contains(semantics, gap.point))
        {
            return Ok(Some(reason::CONTROL_EVIDENCE_INCOMPLETE));
        }
    }
    for point in semantics.points() {
        request.visit_node::<ProgramPointId>()?;
        if !reachable.contains(semantics, point.id) {
            continue;
        }
        if !complete_evidence(point.evidence) && !candidate_evidence.contains(&point.evidence) {
            return Ok(Some(reason::CONTROL_EVIDENCE_INCOMPLETE));
        }
        if point.id != semantics.normal_exit_point()
            && point.id != semantics.exceptional_exit_point()
            && semantics.successor_edges(point.id).len() == 0
        {
            return Ok(Some(reason::CONTROL_FRONTIER_INCOMPLETE));
        }
    }
    for edge in semantics.control_edges() {
        request.visit_edge::<ProgramPointId>()?;
        if reachable.contains(semantics, edge.source_point)
            && !control_edge_proves_route(semantics, edge.evidence)
            && !candidate_evidence.contains(&edge.evidence)
        {
            return Ok(Some(reason::CONTROL_EVIDENCE_INCOMPLETE));
        }
    }
    Ok(None)
}

#[doc(hidden)]
pub fn weight_statement_assessments(
    _key: &(
        crate::analyzer::semantic::SemanticArtifactMaterializationId,
        crate::analyzer::semantic::ProcedureId,
    ),
    value: &Arc<StatementAssessments>,
) -> u32 {
    let size = size_of::<StatementAssessments>().saturating_add(
        value
            .rows
            .capacity()
            .saturating_mul(size_of::<StatementAssessment>()),
    );
    size.clamp(1, u32::MAX as usize) as u32
}
