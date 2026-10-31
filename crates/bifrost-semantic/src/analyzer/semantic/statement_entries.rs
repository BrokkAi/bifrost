//! Exact source statement entries from one immutable procedure artifact.
//!
//! A query must enumerate executable syntax from a prepared tree before asking
//! for an entry. A missing producer site for such syntax is open coverage, not
//! evidence that the statement is unreachable.

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmError;

use crate::analyzer::semantic::cfg_algorithms::CfgAlgorithmRequest;

use crate::analyzer::semantic::cfg_algorithms::Reachability;

use crate::analyzer::semantic::ContentIdentity;

use crate::analyzer::semantic::EvidenceCompleteness;

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
        let content =
            ContentIdentity::from_digest(StableDigest::from_array(prepared.source_sha256()));
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
    let complete_evidence = |id| {
        let evidence = semantics
            .evidence_row(id)
            .expect("validated control row has evidence");
        evidence.proof == ProofStatus::Proven
            && evidence.completeness == EvidenceCompleteness::Complete
    };
    for gap in semantics.gaps() {
        request.visit_node::<ProgramPointId>()?;
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
        if !complete_evidence(point.evidence) {
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
        if reachable.contains(semantics, edge.source_point) && !complete_evidence(edge.evidence) {
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
