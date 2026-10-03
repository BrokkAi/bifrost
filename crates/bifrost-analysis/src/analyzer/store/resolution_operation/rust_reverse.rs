//! Demand-driven reverse queries sharing one selected inventory and fact session.

use super::*;
use crate::analyzer::resolution::FactReverseReferenceBinding;

#[derive(Debug)]
pub(crate) struct SelectedRustTargetReferences {
    pub(crate) target: CodeUnit,
    pub(crate) search: SelectedReferenceSearchAnswer,
    pub(crate) bindings: Box<[FactReverseReferenceBinding]>,
    pub(crate) metrics: FactReverseResolutionMetrics,
}

pub(crate) enum SelectedRustReverseBatchOutcome {
    Ready(Vec<SelectedRustTargetReferences>),
    Unavailable(SelectedResolutionUnavailable),
    Cancelled,
}

/// Values returned inside this callback are provisional. Only the enclosing
/// selected operation can authorize publication after its final authority check.
pub(crate) trait SelectedRustReverseQueries {
    fn candidate_files(&mut self, _targets: &[CodeUnit]) -> Result<Option<HashSet<ProjectFile>>> {
        Err(StoreError::new(
            "candidate admission requires crate-row discovery",
        ))
    }
    fn references_to(&mut self, targets: &[CodeUnit]) -> Result<SelectedRustReverseBatchOutcome>;

    /// Resolve requested canonical occurrences in this same selected session.
    /// None stops publication; the enclosing operation retains its terminal.
    fn resolve_references(
        &mut self,
        references: &[SemanticId],
    ) -> Result<Option<Vec<FactResolutionAnswer>>>;

    #[cfg(test)]
    /// Actual persisted definition-map loads in this selected operation. This
    /// excludes transient lookups and is not a count of queried definitions.
    fn definition_mount_read_count(&self) -> usize;

    #[cfg(test)]
    fn begin_sql_work_trace(&self) {
        unreachable!("test reverse source does not own a selected SQL reader")
    }

    #[cfg(test)]
    fn finish_sql_work_trace(&self) -> (usize, usize) {
        unreachable!("test reverse source does not own a selected SQL reader")
    }
}
