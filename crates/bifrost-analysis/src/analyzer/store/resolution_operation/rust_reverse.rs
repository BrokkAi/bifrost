//! Demand-driven reverse queries sharing one selected inventory and fact session.

use super::rust_reverse_rows::RustReverseCandidateSet;
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

#[cfg(test)]
fn test_reverse_source_does_not_own_sql_reader() -> ! {
    unreachable!("test reverse source does not own a selected SQL reader")
}

/// One requested reference retains all of its selected root answers.
pub(crate) enum ReferenceResolution {
    Answered(Vec<FactResolutionAnswer>),
    Omitted(ReferenceOmission),
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ReferenceOmission {
    ReceiverBudget(brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit),
    TimeBudgetExceeded,
}

/// Values returned inside this callback are provisional. Only the enclosing
/// selected operation can authorize publication after its final authority check.
pub(crate) trait SelectedRustReverseQueries {
    /// The project's analysis generation, as this operation captured it when
    /// it opened. `finish` checks it again before authorizing publication.
    fn analysis_generation(&self) -> u64;

    /// Enumerate each target's reverse candidates, one set per target in
    /// order. None stops the query; a target without a selected definition
    /// becomes this operation's unavailable outcome.
    fn candidate_sets(
        &mut self,
        targets: &[CodeUnit],
    ) -> Result<Option<Vec<RustReverseCandidateSet>>>;

    /// Query one batch of targets with the sets `candidate_sets` returned for
    /// them. A set is consumed here without being enumerated again, and may
    /// come from an earlier selected operation.
    fn references_to(
        &mut self,
        targets: &[CodeUnit],
        candidates: &[RustReverseCandidateSet],
    ) -> Result<SelectedRustReverseBatchOutcome>;

    fn rust_cfg_activation_for_caller_under_site_cfg(
        &mut self,
        caller: &std::path::Path,
        condition: &brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition,
        cancellation: &CancellationToken,
    ) -> Result<
        Option<(
            brokk_bifrost_rust::selected_context::RustSelectedActivation,
            bool,
        )>,
    >;

    /// Resolve canonical occurrences in request order, one slot per reference.
    /// None stops publication; the enclosing operation retains its terminal.
    fn resolve_references(
        &mut self,
        references: &[SemanticId],
    ) -> Result<Option<Vec<ReferenceResolution>>>;

    #[cfg(test)]
    /// Actual persisted definition-map loads in this selected operation. This
    /// excludes transient lookups and is not a count of queried definitions.
    fn definition_mount_read_count(&self) -> usize;

    #[cfg(test)]
    fn begin_sql_work_trace(&self) {
        test_reverse_source_does_not_own_sql_reader()
    }

    #[cfg(test)]
    fn finish_sql_work_trace(&self) -> (usize, usize) {
        test_reverse_source_does_not_own_sql_reader()
    }
}
