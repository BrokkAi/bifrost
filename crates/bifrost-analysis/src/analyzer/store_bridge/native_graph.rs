//! Shared request-local graph construction over language-owned staging.
use crate::CancellationToken;
use crate::analyzer::store::resolution_operation::graph_stage::GraphStageResult;
use crate::analyzer::store::{Result, resolution_operation::*};
use crate::analyzer::usages::workspace_graph::{
    UsageEcosystem,
    canonical_workspace_graph::{
        NativeWorkspaceGraphBuilder, SelectedWorkspaceUsageGraphProjectionOutcome as Outcome,
    },
};
use crate::analyzer::{IAnalyzer, ProjectFile};
use crate::hash::HashSet;

/// Languages own selection and staging rules; this runner owns the common
/// caller catalog, stage outcome and canonical projection lifecycle.
#[allow(clippy::too_many_arguments)]
pub fn project_native_workspace_graph(
    analyzer: &dyn IAnalyzer,
    operation: &mut SelectedResolutionOperation<'_, '_>,
    callers: &HashSet<ProjectFile>,
    ecosystem: UsageEcosystem,
    cancellation: &CancellationToken,
    stage: impl FnOnce(
        &SelectedResolutionOperation<'_, '_>,
        &mut NativeWorkspaceGraphBuilder,
    ) -> Result<SelectedResolutionOperationOutcome<GraphStageResult>>,
) -> Result<Outcome> {
    let Some(mut builder) = NativeWorkspaceGraphBuilder::new(analyzer, callers, cancellation)
    else {
        return Ok(Outcome::Cancelled);
    };
    let staged = match stage(operation, &mut builder)? {
        SelectedResolutionOperationOutcome::Native(staged) => staged,
        SelectedResolutionOperationOutcome::Cancelled(_) => return Ok(Outcome::Cancelled),
        SelectedResolutionOperationOutcome::Stale(_) => return Ok(Outcome::Stale),
        SelectedResolutionOperationOutcome::Unavailable(reason) => {
            return Ok(Outcome::Unavailable(format!("{reason:?}")));
        }
    };
    builder.finish(
        operation,
        staged.summary,
        staged.skipped,
        callers.clone(),
        ecosystem,
        cancellation,
    )
}

/// Common ordered graph worker payload; runtime aliases translate on replay.
pub(crate) struct NativeGraphBatch {
    pub source: crate::analyzer::resolution::FactReferenceBatchAnswer,
    pub edges: crate::analyzer::resolution::FactReferenceEdgeBatch,
}
impl crate::analyzer::resolution::worker_transport::WorkerAnswer for NativeGraphBatch {
    fn translate(
        self,
        translation: &impl crate::analyzer::resolution::local_identity::ResolutionIdentityTranslation,
    ) -> Self {
        Self {
            source: self.source.translate(translation),
            edges: self.edges.translate(translation),
        }
    }
}
