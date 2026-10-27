//! Analyzer request state for selected graph workers, above the store layer.

use std::sync::Arc;
use std::thread::ThreadId;

use crate::CancellationToken;
use crate::analyzer::i_analyzer::{capture_query_reads, replay_query_reads};
use crate::analyzer::resolution::FactResolutionBatchSummary;
use crate::analyzer::resolution::local_identity::ResolutionIdentityTranslation;
use crate::analyzer::resolution::worker_transport::WorkerAnswer;
use crate::analyzer::semantic_model::{ActiveSemanticModelSnapshot, SemanticModelOverlay};
use crate::analyzer::store::Result;
use crate::analyzer::store::resolution_operation::graph_stage::*;
use crate::analyzer::store::resolution_operation::{
    SelectedResolutionContextMetrics, SelectedResolutionOperation,
    SelectedResolutionOperationOutcome,
};
use crate::analyzer::{AnalyzerQueryScope, IAnalyzer, ProjectFile, ReadLedger};

/// The model publications are captured on the owner, never re-read live by a
/// worker. Cancellation and read capture open ordinary analyzer scopes, so the
/// existing query memos and read-failure/tier recorders remain active too.
struct WorkerAnalyzerState {
    owner: ThreadId,
    snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    overlay: Option<Arc<SemanticModelOverlay>>,
}

struct AnalyzerGraphAdapter<'a, A> {
    analyzer: &'a dyn IAnalyzer,
    adapter: &'a A,
    worker_state: Option<WorkerAnalyzerState>,
}

struct AnalyzerGraphPayload<P> {
    payload: P,
    reads: Option<Arc<ReadLedger>>,
}

impl<P: WorkerAnswer> WorkerAnswer for AnalyzerGraphPayload<P> {
    fn translate(self, translation: &impl ResolutionIdentityTranslation) -> Self {
        Self {
            payload: self.payload.translate(translation),
            // Read keys name stable analyzer inputs, not resolution aliases.
            reads: self.reads,
        }
    }
}

impl<A: GraphStageAdapter> GraphStageAdapter for AnalyzerGraphAdapter<'_, A> {
    const FILE_CHUNKS_REPRODUCE_UNIT: bool = A::FILE_CHUNKS_REPRODUCE_UNIT;

    type Unit = A::Unit;
    type Payload = AnalyzerGraphPayload<A::Payload>;
    type HelperTables<'stage> = A::HelperTables<'stage>;

    fn units(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        files: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<GraphStageAdmission<Self::Unit>>> {
        self.adapter.units(operation, files, cancellation)
    }

    fn helper_tables<'stage>(
        &self,
        operation: &'stage SelectedResolutionOperation<'_, '_>,
        unit: &Self::Unit,
    ) -> Result<Self::HelperTables<'stage>> {
        self.adapter.helper_tables(operation, unit)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_unit<'operation, 'store, 'input>(
        &self,
        operation: &'operation SelectedResolutionOperation<'store, 'input>,
        unit: &Self::Unit,
        files: &[ProjectFile],
        guard: &mut GraphStageGuard<'operation, 'store, Self::HelperTables<'operation>>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        metrics: &mut GraphStageMetrics,
    ) -> Result<SelectedResolutionOperationOutcome<(Self::Payload, FactResolutionBatchSummary)>>
    {
        let mut work = || {
            self.adapter.run_unit(
                operation,
                unit,
                files,
                guard,
                maximum_batch_size,
                cancellation,
                context_metrics,
                metrics,
            )
        };
        let (outcome, reads) = if let Some(state) = &self.worker_state
            && state.owner != std::thread::current().id()
        {
            let _cancellation = AnalyzerQueryScope::with_cancellation(self.analyzer, cancellation);
            let _snapshot = AnalyzerQueryScope::with_active_semantic_model_snapshot(
                self.analyzer,
                state.snapshot.clone(),
            );
            // An explicit overlay can be newer than the snapshot override;
            // install the owner's effective overlay last to retain precedence.
            let _overlay = AnalyzerQueryScope::with_semantic_model_overlay(
                self.analyzer,
                state.overlay.clone(),
            );
            let (outcome, reads) = capture_query_reads(self.analyzer, work);
            (outcome?, Some(reads))
        } else {
            // W=1 and single-connection runs retain the owner's exact scopes.
            (work()?, None)
        };
        Ok(match outcome {
            SelectedResolutionOperationOutcome::Native((payload, summary)) => {
                SelectedResolutionOperationOutcome::Native((
                    AnalyzerGraphPayload { payload, reads },
                    summary,
                ))
            }
            SelectedResolutionOperationOutcome::Cancelled(reason) => {
                SelectedResolutionOperationOutcome::Cancelled(reason)
            }
            SelectedResolutionOperationOutcome::Stale(reason) => {
                SelectedResolutionOperationOutcome::Stale(reason)
            }
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                SelectedResolutionOperationOutcome::Unavailable(reason)
            }
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_analyzer_graph_stages<A: GraphStageAdapter>(
    operation: &SelectedResolutionOperation<'_, '_>,
    analyzer: &dyn IAnalyzer,
    adapter: &A,
    files: &[ProjectFile],
    maximum_batch_size: usize,
    worker_count: usize,
    cancellation: &CancellationToken,
    context_metrics: &mut SelectedResolutionContextMetrics,
    mut replay: impl FnMut(A::Payload) -> Result<bool>,
) -> Result<SelectedResolutionOperationOutcome<GraphStageResult>> {
    let worker_state = (worker_count > 1
        && !operation.worker_store().uses_single_connection_reads())
    .then(|| WorkerAnalyzerState {
        owner: std::thread::current().id(),
        snapshot: analyzer.active_semantic_model_snapshot(),
        overlay: analyzer.semantic_model_overlay(),
    });
    run_graph_stages(
        operation,
        &AnalyzerGraphAdapter {
            analyzer,
            adapter,
            worker_state,
        },
        files,
        maximum_batch_size,
        worker_count,
        cancellation,
        context_metrics,
        |payload| {
            if let Some(reads) = payload.reads {
                replay_query_reads(analyzer, &reads);
            }
            replay(payload.payload)
        },
    )
}
