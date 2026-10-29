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
use crate::analyzer::{AnalyzerQueryScope, IAnalyzer, ProjectFile, ReadAttribution, ReadLedger};

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
    // Install before scheduling captures the request context. Owner replay can
    // overlap live worker captures and must never broadcast into their ledgers.
    let _attribution = ReadAttribution::for_request().install();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::read_ledger::ReadKey;
    use crate::analyzer::semantic::ids::StableDigest;
    use crate::analyzer::store::resolution_operation::{
        SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
    };
    use crate::analyzer::store::{AnalyzerStore, WorkspaceId, WorkspaceSnapshots};
    use crate::analyzer::{Language, MultiAnalyzer, TestProject};
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::mpsc;

    struct ReplayAdapter<'a> {
        analyzer: &'a dyn IAnalyzer,
        reads: &'a ReadLedger,
    }

    struct Helpers;
    impl GraphStageHelperTables for Helpers {}

    impl GraphStageAdapter for ReplayAdapter<'_> {
        const FILE_CHUNKS_REPRODUCE_UNIT: bool = false;
        type Unit = ();
        type Payload = GraphStageBatches<FactResolutionBatchSummary>;
        type HelperTables<'stage> = Helpers;

        fn units(
            &self,
            _: &SelectedResolutionOperation<'_, '_>,
            _: &[ProjectFile],
            _: &CancellationToken,
        ) -> Result<SelectedResolutionOperationOutcome<GraphStageAdmission<()>>> {
            // Exercise the owner recorder inside the real shared request boundary.
            // Keeping admission empty avoids relying on worker scheduling timing.
            replay_query_reads(self.analyzer, self.reads);
            Ok(SelectedResolutionOperationOutcome::Native(
                GraphStageAdmission {
                    units: Vec::new(),
                    skipped: Default::default(),
                },
            ))
        }

        fn helper_tables(
            &self,
            _: &SelectedResolutionOperation<'_, '_>,
            _: &(),
        ) -> Result<Helpers> {
            unreachable!("empty admission has no units")
        }

        fn run_unit<'operation, 'store, 'input>(
            &self,
            _: &'operation SelectedResolutionOperation<'store, 'input>,
            _: &(),
            _: &[ProjectFile],
            _: &mut GraphStageGuard<'operation, 'store, Helpers>,
            _: usize,
            _: &CancellationToken,
            _: &mut SelectedResolutionContextMetrics,
            _: &mut GraphStageMetrics,
        ) -> Result<SelectedResolutionOperationOutcome<(Self::Payload, FactResolutionBatchSummary)>>
        {
            unreachable!("empty admission has no units")
        }
    }

    #[test]
    #[hardwon(
        "#7116: owner replay recorded reads without an attribution frame while workers were live"
    )]
    fn graph_owner_replay_preserves_request_attribution_with_live_worker_capture() {
        let analyzer = MultiAnalyzer::default();
        let key = ReadKey::Configuration(StableDigest::sha256(b"graph-owner-replay"));
        let reads = ReadLedger::new();
        reads.record(key.clone());
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        for with_parent in [false, true] {
            let parent = Arc::new(ReadLedger::new());
            let (ready_tx, ready_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel::<()>();
            std::thread::scope(|threads| {
                let analyzer = &analyzer;
                let worker = threads.spawn(move || {
                    capture_query_reads(analyzer, || {
                        ready_tx.send(()).unwrap();
                        // Disconnection also releases the worker if owner replay panics.
                        done_rx
                            .recv()
                            .expect_err("owner releases capture by disconnecting");
                    })
                    .1
                });
                ready_rx.recv().unwrap();
                pool.install(|| {
                    let _parent = with_parent.then(|| {
                        AnalyzerQueryScope::with_read_ledger(analyzer, Arc::clone(&parent))
                    });
                    let root = tempfile::tempdir().unwrap();
                    let project = TestProject::new(root.path(), Language::Rust);
                    let store = AnalyzerStore::open_ephemeral().unwrap();
                    let workspace = WorkspaceId("graph-owner-attribution".into());
                    let snapshots = WorkspaceSnapshots::default();
                    let cancellation = CancellationToken::default();
                    let input = SelectedResolutionOperationInput::new(
                        &project,
                        &workspace,
                        &snapshots,
                        &[],
                        &[],
                    );
                    let SelectedResolutionOperationOpenOutcome::Ready(operation) = store
                        .open_selected_resolution_operation(input, &cancellation)
                        .unwrap()
                    else {
                        panic!("empty selected operation must be ready");
                    };
                    let result = run_analyzer_graph_stages(
                        &operation,
                        analyzer,
                        &ReplayAdapter {
                            analyzer,
                            reads: &reads,
                        },
                        &[],
                        1,
                        2,
                        &cancellation,
                        &mut SelectedResolutionContextMetrics,
                        |_| panic!("empty admission has no payloads"),
                    )
                    .unwrap();
                    assert!(matches!(
                        result,
                        SelectedResolutionOperationOutcome::Native(_)
                    ));
                });
                drop(done_tx);
                let captured = worker.join().expect("capture worker panicked");
                assert!(
                    captured.keys().is_empty(),
                    "owner replay leaked into worker capture: {:?}",
                    captured.keys()
                );
            });
            assert_eq!(
                parent.keys(),
                if with_parent {
                    vec![key.clone()]
                } else {
                    Vec::new()
                }
            );
        }
    }
}
