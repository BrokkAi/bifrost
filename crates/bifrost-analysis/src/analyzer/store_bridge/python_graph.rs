//! Serial, request-owned Python graph staging on the shared graph unit kernel.
use super::graph_unit::{
    GraphUnitFile, GraphUnitRules, project_native_graph_definitions, stage_unit_reference_edges,
};
use super::graph_workers::run_analyzer_graph_stages;
use super::native_graph::NativeGraphBatch;
use crate::CancellationToken;
use crate::analyzer::resolution::fact_resolution::SelectedFactOperationBlueprint;
use crate::analyzer::resolution::*;
use crate::analyzer::store::python_unit_summaries::PythonSelectedEnvironment;
use crate::analyzer::store::resolution_operation::graph_stage::*;
use crate::analyzer::store::{Result, resolution_operation::*};
use crate::analyzer::{IAnalyzer, ProjectFile};
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use std::collections::BTreeMap;

struct PythonGraphTables;
impl GraphStageHelperTables for PythonGraphTables {}
struct PythonGraphStageAdapter<'a> {
    analyzer: &'a dyn IAnalyzer,
    environment: PythonSelectedEnvironment,
}
impl GraphStageAdapter for PythonGraphStageAdapter<'_> {
    const FILE_CHUNKS_REPRODUCE_UNIT: bool = false;
    type Unit = ();
    type Payload = GraphStageBatches<NativeGraphBatch>;
    type HelperTables<'stage> = PythonGraphTables;
    fn units(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        files: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<GraphStageAdmission<()>>> {
        let mut admitted = Vec::new();
        let mut skipped = BTreeMap::new();
        for file in files {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            let path = selected_path_key(file.rel_path());
            // An unimportable file still has authored references. Resolve its
            // selected source so withheld references retain their names; only
            // missing source mounts lack caller authority.
            if operation
                .mount_table()
                .mount_for_path("python", &path)?
                .is_none()
            {
                skipped.insert(file.clone(), GraphFileSkipReason::Unplaced);
            } else {
                admitted.push(file.clone());
            }
        }
        // One selected environment is one graph unit and one forward operation.
        Ok(SelectedResolutionOperationOutcome::Native(
            GraphStageAdmission {
                units: if admitted.is_empty() {
                    Vec::new()
                } else {
                    vec![((), admitted)]
                },
                skipped,
            },
        ))
    }
    fn helper_tables(
        &self,
        _operation: &SelectedResolutionOperation<'_, '_>,
        _unit: &(),
    ) -> Result<PythonGraphTables> {
        Ok(PythonGraphTables)
    }
    #[allow(clippy::too_many_arguments)]
    fn run_unit<'operation, 'store, 'input>(
        &self,
        operation: &'operation SelectedResolutionOperation<'store, 'input>,
        _unit: &(),
        files: &[ProjectFile],
        _guard: &mut GraphStageGuard<'operation, 'store, PythonGraphTables>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        _metrics: &mut GraphStageMetrics,
    ) -> Result<SelectedResolutionOperationOutcome<(Self::Payload, FactResolutionBatchSummary)>>
    {
        let mut rules = PythonGraphUnitRules {
            environment: self.environment,
            context: Some(operation.empty_contexts(&ResolutionCompletion::Complete)?),
        };
        let mut batches = Vec::new();
        let outcome = stage_unit_reference_edges(
            operation,
            &mut rules,
            files,
            maximum_batch_size.min(MAX_GRAPH_STAGE_READ_BATCH_SIZE),
            cancellation,
            context_metrics,
            &mut NativeReferenceEdgeBatchProjector::new(self.analyzer),
            |projector, definitions, session, missing| {
                project_native_graph_definitions(
                    operation.ready(),
                    projector,
                    definitions,
                    cancellation,
                    session,
                    missing,
                )
            },
            |_file, source, edges, _projector| {
                batches.push(NativeGraphBatch {
                    source: source.clone(),
                    edges: edges.clone(),
                });
                Ok(!cancellation.is_cancelled())
            },
        )?;
        Ok(GraphStageBatches(batches).finish(outcome))
    }
}
struct PythonGraphUnitRules {
    environment: PythonSelectedEnvironment,
    context: Option<SelectedResolutionContextSet>,
}
impl GraphUnitRules for PythonGraphUnitRules {
    fn storage_language(&self) -> &'static str {
        "python"
    }
    fn prepare_file_context(
        &mut self,
        _operation: &SelectedResolutionOperation<'_, '_>,
        _path: &str,
        _cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<Option<SelectedResolutionContextSet>>> {
        Ok(SelectedResolutionOperationOutcome::Native(
            self.context.take(),
        ))
    }
    #[allow(clippy::too_many_arguments)]
    fn stage_unit_batches(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        blueprint: &SelectedFactOperationBlueprint,
        files: &[GraphUnitFile<'_>],
        _lexical: &dyn BatchResolutionFragmentSource,
        _typed: &dyn SelectedTypedFactSource,
        session: &ResolutionSession,
        cancellation: &CancellationToken,
        maximum_batch_size: usize,
        sink: &mut dyn FnMut(&FactReferenceBatchAnswer) -> Result<()>,
    ) -> Result<FactResolutionBatchSummary> {
        let fragments = files.iter().map(|file| file.fragment).collect();
        operation.stage_python_reference_batches(
            &self.environment,
            blueprint,
            &fragments,
            session,
            cancellation,
            maximum_batch_size,
            sink,
        )
    }
}
/// Reuse analyzer read capture and shared graph admission/replay, at width one.
#[allow(clippy::too_many_arguments)]
pub fn stage_python_graph_units(
    operation: &SelectedResolutionOperation<'_, '_>,
    analyzer: &dyn IAnalyzer,
    environment: PythonSelectedEnvironment,
    files: &[ProjectFile],
    cancellation: &CancellationToken,
    sink: &mut dyn FnMut(&FactReferenceBatchAnswer, &FactReferenceEdgeBatch) -> Result<()>,
) -> Result<SelectedResolutionOperationOutcome<GraphStageResult>> {
    run_analyzer_graph_stages(
        operation,
        analyzer,
        &PythonGraphStageAdapter {
            analyzer,
            environment,
        },
        files,
        MAX_REFERENCE_SEEDS_PER_BATCH,
        1,
        cancellation,
        &mut SelectedResolutionContextMetrics,
        |payload| payload.replay(cancellation, |batch| sink(&batch.source, &batch.edges)),
    )
}
