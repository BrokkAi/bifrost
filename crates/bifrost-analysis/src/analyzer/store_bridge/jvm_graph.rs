//! JVM language-unit staging through the shared forward graph kernel.
use super::graph_workers::run_analyzer_graph_stages;

use super::graph_unit::{
    GraphUnitFile, GraphUnitRules, project_native_graph_definitions, stage_unit_reference_edges,
};
use crate::CancellationToken;
use crate::analyzer::resolution::fact_resolution::SelectedFactOperationBlueprint;
use crate::analyzer::resolution::*;
use crate::analyzer::store::resolution_operation::graph_stage::*;
use crate::analyzer::store::resolution_operation::jvm_context::{
    JvmGraphStageTables, JvmImportContext, JvmImportContextGap,
};
use crate::analyzer::store::resolution_operation::jvm_demand::JvmForwardOperationContext;
use crate::analyzer::store::resolution_operation::*;
use crate::analyzer::store::resolution_selection::SelectedResolutionUnavailable;
use crate::analyzer::store::*;
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::common::language_for_file;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use std::collections::BTreeMap;

type JvmBatchStager<'a> =
    dyn FnMut(&FactReferenceBatchAnswer, &FactReferenceEdgeBatch) -> Result<()> + 'a;

use super::native_graph::NativeGraphBatch as JvmGraphBatch;

struct JvmGraphStageAdapter<'a> {
    analyzer: &'a dyn IAnalyzer,
}
/// Expose the adapter contract so the same golden pass checks future activation.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn jvm_graph_file_chunks_reproduce_unit_for_test() -> bool {
    JvmGraphStageAdapter::FILE_CHUNKS_REPRODUCE_UNIT
}

impl GraphStageAdapter for JvmGraphStageAdapter<'_> {
    // #6797: explicit-receiver forward admission depends on the caller set.
    const FILE_CHUNKS_REPRODUCE_UNIT: bool = false;

    type Unit = &'static str;
    type Payload = GraphStageBatches<JvmGraphBatch>;
    type HelperTables<'stage> = JvmGraphStageTables<'stage>;
    fn units(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        files: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<GraphStageAdmission<Self::Unit>>> {
        let mut groups = BTreeMap::<_, Vec<_>>::new();
        for file in files {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            let language = language_for_file(file);
            assert!(matches!(
                language,
                Language::Java | Language::Kotlin | Language::Scala
            ));
            let storage = language.config_label();
            let path = selected_path_key(file.rel_path());
            if operation
                .mount_table()
                .mount_for_path(storage, &path)?
                .is_none()
            {
                return Ok(SelectedResolutionOperationOutcome::Unavailable(
                    SelectedResolutionUnavailable::MissingInterior {
                        storage_language: storage.to_owned(),
                        persisted_relative_path: path,
                    },
                ));
            }
            groups.entry(storage).or_default().push(file.clone());
        }
        for group in groups.values_mut() {
            group.sort();
            group.dedup();
        }
        Ok(SelectedResolutionOperationOutcome::Native(
            GraphStageAdmission {
                units: groups.into_iter().collect(),
                skipped: BTreeMap::new(),
            },
        ))
    }
    fn helper_tables<'stage>(
        &self,
        operation: &'stage SelectedResolutionOperation<'_, '_>,
        _unit: &Self::Unit,
    ) -> Result<Self::HelperTables<'stage>> {
        Ok(operation.jvm_graph_stage_tables())
    }
    #[allow(clippy::too_many_arguments)]
    fn run_unit<'operation, 'store, 'input>(
        &self,
        operation: &'operation SelectedResolutionOperation<'store, 'input>,
        unit: &Self::Unit,
        files: &[ProjectFile],
        _guard: &mut GraphStageGuard<'operation, 'store, Self::HelperTables<'operation>>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        _metrics: &mut GraphStageMetrics,
    ) -> Result<SelectedResolutionOperationOutcome<(Self::Payload, FactResolutionBatchSummary)>>
    {
        let language = match *unit {
            "java" => Language::Java,
            "kotlin" => Language::Kotlin,
            "scala" => Language::Scala,
            _ => unreachable!("a JVM unit has a JVM storage language"),
        };
        let mut rules = JvmGraphUnitRules {
            storage: unit,
            language,
            import_gaps: HashMap::default(),
        };
        let ready = operation.ready();
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
                    ready,
                    projector,
                    definitions,
                    cancellation,
                    session,
                    missing,
                )
            },
            |_file, batch, projected, _projector| {
                batches.push(JvmGraphBatch {
                    source: batch.clone(),
                    edges: projected.clone(),
                });
                Ok(!cancellation.is_cancelled())
            },
        )?;
        Ok(GraphStageBatches(batches).finish(outcome))
    }
}
struct JvmGraphUnitRules {
    storage: &'static str,
    language: Language,
    import_gaps: HashMap<String, Vec<JvmImportContextGap>>,
}
impl GraphUnitRules for JvmGraphUnitRules {
    fn storage_language(&self) -> &'static str {
        self.storage
    }
    fn prepare_file_context(
        &mut self,
        operation: &SelectedResolutionOperation<'_, '_>,
        path: &str,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<Option<SelectedResolutionContextSet>>> {
        Ok(
            match operation.jvm_import_context(self.language, path, cancellation)? {
                JvmImportContext::Ready {
                    context,
                    scoped_gaps,
                    ..
                } => {
                    self.import_gaps.insert(path.to_owned(), scoped_gaps);
                    SelectedResolutionOperationOutcome::Native(Some(*context))
                }
                JvmImportContext::Cancelled => {
                    SelectedResolutionOperationOutcome::Cancelled(cancelled_completion())
                }
                JvmImportContext::Unavailable => SelectedResolutionOperationOutcome::Unavailable(
                    SelectedResolutionUnavailable::JvmContextUnavailable {
                        storage_language: self.storage.to_owned(),
                        persisted_relative_path: path.to_owned(),
                    },
                ),
            },
        )
    }
    fn projection_memo<'a>(
        &self,
        operation: &'a SelectedResolutionOperation<'_, '_>,
    ) -> Option<&'a ContextBlueprintMemo> {
        Some(&operation.jvm_context_blueprints)
    }
    #[allow(clippy::too_many_arguments)]
    fn stage_unit_batches(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        blueprint: &SelectedFactOperationBlueprint,
        files: &[GraphUnitFile<'_>],
        _lexical: &dyn BatchResolutionFragmentSource,
        typed: &dyn SelectedTypedFactSource,
        session: &ResolutionSession,
        cancellation: &CancellationToken,
        maximum_batch_size: usize,
        sink: &mut dyn FnMut(&FactReferenceBatchAnswer) -> Result<()>,
    ) -> Result<FactResolutionBatchSummary> {
        let mut summary = FactResolutionBatchSummary::empty();
        for file in files {
            let fragments = crate::hash::HashSet::from_iter([file.fragment]);
            if cancellation.is_cancelled() {
                break;
            }
            let lexical = operation
                .ready()
                .lexical_source()
                .with_forward_reference_fragments(&fragments);
            let lexical = SeamProfiled::observing(&lexical);
            summary.accumulate(
                operation.stage_jvm_reference_batches(
                    JvmForwardOperationContext {
                        storage_language: self.storage,
                        blueprint,
                        caller_path: &file.path,
                        import_gaps: self
                            .import_gaps
                            .get(&file.path)
                            .expect("every staged JVM file prepared its context"),
                        lexical: &lexical,
                        typed,
                        session,
                        cancellation,
                    },
                    maximum_batch_size,
                    sink,
                )?,
            );
        }
        Ok(summary)
    }
}
#[doc(hidden)]
pub trait JvmGraphStageExt {
    #[allow(clippy::too_many_arguments)]
    fn stage_jvm_graph_units(
        &self,
        analyzer: &dyn IAnalyzer,
        files: &[ProjectFile],
        maximum_batch_size: usize,
        worker_count: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        stage: &mut JvmBatchStager<'_>,
    ) -> Result<SelectedResolutionOperationOutcome<GraphStageResult>>;
}
impl JvmGraphStageExt for SelectedResolutionOperation<'_, '_> {
    #[allow(clippy::too_many_arguments)]
    fn stage_jvm_graph_units(
        &self,
        analyzer: &dyn IAnalyzer,
        files: &[ProjectFile],
        maximum_batch_size: usize,
        worker_count: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        stage: &mut JvmBatchStager<'_>,
    ) -> Result<SelectedResolutionOperationOutcome<GraphStageResult>> {
        run_analyzer_graph_stages(
            self,
            analyzer,
            &JvmGraphStageAdapter { analyzer },
            files,
            maximum_batch_size,
            worker_count,
            cancellation,
            context_metrics,
            |payload| payload.replay(cancellation, |batch| stage(&batch.source, &batch.edges)),
        )
    }
}
