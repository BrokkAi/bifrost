//! File-scoped native Go forward graph staging in one selected operation.
use super::graph_workers::run_analyzer_graph_stages;

use super::graph_unit::{GraphUnitFile, GraphUnitRules, stage_unit_reference_edges};
use crate::CancellationToken;
use crate::analyzer::resolution::fact_resolution::SelectedFactOperationBlueprint;
use crate::analyzer::resolution::local_identity::ResolutionIdentityTranslation;
use crate::analyzer::resolution::worker_transport::WorkerAnswer;
use crate::analyzer::resolution::*;
use crate::analyzer::resolution::{FactReferenceEdgeBatch, NativeReferenceEdgeBatchProjector};
use crate::analyzer::store::go_package_context::GoContextIdentity;
use crate::analyzer::store::resolution_operation::go_demand::GoForwardOperationContext;
use crate::analyzer::store::resolution_operation::go_named::{GoDemandContext, GoPackageStageUnit};
use crate::analyzer::store::resolution_operation::graph_stage::{
    GraphStageAdapter, GraphStageAdmission, GraphStageBatches, GraphStageGuard, GraphStageMetrics,
    GraphStageResult, MAX_GRAPH_STAGE_READ_BATCH_SIZE,
};
use crate::analyzer::store::resolution_operation::*;
use crate::analyzer::store::resolution_selection::SelectedResolutionUnavailable;
use crate::analyzer::store::*;
use crate::analyzer::{CodeUnit, IAnalyzer};
use crate::analyzer::{Language, ProjectFile};
use crate::hash::HashSet;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use std::collections::BTreeMap;

#[derive(Clone)]
#[doc(hidden)]
pub struct GoReferenceBatchProjection {
    #[doc(hidden)]
    pub reference_owner: Option<CodeUnit>,
    #[doc(hidden)]
    pub binding_targets: Vec<Option<CodeUnit>>,
}

pub(crate) type GoReferenceEdgeBatchStager<'a> = dyn FnMut(
        &ProjectFile,
        &FactReferenceBatchAnswer,
        &FactReferenceEdgeBatch,
        &[GoReferenceBatchProjection],
    ) -> Result<()>
    + 'a;

struct GoGraphBatch {
    file: ProjectFile,
    source: FactReferenceBatchAnswer,
    edges: FactReferenceEdgeBatch,
    projections: Vec<GoReferenceBatchProjection>,
}

impl WorkerAnswer for GoGraphBatch {
    fn translate(self, translation: &impl ResolutionIdentityTranslation) -> Self {
        Self {
            file: self.file,
            source: self.source.translate(translation),
            edges: self.edges.translate(translation),
            // Projected CodeUnits contain stable declaration identities, not runtime aliases.
            projections: self.projections,
        }
    }
}

struct GoGraphPayload {
    batches: GraphStageBatches<GoGraphBatch>,
    publications: Vec<GoContextIdentity>,
}

impl WorkerAnswer for GoGraphPayload {
    fn translate(self, translation: &impl ResolutionIdentityTranslation) -> Self {
        Self {
            batches: self.batches.translate(translation),
            // Persisted publication identities contain no runtime aliases.
            publications: self.publications,
        }
    }
}

struct GoGraphStageAdapter<'callback> {
    analyzer: &'callback dyn IAnalyzer,
    base_profile: [u8; 32],
}

impl GraphStageAdapter for GoGraphStageAdapter<'_> {
    // File-major staging below; persisted whole-package peers: go_same_package.rs:291-328.
    const FILE_CHUNKS_REPRODUCE_UNIT: bool = true;

    type Unit = GoPackageStageUnit;
    type Payload = GoGraphPayload;
    type HelperTables<'stage> = FileContextPeerMemoGuard<'stage>;

    fn units(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        files: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<GraphStageAdmission<Self::Unit>>> {
        let mounts = operation.mount_table();
        let mut groups = BTreeMap::<GoPackageStageUnit, Vec<ProjectFile>>::new();
        let mut skipped = BTreeMap::new();
        let mut modules = None;
        let support = crate::analyzer::languages::language_support_for_hook(
            Language::Go,
            "selected_graph_fallback_active",
        )
        .expect("Go stage has a Go analyzer");
        let fallback = support.selected_graph_fallback_active(self.analyzer);
        for file in files {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            if fallback {
                let modules = modules.get_or_insert_with(|| {
                    brokk_bifrost_go::packages::go_module_roots(self.analyzer.project())
                });
                if let Some(reason) =
                    support.selected_graph_fallback_exclusion(self.analyzer, file, modules)
                {
                    skipped.insert(file.clone(), reason);
                    continue;
                }
            }
            let path = selected_path_key(file.rel_path());
            let placement_context = operation.go_context_for_file(&self.base_profile, &path)?;
            let unit = if let Some(mount) = mounts.mount_for_path("go", &path)? {
                assert_eq!(mount.semantic_language(), Language::Go);
                if let Some(context) = &placement_context {
                    operation.go_package_stage_unit_for_path(
                        context.context_id,
                        &path,
                        cancellation,
                    )?
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(unit) = unit {
                groups.entry(unit).or_default().push(file.clone());
                continue;
            }
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            // Read module roots only when a caller lacks a selected unit.
            let modules = modules.get_or_insert_with(|| {
                brokk_bifrost_go::packages::go_module_roots(self.analyzer.project())
            });
            let module = modules
                .iter()
                .filter(|module| file.parent().starts_with(&module.workspace_dir))
                .max_by_key(|module| module.workspace_dir.components().count());
            let unnamed_root = support.unnamed_module_root_for_file(self.analyzer, file);
            let reason = if let Some(root) = unnamed_root {
                crate::analyzer::store::resolution_operation::graph_stage::GraphFileSkipReason::OutsideSelectedModules {
                    module_path: root
                        .to_string_lossy()
                        .replace('\\', "/"),
                }
            } else {
                operation.go_graph_file_exclusion_for_domain(
                    &self.base_profile,
                    &path,
                    placement_context.as_ref().map(|context| context.context_id),
                    module.map(|module| module.workspace_dir.as_path()),
                    module.map(|module| module.import_path.as_str()),
                )?
            };
            skipped.insert(file.clone(), reason);
        }
        for group in groups.values_mut() {
            group.sort();
            group.dedup();
        }
        Ok(SelectedResolutionOperationOutcome::Native(
            GraphStageAdmission {
                units: groups.into_iter().collect(),
                skipped,
            },
        ))
    }

    fn helper_tables<'stage>(
        &self,
        operation: &'stage SelectedResolutionOperation<'_, '_>,
        _unit: &Self::Unit,
    ) -> Result<Self::HelperTables<'stage>> {
        Ok(operation.file_context_peer_memo_scope())
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
        operation.initialize_go_base_profile(&self.base_profile);
        let mut rules = GoGraphUnitRules {
            prepare: |path: &str, cancellation: &CancellationToken| {
                operation.go_file_import_context_with_role(
                    unit.context_id,
                    path,
                    &unit.source_role,
                    cancellation,
                )
            },
            demand: None,
        };
        let previous_publications = operation
            .bound_go_context_publications()
            .into_iter()
            .map(|publication| publication.context_id)
            .collect::<HashSet<_>>();
        let mut batches = Vec::new();
        let outcome = stage_go_unit(
            operation,
            &mut rules,
            files,
            maximum_batch_size.min(MAX_GRAPH_STAGE_READ_BATCH_SIZE),
            cancellation,
            context_metrics,
            &mut NativeReferenceEdgeBatchProjector::new(self.analyzer),
            &mut |file, source, edges, projections| {
                batches.push(GoGraphBatch {
                    file: file.clone(),
                    source: source.clone(),
                    edges: edges.clone(),
                    projections: projections.to_vec(),
                });
                Ok(())
            },
        )?;
        Ok(match outcome {
            SelectedResolutionOperationOutcome::Native(summary) => {
                let publications = operation
                    .bound_go_context_publications()
                    .into_iter()
                    .filter(|publication| !previous_publications.contains(&publication.context_id))
                    .collect();
                SelectedResolutionOperationOutcome::Native((
                    GoGraphPayload {
                        batches: GraphStageBatches(batches),
                        publications,
                    },
                    summary,
                ))
            }
            SelectedResolutionOperationOutcome::Cancelled(completion) => {
                SelectedResolutionOperationOutcome::Cancelled(completion)
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

#[doc(hidden)]
pub trait GoGraphStageExt {
    /// Stage selected Go reference batches for the admitted caller files.
    ///
    /// Each file gets its own file-local package/import context, while the
    /// selected operation, declaration catalog, and owner memo remain
    /// request-scoped across the whole file set.
    #[allow(clippy::too_many_arguments)]
    fn stage_go_reference_edge_batches_in_files(
        &self,
        analyzer: &dyn IAnalyzer,
        context_id: i64,
        files: &HashSet<ProjectFile>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        stage: &mut GoReferenceEdgeBatchStager<'_>,
    ) -> Result<SelectedResolutionOperationOutcome<FactResolutionBatchSummary>>;

    /// Stage the workspace graph from each admitted file's own import context.
    /// The demand provider admits other package mounts as references reach
    /// them, including package files needed for receiver method visibility.
    #[allow(clippy::too_many_arguments)]
    fn stage_go_graph_reference_edge_batches_in_files(
        &self,
        analyzer: &dyn IAnalyzer,
        base_profile: [u8; 32],
        files: &HashSet<ProjectFile>,
        maximum_batch_size: usize,
        worker_count: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        stage: &mut GoReferenceEdgeBatchStager<'_>,
    ) -> Result<SelectedResolutionOperationOutcome<GraphStageResult>>;

    #[allow(clippy::too_many_arguments)]
    fn stage_go_reference_edge_batches_in_files_with_context(
        &self,
        analyzer: &dyn IAnalyzer,
        files: &HashSet<ProjectFile>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        prepare_file_context: impl FnMut(
            &str,
            &CancellationToken,
        ) -> Result<GoPreparedImportContextOutcome>,
        stage: &mut GoReferenceEdgeBatchStager<'_>,
    ) -> Result<SelectedResolutionOperationOutcome<FactResolutionBatchSummary>>;
}

impl GoGraphStageExt for SelectedResolutionOperation<'_, '_> {
    /// Stage selected Go reference batches for the admitted caller files.
    ///
    /// Each file gets its own file-local package/import context, while the
    /// selected operation, declaration catalog, and owner memo remain
    /// request-scoped across the whole file set.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    fn stage_go_reference_edge_batches_in_files(
        &self,
        analyzer: &dyn IAnalyzer,
        context_id: i64,
        files: &HashSet<ProjectFile>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        stage: &mut GoReferenceEdgeBatchStager<'_>,
    ) -> Result<SelectedResolutionOperationOutcome<FactResolutionBatchSummary>> {
        self.stage_go_reference_edge_batches_in_files_with_context(
            analyzer,
            files,
            maximum_batch_size,
            cancellation,
            context_metrics,
            |path, cancellation| self.go_file_import_context(context_id, path, cancellation),
            stage,
        )
    }

    /// Stage the workspace graph from each admitted file's own import context.
    /// The demand provider admits other package mounts as references reach
    /// them, including package files needed for receiver method visibility.
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    fn stage_go_graph_reference_edge_batches_in_files(
        &self,
        analyzer: &dyn IAnalyzer,
        base_profile: [u8; 32],
        files: &HashSet<ProjectFile>,
        maximum_batch_size: usize,
        worker_count: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        stage: &mut GoReferenceEdgeBatchStager<'_>,
    ) -> Result<SelectedResolutionOperationOutcome<GraphStageResult>> {
        let files = files.iter().cloned().collect::<Vec<_>>();
        let adapter = GoGraphStageAdapter {
            analyzer,
            base_profile,
        };
        let outcome = run_analyzer_graph_stages(
            self,
            analyzer,
            &adapter,
            &files,
            maximum_batch_size,
            worker_count,
            cancellation,
            context_metrics,
            |payload| {
                for publication in payload.publications {
                    self.bind_go_context_publication(publication);
                }
                payload.batches.replay(cancellation, |batch| {
                    stage(&batch.file, &batch.source, &batch.edges, &batch.projections)
                })
            },
        )?;
        Ok(outcome)
    }

    #[allow(clippy::too_many_arguments)]
    fn stage_go_reference_edge_batches_in_files_with_context(
        &self,
        analyzer: &dyn IAnalyzer,
        files: &HashSet<ProjectFile>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        mut prepare_file_context: impl FnMut(
            &str,
            &CancellationToken,
        ) -> Result<GoPreparedImportContextOutcome>,
        stage: &mut GoReferenceEdgeBatchStager<'_>,
    ) -> Result<SelectedResolutionOperationOutcome<FactResolutionBatchSummary>> {
        assert!(
            (1..=MAX_REFERENCE_SEEDS_PER_BATCH).contains(&maximum_batch_size),
            "reference batch size must be in 1..={MAX_REFERENCE_SEEDS_PER_BATCH}"
        );
        let mut ordered_files = files.iter().cloned().collect::<Vec<_>>();
        ordered_files.sort();
        let mut projector = NativeReferenceEdgeBatchProjector::new(analyzer);
        let mut summary = FactResolutionBatchSummary::empty();
        for file in &ordered_files {
            let mut rules = GoGraphUnitRules {
                prepare: &mut prepare_file_context,
                demand: None,
            };
            match stage_go_unit(
                self,
                &mut rules,
                std::slice::from_ref(file),
                maximum_batch_size,
                cancellation,
                context_metrics,
                &mut projector,
                stage,
            )? {
                SelectedResolutionOperationOutcome::Native(staged) => summary.accumulate(staged),
                outcome => return Ok(outcome),
            }
        }
        Ok(SelectedResolutionOperationOutcome::Native(summary))
    }
}

struct GoGraphUnitRules<P> {
    prepare: P,
    demand: Option<GoDemandContext>,
}

impl<P> GraphUnitRules for GoGraphUnitRules<P>
where
    P: FnMut(&str, &CancellationToken) -> Result<GoPreparedImportContextOutcome>,
{
    fn storage_language(&self) -> &'static str {
        "go"
    }

    fn prepare_file_context(
        &mut self,
        _operation: &SelectedResolutionOperation<'_, '_>,
        path: &str,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<Option<SelectedResolutionContextSet>>> {
        Ok(match (self.prepare)(path, cancellation)? {
            GoPreparedImportContextOutcome::Ready(prepared) => {
                let prepared = *prepared;
                if let Some(demand) = self.demand.as_mut() {
                    demand.merge(prepared.demand);
                } else {
                    self.demand = Some(prepared.demand);
                }
                SelectedResolutionOperationOutcome::Native(Some(prepared.context))
            }
            GoPreparedImportContextOutcome::Unavailable => {
                SelectedResolutionOperationOutcome::Unavailable(
                    SelectedResolutionUnavailable::GoContextUnavailable {
                        persisted_relative_path: path.to_owned(),
                    },
                )
            }
            GoPreparedImportContextOutcome::Cancelled => {
                SelectedResolutionOperationOutcome::Cancelled(cancelled_completion())
            }
        })
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
        let demand = self
            .demand
            .as_ref()
            .expect("an admitted Go unit has demand inputs");
        let mut summary = FactResolutionBatchSummary::empty();
        for file in files {
            if cancellation.is_cancelled() {
                break;
            }
            let fragments = HashSet::from_iter([file.fragment]);
            let lexical = operation
                .ready()
                .lexical_source()
                .with_forward_reference_fragments(&fragments);
            let observed_lexical = SeamProfiled::observing(&lexical);
            let staged = operation.stage_go_reference_batches(
                GoForwardOperationContext {
                    blueprint,
                    demand: demand.clone(),
                    caller_path: &file.path,
                    lexical: &observed_lexical,
                    typed,
                    cancellation,
                    session,
                },
                maximum_batch_size,
                sink,
            )?;
            summary.accumulate(staged);
        }
        Ok(summary)
    }
}

#[allow(clippy::too_many_arguments)]
fn stage_go_unit<P>(
    operation: &SelectedResolutionOperation<'_, '_>,
    rules: &mut GoGraphUnitRules<P>,
    files: &[ProjectFile],
    maximum_batch_size: usize,
    cancellation: &CancellationToken,
    context_metrics: &mut SelectedResolutionContextMetrics,
    projector: &mut NativeReferenceEdgeBatchProjector<'_>,
    stage: &mut GoReferenceEdgeBatchStager<'_>,
) -> Result<SelectedResolutionOperationOutcome<FactResolutionBatchSummary>>
where
    P: FnMut(&str, &CancellationToken) -> Result<GoPreparedImportContextOutcome>,
{
    stage_unit_reference_edges(
        operation,
        rules,
        files,
        maximum_batch_size,
        cancellation,
        context_metrics,
        projector,
        |projector, definitions, session, unprojected| {
            super::graph_unit::project_native_graph_definitions(
                operation.ready(),
                projector,
                definitions,
                cancellation,
                session,
                unprojected,
            )
        },
        |file, batch, projected, projector| {
            stage_go_graph_projection(file, batch, projected, projector, cancellation, stage)
        },
    )
}

fn stage_go_graph_projection(
    file: &ProjectFile,
    batch: &FactReferenceBatchAnswer,
    projected: &FactReferenceEdgeBatch,
    edge_projector: &mut NativeReferenceEdgeBatchProjector<'_>,
    cancellation: &CancellationToken,
    stage: &mut GoReferenceEdgeBatchStager<'_>,
) -> Result<bool> {
    let mut projections = Vec::with_capacity(batch.answers().len());
    for answer in batch.answers() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let reference_owner = match answer.reference_owner().flatten() {
            Some(owner) => edge_projector
                .catalog_mut()
                .graph_declaration(owner)?
                .cloned(),
            None => None,
        };
        let mut binding_targets = Vec::with_capacity(answer.answer().binding().targets().len());
        for &target in answer.answer().binding().targets() {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            binding_targets.push(
                edge_projector
                    .catalog_mut()
                    .graph_declaration(target)?
                    .cloned(),
            );
        }
        projections.push(GoReferenceBatchProjection {
            reference_owner,
            binding_targets,
        });
    }
    stage(file, batch, projected, &projections)?;
    Ok(true)
}
