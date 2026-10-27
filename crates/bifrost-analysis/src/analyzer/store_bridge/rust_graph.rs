//! File-major native Rust graph projection inside one selected operation.
use super::graph_workers::run_analyzer_graph_stages;

use super::graph_unit::{GraphUnitFile, GraphUnitRules, stage_unit_reference_edges};
use crate::CancellationToken;
use crate::analyzer::IAnalyzer;
use crate::analyzer::ProjectFile;
use crate::analyzer::resolution::fact_resolution::SelectedFactOperationBlueprint;
use crate::analyzer::resolution::*;
use crate::analyzer::resolution::{FactReferenceEdgeBatch, NativeReferenceEdgeBatchProjector};
use crate::analyzer::store::resolution_operation::graph_stage::{
    GraphStageAdapter, GraphStageAdmission, GraphStageBatches, GraphStageGuard, GraphStageMetrics,
    GraphStageResult,
};
use crate::analyzer::store::resolution_operation::*;
use crate::analyzer::store::resolution_stage::SelectedResolutionStageOutcome;
use crate::analyzer::store::*;
use crate::hash::HashSet;
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RustGraphStageUnit {
    Crate([u8; 32]),
    OutsideCrates,
}

struct RustGraphStageAdapter<'a> {
    project_root: &'a Path,
    analyzer: &'a dyn IAnalyzer,
}

impl GraphStageAdapter for RustGraphStageAdapter<'_> {
    // lexical_readers.rs emits persisted references by mount, then generated references.
    const FILE_CHUNKS_REPRODUCE_UNIT: bool = false;

    type Unit = RustGraphStageUnit;
    type Payload = GraphStageBatches<FactReferenceEdgeBatch>;
    type HelperTables<'stage> =
        crate::analyzer::store::resolution_operation::rust_crate_rows::RustGraphStageTables<'stage>;

    fn units(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        files: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<GraphStageAdmission<Self::Unit>>> {
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
        let requested = files.iter().cloned().collect::<HashSet<_>>();
        let keys = operation
            .rust_crate_keys_for_files(requested.iter().map(ProjectFile::rel_path), cancellation)?;
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }

        let mut outside_crates = requested.clone();
        let mut groups = Vec::with_capacity(keys.len() + 1);
        for key in keys {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            let mut crate_files = Vec::new();
            for member in operation.rust_crate_member_paths(key, cancellation)? {
                if cancellation.is_cancelled() {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    ));
                }
                let file = ProjectFile::new(self.project_root, PathBuf::from(member));
                if requested.contains(&file) {
                    outside_crates.remove(&file);
                    crate_files.push(file);
                }
            }
            if !crate_files.is_empty() {
                groups.push((RustGraphStageUnit::Crate(key), crate_files));
            }
        }
        if !outside_crates.is_empty() {
            groups.push((
                RustGraphStageUnit::OutsideCrates,
                outside_crates.into_iter().collect(),
            ));
        }
        Ok(SelectedResolutionOperationOutcome::Native(
            GraphStageAdmission {
                units: groups,
                skipped: Default::default(),
            },
        ))
    }

    fn helper_tables<'stage>(
        &self,
        operation: &'stage SelectedResolutionOperation<'_, '_>,
        _unit: &Self::Unit,
    ) -> Result<Self::HelperTables<'stage>> {
        Ok(operation.rust_graph_stage_tables())
    }

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
        let crate_keys = match unit {
            RustGraphStageUnit::Crate(key) => vec![*key],
            RustGraphStageUnit::OutsideCrates => Vec::new(),
        };
        let crate_files = files.iter().cloned().collect::<HashSet<_>>();
        let context = match operation.rust_context_for_crate_files(
            crate_keys.clone(),
            &crate_files,
            cancellation,
        )? {
            SelectedRustContextOutcome::Ready(context) => context,
            SelectedRustContextOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
        };
        let mut batches = Vec::new();
        let outcome = operation.stage_rust_reference_edge_batches_in_files(
            self.analyzer,
            context,
            &crate_keys,
            &crate_files,
            maximum_batch_size,
            cancellation,
            context_metrics,
            &mut |edges| {
                batches.push(edges.clone());
                Ok(())
            },
        )?;
        Ok(GraphStageBatches(batches).finish(outcome))
    }
}

#[doc(hidden)]
pub trait RustGraphStageExt {
    #[allow(clippy::too_many_arguments)]
    fn stage_rust_graph_units(
        &self,
        project_root: &Path,
        analyzer: &dyn IAnalyzer,
        files: &[ProjectFile],
        maximum_batch_size: usize,
        worker_count: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        stage: &mut dyn FnMut(&FactReferenceEdgeBatch) -> Result<()>,
    ) -> Result<SelectedResolutionOperationOutcome<GraphStageResult>>;

    #[allow(clippy::too_many_arguments)]
    fn stage_rust_reference_edge_batches_in_files(
        &self,
        analyzer: &dyn IAnalyzer,
        context: SelectedResolutionContextSet,
        crate_keys: &[[u8; 32]],
        files: &HashSet<ProjectFile>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        stage: &mut dyn FnMut(&FactReferenceEdgeBatch) -> Result<()>,
    ) -> Result<SelectedResolutionOperationOutcome<FactResolutionBatchSummary>>;
}

impl RustGraphStageExt for SelectedResolutionOperation<'_, '_> {
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    fn stage_rust_graph_units(
        &self,
        project_root: &Path,
        analyzer: &dyn IAnalyzer,
        files: &[ProjectFile],
        maximum_batch_size: usize,
        worker_count: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        stage: &mut dyn FnMut(&FactReferenceEdgeBatch) -> Result<()>,
    ) -> Result<SelectedResolutionOperationOutcome<GraphStageResult>> {
        let adapter = RustGraphStageAdapter {
            project_root,
            analyzer,
        };
        run_analyzer_graph_stages(
            self,
            analyzer,
            &adapter,
            files,
            maximum_batch_size,
            worker_count,
            cancellation,
            context_metrics,
            |payload| payload.replay(cancellation, |batch| stage(&batch)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn stage_rust_reference_edge_batches_in_files(
        &self,
        analyzer: &dyn IAnalyzer,
        context: SelectedResolutionContextSet,
        crate_keys: &[[u8; 32]],
        files: &HashSet<ProjectFile>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        stage: &mut dyn FnMut(&FactReferenceEdgeBatch) -> Result<()>,
    ) -> Result<SelectedResolutionOperationOutcome<FactResolutionBatchSummary>> {
        let unit_files = files.iter().cloned().collect::<Vec<_>>();
        let mut rules = RustGraphUnitRules {
            context: Some(context),
            crate_keys,
            cancellation,
        };
        let mut projector = NativeReferenceEdgeBatchProjector::new(analyzer);
        let trace = crate::profiling::enabled();
        let mut staged_batches = 0_usize;
        let outcome = stage_unit_reference_edges(
            self,
            &mut rules,
            &unit_files,
            maximum_batch_size,
            cancellation,
            context_metrics,
            &mut projector,
            |edge_projector, definitions, _session, unprojected_definitions| {
                project_rust_graph_definitions(
                    self,
                    edge_projector,
                    definitions,
                    cancellation,
                    unprojected_definitions,
                )
            },
            |_file, _batch, projected, _projector| {
                if trace && (staged_batches == 0 || staged_batches.is_power_of_two()) {
                    crate::profiling::note(format!("rust graph stage batch={staged_batches}"));
                }
                staged_batches += 1;
                stage(projected)?;
                Ok(true)
            },
        )?;
        if trace {
            crate::profiling::note(format!(
                "rust graph stage complete batches={staged_batches}"
            ));
        }
        Ok(outcome)
    }
}

struct RustGraphUnitRules<'a> {
    context: Option<SelectedResolutionContextSet>,
    crate_keys: &'a [[u8; 32]],
    cancellation: &'a CancellationToken,
}

impl GraphUnitRules for RustGraphUnitRules<'_> {
    fn storage_language(&self) -> &'static str {
        "rust"
    }

    fn before_unit(
        &mut self,
        operation: &SelectedResolutionOperation<'_, '_>,
        files: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<()>> {
        // Macro answers and generated rows belong to this crate stage, not the
        // workspace request. Admission witnesses remain request-owned.
        operation.clear_selected_macro_walk_answers();
        operation.clear_selected_macro_overlay()?;
        if !operation.ensure_selected_rust_inputs(cancellation)? {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
        let mut macro_files = files.iter().map(ProjectFile::rel_path).collect::<Vec<_>>();
        let macro_item_hosts = operation.rust_macro_item_hosts(&macro_files)?;
        for host in &macro_item_hosts {
            if !macro_files.contains(&host.as_path()) {
                macro_files.push(host.as_path());
            }
        }
        Ok(
            match operation
                .prepare_selected_macro_frontiers_for_files(&macro_files, cancellation)?
            {
                SelectedResolutionStageOutcome::Ready => {
                    SelectedResolutionOperationOutcome::Native(())
                }
                SelectedResolutionStageOutcome::Cancelled => {
                    SelectedResolutionOperationOutcome::Cancelled(cancelled_completion())
                }
                SelectedResolutionStageOutcome::Stale(reason) => {
                    SelectedResolutionOperationOutcome::Stale(reason)
                }
                SelectedResolutionStageOutcome::Unavailable(reason) => {
                    SelectedResolutionOperationOutcome::Unavailable(reason)
                }
            },
        )
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

    fn with_unit_scope<T>(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        run: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        operation.with_rust_forward_crate_scope(self.crate_keys, self.cancellation, run)
    }

    #[allow(clippy::too_many_arguments)]
    fn stage_unit_batches(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        blueprint: &SelectedFactOperationBlueprint,
        _files: &[GraphUnitFile<'_>],
        lexical: &dyn BatchResolutionFragmentSource,
        typed: &dyn SelectedTypedFactSource,
        _session: &ResolutionSession,
        cancellation: &CancellationToken,
        maximum_batch_size: usize,
        sink: &mut dyn FnMut(&FactReferenceBatchAnswer) -> Result<()>,
    ) -> Result<FactResolutionBatchSummary> {
        operation.ready().with_rust_workspace_fact_operation(
            blueprint,
            lexical,
            typed,
            cancellation,
            |facts| facts.stage_all_reference_batches(maximum_batch_size, sink),
        )
    }
}

fn project_rust_graph_definitions(
    operation: &SelectedResolutionOperation<'_, '_>,
    edge_projector: &mut NativeReferenceEdgeBatchProjector<'_>,
    definitions: &[SemanticId],
    cancellation: &CancellationToken,
    unprojected_definitions: &mut Vec<SemanticId>,
) -> Result<bool> {
    match project_rust_source_definitions(
        operation.ready(),
        operation.mount_table(),
        definitions,
        cancellation,
        &ResolutionSession::unbounded(),
    )? {
        SelectedRustSourceDefinitionProjection::Complete(definitions) => {
            for (semantic, definition) in definitions {
                match definition {
                    SelectedRustSourceDefinition::Unit(unit) => edge_projector
                        .catalog_mut()
                        .insert_graph_declaration(semantic, unit)?,
                    // A lexical binding has no `CodeUnit`, and
                    // neither has an item the parser could not
                    // name. The graph's nodes are `CodeUnit`s,
                    // so both are edge endpoints the graph
                    // cannot draw, not failures of the request.
                    // A language universe entry (`i64`) is the
                    // same kind of endpoint: it declares no
                    // `CodeUnit` anywhere in the workspace.
                    SelectedRustSourceDefinition::Lexical(_)
                    | SelectedRustSourceDefinition::UniverseEntry
                    | SelectedRustSourceDefinition::WithoutUnit { .. } => edge_projector
                        .catalog_mut()
                        .insert_out_of_graph_declaration(semantic),
                }
                edge_projector.mark_projected(semantic);
            }
        }
        // A batch the projection cannot answer is one the graph
        // cannot draw those endpoints for. It is a hole in this
        // answer, not a reason to fail the request: a whole
        // workspace graph over tract died on one such batch and
        // published nothing at all, where 13,370 nodes and
        // 14,985 edges were available. Each definition becomes
        // an endpoint the graph does not draw, and the request
        // says so.
        SelectedRustSourceDefinitionProjection::Unavailable => {
            for &semantic in definitions {
                edge_projector
                    .catalog_mut()
                    .insert_out_of_graph_declaration(semantic);
                edge_projector.mark_projected(semantic);
                unprojected_definitions.push(semantic);
            }
        }
        SelectedRustSourceDefinitionProjection::Cancelled => {
            return Ok(false);
        }
    }
    Ok(true)
}
