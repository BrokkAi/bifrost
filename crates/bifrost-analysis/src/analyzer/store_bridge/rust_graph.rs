//! File-major native Rust graph projection inside one selected operation.

use crate::CancellationToken;
use crate::analyzer::IAnalyzer;
use crate::analyzer::resolution::*;
use crate::analyzer::resolution::{FactReferenceEdgeBatch, NativeReferenceEdgeBatchProjector};
use crate::analyzer::store::resolution_operation::graph_stage::{
    GraphStageAdapter, GraphStageAdmission, GraphStageGuard, GraphStageMetrics, GraphStageResult,
    run_graph_stages,
};
use crate::analyzer::store::resolution_operation::*;
use crate::analyzer::store::resolution_stage::SelectedResolutionStageOutcome;
use crate::analyzer::store::*;
use crate::analyzer::{Language, ProjectFile};
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
    stage: &'a mut dyn FnMut(&FactReferenceEdgeBatch) -> Result<()>,
}

impl GraphStageAdapter for RustGraphStageAdapter<'_> {
    type Unit = RustGraphStageUnit;
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
        &mut self,
        operation: &'operation SelectedResolutionOperation<'store, 'input>,
        unit: &Self::Unit,
        files: &[ProjectFile],
        _guard: &mut GraphStageGuard<'operation, 'store, Self::HelperTables<'operation>>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        _metrics: &mut GraphStageMetrics,
    ) -> Result<SelectedResolutionOperationOutcome<FactResolutionBatchSummary>> {
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
        operation.stage_rust_reference_edge_batches_in_files(
            self.analyzer,
            context,
            &crate_keys,
            &crate_files,
            maximum_batch_size,
            cancellation,
            context_metrics,
            &mut *self.stage,
        )
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
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        stage: &mut dyn FnMut(&FactReferenceEdgeBatch) -> Result<()>,
    ) -> Result<SelectedResolutionOperationOutcome<GraphStageResult>> {
        let mut adapter = RustGraphStageAdapter {
            project_root,
            analyzer,
            stage,
        };
        run_graph_stages(
            self,
            &mut adapter,
            files,
            maximum_batch_size,
            cancellation,
            context_metrics,
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
        // The macro walk's answers are this stage's, as its context and its
        // mounts are. They are keyed by file and the walk reads a file's whole
        // usage facts to answer them, identifier occurrences included, so a
        // whole-workspace request that kept them would hold every macro host
        // and every module above it at once. Dropping them here costs a reread
        // for a file two crates both compile and strands nothing.
        self.clear_selected_macro_walk_answers();
        // Generated facts belong to this crate stage. Clear their SQL rows
        // before preparing the next stage, while admission witnesses and
        // committed allocation counters remain request-owned.
        self.clear_selected_macro_overlay()?;
        if !self.ensure_selected_rust_inputs(cancellation)? {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
        let mut edge_projector = NativeReferenceEdgeBatchProjector::new(analyzer);
        let mut fragments = HashSet::default();
        let mut missing_files = Vec::new();
        // The request names the files. A graph build calls this once per crate,
        // so walking the selection here cost one pass over every selected file
        // per crate; seeking each requested file through the selection's path
        // index costs one probe per file the crate actually asked for.
        let mounts = self.mount_table();
        let mut macro_files = Vec::new();
        for file in files {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            let Some(mount) = mounts.mount_for_path("rust", &selected_path_key(file.rel_path()))?
            else {
                missing_files.push(file.clone());
                continue;
            };
            assert_eq!(mount.semantic_language(), Language::Rust);
            fragments.insert(mount.fragment());
            macro_files.push(file.rel_path());
            edge_projector
                .catalog_mut()
                .insert_file(mount.fragment(), file.clone())?;
        }
        if !missing_files.is_empty() {
            return Err(StoreError::new(format!(
                "admitted Rust graph files lack selected mounts: {missing_files:?}"
            )));
        }
        // A crate-declared macro item a file here names is defined by its
        // invoking file's capsule, which may be outside this graph's files.
        let macro_item_hosts = self.rust_macro_item_hosts(&macro_files)?;
        for host in &macro_item_hosts {
            if !macro_files.contains(&host.as_path()) {
                macro_files.push(host.as_path());
            }
        }
        match self.prepare_selected_macro_frontiers_for_files(&macro_files, cancellation)? {
            SelectedResolutionStageOutcome::Ready => {}
            SelectedResolutionStageOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            SelectedResolutionStageOutcome::Stale(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Stale(reason));
            }
            SelectedResolutionStageOutcome::Unavailable(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
            }
        }
        let context = match self.prepare_context(context, cancellation, context_metrics)? {
            SelectedResolutionContextValidationOutcome::Ready(context) => context,
            SelectedResolutionContextValidationOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
        };
        let ready = self.ready();
        // Definitions the projection could not answer at all. They are edge
        // endpoints this graph does not draw, and the summary carries one
        // incompleteness reason for each so a caller reading the graph knows
        // what it is missing rather than reading a store error instead of a
        // graph.
        let mut unprojected_definitions = Vec::new();
        let mut projection_cancelled = false;
        let trace = crate::profiling::enabled();
        let mut staged_batches = 0_usize;
        // Every membership read inside the stage binds into the staged crate's
        // dependency closure and nothing else. A reference in this crate
        // cannot resolve into a crate that depends on it, and opening those
        // blobs to find out is what the batch spent.
        let staged = self.with_rust_forward_crate_scope(crate_keys, cancellation, || {
            let persisted_lexical = ready
                .lexical_source()
                .with_forward_reference_fragments(&fragments);
            let persisted_typed = ready.typed_source();
            let observed_lexical = SeamProfiled::observing(&persisted_lexical);
            let observed_typed = SeamProfiled::observing(&persisted_typed);
            let blueprint = match ready.collect_blueprint(context, cancellation)? {
                SelectedFactOperationBlueprintConstruction::Ready(blueprint) => blueprint,
                SelectedFactOperationBlueprintConstruction::Cancelled { .. } => {
                    return Ok(None);
                }
            };
            if matches!(
                ready.register_context(&blueprint, cancellation)?,
                ContextRegistrationOutcome::Cancelled
            ) {
                return Ok(None);
            }
            Ok(Some(ready.with_rust_workspace_fact_operation(
                &blueprint,
                &observed_lexical,
                &observed_typed,
                cancellation,
                |facts| {
                    facts.stage_all_reference_batches(maximum_batch_size, &mut |batch| {
                        if cancellation.is_cancelled() {
                            projection_cancelled = true;
                            return Ok(());
                        }
                        if trace && (staged_batches == 0 || staged_batches.is_power_of_two()) {
                            crate::profiling::note(format!(
                                "rust graph stage batch={staged_batches}"
                            ));
                        }
                        staged_batches += 1;
                        let projection_facts =
                            persisted_lexical.reference_projection_facts(batch, cancellation)?;
                        if cancellation.is_cancelled() {
                            projection_cancelled = true;
                            return Ok(());
                        }
                        edge_projector
                            .catalog_mut()
                            .replace_reference_facts(projection_facts);
                        let definitions = edge_projector.pending_definitions(batch);
                        match project_rust_source_definitions(
                            ready,
                            self.mount_table(),
                            &definitions,
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
                                        | SelectedRustSourceDefinition::WithoutUnit { .. } => {
                                            edge_projector
                                                .catalog_mut()
                                                .insert_out_of_graph_declaration(semantic)
                                        }
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
                                for semantic in definitions {
                                    edge_projector
                                        .catalog_mut()
                                        .insert_out_of_graph_declaration(semantic);
                                    edge_projector.mark_projected(semantic);
                                    unprojected_definitions.push(semantic);
                                }
                            }
                            SelectedRustSourceDefinitionProjection::Cancelled => {
                                projection_cancelled = true;
                                return Ok(());
                            }
                        }
                        let projected = edge_projector.project_batch(batch, cancellation)?;
                        stage(&projected)
                    })
                },
            )?))
        })?;
        if trace {
            crate::profiling::note(format!(
                "rust graph stage complete batches={staged_batches}"
            ));
        }
        let Some(mut summary) = staged else {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        };
        if projection_cancelled || cancellation.is_cancelled() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
        if !unprojected_definitions.is_empty() {
            crate::profiling::note(format!(
                "rust graph definitions without a canonical source projection: \
                 {unprojected_definitions:?}"
            ));
            summary.include_completion(&ResolutionCompletion::incomplete(
                unprojected_definitions
                    .into_iter()
                    .map(ResolutionIncompleteReason::UnsupportedSemantic),
            ));
        }
        Ok(SelectedResolutionOperationOutcome::Native(summary))
    }
}
