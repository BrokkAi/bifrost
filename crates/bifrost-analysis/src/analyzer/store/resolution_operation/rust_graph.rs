//! File-major native Rust graph projection inside one selected operation.

use super::*;
use crate::analyzer::IAnalyzer;
use crate::analyzer::resolution::{
    FactReferenceEdgeBatch, FactReferenceEdgeCatalog, project_fact_reference_edge_batch,
};
use crate::analyzer::structural::reference_edges::OwnerRelationMemo;

impl SelectedResolutionOperation<'_, '_> {
    /// Remember this crate's export, placement and membership answers, and
    /// the publications it has checked, until the returned guard drops. A graph build takes one per crate, before it
    /// compiles the crate's context, so the context and the crate's batches
    /// share it: on tract_core 13,302 of the batches' 13,307 distinct export
    /// keys were already asked by the context.
    pub(crate) fn crate_stage_memos(&self) -> Result<super::rust_crate_rows::CrateStageMemos<'_>> {
        self.ready.crate_stage_memos()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stage_rust_reference_edge_batches_in_files(
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
        let mut catalog = FactReferenceEdgeCatalog::new(analyzer);
        // This stage's owner relations, keyed by site type. Dropped with the
        // stage, as the catalog is.
        let mut owner_relations = OwnerRelationMemo::default();
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
            catalog.insert_file(mount.fragment(), file.clone())?;
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
        let ready = &self.ready;
        let mut projected_definitions = HashSet::default();
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
                        let mut definitions = HashSet::default();
                        for answer in batch.answers() {
                            definitions.extend(answer.answer().binding().targets().iter().copied());
                            if let Some(owner) = answer
                                .site_metadata()
                                .and_then(|metadata| metadata.reference_owner())
                                .flatten()
                            {
                                definitions.insert(owner);
                            }
                        }
                        let definitions = definitions
                            .into_iter()
                            .filter(|definition| !projected_definitions.contains(definition))
                            .collect::<Vec<_>>();
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
                                        SelectedRustSourceDefinition::Unit(unit) => {
                                            catalog.insert_graph_declaration(semantic, unit)?
                                        }
                                        // A lexical binding has no `CodeUnit`, and
                                        // neither has an item the parser could not
                                        // name. The graph's nodes are `CodeUnit`s,
                                        // so both are edge endpoints the graph
                                        // cannot draw, not failures of the request.
                                        SelectedRustSourceDefinition::Lexical(_)
                                        | SelectedRustSourceDefinition::WithoutUnit { .. } => {
                                            catalog.insert_out_of_graph_declaration(semantic)
                                        }
                                    }
                                    assert!(projected_definitions.insert(semantic));
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
                                    catalog.insert_out_of_graph_declaration(semantic);
                                    assert!(projected_definitions.insert(semantic));
                                    unprojected_definitions.push(semantic);
                                }
                            }
                            SelectedRustSourceDefinitionProjection::Cancelled => {
                                projection_cancelled = true;
                                return Ok(());
                            }
                        }
                        let projected = project_fact_reference_edge_batch(
                            &catalog,
                            batch,
                            &mut owner_relations,
                            cancellation,
                        )?;
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
