//! Query-local graph unit assembly, publication and edge projection.

use crate::CancellationToken;
use crate::analyzer::ProjectFile;
use crate::analyzer::resolution::fact_resolution::SelectedFactOperationBlueprint;
use crate::analyzer::resolution::*;
use crate::analyzer::resolution::{FactReferenceEdgeBatch, NativeReferenceEdgeBatchProjector};
use crate::analyzer::store::resolution_operation::*;
use crate::analyzer::store::*;
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

pub(crate) struct GraphUnitFile<'a> {
    pub file: &'a ProjectFile,
    pub path: String,
    pub fragment: BindingFragmentId,
}

/// Hooks retain language authority and forward-operation lifetime. The shared
/// kernel owns context assembly, publication and the projection lifecycle.
pub(crate) trait GraphUnitRules {
    fn storage_language(&self) -> &'static str;

    fn before_unit(
        &mut self,
        _operation: &SelectedResolutionOperation<'_, '_>,
        _files: &[ProjectFile],
        _cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<()>> {
        Ok(SelectedResolutionOperationOutcome::Native(()))
    }

    /// None means this file contributes to an already prepared unit context.
    fn prepare_file_context(
        &mut self,
        operation: &SelectedResolutionOperation<'_, '_>,
        path: &str,
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<Option<SelectedResolutionContextSet>>>;

    fn projection_memo<'a>(
        &self,
        _operation: &'a SelectedResolutionOperation<'_, '_>,
    ) -> Option<&'a ContextBlueprintMemo> {
        None
    }

    fn with_unit_scope<T>(
        &self,
        _operation: &SelectedResolutionOperation<'_, '_>,
        run: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        run()
    }

    #[allow(clippy::too_many_arguments)]
    fn stage_unit_batches(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        blueprint: &SelectedFactOperationBlueprint,
        files: &[GraphUnitFile<'_>],
        lexical: &dyn BatchResolutionFragmentSource,
        typed: &dyn SelectedTypedFactSource,
        session: &ResolutionSession,
        cancellation: &CancellationToken,
        maximum_batch_size: usize,
        sink: &mut dyn FnMut(&FactReferenceBatchAnswer) -> Result<()>,
    ) -> Result<FactResolutionBatchSummary>;
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn stage_unit_reference_edges(
    operation: &SelectedResolutionOperation<'_, '_>,
    rules: &mut impl GraphUnitRules,
    files: &[ProjectFile],
    maximum_batch_size: usize,
    cancellation: &CancellationToken,
    context_metrics: &mut SelectedResolutionContextMetrics,
    projector: &mut NativeReferenceEdgeBatchProjector<'_>,
    mut project_definitions: impl FnMut(
        &mut NativeReferenceEdgeBatchProjector<'_>,
        &[SemanticId],
        &ResolutionSession,
        &mut Vec<SemanticId>,
    ) -> Result<bool>,
    mut stage: impl FnMut(
        &ProjectFile,
        &FactReferenceBatchAnswer,
        &FactReferenceEdgeBatch,
        &mut NativeReferenceEdgeBatchProjector<'_>,
    ) -> Result<bool>,
) -> Result<SelectedResolutionOperationOutcome<FactResolutionBatchSummary>> {
    assert!((1..=MAX_REFERENCE_SEEDS_PER_BATCH).contains(&maximum_batch_size));
    macro_rules! native {
        ($value:expr) => {
            match $value? {
                SelectedResolutionOperationOutcome::Native(value) => value,
                SelectedResolutionOperationOutcome::Cancelled(reason) => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(reason))
                }
                SelectedResolutionOperationOutcome::Unavailable(reason) => {
                    return Ok(SelectedResolutionOperationOutcome::Unavailable(reason))
                }
                SelectedResolutionOperationOutcome::Stale(reason) => {
                    return Ok(SelectedResolutionOperationOutcome::Stale(reason))
                }
            }
        };
    }
    native!(rules.before_unit(operation, files, cancellation));
    let mounts = operation.mount_table();
    let mut context: Option<SelectedResolutionContextSet> = None;
    for file in files {
        if cancellation.is_cancelled() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
        let path = selected_path_key(file.rel_path());
        if let Some(prepared) = native!(rules.prepare_file_context(operation, &path, cancellation))
        {
            context = Some(if let Some(existing) = context.take() {
                let Some(merged) = existing.merge(prepared, cancellation, &|fragment| {
                    Ok(mounts
                        .mount_for_fragment(fragment)?
                        .map(|mount| (mount.ordinal(), mount.semantic_language())))
                })?
                else {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    ));
                };
                merged
            } else {
                prepared
            });
        }
    }
    let context = match operation.prepare_context(
        context.expect("a graph stage has an admitted context"),
        cancellation,
        context_metrics,
    )? {
        SelectedResolutionContextValidationOutcome::Ready(context) => context,
        SelectedResolutionContextValidationOutcome::Cancelled => {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
    };
    let ready = operation.ready();
    rules.with_unit_scope(operation, || {
        // Publication keeps its own derivation session, as the old collect +
        // register chain did; projection and forward staging share a unit session.
        let Some(blueprint) = ready.publish_prepared_context(
            context,
            cancellation,
            &ResolutionSession::unbounded(),
            rules.projection_memo(operation),
            |blueprint| ready.register_context(blueprint, cancellation),
        )?
        else {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        };
        let mut unit_files = Vec::with_capacity(files.len());
        for file in files {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            let path = selected_path_key(file.rel_path());
            let Some(mount) = mounts.mount_for_path(rules.storage_language(), &path)? else {
                return Err(StoreError::new(format!(
                    "admitted graph file lacks selected {} mount: {file:?}",
                    rules.storage_language()
                )));
            };
            let fragment = mount.fragment();
            projector
                .catalog_mut()
                .insert_file(fragment, file.clone())?;
            unit_files.push(GraphUnitFile {
                file,
                path,
                fragment,
            });
        }
        let files_by_fragment = unit_files
            .iter()
            .map(|file| (file.fragment, file.file))
            .collect::<HashMap<_, _>>();
        let fragments = unit_files
            .iter()
            .map(|file| file.fragment)
            .collect::<HashSet<_>>();
        let lexical = ready
            .lexical_source()
            .with_forward_reference_fragments(&fragments);
        let typed = ready.typed_source();
        let observed_lexical = SeamProfiled::observing(&lexical);
        let observed_typed = SeamProfiled::observing(&typed);
        let session = ResolutionSession::unbounded();
        let mut unprojected = Vec::new();
        let mut projection_cancelled = false;
        let mut summary = rules.stage_unit_batches(
            operation,
            &blueprint,
            &unit_files,
            &observed_lexical,
            &observed_typed,
            &session,
            cancellation,
            maximum_batch_size,
            &mut |batch| {
                if cancellation.is_cancelled() {
                    projection_cancelled = true;
                    return Ok(());
                }
                let projection_facts = ready
                    .lexical_source()
                    .reference_projection_facts(batch, cancellation)?;
                if cancellation.is_cancelled() {
                    projection_cancelled = true;
                    return Ok(());
                }
                projector
                    .catalog_mut()
                    .replace_reference_facts(projection_facts);
                let definitions = projector.pending_definitions(batch);
                if !project_definitions(projector, &definitions, &session, &mut unprojected)? {
                    projection_cancelled = true;
                    return Ok(());
                }
                let projected = projector.project_batch(batch, cancellation)?;
                let file = files_by_fragment
                    .get(&batch.fragment())
                    .expect("a staged reference batch belongs to an admitted unit file");
                if !stage(file, batch, &projected, projector)? {
                    projection_cancelled = true;
                }
                Ok(())
            },
        )?;
        if projection_cancelled || cancellation.is_cancelled() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
        if !unprojected.is_empty() {
            summary.include_completion(&ResolutionCompletion::incomplete(
                unprojected
                    .into_iter()
                    .map(ResolutionIncompleteReason::UnsupportedSemantic),
            ));
        }
        Ok(SelectedResolutionOperationOutcome::Native(summary))
    })
}

pub(crate) fn project_native_graph_definitions(
    ready: &ReadySelectedResolution<'_, '_>,
    edge_projector: &mut NativeReferenceEdgeBatchProjector<'_>,
    definitions: &[SemanticId],
    cancellation: &CancellationToken,
    projection_session: &ResolutionSession,
    unprojected_definitions: &mut Vec<SemanticId>,
) -> Result<bool> {
    let selected_lexical = ready.lexical_source();
    let mut source_definitions = Vec::new();
    for &definition in definitions {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let Some(provenance) = selected_lexical.semantic_provenance(definition, cancellation)?
        else {
            return Ok(false);
        };
        if matches!(provenance, SelectedSemanticProvenance::FragmentLocal(_)) {
            source_definitions.push(definition);
        } else {
            edge_projector
                .catalog_mut()
                .insert_out_of_graph_declaration(definition);
            edge_projector.mark_projected(definition);
        }
    }
    if !source_definitions.is_empty() {
        match crate::analyzer::store::resolution_operation::native_units::project_native_definition_units(
                            ready,
                            &source_definitions,
                            cancellation,
                            projection_session,
                        )? {
                            SelectedNativeDefinitions::Ready(definitions) => {
                                for (semantic, definition) in definitions {
                                    match definition {
                                        SelectedNativeDefinition::Unit(unit) => edge_projector
                                            .catalog_mut()
                                            .insert_graph_declaration(semantic, unit)?,
                                        SelectedNativeDefinition::Lexical(_)
                                        | SelectedNativeDefinition::Intrinsic { .. } => {
                                            edge_projector
                                                .catalog_mut()
                                                .insert_out_of_graph_declaration(semantic)
                                        }
                                    }
                                    edge_projector.mark_projected(semantic);
                                }
                            }
                            SelectedNativeDefinitions::Unavailable => {
                                for semantic in source_definitions {
                                    match crate::analyzer::store::resolution_operation::native_units::project_native_definition_units(
                                        ready,
                                        std::slice::from_ref(&semantic),
                                        cancellation,
                                        projection_session,
                                    )? {
                                        SelectedNativeDefinitions::Ready(definitions) => {
                                            for (semantic, definition) in definitions {
                                                match definition {
                                                    SelectedNativeDefinition::Unit(unit) => {
                                                        edge_projector
                                                            .catalog_mut()
                                                            .insert_graph_declaration(
                                                                semantic, unit,
                                                            )?
                                                    }
                                                    SelectedNativeDefinition::Lexical(_)
                                                    | SelectedNativeDefinition::Intrinsic {
                                                        ..
                                                    } => edge_projector
                                                        .catalog_mut()
                                                        .insert_out_of_graph_declaration(semantic),
                                                }
                                                edge_projector.mark_projected(semantic);
                                            }
                                        }
                                        SelectedNativeDefinitions::Unavailable => {
                                            edge_projector
                                                .catalog_mut()
                                                .insert_out_of_graph_declaration(semantic);
                                            edge_projector.mark_projected(semantic);
                                            unprojected_definitions.push(semantic);
                                        }
                                        SelectedNativeDefinitions::Cancelled => {
                                            return Ok(false);
                                        }
                                    }
                                }
                            }
                            SelectedNativeDefinitions::Cancelled => {
                                return Ok(false);
                            }
                        }
    }
    Ok(true)
}
