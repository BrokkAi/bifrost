//! File-scoped native Go forward graph staging in one selected operation.

use super::go_named::{GoDemandContext, GoPackageStageUnit};
use super::go_same_package::GoPackageMemberIndexCache;
use super::graph_stage::{
    GraphStageAdapter, GraphStageGuard, GraphStageMetrics, GraphStageResult,
    MAX_GRAPH_STAGE_READ_BATCH_SIZE, run_graph_stages,
};
use super::*;
use crate::analyzer::resolution::{
    FactReferenceEdgeBatch, NativeReferenceEdgeBatchProjector, SelectedSemanticProvenance,
};
use crate::analyzer::store::resolution_selection::SelectedResolutionUnavailable;
use crate::analyzer::{CodeUnit, IAnalyzer};

pub(crate) struct GoReferenceBatchProjection {
    pub(crate) reference_owner: Option<CodeUnit>,
    pub(crate) binding_targets: Vec<Option<CodeUnit>>,
}

pub(crate) type GoReferenceEdgeBatchStager<'a> = dyn FnMut(
        &ProjectFile,
        &FactReferenceBatchAnswer,
        &FactReferenceEdgeBatch,
        &[GoReferenceBatchProjection],
    ) -> Result<()>
    + 'a;

struct GoGraphStageAdapter<'callback> {
    analyzer: &'callback dyn IAnalyzer,
    context_id: i64,
    stage: &'callback mut GoReferenceEdgeBatchStager<'callback>,
    unprojected_definitions: Vec<SemanticId>,
}

impl GraphStageAdapter for GoGraphStageAdapter<'_> {
    type Unit = GoPackageStageUnit;
    type HelperTables<'stage> = GoPackageMemberIndexCache;

    fn units(
        &self,
        operation: &SelectedResolutionOperation<'_, '_>,
        files: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionOperationOutcome<Vec<(Self::Unit, Vec<ProjectFile>)>>> {
        let mounts = operation.mount_table();
        let mut groups = BTreeMap::<GoPackageStageUnit, Vec<ProjectFile>>::new();
        for file in files {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            let path = selected_path_key(file.rel_path());
            let Some(mount) = mounts.mount_for_path("go", &path)? else {
                return Ok(SelectedResolutionOperationOutcome::Unavailable(
                    SelectedResolutionUnavailable::GoContextUnavailable {
                        persisted_relative_path: path,
                    },
                ));
            };
            assert_eq!(mount.semantic_language(), Language::Go);
            let Some(unit) =
                operation.go_package_stage_unit_for_path(self.context_id, &path, cancellation)?
            else {
                if cancellation.is_cancelled() {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    ));
                }
                return Ok(SelectedResolutionOperationOutcome::Unavailable(
                    SelectedResolutionUnavailable::GoContextUnavailable {
                        persisted_relative_path: path,
                    },
                ));
            };
            groups.entry(unit).or_default().push(file.clone());
        }
        for group in groups.values_mut() {
            group.sort();
            group.dedup();
        }
        Ok(SelectedResolutionOperationOutcome::Native(
            groups.into_iter().collect(),
        ))
    }

    fn helper_tables<'stage>(
        &self,
        _operation: &'stage SelectedResolutionOperation<'_, '_>,
        _unit: &Self::Unit,
    ) -> Result<Self::HelperTables<'stage>> {
        Ok(GoPackageMemberIndexCache::default())
    }

    #[allow(clippy::too_many_arguments)]
    fn run_unit<'operation, 'store, 'input>(
        &mut self,
        operation: &'operation SelectedResolutionOperation<'store, 'input>,
        unit: &Self::Unit,
        files: &[ProjectFile],
        guard: &mut GraphStageGuard<'operation, 'store, Self::HelperTables<'operation>>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        _metrics: &mut GraphStageMetrics,
    ) -> Result<SelectedResolutionOperationOutcome<FactResolutionBatchSummary>> {
        let mounts = operation.mount_table();
        let mut context: Option<SelectedResolutionContextSet> = None;
        let mut demand: Option<GoDemandContext> = None;
        for file in files {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            let path = selected_path_key(file.rel_path());
            let prepared = match operation.go_file_import_context_with_member_cache(
                unit.context_id,
                &path,
                &unit.source_role,
                cancellation,
                guard.helper_tables_mut(),
            )? {
                GoPreparedImportContextOutcome::Ready(prepared) => *prepared,
                GoPreparedImportContextOutcome::Unavailable => {
                    return Ok(SelectedResolutionOperationOutcome::Unavailable(
                        SelectedResolutionUnavailable::GoContextUnavailable {
                            persisted_relative_path: path,
                        },
                    ));
                }
                GoPreparedImportContextOutcome::Cancelled => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    ));
                }
            };
            context = Some(if let Some(existing) = context.take() {
                let Some(merged) = existing.merge(prepared.context, cancellation, &|fragment| {
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
                prepared.context
            });
            if let Some(demand) = demand.as_mut() {
                demand.merge(prepared.demand);
            } else {
                demand = Some(prepared.demand);
            }
        }
        let context = match operation.prepare_context(
            context.expect("a graph stage has at least one admitted file"),
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
        let demand = demand.expect("a graph stage has at least one admitted file");
        let ready = &operation.ready;
        let blueprint = match ready.collect_blueprint(context, cancellation)? {
            SelectedFactOperationBlueprintConstruction::Ready(blueprint) => blueprint,
            SelectedFactOperationBlueprintConstruction::Cancelled { .. } => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
        };
        if matches!(
            ready.register_context(&blueprint, cancellation)?,
            ContextRegistrationOutcome::Cancelled
        ) {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }

        let mut edge_projector = NativeReferenceEdgeBatchProjector::new(self.analyzer);
        let mut summary = FactResolutionBatchSummary::empty();
        let mut projection_cancelled = false;
        let projection_session = ResolutionSession::unbounded();
        let typed = ready.typed_source();
        let observed_typed = SeamProfiled::observing(&typed);
        let stager = &mut *self.stage;
        let root_batch_size = maximum_batch_size.min(MAX_GRAPH_STAGE_READ_BATCH_SIZE);
        for file in files {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            let path = selected_path_key(file.rel_path());
            let Some(mount) = mounts.mount_for_path("go", &path)? else {
                return Err(StoreError::new(format!(
                    "admitted Go graph file lacks selected mount: {file:?}"
                )));
            };
            assert_eq!(mount.semantic_language(), Language::Go);
            let fragment = mount.fragment();
            edge_projector
                .catalog_mut()
                .insert_file(fragment, file.clone())?;
            let mut fragments = HashSet::default();
            fragments.insert(fragment);
            let lexical = ready
                .lexical_source()
                .with_forward_reference_fragments(&fragments);
            let observed_lexical = SeamProfiled::observing(&lexical);
            let staged = operation.stage_go_reference_batches(
                GoForwardOperationContext {
                    blueprint: &blueprint,
                    demand: demand.clone(),
                    caller_path: &path,
                    lexical: &observed_lexical,
                    typed: &observed_typed,
                    cancellation,
                    session: &projection_session,
                },
                root_batch_size,
                &mut |batch| {
                    if cancellation.is_cancelled() {
                        projection_cancelled = true;
                        return Ok(());
                    }
                    let definitions = edge_projector.pending_definitions(batch);
                    let selected_lexical = ready.lexical_source();
                    let mut source_definitions = Vec::new();
                    for definition in definitions {
                        if cancellation.is_cancelled() {
                            projection_cancelled = true;
                            return Ok(());
                        }
                        let Some(provenance) =
                            selected_lexical.semantic_provenance(definition, cancellation)?
                        else {
                            projection_cancelled = true;
                            return Ok(());
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
                        match super::native_units::project_native_definition_units(
                            ready,
                            &source_definitions,
                            cancellation,
                            &projection_session,
                        )? {
                            SelectedNativeDefinitions::Ready(definitions) => {
                                for (semantic, definition) in definitions {
                                    match definition {
                                        SelectedNativeDefinition::Unit(unit) => edge_projector
                                            .catalog_mut()
                                            .insert_graph_declaration(semantic, unit)?,
                                        SelectedNativeDefinition::Lexical(_) => edge_projector
                                            .catalog_mut()
                                            .insert_out_of_graph_declaration(semantic),
                                    }
                                    edge_projector.mark_projected(semantic);
                                }
                            }
                            SelectedNativeDefinitions::Unavailable => {
                                for semantic in source_definitions {
                                    match super::native_units::project_native_definition_units(
                                        ready,
                                        std::slice::from_ref(&semantic),
                                        cancellation,
                                        &projection_session,
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
                                                    SelectedNativeDefinition::Lexical(_) => {
                                                        edge_projector
                                                            .catalog_mut()
                                                            .insert_out_of_graph_declaration(
                                                                semantic,
                                                            )
                                                    }
                                                }
                                                edge_projector.mark_projected(semantic);
                                            }
                                        }
                                        SelectedNativeDefinitions::Unavailable => {
                                            edge_projector
                                                .catalog_mut()
                                                .insert_out_of_graph_declaration(semantic);
                                            edge_projector.mark_projected(semantic);
                                            self.unprojected_definitions.push(semantic);
                                        }
                                        SelectedNativeDefinitions::Cancelled => {
                                            projection_cancelled = true;
                                            return Ok(());
                                        }
                                    }
                                }
                            }
                            SelectedNativeDefinitions::Cancelled => {
                                projection_cancelled = true;
                                return Ok(());
                            }
                        }
                    }
                    let projected = edge_projector.project_batch(batch, cancellation)?;
                    let mut projections = Vec::with_capacity(batch.answers().len());
                    for answer in batch.answers() {
                        if cancellation.is_cancelled() {
                            projection_cancelled = true;
                            return Ok(());
                        }
                        let reference_owner = match answer.reference_owner().flatten() {
                            Some(owner) => edge_projector
                                .catalog_mut()
                                .graph_declaration(owner)?
                                .cloned(),
                            None => None,
                        };
                        let mut binding_targets =
                            Vec::with_capacity(answer.answer().binding().targets().len());
                        for &target in answer.answer().binding().targets() {
                            if cancellation.is_cancelled() {
                                projection_cancelled = true;
                                return Ok(());
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
                    stager(file, batch, &projected, &projections)
                },
            )?;
            if projection_cancelled || cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            summary.accumulate(staged);
        }
        Ok(SelectedResolutionOperationOutcome::Native(summary))
    }
}

impl SelectedResolutionOperation<'_, '_> {
    /// Stage selected Go reference batches for the admitted caller files.
    ///
    /// Each file gets its own file-local package/import context, while the
    /// selected operation, declaration catalog, and owner memo remain
    /// request-scoped across the whole file set.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stage_go_reference_edge_batches_in_files(
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
    pub(crate) fn stage_go_graph_reference_edge_batches_in_files(
        &self,
        analyzer: &dyn IAnalyzer,
        context_id: i64,
        files: &HashSet<ProjectFile>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        stage: &mut GoReferenceEdgeBatchStager<'_>,
    ) -> Result<SelectedResolutionOperationOutcome<GraphStageResult>> {
        let files = files.iter().cloned().collect::<Vec<_>>();
        let mut adapter = GoGraphStageAdapter {
            analyzer,
            context_id,
            stage,
            unprojected_definitions: Vec::new(),
        };
        let mut outcome = run_graph_stages(
            self,
            &mut adapter,
            &files,
            maximum_batch_size,
            cancellation,
            context_metrics,
        )?;
        if let SelectedResolutionOperationOutcome::Native(result) = &mut outcome
            && !adapter.unprojected_definitions.is_empty()
        {
            result
                .summary
                .include_completion(&ResolutionCompletion::incomplete(
                    adapter
                        .unprojected_definitions
                        .drain(..)
                        .map(ResolutionIncompleteReason::UnsupportedSemantic),
                ));
        }
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
        let mounts = self.mount_table();
        let mut edge_projector = NativeReferenceEdgeBatchProjector::new(analyzer);
        let mut summary = FactResolutionBatchSummary::empty();
        let mut unprojected_definitions = Vec::new();
        let mut ordered_files = files.iter().cloned().collect::<Vec<_>>();
        ordered_files.sort();

        for file in &ordered_files {
            if cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            let path = selected_path_key(file.rel_path());
            let Some(mount) = mounts.mount_for_path("go", &path)? else {
                return Err(StoreError::new(format!(
                    "admitted Go graph file lacks selected mount: {file:?}"
                )));
            };
            assert_eq!(mount.semantic_language(), Language::Go);
            let fragment = mount.fragment();
            edge_projector
                .catalog_mut()
                .insert_file(fragment, file.clone())?;

            let prepared = match prepare_file_context(&path, cancellation)? {
                GoPreparedImportContextOutcome::Ready(context) => *context,
                GoPreparedImportContextOutcome::Unavailable => {
                    return Ok(SelectedResolutionOperationOutcome::Unavailable(
                        SelectedResolutionUnavailable::GoContextUnavailable {
                            persisted_relative_path: path,
                        },
                    ));
                }
                GoPreparedImportContextOutcome::Cancelled => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    ));
                }
            };
            let demand = prepared.demand;
            let context =
                match self.prepare_context(prepared.context, cancellation, context_metrics)? {
                    SelectedResolutionContextValidationOutcome::Ready(context) => context,
                    SelectedResolutionContextValidationOutcome::Cancelled => {
                        return Ok(SelectedResolutionOperationOutcome::Cancelled(
                            cancelled_completion(),
                        ));
                    }
                };
            let ready = &self.ready;
            let mut fragments = HashSet::default();
            fragments.insert(fragment);
            let lexical = ready
                .lexical_source()
                .with_forward_reference_fragments(&fragments);
            let observed_lexical = SeamProfiled::observing(&lexical);
            let typed = ready.typed_source();
            let observed_typed = SeamProfiled::observing(&typed);
            let blueprint = match ready.collect_blueprint(context, cancellation)? {
                SelectedFactOperationBlueprintConstruction::Ready(blueprint) => blueprint,
                SelectedFactOperationBlueprintConstruction::Cancelled { .. } => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancelled_completion(),
                    ));
                }
            };
            if matches!(
                ready.register_context(&blueprint, cancellation)?,
                ContextRegistrationOutcome::Cancelled
            ) {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }

            let mut projection_cancelled = false;
            let projection_session = ResolutionSession::unbounded();
            let staged = self.stage_go_reference_batches(
                GoForwardOperationContext {
                    blueprint: &blueprint,
                    demand,
                    caller_path: &path,
                    lexical: &observed_lexical,
                    typed: &observed_typed,
                    cancellation,
                    session: &projection_session,
                },
                maximum_batch_size,
                &mut |batch| {
                    if cancellation.is_cancelled() {
                        projection_cancelled = true;
                        return Ok(());
                    }
                    let definitions = edge_projector.pending_definitions(batch);
                    let selected_lexical = ready.lexical_source();
                    let mut source_definitions = Vec::new();
                    for definition in definitions {
                        if cancellation.is_cancelled() {
                            projection_cancelled = true;
                            return Ok(());
                        }
                        let Some(provenance) =
                            selected_lexical.semantic_provenance(definition, cancellation)?
                        else {
                            projection_cancelled = true;
                            return Ok(());
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
                        match super::native_units::project_native_definition_units(
                            ready,
                            &source_definitions,
                            cancellation,
                            &projection_session,
                        )? {
                            SelectedNativeDefinitions::Ready(definitions) => {
                                for (semantic, definition) in definitions {
                                    match definition {
                                        SelectedNativeDefinition::Unit(unit) => edge_projector
                                            .catalog_mut()
                                            .insert_graph_declaration(semantic, unit)?,
                                        SelectedNativeDefinition::Lexical(_) => edge_projector
                                            .catalog_mut()
                                            .insert_out_of_graph_declaration(semantic),
                                    }
                                    edge_projector.mark_projected(semantic);
                                }
                            }
                            SelectedNativeDefinitions::Unavailable => {
                                // One declaration outside the source-backed
                                // CodeUnit domain must not prevent other
                                // definitions in this reference batch from
                                // being projected. In particular, each
                                // reference owner needs its own canonical
                                // projection for providers that attribute
                                // source sites to their enclosing callable.
                                for semantic in source_definitions {
                                    match super::native_units::project_native_definition_units(
                                        ready,
                                        std::slice::from_ref(&semantic),
                                        cancellation,
                                        &projection_session,
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
                                                    SelectedNativeDefinition::Lexical(_) => {
                                                        edge_projector
                                                            .catalog_mut()
                                                            .insert_out_of_graph_declaration(
                                                                semantic,
                                                            )
                                                    }
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
                                            projection_cancelled = true;
                                            return Ok(());
                                        }
                                    }
                                }
                            }
                            SelectedNativeDefinitions::Cancelled => {
                                projection_cancelled = true;
                                return Ok(());
                            }
                        }
                    }
                    let projected = edge_projector.project_batch(batch, cancellation)?;
                    let mut projections = Vec::with_capacity(batch.answers().len());
                    for answer in batch.answers() {
                        if cancellation.is_cancelled() {
                            projection_cancelled = true;
                            return Ok(());
                        }
                        let reference_owner = match answer.reference_owner().flatten() {
                            Some(owner) => edge_projector
                                .catalog_mut()
                                .graph_declaration(owner)?
                                .cloned(),
                            None => None,
                        };
                        let mut binding_targets =
                            Vec::with_capacity(answer.answer().binding().targets().len());
                        for &target in answer.answer().binding().targets() {
                            if cancellation.is_cancelled() {
                                projection_cancelled = true;
                                return Ok(());
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
                    stage(file, batch, &projected, &projections)
                },
            )?;
            if projection_cancelled || cancellation.is_cancelled() {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            summary.accumulate(staged);
        }

        if !unprojected_definitions.is_empty() {
            summary.include_completion(&ResolutionCompletion::incomplete(
                unprojected_definitions
                    .into_iter()
                    .map(ResolutionIncompleteReason::UnsupportedSemantic),
            ));
        }
        Ok(SelectedResolutionOperationOutcome::Native(summary))
    }
}
