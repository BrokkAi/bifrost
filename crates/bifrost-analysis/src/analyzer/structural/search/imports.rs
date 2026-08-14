use super::*;

pub(super) fn push_seed_provider_omission(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    language: Language,
    file: &ProjectFile,
    unavailable: &str,
) {
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: language.config_label(),
        message: format!(
            "structural seed omitted {} because its provider returned no {unavailable}",
            rel_path_string(file)
        ),
    });
}

pub(super) fn acquire_direct_import_layer(
    state: &mut QueryExecutionState<'_>,
    request: DerivedLayerRequest,
    limits: CodeQueryExecutionLimits,
    layer_requested: bool,
) -> Option<DerivedLayerLifecycle> {
    let Some(cache) = state
        .analyzer
        .snapshot_caches()
        .map(crate::analyzer::AnalyzerSnapshotCaches::derived_layers)
    else {
        if let Some(profile) = &mut state.cache_profile {
            let topology = &mut profile.direct_import_topology;
            topology.lookups = topology.lookups.saturating_add(1);
            topology.misses = topology.misses.saturating_add(1);
            topology.unavailable = topology.unavailable.saturating_add(1);
            topology.fallbacks = topology.fallbacks.saturating_add(1);
        }
        if layer_requested && state.access_mode == StructuralAccessMode::IndexedRequired {
            state
                .access_failure
                .get_or_insert_with(|| "analyzer has no snapshot derived-layer cache".to_string());
        }
        return None;
    };
    let uncancelled = CancellationToken::default();
    let cancellation = state.cancellation.unwrap_or(&uncancelled);
    let source_generations = state.analyzer.snapshot_source_generations();
    if state
        .direct_import_layer_generations
        .as_deref()
        .is_some_and(|generations| generations != source_generations.as_ref())
    {
        state.direct_import_layer = None;
        state.direct_import_layer_generations = None;
    }
    let ready = cache.get_ready(request, &source_generations, cancellation);
    let mut fallback_graph = None;
    let remaining_import_files = limits
        .max_scanned_files
        .saturating_sub(state.budget.import_files_resolved);
    let remaining_import_edges = limits
        .max_pipeline_rows
        .saturating_sub(state.budget.import_edges_resolved);
    let acquisition = match ready {
        Some(layer)
            if state
                .analyzer
                .snapshot_generations_match(&source_generations) =>
        {
            DerivedLayerAcquisition::Ready {
                layer,
                lifecycle: DerivedLayerLifecycle::Hit,
                wait: Default::default(),
                build: DerivedLayerBuildMetrics::default(),
            }
        }
        Some(_) => DerivedLayerAcquisition::Unavailable {
            reason: "derived-layer source generation changed before reuse".to_string(),
            over_budget: false,
            rejection_scope: None,
            wait: Default::default(),
            build: DerivedLayerBuildMetrics::default(),
        },
        None if !layer_requested
            || (state.access_mode.uses_snapshot_import_auto_admission()
                && (state.deferred_derived_builds.contains(&request)
                    || !cache.observe_auto_reuse_opportunity(
                        request,
                        &source_generations,
                        remaining_import_files,
                        remaining_import_edges,
                    ))) =>
        {
            if layer_requested && state.access_mode.uses_snapshot_import_auto_admission() {
                state.deferred_derived_builds.insert(request);
            }
            if let Some(profile) = &mut state.cache_profile {
                let topology = &mut profile.direct_import_topology;
                topology.lookups = topology.lookups.saturating_add(1);
                topology.misses = topology.misses.saturating_add(1);
                topology.fallbacks = topology.fallbacks.saturating_add(1);
            }
            return None;
        }
        None => cache.acquire(
            request,
            &source_generations,
            cancellation,
            || {
                let build = build_direct_import_topology(
                    state.analyzer,
                    cancellation,
                    DirectImportTopologyLimits {
                        max_files: remaining_import_files,
                        max_edges: remaining_import_edges,
                        max_retained_bytes: cache.max_retained_bytes(),
                    },
                );
                fallback_graph = build.fallback;
                build.outcome
            },
            || {
                state
                    .analyzer
                    .snapshot_generations_match(&source_generations)
            },
        ),
    };

    let (wait, build) = match &acquisition {
        DerivedLayerAcquisition::Ready { wait, build, .. }
        | DerivedLayerAcquisition::Cancelled { wait, build }
        | DerivedLayerAcquisition::Unavailable { wait, build, .. } => (*wait, *build),
    };
    state.budget.import_files_resolved = state
        .budget
        .import_files_resolved
        .saturating_add(usize::try_from(build.resolved_files).unwrap_or(usize::MAX));
    state.budget.import_edges_resolved = state
        .budget
        .import_edges_resolved
        .saturating_add(usize::try_from(build.resolved_edges).unwrap_or(usize::MAX));
    if let Some(profile) = &mut state.cache_profile {
        let topology = &mut profile.direct_import_topology;
        topology.lookups = topology.lookups.saturating_add(1);
        topology.waits = topology.waits.saturating_add(wait.waits);
        topology.wait_ns = topology.wait_ns.saturating_add(wait.wait_ns);
        topology.build_files = topology.build_files.saturating_add(build.resolved_files);
        topology.build_edges = topology.build_edges.saturating_add(build.resolved_edges);
        topology.build_ns = topology.build_ns.saturating_add(build.elapsed_ns);
    }

    match acquisition {
        DerivedLayerAcquisition::Ready { lifecycle, .. }
            if !state
                .analyzer
                .snapshot_generations_match(&source_generations) =>
        {
            if let Some(profile) = &mut state.cache_profile {
                let topology = &mut profile.direct_import_topology;
                topology.misses = topology.misses.saturating_add(1);
                topology.unavailable = topology.unavailable.saturating_add(1);
                topology.fallbacks = topology.fallbacks.saturating_add(1);
                topology.builds = topology
                    .builds
                    .saturating_add(u64::from(lifecycle == DerivedLayerLifecycle::Built));
            }
            if layer_requested && state.access_mode == StructuralAccessMode::IndexedRequired {
                state.access_failure.get_or_insert_with(|| {
                    "derived-layer source generation changed before selection".to_string()
                });
            }
            state.direct_import_layer = None;
            state.direct_import_layer_generations = None;
            None
        }
        DerivedLayerAcquisition::Ready {
            layer, lifecycle, ..
        } => {
            if let Some(profile) = &mut state.cache_profile {
                let topology = &mut profile.direct_import_topology;
                match lifecycle {
                    DerivedLayerLifecycle::Hit => {
                        topology.hits = topology.hits.saturating_add(1);
                        topology.complete_hits = topology.complete_hits.saturating_add(1);
                        topology.replayed_items = topology.replayed_items.saturating_add(
                            u64::try_from(layer.direct_import_topology().resolved_edges())
                                .unwrap_or(u64::MAX),
                        );
                    }
                    DerivedLayerLifecycle::Built => {
                        topology.misses = topology.misses.saturating_add(1);
                        topology.builds = topology.builds.saturating_add(1);
                        topology.complete_builds = topology.complete_builds.saturating_add(1);
                    }
                }
                let first_observation =
                    state.retained_value_census.as_ref().is_some_and(|census| {
                        census
                            .first_observation(QueryRetainedValueKind::DirectImportTopology, &layer)
                    });
                if first_observation {
                    topology.retained_bytes = topology
                        .retained_bytes
                        .saturating_add(layer.direct_import_topology().retained_bytes());
                }
            }
            state.direct_import_layer = Some(layer);
            state.direct_import_layer_generations = Some(source_generations);
            Some(lifecycle)
        }
        DerivedLayerAcquisition::Cancelled { .. } => {
            if let Some(profile) = &mut state.cache_profile {
                let topology = &mut profile.direct_import_topology;
                topology.misses = topology.misses.saturating_add(1);
                topology.cancelled = topology.cancelled.saturating_add(1);
                topology.fallbacks = topology.fallbacks.saturating_add(1);
                if build.elapsed_ns > 0 {
                    topology.builds = topology.builds.saturating_add(1);
                }
            }
            if layer_requested && state.access_mode == StructuralAccessMode::IndexedRequired {
                state.access_failure.get_or_insert_with(|| {
                    "direct import topology acquisition cancelled".to_string()
                });
            }
            None
        }
        DerivedLayerAcquisition::Unavailable {
            reason,
            over_budget,
            rejection_scope,
            ..
        } => {
            if let Some(graph) = fallback_graph
                && state
                    .analyzer
                    .snapshot_generations_match(&source_generations)
            {
                state.import_graph = Some(graph);
                state.import_graph_generations = Some(source_generations.clone());
            }
            if let Some(rejection_scope) = rejection_scope
                && state.access_mode.uses_snapshot_import_auto_admission()
            {
                cache.record_auto_rejection(
                    request,
                    &source_generations,
                    remaining_import_files,
                    remaining_import_edges,
                    rejection_scope,
                );
            }
            if let Some(profile) = &mut state.cache_profile {
                let topology = &mut profile.direct_import_topology;
                topology.misses = topology.misses.saturating_add(1);
                topology.unavailable = topology.unavailable.saturating_add(1);
                topology.over_budget = topology.over_budget.saturating_add(u64::from(over_budget));
                topology.fallbacks = topology.fallbacks.saturating_add(1);
                if build.elapsed_ns > 0 {
                    topology.builds = topology.builds.saturating_add(1);
                }
            }
            if layer_requested && state.access_mode == StructuralAccessMode::IndexedRequired {
                state.access_failure.get_or_insert(reason);
            }
            None
        }
    }
}

pub(super) fn discard_stale_direct_import_layer(
    state: &mut QueryExecutionState<'_>,
    required: bool,
) {
    let Some(layer_generations) = state.direct_import_layer_generations.as_deref() else {
        return;
    };
    if state.analyzer.snapshot_generations_match(layer_generations) {
        return;
    }
    state.direct_import_layer = None;
    state.direct_import_layer_generations = None;
    if let Some(profile) = &mut state.cache_profile {
        let topology = &mut profile.direct_import_topology;
        topology.unavailable = topology.unavailable.saturating_add(1);
        topology.fallbacks = topology.fallbacks.saturating_add(1);
    }
    if required && state.access_mode == StructuralAccessMode::IndexedRequired {
        state
            .access_failure
            .get_or_insert_with(|| "direct import topology became stale before use".to_string());
    }
}

pub(super) fn discard_stale_request_import_graph(state: &mut QueryExecutionState<'_>) {
    let Some(generations) = state.import_graph_generations.as_deref() else {
        return;
    };
    if state.analyzer.snapshot_generations_match(generations) {
        return;
    }
    state.import_graph = None;
    state.import_graph_generations = None;
}

pub(super) fn record_direct_import_fallback(
    state: &mut QueryExecutionState<'_>,
    reason: &str,
    required: bool,
) {
    if let Some(profile) = &mut state.cache_profile {
        profile.direct_import_topology.fallbacks =
            profile.direct_import_topology.fallbacks.saturating_add(1);
    }
    if required && state.access_mode == StructuralAccessMode::IndexedRequired {
        state
            .access_failure
            .get_or_insert_with(|| reason.to_string());
    }
}
