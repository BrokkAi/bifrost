use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_plan_step(
    step: &QueryStep,
    derived_layer_request: Option<DerivedLayerRequest>,
    final_in_authored_suffix: bool,
    rows: Vec<PipelineRow>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    terminal_cap: Option<usize>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    instrumentation: Option<&mut QueryStepInstrumentation>,
) -> PlanExecution {
    let mut truncated = false;
    if state
        .cancellation
        .is_some_and(CancellationToken::is_cancelled)
    {
        return PlanExecution {
            rows: Vec::new(),
            truncated: true,
            cancelled: true,
            pipeline_halted: false,
        };
    }
    let mut use_snapshot_imports = false;
    let mut snapshot_lifecycle = None;
    let mut snapshot_relation_complete = true;
    if !rows.is_empty() && matches!(step, QueryStep::ImportsOf | QueryStep::ImportersOf) {
        discard_stale_request_import_graph(state);
        if state.access_mode.permits_snapshot_import_topology() {
            let request = derived_layer_request
                .unwrap_or_else(DerivedLayerRequest::complete_direct_import_topology);
            let build_if_missing = derived_layer_request.is_some();
            snapshot_lifecycle =
                acquire_direct_import_layer(state, request, limits, build_if_missing);
        }
        discard_stale_direct_import_layer(state, derived_layer_request.is_some());
        if let Some(topology) = state
            .direct_import_layer
            .as_deref()
            .map(DerivedLayer::direct_import_topology)
        {
            let within_request_budget = topology.resolved_files() <= limits.max_scanned_files
                && topology.resolved_edges() <= limits.max_pipeline_rows;
            let relation_complete =
                step == &QueryStep::ImportsOf || topology.reverse_relation_complete();
            use_snapshot_imports = within_request_budget;
            snapshot_relation_complete = relation_complete;
            if !within_request_budget || !relation_complete {
                record_direct_import_fallback(
                    state,
                    "complete direct import topology cannot satisfy this request",
                    derived_layer_request.is_some(),
                );
            }
        }

        if use_snapshot_imports {
            let topology = state
                .direct_import_layer
                .as_deref()
                .expect("snapshot import layer was selected")
                .direct_import_topology();
            let replayed_edges = rows
                .iter()
                .filter_map(|row| match &row.value {
                    PipelineValue::File(file) if step == &QueryStep::ImportersOf => {
                        Some(topology.known_importer_count(file))
                    }
                    PipelineValue::File(file) => topology.import_count(file),
                    PipelineValue::StructuralMatch(_)
                    | PipelineValue::Declaration(_)
                    | PipelineValue::Semantic(_)
                    | PipelineValue::ReferenceSite(_)
                    | PipelineValue::CallSite(_)
                    | PipelineValue::ExpressionSite(_)
                    | PipelineValue::ReceiverAnalysis(_)
                    | PipelineValue::ReceiverOutcome(_)
                    | PipelineValue::ReceiverEvidence(_)
                    | PipelineValue::CallShape(_)
                    | PipelineValue::CallArgumentGroup(_)
                    | PipelineValue::CallArgument(_)
                    | PipelineValue::MemberSelection(_)
                    | PipelineValue::Occurrence(_)
                    | PipelineValue::LexicalScope(_)
                    | PipelineValue::Binding(_)
                    | PipelineValue::ResolutionCandidate(_)
                    | PipelineValue::CandidateHop(_)
                    | PipelineValue::DispatchOutcome(_)
                    | PipelineValue::DispatchTarget(_)
                    | PipelineValue::MemberFamily(_)
                    | PipelineValue::MemberFamilyEdge(_)
                    | PipelineValue::GenerationSite(_)
                    | PipelineValue::Export(_)
                    | PipelineValue::DeclarationState(_)
                    | PipelineValue::ReferenceEdge(_) => None,
                    PipelineValue::QualifiedPath(_) | PipelineValue::PathSegment(_) => None,
                })
                .sum();
            if let Some(profile) = &mut state.cache_profile {
                let relation = if step == &QueryStep::ImportersOf {
                    &mut profile.import_reverse
                } else {
                    &mut profile.import_forward
                };
                if snapshot_lifecycle == Some(DerivedLayerLifecycle::Built) {
                    relation.record_miss();
                    relation.record_build(Some(snapshot_relation_complete));
                } else {
                    relation.record_hit(Some(snapshot_relation_complete), replayed_edges);
                }
            }
        } else {
            if state.import_graph.is_none() {
                state.import_graph = Some(RequestLocalDirectImportGraph::new(state.analyzer));
                state.import_graph_generations = Some(state.analyzer.snapshot_source_generations());
            }
            let graph = state
                .import_graph
                .as_mut()
                .expect("request import graph was initialized");
            let graph_exhausted = if step == &QueryStep::ImportersOf {
                let cache_observation = state
                    .cache_profile
                    .as_ref()
                    .map(|_| (graph.is_complete(), graph.reverse_relation_complete()));
                if let (Some(profile), Some((cache_hit, cache_complete))) =
                    (&mut state.cache_profile, cache_observation)
                {
                    if cache_hit {
                        let replayed_edges = rows
                            .iter()
                            .filter_map(|row| match &row.value {
                                PipelineValue::File(file) => Some(graph.importer_count(file)),
                                PipelineValue::StructuralMatch(_)
                                | PipelineValue::Declaration(_)
                                | PipelineValue::Semantic(_)
                                | PipelineValue::ReferenceSite(_)
                                | PipelineValue::CallSite(_)
                                | PipelineValue::ExpressionSite(_)
                                | PipelineValue::ReceiverAnalysis(_)
                                | PipelineValue::ReceiverOutcome(_)
                                | PipelineValue::ReceiverEvidence(_)
                                | PipelineValue::CallShape(_)
                                | PipelineValue::CallArgumentGroup(_)
                                | PipelineValue::CallArgument(_)
                                | PipelineValue::MemberSelection(_)
                                | PipelineValue::Occurrence(_)
                                | PipelineValue::LexicalScope(_)
                                | PipelineValue::Binding(_)
                                | PipelineValue::ResolutionCandidate(_)
                                | PipelineValue::CandidateHop(_)
                                | PipelineValue::DispatchOutcome(_)
                                | PipelineValue::DispatchTarget(_)
                                | PipelineValue::MemberFamily(_)
                                | PipelineValue::MemberFamilyEdge(_)
                                | PipelineValue::GenerationSite(_)
                                | PipelineValue::Export(_)
                                | PipelineValue::DeclarationState(_)
                                | PipelineValue::ReferenceEdge(_)
                                | PipelineValue::QualifiedPath(_)
                                | PipelineValue::PathSegment(_) => None,
                            })
                            .sum();
                        profile
                            .import_reverse
                            .record_hit(Some(cache_complete), replayed_edges);
                    } else {
                        profile.import_reverse.record_miss();
                    }
                }
                let resolved_files_before = graph.resolved_files();
                let resolved_edges_before = graph.resolved_edges();
                let max_files = graph.resolved_files().saturating_add(
                    limits
                        .max_scanned_files
                        .saturating_sub(state.budget.import_files_resolved),
                );
                let max_edges = graph.resolved_edges().saturating_add(
                    limits
                        .max_pipeline_rows
                        .saturating_sub(state.budget.import_edges_resolved),
                );
                let exhausted =
                    graph.ensure_complete(state.analyzer, max_files, max_edges, state.cancellation);
                state.budget.import_files_resolved = state
                    .budget
                    .import_files_resolved
                    .saturating_add(graph.resolved_files().saturating_sub(resolved_files_before));
                state.budget.import_edges_resolved = state
                    .budget
                    .import_edges_resolved
                    .saturating_add(graph.resolved_edges().saturating_sub(resolved_edges_before));
                if cache_observation.is_some_and(|(cache_hit, _)| !cache_hit)
                    && let Some(profile) = &mut state.cache_profile
                {
                    profile
                        .import_reverse
                        .record_build(Some(!exhausted && graph.reverse_relation_complete()));
                }
                exhausted
            } else {
                let mut frontier = rows
                    .iter()
                    .filter_map(|row| match &row.value {
                        PipelineValue::File(file) => Some(file.clone()),
                        PipelineValue::StructuralMatch(_)
                        | PipelineValue::Declaration(_)
                        | PipelineValue::Semantic(_)
                        | PipelineValue::ReferenceSite(_)
                        | PipelineValue::CallSite(_)
                        | PipelineValue::ExpressionSite(_)
                        | PipelineValue::ReceiverAnalysis(_)
                        | PipelineValue::ReceiverOutcome(_)
                        | PipelineValue::ReceiverEvidence(_)
                        | PipelineValue::CallShape(_)
                        | PipelineValue::CallArgumentGroup(_)
                        | PipelineValue::CallArgument(_)
                        | PipelineValue::MemberSelection(_)
                        | PipelineValue::Occurrence(_)
                        | PipelineValue::LexicalScope(_)
                        | PipelineValue::Binding(_)
                        | PipelineValue::ResolutionCandidate(_)
                        | PipelineValue::CandidateHop(_)
                        | PipelineValue::DispatchOutcome(_)
                        | PipelineValue::DispatchTarget(_)
                        | PipelineValue::MemberFamily(_)
                        | PipelineValue::MemberFamilyEdge(_)
                        | PipelineValue::GenerationSite(_)
                        | PipelineValue::Export(_)
                        | PipelineValue::DeclarationState(_)
                        | PipelineValue::ReferenceEdge(_) => None,
                        PipelineValue::QualifiedPath(_) | PipelineValue::PathSegment(_) => None,
                    })
                    .collect::<Vec<_>>();
                frontier.sort_by_key(rel_path_string);
                frontier.dedup();
                let cache_observation = state.cache_profile.as_ref().map(|_| {
                    let cache_hit = frontier.iter().all(|file| graph.has_cached_forward(file));
                    let cache_complete = cache_hit && graph.forward_relation_complete(&frontier);
                    let replayed_edges = frontier
                        .iter()
                        .map(|file| graph.cached_forward_edge_count(file))
                        .sum();
                    (cache_hit, cache_complete, replayed_edges)
                });
                if let (Some(profile), Some((cache_hit, cache_complete, replayed_edges))) =
                    (&mut state.cache_profile, cache_observation)
                {
                    if cache_hit {
                        profile
                            .import_forward
                            .record_hit(Some(cache_complete), replayed_edges);
                    } else {
                        profile.import_forward.record_miss();
                    }
                }
                let resolved_files_before = graph.resolved_files();
                let resolved_edges_before = graph.resolved_edges();
                let max_files = graph.resolved_files().saturating_add(
                    limits
                        .max_scanned_files
                        .saturating_sub(state.budget.import_files_resolved),
                );
                let max_edges = graph.resolved_edges().saturating_add(
                    limits
                        .max_pipeline_rows
                        .saturating_sub(state.budget.import_edges_resolved),
                );
                let exhausted = graph.ensure_forward(
                    state.analyzer,
                    &frontier,
                    max_files,
                    max_edges,
                    state.cancellation,
                );
                state.budget.import_files_resolved = state
                    .budget
                    .import_files_resolved
                    .saturating_add(graph.resolved_files().saturating_sub(resolved_files_before));
                state.budget.import_edges_resolved = state
                    .budget
                    .import_edges_resolved
                    .saturating_add(graph.resolved_edges().saturating_sub(resolved_edges_before));
                if cache_observation.is_some_and(|(cache_hit, _, _)| !cache_hit)
                    && let Some(profile) = &mut state.cache_profile
                {
                    profile.import_forward.record_build(Some(
                        !exhausted && graph.forward_relation_complete(&frontier),
                    ));
                }
                exhausted
            };
            if state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
            {
                return cancelled_plan_execution();
            }
            if graph_exhausted {
                truncated = true;
                push_import_graph_budget_diagnostic(diagnostics, graph);
            }
        }
    }
    let max_step_outputs = if final_in_authored_suffix {
        terminal_cap.unwrap_or(limits.max_pipeline_rows)
    } else {
        limits.max_pipeline_rows
    };
    let import_access = if use_snapshot_imports {
        state
            .direct_import_layer
            .as_deref()
            .map(DerivedLayer::direct_import_topology)
            .map(DirectImportAccess::Snapshot)
    } else {
        state
            .import_graph
            .as_ref()
            .map(DirectImportAccess::RequestLocal)
    };
    let selected_layer_generations = if use_snapshot_imports {
        state.direct_import_layer_generations.clone()
    } else {
        state.import_graph_generations.clone()
    };
    let (mut rows, mut exhausted, mut step_truncated) = apply_pipeline_step(
        state.analyzer,
        state.workspace,
        step,
        rows,
        import_access,
        Some(&mut state.indexed_declarations),
        &mut state.reference_cache,
        &mut state.call_cache,
        &mut state.occurrence_cache,
        &mut state.environment_cache,
        &mut state.materialization_cache,
        &mut state.edge_cache,
        &mut state.path_cache,
        &mut state.receiver_facts,
        &mut state.semantic,
        &mut state.budget,
        limits,
        max_step_outputs,
        state.cancellation,
        diagnostics,
        state.receiver_budget_override,
        &mut state.cache_profile,
        instrumentation,
    );
    if let Some(semantic) = &mut state.semantic {
        diagnostics.extend(semantic.take_diagnostics());
    }
    if let Some(selected_generations) = selected_layer_generations
        && !state
            .analyzer
            .snapshot_generations_match(&selected_generations)
    {
        rows.clear();
        exhausted = true;
        step_truncated = true;
        state.direct_import_layer = None;
        state.direct_import_layer_generations = None;
        state.import_graph = None;
        state.import_graph_generations = None;
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: "workspace",
            message: "source generation changed during direct import relation replay; retry the query for a coherent snapshot".to_string(),
        });
        if state.access_mode == StructuralAccessMode::IndexedRequired {
            state.access_failure.get_or_insert_with(|| {
                "direct import topology became stale during replay".to_string()
            });
        }
    }
    truncated |= step_truncated;
    if state
        .cancellation
        .is_some_and(CancellationToken::is_cancelled)
    {
        // A partially produced row is usable only after the final step:
        // before then its value belongs to an intermediate domain and
        // cannot satisfy the query's validated terminal contract.
        if !final_in_authored_suffix {
            rows.clear();
        }
        return PlanExecution {
            rows,
            truncated: true,
            cancelled: true,
            pipeline_halted: false,
        };
    }
    if exhausted {
        truncated = true;
        if state.budget.pipeline_rows >= limits.max_pipeline_rows
            || state.budget.provenance_steps >= limits.max_pipeline_rows
        {
            push_pipeline_budget_diagnostic(diagnostics, &state.budget);
        }
        if !final_in_authored_suffix {
            rows.clear();
        }
    }
    PlanExecution {
        rows,
        truncated,
        cancelled: false,
        pipeline_halted: exhausted && !final_in_authored_suffix,
    }
}

pub(super) fn fair_branch_limits(
    budget: &CodeQueryExecutionBudget,
    parent: CodeQueryExecutionLimits,
    remaining_branches: usize,
) -> CodeQueryExecutionLimits {
    fn fair_cap(current: usize, maximum: usize, remaining: usize) -> usize {
        current.saturating_add(maximum.saturating_sub(current).div_ceil(remaining.max(1)))
    }
    CodeQueryExecutionLimits {
        max_scanned_files: fair_cap(
            budget.scanned_files,
            parent.max_scanned_files,
            remaining_branches,
        ),
        max_scanned_source_bytes: fair_cap(
            budget.scanned_source_bytes,
            parent.max_scanned_source_bytes,
            remaining_branches,
        ),
        max_fact_nodes: fair_cap(
            budget.fact_nodes.saturating_add(budget.examined_references),
            parent.max_fact_nodes,
            remaining_branches,
        ),
        max_pipeline_rows: fair_cap(
            budget.pipeline_rows.max(budget.provenance_steps),
            parent.max_pipeline_rows,
            remaining_branches,
        ),
        // Semantic materialization is request-scoped and shared rather than
        // divided among independently scheduled structural seed branches.
        semantic: parent.semantic,
        typestate: parent.typestate,
        value_flow: parent.value_flow,
        taint: parent.taint,
    }
}

pub(super) fn prefix_branch_rows(rows: &mut [PipelineRow], branch: usize) {
    for row in rows {
        for trace in &mut row.traces {
            trace.branch.insert(0, branch);
        }
    }
}

pub(super) fn prefix_branch_diagnostics(diagnostics: &mut [CodeQueryDiagnostic], branch: usize) {
    for diagnostic in diagnostics {
        diagnostic.branch.insert(0, branch);
    }
}

pub(super) struct SetMergeMeasurement {
    pub(super) rows_discarded: usize,
    pub(super) temporary_capacity_bytes_lower_bound: u64,
}

pub(super) fn combine_set_rows(
    op: SetOperator,
    mut branches: Vec<Vec<PipelineRow>>,
    measure: bool,
) -> (Vec<PipelineRow>, Option<SetMergeMeasurement>) {
    let input_rows = if measure {
        branches.iter().map(Vec::len).sum::<usize>()
    } else {
        0
    };
    match op {
        SetOperator::Union => {
            let mut output = Vec::new();
            let mut indexes = HashMap::default();
            for branch in branches {
                for row in branch {
                    insert_pipeline_row(
                        &mut output,
                        &mut indexes,
                        row.value,
                        row.traces,
                        row.provenance_truncated,
                    );
                }
            }
            let measurement = measure.then(|| SetMergeMeasurement {
                rows_discarded: input_rows.saturating_sub(output.len()),
                temporary_capacity_bytes_lower_bound: hash_capacity_bytes_lower_bound::<
                    PipelineKey,
                    usize,
                >(indexes.capacity()),
            });
            (output, measurement)
        }
        SetOperator::Intersect => {
            let first = branches.remove(0);
            let mut later = branches
                .into_iter()
                .map(|branch| {
                    branch
                        .into_iter()
                        .map(|row| (row.value.key(), row))
                        .collect::<HashMap<_, _>>()
                })
                .collect::<Vec<_>>();
            let mut output = Vec::new();
            let mut indexes = HashMap::default();
            for mut row in first {
                let key = row.value.key();
                let mut contributions = Vec::with_capacity(later.len());
                let mut present = true;
                for branch in &mut later {
                    if let Some(contribution) = branch.remove(&key) {
                        contributions.push(contribution);
                    } else {
                        present = false;
                        break;
                    }
                }
                if present {
                    for contribution in contributions {
                        row.traces.extend(contribution.traces);
                        row.provenance_truncated |= contribution.provenance_truncated;
                    }
                    insert_pipeline_row(
                        &mut output,
                        &mut indexes,
                        row.value,
                        row.traces,
                        row.provenance_truncated,
                    );
                }
            }
            let measurement = measure.then(|| SetMergeMeasurement {
                rows_discarded: input_rows.saturating_sub(output.len()),
                temporary_capacity_bytes_lower_bound: later
                    .iter()
                    .map(|branch| {
                        hash_capacity_bytes_lower_bound::<PipelineKey, PipelineRow>(
                            branch.capacity(),
                        )
                    })
                    .fold(0u64, u64::saturating_add)
                    .saturating_add(hash_capacity_bytes_lower_bound::<PipelineKey, usize>(
                        indexes.capacity(),
                    )),
            });
            (output, measurement)
        }
        SetOperator::Except => {
            let first = branches.remove(0);
            let excluded = branches
                .into_iter()
                .flatten()
                .map(|row| row.value.key())
                .collect::<HashSet<_>>();
            let output = first
                .into_iter()
                .filter(|row| !excluded.contains(&row.value.key()))
                .collect::<Vec<_>>();
            let measurement = measure.then(|| SetMergeMeasurement {
                rows_discarded: input_rows.saturating_sub(output.len()),
                temporary_capacity_bytes_lower_bound: hash_capacity_bytes_lower_bound::<
                    PipelineKey,
                    (),
                >(excluded.capacity()),
            });
            (output, measurement)
        }
    }
}

pub(super) fn hash_capacity_bytes_lower_bound<K, V>(capacity: usize) -> u64 {
    u64::try_from(
        capacity.saturating_mul(std::mem::size_of::<K>().saturating_add(std::mem::size_of::<V>())),
    )
    .unwrap_or(u64::MAX)
}

pub(super) fn cancelled_query_result() -> CodeQueryResult {
    let mut diagnostics = Vec::new();
    push_cancelled_diagnostic(&mut diagnostics);
    CodeQueryResult {
        results: Vec::new(),
        truncated: true,
        diagnostics,
    }
}

pub(super) fn invalid_plan_result(error: impl ToString) -> CodeQueryResult {
    CodeQueryResult {
        results: Vec::new(),
        truncated: false,
        diagnostics: vec![CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::InvalidPlan,
            impact: CodeQueryDiagnosticImpact::Invalid,
            branch: Vec::new(),
            language: "workspace",
            message: error.to_string(),
        }],
    }
}

pub(super) fn query_plan_requires_semantic(plan: &CodeQueryPlan) -> bool {
    let mut pending = vec![plan];
    while let Some(plan) = pending.pop() {
        if plan.steps.iter().any(query_step_requires_semantic) {
            return true;
        }
        if let CodeQueryPlanSource::Set { branches, .. } = &plan.source {
            pending.extend(branches);
        }
    }
    false
}

pub(super) fn query_plan_requires_typestate(plan: &CodeQueryPlan) -> bool {
    let mut pending = vec![plan];
    while let Some(plan) = pending.pop() {
        if plan
            .steps
            .iter()
            .any(|step| matches!(step, QueryStep::Typestate(_)))
        {
            return true;
        }
        if let CodeQueryPlanSource::Set { branches, .. } = &plan.source {
            pending.extend(branches);
        }
    }
    false
}

pub(super) fn query_plan_requires_value_flow(plan: &CodeQueryPlan) -> bool {
    let mut pending = vec![plan];
    while let Some(plan) = pending.pop() {
        if plan
            .steps
            .iter()
            .any(|step| matches!(step, QueryStep::ValueFlow(_)))
        {
            return true;
        }
        if let CodeQueryPlanSource::Set { branches, .. } = &plan.source {
            pending.extend(branches);
        }
    }
    false
}

pub(super) fn query_plan_requires_taint(plan: &CodeQueryPlan) -> bool {
    let mut pending = vec![plan];
    while let Some(plan) = pending.pop() {
        if plan
            .steps
            .iter()
            .any(|step| matches!(step, QueryStep::Taint(_)))
        {
            return true;
        }
        if let CodeQueryPlanSource::Set { branches, .. } = &plan.source {
            pending.extend(branches);
        }
    }
    false
}

pub(super) fn requested_protocol_refs(plan: &CodeQueryPlan) -> Vec<ProtocolRef> {
    let mut pending = vec![plan];
    let mut requested = Vec::new();
    while let Some(plan) = pending.pop() {
        for step in &plan.steps {
            if let QueryStep::Typestate(traversal) = step
                && !requested.contains(&traversal.protocol_ref)
            {
                requested.push(traversal.protocol_ref.clone());
            }
        }
        if let CodeQueryPlanSource::Set { branches, .. } = &plan.source {
            pending.extend(branches.iter().rev());
        }
    }
    requested
}

pub(super) fn requested_value_flow_refs(plan: &CodeQueryPlan) -> Vec<ValueFlowPlanRef> {
    let mut pending = vec![plan];
    let mut requested = Vec::new();
    while let Some(plan) = pending.pop() {
        for step in &plan.steps {
            if let QueryStep::ValueFlow(traversal) = step
                && !requested.contains(&traversal.plan_ref)
            {
                requested.push(traversal.plan_ref.clone());
            }
        }
        if let CodeQueryPlanSource::Set { branches, .. } = &plan.source {
            pending.extend(branches.iter().rev());
        }
    }
    requested
}

pub(super) fn requested_taint_result_refs(plan: &CodeQueryPlan) -> Vec<TaintResultRef> {
    let mut pending = vec![plan];
    let mut requested = Vec::new();
    while let Some(plan) = pending.pop() {
        for step in &plan.steps {
            if let QueryStep::Taint(traversal) = step
                && !requested.contains(&traversal.taint_ref)
            {
                requested.push(traversal.taint_ref.clone());
            }
        }
        if let CodeQueryPlanSource::Set { branches, .. } = &plan.source {
            pending.extend(branches.iter().rev());
        }
    }
    requested
}

pub(super) fn query_analysis_context_error_result(
    error: QueryAnalysisContextError,
) -> CodeQueryResult {
    let code = match error {
        QueryAnalysisContextError::UnresolvedReference { .. } => {
            CodeQueryDiagnosticCode::UnresolvedProtocolReference
        }
        QueryAnalysisContextError::AnalysisRootMismatch => {
            CodeQueryDiagnosticCode::TypestateRootMismatch
        }
        QueryAnalysisContextError::StaleHandle => CodeQueryDiagnosticCode::TypestateHandleStale,
        QueryAnalysisContextError::UnresolvedValueFlowPlanReference { .. } => {
            CodeQueryDiagnosticCode::UnresolvedValueFlowPlanReference
        }
        QueryAnalysisContextError::ValueFlowRootMismatch => {
            CodeQueryDiagnosticCode::ValueFlowRootMismatch
        }
        QueryAnalysisContextError::StaleValueFlowPlanHandle => {
            CodeQueryDiagnosticCode::ValueFlowHandleStale
        }
        QueryAnalysisContextError::ValueFlowRegistrationInvalid { .. } => {
            CodeQueryDiagnosticCode::ValueFlowRegistrationStale
        }
        QueryAnalysisContextError::UnresolvedTaintResultReference { .. } => {
            CodeQueryDiagnosticCode::UnresolvedTaintResultReference
        }
        QueryAnalysisContextError::TaintRegistrationInvalid { .. } => {
            CodeQueryDiagnosticCode::TaintRegistrationStale
        }
        QueryAnalysisContextError::TaintResultRootMismatch => {
            CodeQueryDiagnosticCode::TaintRootMismatch
        }
        QueryAnalysisContextError::TaintPlanReportMismatch => {
            CodeQueryDiagnosticCode::TaintPlanReportMismatch
        }
        QueryAnalysisContextError::StaleTaintResultHandle => {
            CodeQueryDiagnosticCode::TaintHandleStale
        }
        QueryAnalysisContextError::Cancelled => CodeQueryDiagnosticCode::Cancelled,
        QueryAnalysisContextError::ValidationBudgetExceeded { .. } => {
            CodeQueryDiagnosticCode::SemanticBudgetExhausted
        }
        QueryAnalysisContextError::GenerationExhausted
        | QueryAnalysisContextError::TooManyResolvedProtocols
        | QueryAnalysisContextError::TooManyResolvedValueFlowPlans
        | QueryAnalysisContextError::TooManyResolvedTaintResults
        | QueryAnalysisContextError::WorkspaceGenerationMismatch { .. }
        | QueryAnalysisContextError::StaleArtifact { .. }
        | QueryAnalysisContextError::ArtifactIdentityUnavailable { .. }
        | QueryAnalysisContextError::ArtifactValidationFailed { .. } => {
            CodeQueryDiagnosticCode::TypestateRegistrationStale
        }
    };
    CodeQueryResult {
        results: Vec::new(),
        truncated: true,
        diagnostics: vec![CodeQueryDiagnostic {
            code,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: "workspace",
            message: error.to_string(),
        }],
    }
}

pub(super) fn query_step_requires_semantic(step: &QueryStep) -> bool {
    !step.op().semantic_facets().is_empty()
}

pub(super) fn push_cancelled_diagnostic(diagnostics: &mut Vec<CodeQueryDiagnostic>) {
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::Cancelled)
    {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::Cancelled,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: "query_code cancelled; any already-produced results are partial".to_string(),
    });
}

#[allow(clippy::too_many_arguments)]
pub(super) fn apply_pipeline_step(
    analyzer: &dyn IAnalyzer,
    workspace: Option<&WorkspaceAnalyzer>,
    step: &QueryStep,
    rows: Vec<PipelineRow>,
    import_graph: Option<DirectImportAccess<'_>>,
    indexed_declarations: Option<&mut IndexedDeclarations>,
    reference_cache: &mut ReferenceTraversalCache,
    call_cache: &mut CallTraversalCache,
    occurrence_cache: &mut OccurrenceTraversalCache,
    environment_cache: &mut EnvironmentTraversalCache,
    materialization_cache: &mut materialization::MaterializationTraversalCache,
    edge_cache: &mut EdgeTraversalCache,
    path_cache: &mut PathTraversalCache,
    receiver_facts: &mut HashMap<ProjectFile, Arc<FileFacts>>,
    semantic: &mut Option<SemanticQueryContext<'_>>,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    max_step_outputs: usize,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    cache_profile: &mut Option<QueryCacheProfile>,
    instrumentation: Option<&mut QueryStepInstrumentation>,
) -> (Vec<PipelineRow>, bool, bool) {
    let max_pipeline_rows = limits.max_pipeline_rows;
    let mut output = Vec::new();
    let mut indexes: HashMap<PipelineKey, usize> = HashMap::default();
    let mut unsupported_languages = BTreeSet::new();
    let mut semantic_omissions: BTreeMap<(Language, &'static str), usize> = BTreeMap::new();
    let mut receiver_diagnostics = ReceiverDiagnostics::new();
    let mut enclosing_declarations: HashMap<ProjectFile, EnclosingDeclarationIndex> =
        HashMap::default();
    let mut exhausted = false;
    let mut receiver_truncated = false;
    let receiver_service = matches!(
        step,
        QueryStep::ReceiverTargets(_) | QueryStep::PointsTo(_) | QueryStep::MemberTargets(_)
    )
    .then(|| {
        workspace.map_or_else(
            || ReceiverQueryService::new(analyzer),
            ReceiverQueryService::from_workspace,
        )
    });
    if query_step_requires_semantic(step) && semantic.is_none() {
        if !diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::SemanticWorkspaceRequired)
        {
            diagnostics.push(CodeQueryDiagnostic {
                code: CodeQueryDiagnosticCode::SemanticWorkspaceRequired,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: "workspace",
                message: format!(
                    "{} requires WorkspaceAnalyzer-backed semantic services",
                    step.label()
                ),
            });
        }
        return (Vec::new(), true, false);
    }
    let mut instrumentation = instrumentation;

    let mut indexed_declarations = indexed_declarations;
    'rows: for row in rows {
        if output.len() >= max_step_outputs {
            break;
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return (output, true, receiver_truncated);
        }
        if let Some(instrumentation) = instrumentation.as_deref_mut() {
            instrumentation.rows_visited = instrumentation.rows_visited.saturating_add(1);
        }
        if query_step_requires_semantic(step)
            && !semantic_row_seed_generations_current(
                semantic
                    .as_mut()
                    .expect("semantic context exists for semantic steps"),
                &row,
            )
        {
            continue;
        }
        let mut row_exhausted = false;
        if let (
            PipelineValue::StructuralMatch(_),
            QueryStep::ReceiverTargets(filter)
            | QueryStep::PointsTo(filter)
            | QueryStep::MemberTargets(filter),
        ) = (&row.value, step)
            && filter.capture.is_some()
        {
            let operation = receiver_operation(step);
            for trace in &row.traces {
                if output.len() >= max_step_outputs {
                    break;
                }
                let (ranges, input) =
                    structural_receiver_ranges(&trace.seed, operation, filter.capture.as_deref());
                let mut trace_exhausted = false;
                let expansions = receiver_analysis_expansions(
                    receiver_service
                        .as_ref()
                        .expect("receiver query service exists for receiver steps"),
                    analyzer,
                    operation,
                    &trace.seed.file,
                    Some(&trace.seed.facts),
                    ranges,
                    input,
                    filter.capture.clone(),
                    budget,
                    limits,
                    receiver_budget_override,
                    max_step_outputs.saturating_sub(output.len()),
                    cancellation,
                    &mut receiver_diagnostics,
                    &mut trace_exhausted,
                    &mut receiver_truncated,
                );
                if let Some(instrumentation) = instrumentation.as_deref_mut() {
                    instrumentation.relation_expansions = instrumentation
                        .relation_expansions
                        .saturating_add(expansions.len());
                }
                for expansion in expansions {
                    insert_pipeline_row(
                        &mut output,
                        &mut indexes,
                        expansion.value,
                        vec![advance_pipeline_trace(
                            trace.clone(),
                            step,
                            &expansion.trace,
                        )],
                        row.provenance_truncated,
                    );
                }
                if trace_exhausted {
                    exhausted = true;
                    break 'rows;
                }
            }
            continue;
        }
        let expansions = match (&row.value, step) {
            (PipelineValue::StructuralMatch(seed), QueryStep::ProcedureOf) => {
                let declaration =
                    exact_callable_declaration_value(analyzer, seed, &mut enclosing_declarations);
                let mut semantic = semantic
                    .as_mut()
                    .expect("CFG query service exists for semantic steps")
                    .cfg();
                let procedures = match declaration {
                    Some(declaration) => semantic.procedure_of_declaration(&declaration),
                    None => semantic.procedure_of_match(seed),
                };
                procedures
                    .into_iter()
                    .map(SemanticPipelineValue::Procedure)
                    .map(PipelineValue::Semantic)
                    .map(pipeline_expansion)
                    .collect()
            }
            (PipelineValue::Declaration(declaration), QueryStep::ProcedureOf) => semantic
                .as_mut()
                .expect("CFG query service exists for semantic steps")
                .cfg()
                .procedure_of_declaration(declaration)
                .into_iter()
                .map(SemanticPipelineValue::Procedure)
                .map(PipelineValue::Semantic)
                .map(pipeline_expansion)
                .collect(),
            (
                PipelineValue::Semantic(SemanticPipelineValue::Procedure(procedure)),
                QueryStep::CfgEntry,
            ) => semantic
                .as_mut()
                .expect("CFG query service exists for semantic steps")
                .cfg()
                .entry(procedure)
                .map(SemanticPipelineValue::ProgramPoint)
                .map(PipelineValue::Semantic)
                .into_iter()
                .map(pipeline_expansion)
                .collect(),
            (
                PipelineValue::Semantic(SemanticPipelineValue::Procedure(procedure)),
                QueryStep::CfgExits,
            ) => semantic
                .as_mut()
                .expect("CFG query service exists for semantic steps")
                .cfg()
                .exits(procedure)
                .into_iter()
                .map(SemanticPipelineValue::ProgramPoint)
                .map(PipelineValue::Semantic)
                .map(pipeline_expansion)
                .collect(),
            (
                PipelineValue::Semantic(SemanticPipelineValue::ProgramPoint(point)),
                QueryStep::CfgSuccessorEdges,
            ) => semantic
                .as_mut()
                .expect("CFG query service exists for semantic steps")
                .cfg()
                .successor_edges(point, max_step_outputs.saturating_sub(output.len()))
                .into_iter()
                .map(SemanticPipelineValue::ControlEdge)
                .map(PipelineValue::Semantic)
                .map(pipeline_expansion)
                .collect(),
            (
                PipelineValue::Semantic(SemanticPipelineValue::ProgramPoint(point)),
                QueryStep::CfgPredecessorEdges,
            ) => semantic
                .as_mut()
                .expect("CFG query service exists for semantic steps")
                .cfg()
                .predecessor_edges(point, max_step_outputs.saturating_sub(output.len()))
                .into_iter()
                .map(SemanticPipelineValue::ControlEdge)
                .map(PipelineValue::Semantic)
                .map(pipeline_expansion)
                .collect(),
            (
                PipelineValue::Semantic(SemanticPipelineValue::ControlEdge(edge)),
                QueryStep::CfgEdgeSource,
            ) => semantic
                .as_mut()
                .expect("CFG query service exists for semantic steps")
                .cfg()
                .edge_source(edge)
                .map(SemanticPipelineValue::ProgramPoint)
                .map(PipelineValue::Semantic)
                .into_iter()
                .map(pipeline_expansion)
                .collect(),
            (
                PipelineValue::Semantic(SemanticPipelineValue::ControlEdge(edge)),
                QueryStep::CfgEdgeTarget,
            ) => semantic
                .as_mut()
                .expect("CFG query service exists for semantic steps")
                .cfg()
                .edge_target(edge)
                .map(SemanticPipelineValue::ProgramPoint)
                .map(PipelineValue::Semantic)
                .into_iter()
                .map(pipeline_expansion)
                .collect(),
            (
                PipelineValue::Semantic(SemanticPipelineValue::Procedure(procedure)),
                QueryStep::Typestate(traversal),
            ) => semantic
                .as_mut()
                .expect("typestate query service exists for semantic steps")
                .typestate_findings(procedure, &traversal.protocol_ref)
                .into_iter()
                .map(SemanticPipelineValue::TypestateFinding)
                .map(PipelineValue::Semantic)
                .map(pipeline_expansion)
                .collect(),
            (
                PipelineValue::Semantic(SemanticPipelineValue::Procedure(procedure)),
                QueryStep::ValueFlow(traversal),
            ) => semantic
                .as_mut()
                .expect("value-flow query service exists for semantic steps")
                .value_flow_endpoints(
                    procedure,
                    &traversal.plan_ref,
                    max_step_outputs.saturating_sub(output.len()),
                )
                .into_iter()
                .map(|endpoint| SemanticPipelineValue::FlowEndpoint(Box::new(endpoint)))
                .map(PipelineValue::Semantic)
                .map(pipeline_expansion)
                .collect(),
            (
                PipelineValue::Semantic(SemanticPipelineValue::Procedure(procedure)),
                QueryStep::Taint(traversal),
            ) => semantic
                .as_mut()
                .expect("taint projection service exists for semantic steps")
                .taint_findings(
                    procedure,
                    &traversal.taint_ref,
                    max_step_outputs.saturating_sub(output.len()),
                )
                .into_iter()
                .map(|finding| SemanticPipelineValue::TaintFinding(Box::new(finding)))
                .map(PipelineValue::Semantic)
                .map(pipeline_expansion)
                .collect(),
            (
                PipelineValue::Semantic(SemanticPipelineValue::TypestateFinding(finding)),
                QueryStep::Witness(traversal),
            ) => {
                let (witnesses, truncated_count) = finding.witnesses(
                    workspace.expect("typestate findings require a workspace"),
                    traversal,
                    limits.typestate,
                );
                semantic
                    .as_mut()
                    .expect("typestate witness projection retains its semantic context")
                    .typestate_witness_truncated(truncated_count);
                witnesses
                    .into_iter()
                    .map(SemanticPipelineValue::TypestateWitness)
                    .map(PipelineValue::Semantic)
                    .map(pipeline_expansion)
                    .collect()
            }
            (
                PipelineValue::Semantic(SemanticPipelineValue::FlowEndpoint(endpoint)),
                QueryStep::Witness(traversal),
            ) => semantic
                .as_mut()
                .expect("value-flow witness projection retains its semantic context")
                .value_flow_witnesses(endpoint, traversal)
                .into_iter()
                .map(SemanticPipelineValue::FlowWitness)
                .map(PipelineValue::Semantic)
                .map(pipeline_expansion)
                .collect(),
            (PipelineValue::StructuralMatch(seed), QueryStep::EnclosingDecl) => {
                let (enclosing, projection_omitted) =
                    enclosing_declaration_value(analyzer, seed, &mut enclosing_declarations);
                if projection_omitted {
                    record_semantic_omission(
                        &mut semantic_omissions,
                        &CodeUnit::file_scope(seed.file.clone()),
                        "a real declaration in the seed file had no exact indexed range",
                    );
                    row_exhausted = true;
                }
                enclosing
                    .map(PipelineValue::Declaration)
                    .into_iter()
                    .map(pipeline_expansion)
                    .collect()
            }
            (PipelineValue::StructuralMatch(seed), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(seed.file.clone()))]
            }
            (PipelineValue::Declaration(declaration), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    declaration.unit.source().clone(),
                ))]
            }
            (
                PipelineValue::Semantic(SemanticPipelineValue::Procedure(procedure)),
                QueryStep::FileOf,
            ) => {
                vec![pipeline_expansion(PipelineValue::File(
                    procedure.file().clone(),
                ))]
            }
            (
                PipelineValue::Semantic(SemanticPipelineValue::ProgramPoint(point)),
                QueryStep::FileOf,
            ) => {
                vec![pipeline_expansion(PipelineValue::File(
                    point.file().clone(),
                ))]
            }
            (
                PipelineValue::Semantic(SemanticPipelineValue::ControlEdge(edge)),
                QueryStep::FileOf,
            ) => {
                vec![pipeline_expansion(PipelineValue::File(edge.file().clone()))]
            }
            (
                PipelineValue::Semantic(SemanticPipelineValue::TypestateFinding(finding)),
                QueryStep::FileOf,
            ) => {
                vec![pipeline_expansion(PipelineValue::File(
                    finding.file().clone(),
                ))]
            }
            (
                PipelineValue::Semantic(SemanticPipelineValue::TypestateWitness(witness)),
                QueryStep::FileOf,
            ) => {
                vec![pipeline_expansion(PipelineValue::File(
                    witness.file().clone(),
                ))]
            }
            (
                PipelineValue::Semantic(SemanticPipelineValue::FlowEndpoint(endpoint)),
                QueryStep::FileOf,
            ) => vec![pipeline_expansion(PipelineValue::File(
                endpoint.file().clone(),
            ))],
            (
                PipelineValue::Semantic(SemanticPipelineValue::FlowWitness(witness)),
                QueryStep::FileOf,
            ) => vec![pipeline_expansion(PipelineValue::File(
                witness.file().clone(),
            ))],
            (
                PipelineValue::Semantic(SemanticPipelineValue::TaintFinding(finding)),
                QueryStep::FileOf,
            ) => vec![pipeline_expansion(PipelineValue::File(
                finding.file().clone(),
            ))],
            (PipelineValue::ReferenceSite(site), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(site.file.clone()))]
            }
            (PipelineValue::CallSite(site), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(site.0.file.clone()))]
            }
            (PipelineValue::ExpressionSite(site), QueryStep::FileOf) => vec![pipeline_expansion(
                PipelineValue::File(site.call_site.0.file.clone()),
            )],
            (PipelineValue::ReceiverAnalysis(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.report.site.file.clone(),
                ))]
            }
            (PipelineValue::DispatchOutcome(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.file().clone(),
                ))]
            }
            (PipelineValue::DispatchTarget(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.file().clone(),
                ))]
            }
            (PipelineValue::MemberFamily(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.file().clone(),
                ))]
            }
            (PipelineValue::MemberFamilyEdge(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.file().clone(),
                ))]
            }
            (PipelineValue::ReceiverOutcome(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.report.site.file.clone(),
                ))]
            }
            (PipelineValue::CallShape(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.report.outcome.file.clone(),
                ))]
            }
            (PipelineValue::CallArgumentGroup(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.shape.report.outcome.file.clone(),
                ))]
            }
            (PipelineValue::CallArgument(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.shape.report.outcome.file.clone(),
                ))]
            }
            (PipelineValue::ReceiverEvidence(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.receiver.report.site.file.clone(),
                ))]
            }
            (PipelineValue::File(file), QueryStep::ImportsOf) => {
                let graph = import_graph.expect("import graph exists for import steps");
                match graph.imports_of(file) {
                    Some(imports) => imports
                        .into_iter()
                        .map(PipelineValue::File)
                        .map(pipeline_expansion)
                        .collect(),
                    None => {
                        unsupported_languages
                            .insert(crate::analyzer::common::language_for_file(file));
                        Vec::new()
                    }
                }
            }
            (PipelineValue::File(file), QueryStep::ImportersOf) => import_graph
                .expect("import graph exists for import steps")
                .importers_of(file)
                .into_iter()
                .map(PipelineValue::File)
                .map(pipeline_expansion)
                .collect(),
            (
                PipelineValue::Declaration(declaration),
                QueryStep::Supertypes(traversal) | QueryStep::Subtypes(traversal),
            ) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let (expansions, hierarchy_exhausted) = expand_hierarchy(
                    analyzer,
                    declaration,
                    step,
                    *traversal,
                    indexed,
                    budget,
                    max_pipeline_rows,
                    &mut semantic_omissions,
                );
                row_exhausted = hierarchy_exhausted;
                expansions
            }
            (PipelineValue::Declaration(declaration), QueryStep::Members) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                if !is_type_declaration(analyzer, &declaration.unit) {
                    record_semantic_omission(
                        &mut semantic_omissions,
                        &declaration.unit,
                        "input is not a type declaration",
                    );
                    Vec::new()
                } else {
                    let (expansions, members_exhausted) = direct_member_expansions(
                        analyzer,
                        declaration,
                        analyzer.direct_children(&declaration.unit),
                        indexed,
                        budget,
                        max_pipeline_rows,
                        &mut semantic_omissions,
                    );
                    row_exhausted = members_exhausted;
                    expansions
                }
            }
            (PipelineValue::Declaration(declaration), QueryStep::Owner) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let (owner, owner_exhausted) = indexed.owner_of(
                    analyzer,
                    &declaration.unit,
                    &mut budget.pipeline_rows,
                    max_pipeline_rows,
                );
                row_exhausted = owner_exhausted;
                match owner {
                    Some(owner) => vec![budgeted_declaration_expansion(owner)],
                    None if !owner_exhausted => {
                        record_semantic_omission(
                            &mut semantic_omissions,
                            &declaration.unit,
                            "input is not a direct member declaration",
                        );
                        Vec::new()
                    }
                    None => Vec::new(),
                }
            }
            (
                PipelineValue::Declaration(declaration),
                QueryStep::ReferencesOf(filter) | QueryStep::UsedBy(filter),
            ) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let (expansions, reference_exhausted) = inbound_reference_expansions(
                    analyzer,
                    declaration,
                    step,
                    filter,
                    indexed,
                    reference_cache,
                    budget,
                    limits,
                    diagnostics,
                    max_pipeline_rows.saturating_sub(budget.pipeline_rows),
                    cancellation,
                    cache_profile,
                );
                row_exhausted = reference_exhausted;
                expansions
            }
            (PipelineValue::Declaration(declaration), QueryStep::Uses(filter)) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let (expansions, reference_exhausted) = outbound_reference_expansions(
                    analyzer,
                    declaration,
                    filter,
                    indexed,
                    reference_cache,
                    budget,
                    limits,
                    max_step_outputs,
                    cancellation,
                    diagnostics,
                    cache_profile,
                );
                row_exhausted = reference_exhausted;
                expansions
            }
            (
                PipelineValue::Declaration(declaration),
                QueryStep::Callers(filter) | QueryStep::Callees(filter),
            ) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let (expansions, call_exhausted) = call_declaration_expansions(
                    analyzer,
                    declaration,
                    step,
                    filter,
                    indexed,
                    call_cache,
                    budget,
                    limits,
                    max_step_outputs,
                    cancellation,
                    diagnostics,
                    cache_profile,
                );
                row_exhausted = call_exhausted;
                expansions
            }
            (
                PipelineValue::Declaration(declaration),
                QueryStep::CallSitesTo(filter) | QueryStep::CallSitesFrom(filter),
            ) => {
                let (expansions, call_exhausted) = call_site_expansions(
                    analyzer,
                    declaration,
                    step,
                    filter,
                    call_cache,
                    budget,
                    limits,
                    max_step_outputs,
                    cancellation,
                    diagnostics,
                    cache_profile,
                );
                row_exhausted = call_exhausted;
                expansions
            }
            (PipelineValue::CallSite(site), QueryStep::CallInput(selector)) => {
                let (expansions, binding_incomplete) = call_input_expansions(site, selector);
                if binding_incomplete {
                    record_semantic_omission(
                        &mut semantic_omissions,
                        &site.0.callee,
                        "a retained call site had no exact formal-parameter binding layout",
                    );
                    row_exhausted = true;
                }
                expansions
            }
            (
                PipelineValue::StructuralMatch(seed),
                QueryStep::ReceiverTargets(filter)
                | QueryStep::PointsTo(filter)
                | QueryStep::MemberTargets(filter),
            ) => {
                let operation = receiver_operation(step);
                let (ranges, input) =
                    structural_receiver_ranges(seed, operation, filter.capture.as_deref());
                receiver_analysis_expansions(
                    receiver_service
                        .as_ref()
                        .expect("receiver query service exists for receiver steps"),
                    analyzer,
                    operation,
                    &seed.file,
                    Some(&seed.facts),
                    ranges,
                    input,
                    filter.capture.clone(),
                    budget,
                    limits,
                    receiver_budget_override,
                    max_step_outputs.saturating_sub(output.len()),
                    cancellation,
                    &mut receiver_diagnostics,
                    &mut row_exhausted,
                    &mut receiver_truncated,
                )
            }
            (
                PipelineValue::ReferenceSite(site),
                QueryStep::ReceiverTargets(_)
                | QueryStep::PointsTo(_)
                | QueryStep::MemberTargets(_),
            ) => receiver_analysis_expansions_for_pipeline_row(
                analyzer,
                receiver_service
                    .as_ref()
                    .expect("receiver query service exists for receiver steps"),
                receiver_operation(step),
                &site.file,
                &row.traces,
                vec![site.range],
                if matches!(step, QueryStep::PointsTo(_)) {
                    ReceiverQueryInput::Expression
                } else {
                    ReceiverQueryInput::ContainingSite
                },
                receiver_facts,
                budget,
                limits,
                receiver_budget_override,
                max_step_outputs.saturating_sub(output.len()),
                cancellation,
                diagnostics,
                cache_profile,
                &mut receiver_diagnostics,
                &mut row_exhausted,
                &mut receiver_truncated,
            ),
            (PipelineValue::CallSite(site), QueryStep::ReceiverTargets(_)) => {
                receiver_analysis_expansions_for_pipeline_row(
                    analyzer,
                    receiver_service
                        .as_ref()
                        .expect("receiver query service exists for receiver steps"),
                    ReceiverQueryOperation::ReceiverTargets,
                    &site.0.file,
                    &row.traces,
                    vec![site.0.range],
                    ReceiverQueryInput::ContainingSite,
                    receiver_facts,
                    budget,
                    limits,
                    receiver_budget_override,
                    max_step_outputs.saturating_sub(output.len()),
                    cancellation,
                    diagnostics,
                    cache_profile,
                    &mut receiver_diagnostics,
                    &mut row_exhausted,
                    &mut receiver_truncated,
                )
            }
            (
                PipelineValue::ExpressionSite(site),
                QueryStep::ReceiverTargets(_) | QueryStep::PointsTo(_),
            ) => receiver_analysis_expansions_for_pipeline_row(
                analyzer,
                receiver_service
                    .as_ref()
                    .expect("receiver query service exists for receiver steps"),
                receiver_operation(step),
                &site.call_site.0.file,
                &row.traces,
                vec![site.range],
                ReceiverQueryInput::Expression,
                receiver_facts,
                budget,
                limits,
                receiver_budget_override,
                max_step_outputs.saturating_sub(output.len()),
                cancellation,
                diagnostics,
                cache_profile,
                &mut receiver_diagnostics,
                &mut row_exhausted,
                &mut receiver_truncated,
            ),
            (
                PipelineValue::Occurrence(value),
                QueryStep::ReceiverTargets(_)
                | QueryStep::PointsTo(_)
                | QueryStep::MemberTargets(_),
            ) => {
                let operation = receiver_operation(step);
                let input = if value.row.role == OccurrenceRole::ReceiverPosition
                    && operation != ReceiverQueryOperation::MemberTargets
                {
                    ReceiverQueryInput::Expression
                } else {
                    ReceiverQueryInput::ContainingSite
                };
                let mut expansions = receiver_analysis_expansions_for_pipeline_row(
                    analyzer,
                    receiver_service
                        .as_ref()
                        .expect("receiver query service exists for receiver steps"),
                    operation,
                    value.file(),
                    &row.traces,
                    vec![value.row.range],
                    input,
                    receiver_facts,
                    budget,
                    limits,
                    receiver_budget_override,
                    max_step_outputs.saturating_sub(output.len()),
                    cancellation,
                    diagnostics,
                    cache_profile,
                    &mut receiver_diagnostics,
                    &mut row_exhausted,
                    &mut receiver_truncated,
                );
                correlate_receiver_expansions(&mut expansions, value.row.ast_id());
                expansions
            }
            (PipelineValue::ReceiverAnalysis(value), QueryStep::ReceiverOutcome) => {
                vec![PipelineExpansion {
                    value: PipelineValue::ReceiverOutcome(value.clone()),
                    trace: vec![(PipelineTraceValue::ReceiverOutcome(value.clone()), None)],
                    budgeted: false,
                }]
            }
            (PipelineValue::ReceiverAnalysis(value), QueryStep::ReceiverEvidence) => {
                receiver_evidence_expansions(value)
            }
            (PipelineValue::StructuralMatch(seed), QueryStep::CallShape) => {
                let fact_range = seed.facts.node(seed.fact_match.node).range;
                call_shape::call_shape_expansions_for_input(
                    analyzer,
                    &row.traces,
                    &seed.file,
                    fact_range,
                    Some(&seed.facts),
                    Some(seed.fact_match.node),
                    receiver_facts,
                    budget,
                    limits,
                    cancellation,
                    diagnostics,
                    cache_profile,
                    &mut row_exhausted,
                )
            }
            (PipelineValue::CallSite(site), QueryStep::CallShape) => {
                call_shape::call_shape_expansions_for_input(
                    analyzer,
                    &row.traces,
                    &site.0.file,
                    site.0.range,
                    None,
                    None,
                    receiver_facts,
                    budget,
                    limits,
                    cancellation,
                    diagnostics,
                    cache_profile,
                    &mut row_exhausted,
                )
            }
            (PipelineValue::Occurrence(value), QueryStep::CallShape) => {
                call_shape::call_shape_expansions_for_input(
                    analyzer,
                    &row.traces,
                    value.file(),
                    value.row.range,
                    None,
                    None,
                    receiver_facts,
                    budget,
                    limits,
                    cancellation,
                    diagnostics,
                    cache_profile,
                    &mut row_exhausted,
                )
            }
            (
                PipelineValue::StructuralMatch(seed),
                QueryStep::DispatchOutcome | QueryStep::DispatchTargets,
            ) => dispatch::dispatch_expansions_for_input(
                analyzer,
                semantic
                    .as_mut()
                    .expect("semantic context exists for semantic steps"),
                &row.traces,
                &seed.file,
                seed_range(seed),
                None,
                matches!(step, QueryStep::DispatchTargets),
            ),
            (
                PipelineValue::CallSite(site),
                QueryStep::DispatchOutcome | QueryStep::DispatchTargets,
            ) => dispatch::dispatch_expansions_for_input(
                analyzer,
                semantic
                    .as_mut()
                    .expect("semantic context exists for semantic steps"),
                &row.traces,
                &site.0.file,
                site.0.range,
                None,
                matches!(step, QueryStep::DispatchTargets),
            ),
            (
                PipelineValue::ReferenceSite(site),
                QueryStep::DispatchOutcome | QueryStep::DispatchTargets,
            ) => dispatch::dispatch_expansions_for_input(
                analyzer,
                semantic
                    .as_mut()
                    .expect("semantic context exists for semantic steps"),
                &row.traces,
                &site.file,
                site.range,
                None,
                matches!(step, QueryStep::DispatchTargets),
            ),
            (
                PipelineValue::Occurrence(value),
                QueryStep::DispatchOutcome | QueryStep::DispatchTargets,
            ) => dispatch::dispatch_expansions_for_input(
                analyzer,
                semantic
                    .as_mut()
                    .expect("semantic context exists for semantic steps"),
                &row.traces,
                value.file(),
                value.row.range,
                Some(value.row.ast_id()),
                matches!(step, QueryStep::DispatchTargets),
            ),
            (PipelineValue::CallShape(value), QueryStep::CallArgumentGroups) => {
                call_shape::call_argument_group_expansions(value)
            }
            (PipelineValue::CallArgumentGroup(value), QueryStep::CallArguments) => {
                call_shape::call_argument_expansions(value)
            }
            (PipelineValue::File(file), QueryStep::OccurrencesIn(filter)) => {
                occurrence_expansions_for_file(
                    analyzer,
                    occurrence_cache,
                    file,
                    filter,
                    None,
                    cancellation,
                    diagnostics,
                    &mut row_exhausted,
                )
            }
            (PipelineValue::StructuralMatch(seed), QueryStep::OccurrencesIn(filter)) => {
                // Containment is the arena's own pre-order subtree interval,
                // not a byte-range comparison: facts are stored in pre-order,
                // so a node's descendants are exactly `node..subtree_end`.
                let containing = OccurrenceSubtree {
                    content_identity: seed.facts.source_identity(),
                    root: seed.fact_match.node,
                    subtree_end: seed.facts.node(seed.fact_match.node).subtree_end,
                };
                occurrence_expansions_for_file(
                    analyzer,
                    occurrence_cache,
                    &seed.file,
                    filter,
                    Some(containing),
                    cancellation,
                    diagnostics,
                    &mut row_exhausted,
                )
            }
            (PipelineValue::Declaration(declaration), QueryStep::OccurrencesOf(filter)) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let (expansions, occurrence_exhausted) = occurrences_of_declaration(
                    analyzer,
                    declaration,
                    filter,
                    indexed,
                    reference_cache,
                    occurrence_cache,
                    budget,
                    limits,
                    diagnostics,
                    max_pipeline_rows.saturating_sub(budget.pipeline_rows),
                    cancellation,
                    cache_profile,
                );
                row_exhausted = occurrence_exhausted;
                expansions
            }
            (PipelineValue::Occurrence(value), QueryStep::OccurrenceTarget) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                match &value.row.target {
                    OccurrenceTarget::Resolved(units) => units
                        .iter()
                        .filter_map(|unit| indexed.get(analyzer, unit))
                        .map(|declaration| {
                            pipeline_expansion(PipelineValue::Declaration(declaration))
                        })
                        .collect(),
                    OccurrenceTarget::None
                    | OccurrenceTarget::Lexical(_)
                    | OccurrenceTarget::Unresolved(_) => Vec::new(),
                }
            }
            (PipelineValue::Occurrence(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.file().clone(),
                ))]
            }
            (PipelineValue::LexicalScope(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.file().clone(),
                ))]
            }
            (PipelineValue::Binding(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.file().clone(),
                ))]
            }
            (PipelineValue::Binding(value), QueryStep::ScopeOf) => {
                vec![pipeline_expansion(PipelineValue::LexicalScope(
                    ScopeValue {
                        file: value.file.clone(),
                        result: Arc::clone(&value.result),
                        index: value.row().declaring_scope,
                    },
                ))]
            }
            (PipelineValue::Occurrence(value), QueryStep::ScopeOf) => scope_of_position(
                analyzer,
                environment_cache,
                &value.row.file,
                value.row.range.start_byte,
                diagnostics,
            ),
            (PipelineValue::StructuralMatch(seed), QueryStep::ScopeOf) => scope_of_position(
                analyzer,
                environment_cache,
                &seed.file,
                seed.facts.node(seed.fact_match.node).range.start_byte,
                diagnostics,
            ),
            (PipelineValue::LexicalScope(value), QueryStep::ScopeAncestors) => {
                // `scope_ancestry` returns the scope itself first; the step is
                // documented as excluding it, so the chain is skipped by one.
                value
                    .result
                    .scope_ancestry(value.index)
                    .into_iter()
                    .skip(1)
                    .map(|index| {
                        pipeline_expansion(PipelineValue::LexicalScope(ScopeValue {
                            file: value.file.clone(),
                            result: Arc::clone(&value.result),
                            index,
                        }))
                    })
                    .collect()
            }
            (PipelineValue::LexicalScope(value), QueryStep::BindingsIn(filter)) => {
                environment_cache.report_completeness(
                    &value.file,
                    &value.result,
                    environment::BINDING_QUERY_AXES,
                    diagnostics,
                );
                environment::select_bindings(&value.result, filter)
                    .filter(|index| value.result.bindings[*index].declaring_scope == value.index)
                    .map(|index| {
                        pipeline_expansion(PipelineValue::Binding(BindingValue {
                            file: value.file.clone(),
                            result: Arc::clone(&value.result),
                            index,
                            shadowed: false,
                            reached_from: None,
                        }))
                    })
                    .collect()
            }
            (PipelineValue::StructuralMatch(seed), QueryStep::BindingsIn(filter)) => {
                // Containment over a structural match is the arena's own
                // pre-order subtree interval on the *binder token*, so a
                // binding is inside a match exactly when its declaring token is.
                let node = seed.facts.node(seed.fact_match.node);
                let (start, end) = (node.range.start_byte, node.range.end_byte);
                let result = environment_cache.environment_for(analyzer, &seed.file);
                environment_cache.report_completeness(
                    &seed.file,
                    &result,
                    environment::BINDING_QUERY_AXES,
                    diagnostics,
                );
                environment::select_bindings(&result, filter)
                    .filter(|index| {
                        let row = &result.bindings[*index];
                        row.range.start_byte >= start && row.range.end_byte <= end
                    })
                    .map(|index| {
                        pipeline_expansion(PipelineValue::Binding(BindingValue {
                            file: seed.file.clone(),
                            result: Arc::clone(&result),
                            index,
                            shadowed: false,
                            reached_from: None,
                        }))
                    })
                    .collect()
            }
            (PipelineValue::Occurrence(value), QueryStep::ReachingBinding(options)) => {
                reaching_binding_expansions(
                    analyzer,
                    environment_cache,
                    &value.row,
                    options.include_shadowed,
                    diagnostics,
                )
            }
            (PipelineValue::Binding(value), QueryStep::BindingOccurrence) => {
                binding_occurrence_expansions(
                    analyzer,
                    occurrence_cache,
                    value,
                    cancellation,
                    diagnostics,
                    &mut row_exhausted,
                )
            }
            (PipelineValue::Occurrence(value), QueryStep::CandidatesOf(filter)) => {
                candidate_expansions(
                    analyzer,
                    environment_cache,
                    &value.row,
                    filter,
                    cancellation,
                    diagnostics,
                    &mut row_exhausted,
                )
            }
            (PipelineValue::Occurrence(value), QueryStep::CandidateHierarchy) => {
                candidate_hierarchy_expansions(
                    analyzer,
                    environment_cache,
                    &value.row,
                    cancellation,
                    &mut row_exhausted,
                )
            }
            (
                PipelineValue::Declaration(declaration),
                QueryStep::MemberFamily | QueryStep::FamilyEdges,
            ) => member_family::member_family_expansions_for_declaration(
                analyzer,
                declaration,
                matches!(step, QueryStep::FamilyEdges),
            ),
            (PipelineValue::Occurrence(value), QueryStep::MemberSelection) => {
                member_selection_expansions(
                    analyzer,
                    environment_cache,
                    &value.row,
                    cancellation,
                    &mut row_exhausted,
                )
            }
            (PipelineValue::Declaration(declaration), QueryStep::EdgesOf(filter)) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                inverse_edge_expansions(
                    analyzer,
                    edge_cache,
                    indexed,
                    declaration,
                    filter,
                    cancellation,
                    diagnostics,
                )
            }
            (PipelineValue::Occurrence(value), QueryStep::EdgesFrom(filter)) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                forward_edge_expansions(
                    analyzer,
                    edge_cache,
                    indexed,
                    value,
                    filter,
                    cancellation,
                    diagnostics,
                    &mut row_exhausted,
                )
            }
            (PipelineValue::ReferenceEdge(value), QueryStep::EdgeTarget) => {
                vec![pipeline_expansion(PipelineValue::Declaration(
                    value.target.clone(),
                ))]
            }
            (PipelineValue::ResolutionCandidate(value), QueryStep::CandidateTarget) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                environment::candidate_unit(&value.candidate.candidate)
                    .and_then(|unit| indexed.get(analyzer, unit))
                    .map(|declaration| {
                        vec![pipeline_expansion(PipelineValue::Declaration(declaration))]
                    })
                    .unwrap_or_default()
            }
            (PipelineValue::GenerationSite(value), QueryStep::Generates) => {
                let result = &value.result;
                value
                    .row()
                    .generated
                    .iter()
                    .filter_map(|(unit, _)| {
                        result.states.iter().position(|state| &state.unit == unit)
                    })
                    .map(|index| {
                        pipeline_expansion(PipelineValue::DeclarationState(
                            materialization::DeclarationStateValue {
                                file: value.file.clone(),
                                result: Arc::clone(result),
                                index,
                            },
                        ))
                    })
                    .collect()
            }
            (PipelineValue::GenerationSite(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.file().clone(),
                ))]
            }
            (PipelineValue::Export(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.file().clone(),
                ))]
            }
            (PipelineValue::DeclarationState(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(
                    value.file().clone(),
                ))]
            }
            (PipelineValue::Declaration(declaration), QueryStep::DeclarationStateOf(filter)) => {
                let file = declaration.unit.source().clone();
                let result = materialization_cache.materialization_for(analyzer, &file);
                // A filter over the configuration gate depends on the gating
                // axis: an unevaluated configuration must surface as
                // incomplete, never as a confidently gated/ungated answer.
                let required_axes: &[crate::analyzer::structural::materialization::MaterializationAxis] =
                    if filter.config_gated.is_some() {
                    materialization::DECLARATION_STATE_AND_GATING_QUERY_AXES
                } else {
                    materialization::DECLARATION_STATE_QUERY_AXES
                };
                materialization_cache.report_completeness(
                    &file,
                    &result,
                    required_axes,
                    diagnostics,
                );
                result
                    .states
                    .iter()
                    .enumerate()
                    .filter(|(_, state)| {
                        state.unit == declaration.unit
                            && filter.matches(
                                state.origin,
                                state.declaration_only,
                                state.config_gated,
                            )
                    })
                    .map(|(index, _)| {
                        pipeline_expansion(PipelineValue::DeclarationState(
                            materialization::DeclarationStateValue {
                                file: file.clone(),
                                result: Arc::clone(&result),
                                index,
                            },
                        ))
                    })
                    .collect()
            }
            (PipelineValue::Declaration(declaration), QueryStep::GeneratedBy) => {
                let file = declaration.unit.source().clone();
                let result = materialization_cache.materialization_for(analyzer, &file);
                materialization_cache.report_completeness(
                    &file,
                    &result,
                    materialization::GENERATION_SITE_QUERY_AXES,
                    diagnostics,
                );
                result
                    .sites
                    .iter()
                    .enumerate()
                    .filter(|(_, site)| {
                        site.generated
                            .iter()
                            .any(|(unit, _)| unit == &declaration.unit)
                    })
                    .map(|(index, _)| {
                        pipeline_expansion(PipelineValue::GenerationSite(
                            materialization::GenerationSiteValue {
                                file: file.clone(),
                                result: Arc::clone(&result),
                                index,
                            },
                        ))
                    })
                    .collect()
            }
            (PipelineValue::DeclarationState(value), QueryStep::GeneratedBy) => {
                let unit = value.row().unit.clone();
                let result = &value.result;
                result
                    .sites
                    .iter()
                    .enumerate()
                    .filter(|(_, site)| {
                        site.generated
                            .iter()
                            .any(|(candidate, _)| candidate == &unit)
                    })
                    .map(|(index, _)| {
                        pipeline_expansion(PipelineValue::GenerationSite(
                            materialization::GenerationSiteValue {
                                file: value.file.clone(),
                                result: Arc::clone(result),
                                index,
                            },
                        ))
                    })
                    .collect()
            }
            (PipelineValue::DeclarationState(value), QueryStep::ImplementationOf) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let unit = &value.row().unit;
                value
                    .result
                    .links
                    .iter()
                    .filter(|link| &link.stub == unit)
                    .filter_map(|link| link.implementation.as_ref())
                    .filter_map(|implementation| indexed.get(analyzer, implementation))
                    .map(|declaration| pipeline_expansion(PipelineValue::Declaration(declaration)))
                    .collect()
            }
            (PipelineValue::Declaration(declaration), QueryStep::ImplementationOf) => {
                let file = declaration.unit.source().clone();
                let result = materialization_cache.materialization_for(analyzer, &file);
                materialization_cache.report_completeness(
                    &file,
                    &result,
                    materialization::IMPLEMENTATION_QUERY_AXES,
                    diagnostics,
                );
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                result
                    .links
                    .iter()
                    .filter(|link| link.stub == declaration.unit)
                    .filter_map(|link| link.implementation.as_ref())
                    .filter_map(|implementation| indexed.get(analyzer, implementation))
                    .map(|found| pipeline_expansion(PipelineValue::Declaration(found)))
                    .collect()
            }
            (PipelineValue::Export(value), QueryStep::ExportTarget) => {
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                value
                    .row()
                    .target
                    .as_ref()
                    .and_then(|unit| indexed.get(analyzer, unit))
                    .map(|declaration| {
                        vec![pipeline_expansion(PipelineValue::Declaration(declaration))]
                    })
                    .unwrap_or_default()
            }
            (PipelineValue::QualifiedPath(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(value.file.clone()))]
            }
            (PipelineValue::PathSegment(value), QueryStep::FileOf) => {
                vec![pipeline_expansion(PipelineValue::File(value.file.clone()))]
            }
            (PipelineValue::QualifiedPath(value), QueryStep::SegmentsOf(options)) => {
                // A resolved request derives the file's resolved variant and
                // re-anchors this path's segments in it, so the rows carry
                // statuses; a plain request reuses the result the path row
                // already shares.
                let derived = if options.resolved {
                    path_cache
                        .paths_for(analyzer, &value.file, true, cancellation)
                        .map(|result| (result, RESOLVED_PATH_QUERY_AXES))
                } else {
                    Some((Arc::clone(&value.result), PATH_QUERY_AXES))
                };
                let Some((result, axes)) = derived else {
                    // Only cancellation makes the derivation refuse; the
                    // surrounding loop's own cancellation check reports it,
                    // and an empty expansion list adds nothing meanwhile.
                    continue;
                };
                path_cache.report_completeness(&value.file, &result, axes, diagnostics);
                let terminal = value.row().terminal_node;
                result
                    .segments
                    .iter()
                    .enumerate()
                    .filter(|(_, row)| row.path_terminal_node == terminal)
                    .map(|(index, _)| {
                        pipeline_expansion(PipelineValue::PathSegment(SegmentValue {
                            file: value.file.clone(),
                            result: Arc::clone(&result),
                            index,
                        }))
                    })
                    .collect()
            }
            (PipelineValue::PathSegment(value), QueryStep::SegmentTarget) => {
                // The step needs each segment's own resolution; a row from a
                // rows-only derivation is re-anchored in the resolved variant
                // by its (path, ordinal) identity.
                let indexed = indexed_declarations
                    .as_deref_mut()
                    .expect("semantic declaration index exists");
                let row = value.row();
                let resolved_row;
                let resolution = if row.resolution.is_some() {
                    row.resolution.as_ref()
                } else {
                    match path_cache.paths_for(analyzer, &value.file, true, cancellation) {
                        Some(result) => {
                            path_cache.report_completeness(
                                &value.file,
                                &result,
                                RESOLVED_PATH_QUERY_AXES,
                                diagnostics,
                            );
                            resolved_row = result
                                .segments
                                .iter()
                                .find(|candidate| {
                                    candidate.path_terminal_node == row.path_terminal_node
                                        && candidate.ordinal == row.ordinal
                                })
                                .cloned();
                            resolved_row
                                .as_ref()
                                .and_then(|row| row.resolution.as_ref())
                        }
                        None => None,
                    }
                };
                resolution
                    .map(|resolution| {
                        resolution
                            .targets
                            .iter()
                            .filter_map(|unit| indexed.get(analyzer, unit))
                            .map(|declaration| {
                                pipeline_expansion(PipelineValue::Declaration(declaration))
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            }
            _ => unreachable!("query step domains are validated before execution"),
        };
        if semantic
            .as_ref()
            .is_some_and(|service| service.work().budget_exhausted)
        {
            row_exhausted = true;
        }

        if let Some(instrumentation) = instrumentation.as_deref_mut() {
            instrumentation.relation_expansions = instrumentation
                .relation_expansions
                .saturating_add(expansions.len());
        }

        for expansion in expansions {
            if !expansion.budgeted && budget.pipeline_rows >= max_pipeline_rows {
                exhausted = true;
                break 'rows;
            }
            if !expansion.budgeted {
                budget.pipeline_rows += 1;
            }
            let traces = row
                .traces
                .iter()
                .cloned()
                .map(|trace| advance_pipeline_trace(trace, step, &expansion.trace))
                .collect();
            insert_pipeline_row(
                &mut output,
                &mut indexes,
                expansion.value,
                traces,
                row.provenance_truncated,
            );
        }
        if row_exhausted {
            exhausted = true;
            break;
        }
    }

    if step == &QueryStep::ImportersOf
        && let Some(graph) = import_graph
    {
        unsupported_languages.extend(graph.unsupported_languages());
    }

    for language in unsupported_languages {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UnsupportedImportAnalysis,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "{} does not provide structured import analysis; {} omitted its affected files",
                language.config_label(),
                step.label()
            ),
        });
    }
    append_semantic_omission_diagnostics(diagnostics, step, semantic_omissions);
    for ((code, language, operation, reason), count) in receiver_diagnostics {
        let message = if reason == RECEIVER_PIPELINE_OUTPUT_CAP_REASON {
            format!(
                "{operation} omitted {count} receiver analysis input{} at the pipeline output cap",
                if count == 1 { "" } else { "s" }
            )
        } else if code == CodeQueryDiagnosticCode::ReceiverAnalysisFailed {
            format!(
                "{operation} failed for {count} analysis input{}: {reason}",
                if count == 1 { "" } else { "s" }
            )
        } else {
            format!(
                "{operation} returned {count} analysis row{} with {reason}",
                if count == 1 { "" } else { "s" }
            )
        };
        diagnostics.push(CodeQueryDiagnostic {
            code,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message,
        });
    }
    if let Some(instrumentation) = instrumentation {
        let index_bytes = indexes.capacity().saturating_mul(
            std::mem::size_of::<PipelineKey>().saturating_add(std::mem::size_of::<usize>()),
        );
        instrumentation.temporary_capacity_bytes_lower_bound =
            u64::try_from(index_bytes).unwrap_or(u64::MAX);
    }
    (output, exhausted, receiver_truncated)
}

pub(super) fn advance_pipeline_trace(
    mut trace: PipelineTrace,
    step: &QueryStep,
    expansion: &[(PipelineTraceValue, Option<PipelineVia>)],
) -> PipelineTrace {
    trace.steps.extend(
        expansion
            .iter()
            .cloned()
            .map(|(value, via)| PipelineTraceStep {
                op: step.clone(),
                value,
                via,
            }),
    );
    trace
}
