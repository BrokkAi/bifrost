use super::*;

pub(super) fn execute_plan(
    plan: &PhysicalQueryPlan,
    node_id: PhysicalQueryNodeId,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    terminal_cap: Option<usize>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    profile_branch: &mut Option<Vec<usize>>,
) -> PlanExecution {
    let profiling = state.profile.is_some();
    let invocation_started = profiling.then(Instant::now);
    let physical_node = plan.node(node_id);
    let physical_operator = physical_node.operator();
    let logical_operator = plan.logical_node(node_id).operator();
    let mut input_rows = 0;
    let mut rows_visited = 0;
    let mut relation_expansions = 0;
    let mut rows_discarded = None;
    let mut temporary_capacity_bytes_lower_bound = 0;
    let mut disposition = QueryOperatorDisposition::Completed;
    let mut self_truncated = false;
    let mut dependency_execution_ns = 0u64;
    let mut dependency_wait_ns = 0u64;
    let mut merge_ns = 0u64;
    let mut scheduling_overhead_ns = 0u64;
    let mut terminations = profiling.then(Vec::new);
    let mut work_started = profiling.then(|| state_execution_work_snapshot(state));
    let mut cache_started = state.cache_profile;
    let mut own_diagnostic_start = diagnostics.len();

    let execution = match (physical_operator, logical_operator) {
        (PhysicalQueryOperator::OccurrenceScan, LogicalQueryOperator::OccurrenceSeed(seed)) => {
            if state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
            {
                disposition = QueryOperatorDisposition::Skipped;
                push_operator_termination(
                    &mut terminations,
                    QueryOperatorTermination::CancellationBeforeWork,
                );
                cancelled_plan_execution()
            } else {
                let execution =
                    execute_occurrence_seed(seed, terminal_cap, state, limits, diagnostics);
                if terminal_cap.is_some_and(|cap| execution.rows.len() >= cap) {
                    push_operator_termination(
                        &mut terminations,
                        QueryOperatorTermination::TerminalCap,
                    );
                }
                self_truncated = execution.truncated;
                if execution.cancelled {
                    disposition = QueryOperatorDisposition::Cancelled;
                }
                execution
            }
        }
        (PhysicalQueryOperator::ScopeScan, LogicalQueryOperator::ScopeSeed(seed)) => {
            if state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
            {
                disposition = QueryOperatorDisposition::Skipped;
                push_operator_termination(
                    &mut terminations,
                    QueryOperatorTermination::CancellationBeforeWork,
                );
                cancelled_plan_execution()
            } else {
                let execution = execute_environment_seed(
                    EnvironmentSeedKind::Scopes(&seed.filter),
                    &seed.where_globs,
                    &seed.languages,
                    terminal_cap,
                    state,
                    limits,
                    diagnostics,
                );
                if terminal_cap.is_some_and(|cap| execution.rows.len() >= cap) {
                    push_operator_termination(
                        &mut terminations,
                        QueryOperatorTermination::TerminalCap,
                    );
                }
                self_truncated = execution.truncated;
                if execution.cancelled {
                    disposition = QueryOperatorDisposition::Cancelled;
                }
                execution
            }
        }
        (PhysicalQueryOperator::BindingScan, LogicalQueryOperator::BindingSeed(seed)) => {
            if state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
            {
                disposition = QueryOperatorDisposition::Skipped;
                push_operator_termination(
                    &mut terminations,
                    QueryOperatorTermination::CancellationBeforeWork,
                );
                cancelled_plan_execution()
            } else {
                let execution = execute_environment_seed(
                    EnvironmentSeedKind::Bindings(&seed.filter),
                    &seed.where_globs,
                    &seed.languages,
                    terminal_cap,
                    state,
                    limits,
                    diagnostics,
                );
                if terminal_cap.is_some_and(|cap| execution.rows.len() >= cap) {
                    push_operator_termination(
                        &mut terminations,
                        QueryOperatorTermination::TerminalCap,
                    );
                }
                self_truncated = execution.truncated;
                if execution.cancelled {
                    disposition = QueryOperatorDisposition::Cancelled;
                }
                execution
            }
        }
        (
            PhysicalQueryOperator::GenerationSiteScan,
            LogicalQueryOperator::GenerationSiteSeed(seed),
        ) => {
            if state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
            {
                disposition = QueryOperatorDisposition::Skipped;
                push_operator_termination(
                    &mut terminations,
                    QueryOperatorTermination::CancellationBeforeWork,
                );
                cancelled_plan_execution()
            } else {
                let execution = execute_materialization_seed(
                    MaterializationSeedKind::GenerationSites(&seed.filter),
                    &seed.where_globs,
                    &seed.languages,
                    terminal_cap,
                    state,
                    limits,
                    diagnostics,
                );
                if terminal_cap.is_some_and(|cap| execution.rows.len() >= cap) {
                    push_operator_termination(
                        &mut terminations,
                        QueryOperatorTermination::TerminalCap,
                    );
                }
                self_truncated = execution.truncated;
                if execution.cancelled {
                    disposition = QueryOperatorDisposition::Cancelled;
                }
                execution
            }
        }
        (PhysicalQueryOperator::ExportScan, LogicalQueryOperator::ExportSeed(seed)) => {
            if state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
            {
                disposition = QueryOperatorDisposition::Skipped;
                push_operator_termination(
                    &mut terminations,
                    QueryOperatorTermination::CancellationBeforeWork,
                );
                cancelled_plan_execution()
            } else {
                let execution = execute_materialization_seed(
                    MaterializationSeedKind::Exports(&seed.filter),
                    &seed.where_globs,
                    &seed.languages,
                    terminal_cap,
                    state,
                    limits,
                    diagnostics,
                );
                if terminal_cap.is_some_and(|cap| execution.rows.len() >= cap) {
                    push_operator_termination(
                        &mut terminations,
                        QueryOperatorTermination::TerminalCap,
                    );
                }
                self_truncated = execution.truncated;
                if execution.cancelled {
                    disposition = QueryOperatorDisposition::Cancelled;
                }
                execution
            }
        }
        (PhysicalQueryOperator::PathScan, LogicalQueryOperator::PathSeed(seed)) => {
            if state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
            {
                disposition = QueryOperatorDisposition::Skipped;
                push_operator_termination(
                    &mut terminations,
                    QueryOperatorTermination::CancellationBeforeWork,
                );
                cancelled_plan_execution()
            } else {
                let execution = execute_path_seed(
                    &seed.filter,
                    &seed.where_globs,
                    &seed.languages,
                    terminal_cap,
                    state,
                    limits,
                    diagnostics,
                );
                if terminal_cap.is_some_and(|cap| execution.rows.len() >= cap) {
                    push_operator_termination(
                        &mut terminations,
                        QueryOperatorTermination::TerminalCap,
                    );
                }
                self_truncated = execution.truncated;
                if execution.cancelled {
                    disposition = QueryOperatorDisposition::Cancelled;
                }
                execution
            }
        }
        (PhysicalQueryOperator::SeedScan, LogicalQueryOperator::Seed(seed)) => {
            if state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
            {
                disposition = QueryOperatorDisposition::Skipped;
                push_operator_termination(
                    &mut terminations,
                    QueryOperatorTermination::CancellationBeforeWork,
                );
                cancelled_plan_execution()
            } else {
                let execution = execute_seed(seed, terminal_cap, state, limits, diagnostics);
                if terminal_cap.is_some_and(|cap| execution.rows.len() >= cap) {
                    push_operator_termination(
                        &mut terminations,
                        QueryOperatorTermination::TerminalCap,
                    );
                }
                self_truncated = execution.truncated;
                if execution.cancelled {
                    disposition = QueryOperatorDisposition::Cancelled;
                }
                execution
            }
        }
        (
            PhysicalQueryOperator::PipelineStep,
            LogicalQueryOperator::Step {
                step,
                final_in_authored_suffix,
                ..
            },
        ) => {
            let dependency = physical_node.dependencies()[0];
            let dependency_started = profiling.then(Instant::now);
            let child = execute_plan(
                plan,
                dependency,
                state,
                limits,
                None,
                diagnostics,
                profile_branch,
            );
            if let Some(started) = dependency_started {
                dependency_execution_ns =
                    dependency_execution_ns.saturating_add(elapsed_ns(started));
            }
            input_rows = child.rows.len();
            work_started = profiling.then(|| state_execution_work_snapshot(state));
            cache_started = state.cache_profile;
            own_diagnostic_start = diagnostics.len();
            if child.cancelled {
                disposition = QueryOperatorDisposition::Skipped;
                push_operator_termination(
                    &mut terminations,
                    QueryOperatorTermination::DependencyCancelled,
                );
                child
            } else if child.pipeline_halted {
                disposition = QueryOperatorDisposition::Skipped;
                push_operator_termination(
                    &mut terminations,
                    QueryOperatorTermination::DependencyPipelineHalted,
                );
                PlanExecution {
                    pipeline_halted: !final_in_authored_suffix,
                    ..child
                }
            } else {
                let mut instrumentation = profiling.then(QueryStepInstrumentation::default);
                let mut stepped = apply_plan_step(
                    step,
                    physical_node.derived_layer_request(),
                    *final_in_authored_suffix,
                    child.rows,
                    state,
                    limits,
                    terminal_cap,
                    diagnostics,
                    instrumentation.as_mut(),
                );
                if let Some(instrumentation) = instrumentation {
                    rows_visited = instrumentation.rows_visited;
                    relation_expansions = instrumentation.relation_expansions;
                    temporary_capacity_bytes_lower_bound =
                        instrumentation.temporary_capacity_bytes_lower_bound;
                }
                if terminal_cap.is_some_and(|cap| stepped.rows.len() >= cap) {
                    push_operator_termination(
                        &mut terminations,
                        QueryOperatorTermination::TerminalCap,
                    );
                }
                self_truncated = stepped.truncated;
                if stepped.cancelled {
                    disposition = QueryOperatorDisposition::Cancelled;
                }
                stepped.truncated |= child.truncated;
                stepped
            }
        }
        (
            PhysicalQueryOperator::ParallelUnion,
            LogicalQueryOperator::Set {
                op: SetOperator::Union,
                ..
            },
        ) => {
            let parallel = execute_parallel_seed_union(
                plan,
                physical_node.dependencies(),
                state,
                limits,
                terminal_cap,
                diagnostics,
                profile_branch,
                profiling,
            );
            input_rows = parallel.input_rows;
            rows_visited = parallel.rows_visited;
            rows_discarded = parallel.rows_discarded;
            temporary_capacity_bytes_lower_bound = parallel.temporary_capacity_bytes_lower_bound;
            self_truncated = parallel.operator_truncated;
            dependency_wait_ns = parallel.dependency_wait_ns;
            scheduling_overhead_ns = parallel.scheduling_overhead_ns;
            merge_ns = parallel.merge_ns;
            if self_truncated {
                push_operator_termination(&mut terminations, QueryOperatorTermination::TerminalCap);
            }
            work_started = profiling.then(|| state_execution_work_snapshot(state));
            cache_started = state.cache_profile;
            own_diagnostic_start = diagnostics.len();
            if parallel.execution.cancelled {
                disposition = QueryOperatorDisposition::Skipped;
                push_operator_termination(
                    &mut terminations,
                    QueryOperatorTermination::DependencyCancelled,
                );
            }
            parallel.execution
        }
        (
            PhysicalQueryOperator::SequentialUnion
            | PhysicalQueryOperator::SequentialIntersection
            | PhysicalQueryOperator::SequentialExcept,
            LogicalQueryOperator::Set { op, .. },
        ) => {
            if state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled)
            {
                disposition = QueryOperatorDisposition::Skipped;
                push_operator_termination(
                    &mut terminations,
                    QueryOperatorTermination::CancellationBeforeWork,
                );
                cancelled_plan_execution()
            } else {
                debug_assert_eq!(
                    physical_operator,
                    match op {
                        SetOperator::Union => PhysicalQueryOperator::SequentialUnion,
                        SetOperator::Intersect => PhysicalQueryOperator::SequentialIntersection,
                        SetOperator::Except => PhysicalQueryOperator::SequentialExcept,
                    }
                );
                let dependencies = physical_node.dependencies();
                let mut branch_rows = Vec::with_capacity(dependencies.len());
                let mut cancelled_child = None;
                let mut truncated = false;
                for (index, dependency) in dependencies.iter().copied().enumerate() {
                    let branch_limits = fair_branch_limits(
                        &state.budget,
                        limits,
                        dependencies.len().saturating_sub(index),
                    );
                    let diagnostic_start = diagnostics.len();
                    if let Some(branch) = profile_branch.as_mut() {
                        branch.push(index);
                    }
                    let dependency_started = profiling.then(Instant::now);
                    let mut child = execute_plan(
                        plan,
                        dependency,
                        state,
                        branch_limits,
                        None,
                        diagnostics,
                        profile_branch,
                    );
                    if let Some(started) = dependency_started {
                        dependency_execution_ns =
                            dependency_execution_ns.saturating_add(elapsed_ns(started));
                    }
                    if let Some(branch) = profile_branch.as_mut() {
                        let popped = branch.pop();
                        debug_assert_eq!(popped, Some(index));
                    }
                    input_rows = input_rows.saturating_add(child.rows.len());
                    let prefix_started = profiling.then(Instant::now);
                    prefix_branch_rows(&mut child.rows, index);
                    prefix_branch_diagnostics(&mut diagnostics[diagnostic_start..], index);
                    if let Some(started) = prefix_started {
                        merge_ns = merge_ns.saturating_add(elapsed_ns(started));
                    }
                    work_started = profiling.then(|| state_execution_work_snapshot(state));
                    cache_started = state.cache_profile;
                    own_diagnostic_start = diagnostics.len();
                    truncated |= child.truncated;
                    if child.cancelled {
                        push_operator_termination(
                            &mut terminations,
                            QueryOperatorTermination::DependencyCancelled,
                        );
                        cancelled_child = Some(child);
                        break;
                    }
                    branch_rows.push(child.rows);
                }
                rows_visited = input_rows;
                if let Some(child) = cancelled_child {
                    disposition = QueryOperatorDisposition::Skipped;
                    child
                } else {
                    let merge_started = profiling.then(Instant::now);
                    let (mut rows, merge_measurement) =
                        combine_set_rows(*op, branch_rows, profiling);
                    if let Some(started) = merge_started {
                        merge_ns = merge_ns.saturating_add(elapsed_ns(started));
                    }
                    if let Some(merge_measurement) = merge_measurement {
                        rows_discarded = Some(merge_measurement.rows_discarded);
                        temporary_capacity_bytes_lower_bound =
                            merge_measurement.temporary_capacity_bytes_lower_bound;
                    }
                    if let Some(cap) = terminal_cap
                        && rows.len() > cap
                    {
                        self_truncated = true;
                        rows_discarded = Some(
                            rows_discarded
                                .unwrap_or_default()
                                .saturating_add(rows.len() - cap),
                        );
                        push_operator_termination(
                            &mut terminations,
                            QueryOperatorTermination::TerminalCap,
                        );
                        rows.truncate(cap);
                    }
                    PlanExecution {
                        rows,
                        truncated,
                        cancelled: false,
                        pipeline_halted: false,
                    }
                }
            }
        }
        (PhysicalQueryOperator::Limit, LogicalQueryOperator::Limit { count, .. }) => {
            let dependency = physical_node.dependencies()[0];
            let dependency_started = profiling.then(Instant::now);
            let mut child = execute_plan(
                plan,
                dependency,
                state,
                limits,
                Some(count.saturating_add(1)),
                diagnostics,
                profile_branch,
            );
            if let Some(started) = dependency_started {
                dependency_execution_ns =
                    dependency_execution_ns.saturating_add(elapsed_ns(started));
            }
            input_rows = child.rows.len();
            rows_visited = input_rows;
            rows_discarded = Some(0);
            work_started = profiling.then(|| state_execution_work_snapshot(state));
            cache_started = state.cache_profile;
            own_diagnostic_start = diagnostics.len();
            let dependency_cancelled = child.cancelled;
            let token_cancelled = state
                .cancellation
                .is_some_and(CancellationToken::is_cancelled);
            if dependency_cancelled || token_cancelled {
                push_operator_termination(
                    &mut terminations,
                    if dependency_cancelled {
                        QueryOperatorTermination::DependencyCancelled
                    } else {
                        QueryOperatorTermination::CancellationDuringWork
                    },
                );
                if dependency_cancelled {
                    disposition = QueryOperatorDisposition::Skipped;
                } else if token_cancelled {
                    disposition = QueryOperatorDisposition::Cancelled;
                }
                child.cancelled = true;
                child.truncated = true;
                push_cancelled_diagnostic(diagnostics);
            }
            if child.rows.len() > *count {
                self_truncated = true;
                rows_discarded = Some(child.rows.len() - *count);
                push_operator_termination(&mut terminations, QueryOperatorTermination::ResultLimit);
                push_truncation_diagnostic(diagnostics, &state.budget, *count);
                child.rows.truncate(*count);
                child.truncated = true;
            }
            child
        }
        _ => unreachable!("physical operator must implement its logical query node"),
    };

    if profiling {
        append_diagnostic_terminations(
            &mut terminations,
            &diagnostics[own_diagnostic_start.min(diagnostics.len())..],
        );
        if self_truncated
            && terminations
                .as_ref()
                .is_some_and(|terminations| terminations.is_empty())
        {
            push_operator_termination(
                &mut terminations,
                QueryOperatorTermination::AnalysisIncomplete,
            );
        }
        if execution.cancelled && disposition == QueryOperatorDisposition::Cancelled {
            push_operator_termination(
                &mut terminations,
                QueryOperatorTermination::CancellationDuringWork,
            );
        }
    }

    let observed_work = profiling.then(|| state_execution_work_snapshot(state));
    if let (Some(profile), Some(started)) = (&mut state.profile, invocation_started) {
        let total_elapsed_ns = elapsed_ns(started);
        let work = observed_work
            .unwrap_or_default()
            .saturating_sub(work_started.unwrap_or_default());
        let cache = state
            .cache_profile
            .unwrap_or_default()
            .saturating_sub(cache_started.unwrap_or_default());
        profile.record(QueryOperatorProfile {
            node: node_id,
            branch: profile_branch.as_deref().unwrap_or_default().to_vec(),
            operator: physical_operator,
            disposition,
            elapsed_ns: total_elapsed_ns
                .saturating_sub(dependency_execution_ns)
                .saturating_sub(dependency_wait_ns),
            total_elapsed_ns,
            dependency_execution_ns,
            dependency_wait_ns,
            merge_ns,
            scheduling_overhead_ns,
            input_rows,
            rows_visited,
            relation_expansions,
            rows_discarded,
            temporary_capacity_bytes_lower_bound,
            work,
            cache,
            terminations: terminations.unwrap_or_default(),
            output_rows: execution.rows.len(),
            operator_truncated: self_truncated,
            result_truncated: execution.truncated,
            result_cancelled: execution.cancelled,
        });
    }
    execution
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute_parallel_seed_union(
    plan: &PhysicalQueryPlan,
    dependencies: &[PhysicalQueryNodeId],
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    terminal_cap: Option<usize>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    profile_branch: &Option<Vec<usize>>,
    profiling: bool,
) -> ParallelUnionExecution {
    debug_assert_eq!(dependencies.len(), 2);
    debug_assert!(dependencies.iter().all(|dependency| matches!(
        plan.node(*dependency).operator(),
        PhysicalQueryOperator::SeedScan
    )));
    debug_assert_ne!(dependencies[0], dependencies[1]);

    let coordinator = FairSeedBudgetCoordinator::new(
        state.budget,
        limits,
        dependencies.len(),
        state.cancellation,
    );
    let analyzer = state.analyzer;
    let cancellation = state.cancellation;
    let receiver_budget_override = state.receiver_budget_override;
    let access_mode = state.access_mode;
    let retained_value_census = state.retained_value_census.clone();
    let structural_index_session = state.structural_index_session.clone();
    let scheduler_workers = state.scheduler_workers;
    let base_budget = state.budget;
    let base_profile_branch = profile_branch.as_deref().unwrap_or_default().to_vec();
    let scheduled = BoundedReadyScheduler::new(scheduler_workers).run(
        dependencies.len(),
        cancellation,
        |branch| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let lease = coordinator.lease(branch);
                let mut branch_state = QueryExecutionState {
                    analyzer,
                    // Parallel union dependencies are seed scans only; receiver
                    // steps execute later against the parent workspace state.
                    workspace: None,
                    cancellation,
                    receiver_budget_override,
                    budget: base_budget,
                    seed_cache: HashMap::default(),
                    // Parallel branches dedupe shared per-file charges
                    // through the coordinator ledger, not this one.
                    seed_scan_ledger: SeedScanLedger::default(),
                    indexed_declarations: IndexedDeclarations::default(),
                    reference_cache: ReferenceTraversalCache::default(),
                    occurrence_cache: OccurrenceTraversalCache::default(),
                    environment_cache: EnvironmentTraversalCache::default(),
                    materialization_cache: materialization::MaterializationTraversalCache::default(
                    ),
                    edge_cache: EdgeTraversalCache::default(),
                    path_cache: PathTraversalCache::default(),
                    call_cache: CallTraversalCache::default(),
                    receiver_facts: HashMap::default(),
                    semantic: None,
                    import_graph: None,
                    import_graph_generations: None,
                    direct_import_layer: None,
                    direct_import_layer_generations: None,
                    deferred_derived_builds: HashSet::default(),
                    cache_profile: profiling.then(QueryCacheProfile::default),
                    profile: profiling
                        .then(|| QueryExecutionProfile::new(plan, 0, scheduler_workers)),
                    retained_value_census: retained_value_census.clone(),
                    structural_index_session: structural_index_session.clone(),
                    access_mode,
                    access_failure: None,
                    parallel_seed_budget: Some(lease.clone()),
                    scheduler_workers,
                };
                let mut branch_diagnostics = Vec::new();
                let mut branch_path = profiling.then(|| {
                    let mut path = base_profile_branch.clone();
                    path.push(branch);
                    path
                });
                let execution = execute_plan(
                    plan,
                    dependencies[branch],
                    &mut branch_state,
                    limits,
                    None,
                    &mut branch_diagnostics,
                    &mut branch_path,
                );
                lease.finish(branch_state.budget);
                debug_assert!(branch_state.import_graph.is_none());
                debug_assert!(branch_state.import_graph_generations.is_none());
                debug_assert!(branch_state.direct_import_layer.is_none());
                debug_assert!(branch_state.direct_import_layer_generations.is_none());
                debug_assert!(branch_state.deferred_derived_builds.is_empty());
                debug_assert!(branch_state.reference_cache.inbound.is_empty());
                debug_assert!(branch_state.reference_cache.outbound.is_empty());
                debug_assert!(branch_state.call_cache.incoming.is_empty());
                debug_assert!(branch_state.call_cache.outgoing.is_empty());
                let (operators, access_path) = branch_state.profile.take().map_or_else(
                    || (Vec::new(), QueryAccessPathProfile::default()),
                    |profile| (profile.operators, profile.access_path),
                );
                ParallelSeedBranchResult {
                    execution,
                    diagnostics: branch_diagnostics,
                    seed_cache: branch_state.seed_cache,
                    cache_profile: branch_state.cache_profile,
                    operators,
                    access_path,
                    access_failure: branch_state.access_failure,
                }
            }));
            match result {
                Ok(result) => result,
                Err(payload) => {
                    coordinator.fail();
                    std::panic::resume_unwind(payload)
                }
            }
        },
    );

    let mut scheduler_profile = scheduled.profile;
    scheduler_profile.budget_wait_ns = coordinator.wait_ns();
    let dependency_wait_ns = scheduler_profile.coordinator_wait_ns;
    let scheduling_overhead_ns = scheduler_profile.dispatch_overhead_ns;
    if let Some(profile) = &mut state.profile {
        profile.record_scheduler_run(scheduler_profile);
    }

    let mut input_rows = 0usize;
    let mut branch_rows = Vec::with_capacity(dependencies.len());
    let mut truncated = false;
    let mut cancelled_child = None;
    let prefix_started = profiling.then(Instant::now);
    for (branch, mut result) in scheduled.results.into_iter().enumerate() {
        input_rows = input_rows.saturating_add(result.execution.rows.len());
        let contributes_to_public_prefix = cancelled_child.is_none();
        if contributes_to_public_prefix {
            prefix_branch_rows(&mut result.execution.rows, branch);
            prefix_branch_diagnostics(&mut result.diagnostics, branch);
            diagnostics.append(&mut result.diagnostics);
            truncated |= result.execution.truncated;
        }

        for (key, cached) in result.seed_cache {
            assert!(
                state.seed_cache.insert(key, cached).is_none(),
                "parallel union eligibility requires distinct seed cache keys"
            );
        }
        if let (Some(parent), Some(branch_cache)) = (&mut state.cache_profile, result.cache_profile)
        {
            *parent = parent.saturating_add(branch_cache);
        }
        if let Some(profile) = &mut state.profile {
            profile.operators.extend(result.operators);
            profile.access_path =
                std::mem::take(&mut profile.access_path).saturating_add(result.access_path);
        }
        if state.access_failure.is_none() {
            state.access_failure = result.access_failure;
        }
        if contributes_to_public_prefix {
            if result.execution.cancelled {
                cancelled_child = Some(result.execution);
            } else {
                branch_rows.push(result.execution.rows);
            }
        }
    }
    state.budget = coordinator.committed_budget();
    let mut merge_ns = prefix_started.map(elapsed_ns).unwrap_or(0);

    if let Some(child) = cancelled_child {
        return ParallelUnionExecution {
            execution: child,
            input_rows,
            rows_visited: input_rows,
            rows_discarded: None,
            temporary_capacity_bytes_lower_bound: 0,
            operator_truncated: false,
            dependency_wait_ns,
            scheduling_overhead_ns,
            merge_ns,
        };
    }

    let merge_started = profiling.then(Instant::now);
    let (mut rows, merge_measurement) =
        combine_set_rows(SetOperator::Union, branch_rows, profiling);
    if let Some(started) = merge_started {
        merge_ns = merge_ns.saturating_add(elapsed_ns(started));
    }
    let mut rows_discarded = merge_measurement
        .as_ref()
        .map(|measurement| measurement.rows_discarded);
    let temporary_capacity_bytes_lower_bound = merge_measurement
        .map(|measurement| measurement.temporary_capacity_bytes_lower_bound)
        .unwrap_or_default();
    let mut operator_truncated = false;
    if let Some(cap) = terminal_cap
        && rows.len() > cap
    {
        operator_truncated = true;
        rows_discarded = Some(
            rows_discarded
                .unwrap_or_default()
                .saturating_add(rows.len() - cap),
        );
        rows.truncate(cap);
    }
    ParallelUnionExecution {
        execution: PlanExecution {
            rows,
            truncated,
            cancelled: false,
            pipeline_halted: false,
        },
        input_rows,
        rows_visited: input_rows,
        rows_discarded,
        temporary_capacity_bytes_lower_bound,
        operator_truncated,
        dependency_wait_ns,
        scheduling_overhead_ns,
        merge_ns,
    }
}

pub(super) fn push_operator_termination(
    terminations: &mut Option<Vec<QueryOperatorTermination>>,
    termination: QueryOperatorTermination,
) {
    if let Some(terminations) = terminations
        && !terminations.contains(&termination)
    {
        terminations.push(termination);
    }
}

pub(super) fn append_diagnostic_terminations(
    terminations: &mut Option<Vec<QueryOperatorTermination>>,
    diagnostics: &[CodeQueryDiagnostic],
) {
    for diagnostic in diagnostics {
        if diagnostic.impact == CodeQueryDiagnosticImpact::DeclaredNonExhaustive {
            continue;
        }
        let termination = match diagnostic.code {
            // Cancellation ownership is classified from the executor state
            // below. A diagnostic can be emitted or replayed by a parent that
            // only observed a cancelled dependency, so prose provenance is
            // not sufficient to call it operator-local work.
            CodeQueryDiagnosticCode::Cancelled => None,
            CodeQueryDiagnosticCode::ExecutionBudgetExhausted => {
                Some(QueryOperatorTermination::ExecutionBudget)
            }
            CodeQueryDiagnosticCode::PipelineBudgetExhausted => {
                Some(QueryOperatorTermination::PipelineBudget)
            }
            CodeQueryDiagnosticCode::ImportGraphBudgetExhausted => {
                Some(QueryOperatorTermination::ImportGraphBudget)
            }
            CodeQueryDiagnosticCode::ResultLimitReached => {
                Some(QueryOperatorTermination::ResultLimit)
            }
            CodeQueryDiagnosticCode::CallRelationBudgetExhausted
            | CodeQueryDiagnosticCode::CallRelationCandidateLimit
            | CodeQueryDiagnosticCode::ReferenceSourceBytesTruncated
            | CodeQueryDiagnosticCode::ReferenceCandidateFilesTruncated
            | CodeQueryDiagnosticCode::ReferenceCandidatesOmitted
            | CodeQueryDiagnosticCode::ReferenceCallsiteLimit
            | CodeQueryDiagnosticCode::UsesCandidateLimit
            | CodeQueryDiagnosticCode::UsesCandidatesOmitted
            | CodeQueryDiagnosticCode::SemanticBudgetExhausted
            | CodeQueryDiagnosticCode::TypestateSolverBudgetExhausted
            | CodeQueryDiagnosticCode::TypestateFindingBudgetExhausted
            | CodeQueryDiagnosticCode::TypestateWitnessTruncated
            | CodeQueryDiagnosticCode::ValueFlowSolverBudgetExhausted
            | CodeQueryDiagnosticCode::ValueFlowWitnessTruncated => {
                Some(QueryOperatorTermination::AnalysisLimit)
            }
            CodeQueryDiagnosticCode::TaintFindingTruncated => {
                Some(QueryOperatorTermination::AnalysisLimit)
            }
            CodeQueryDiagnosticCode::UnsupportedStructuralFeature
            | CodeQueryDiagnosticCode::MissingStructuralAdapter
            | CodeQueryDiagnosticCode::UnsupportedImportAnalysis
            | CodeQueryDiagnosticCode::UsesParserUnsupported
            | CodeQueryDiagnosticCode::SemanticWorkspaceRequired
            | CodeQueryDiagnosticCode::SemanticCapabilityUnsupported
            | CodeQueryDiagnosticCode::TypestateCapabilityUnsupported
            | CodeQueryDiagnosticCode::ValueFlowCapabilityUnsupported
            | CodeQueryDiagnosticCode::OccurrenceRoleUnsupported
            | CodeQueryDiagnosticCode::EnvironmentAxisUnsupported
            | CodeQueryDiagnosticCode::MaterializationAxisUnsupported
            | CodeQueryDiagnosticCode::IdentityAxisUnsupported => {
                Some(QueryOperatorTermination::UnsupportedAnalysis)
            }
            CodeQueryDiagnosticCode::OccurrenceRowBudgetExhausted
            | CodeQueryDiagnosticCode::EnvironmentRowBudgetExhausted
            | CodeQueryDiagnosticCode::MaterializationRowBudgetExhausted => {
                Some(QueryOperatorTermination::AnalysisLimit)
            }
            CodeQueryDiagnosticCode::SemanticResultsOmitted
            | CodeQueryDiagnosticCode::SemanticAnalysisPartial
            | CodeQueryDiagnosticCode::SemanticProviderFailed
            | CodeQueryDiagnosticCode::UnresolvedProtocolReference
            | CodeQueryDiagnosticCode::TypestateRegistrationStale
            | CodeQueryDiagnosticCode::TypestateHandleStale
            | CodeQueryDiagnosticCode::TypestateRootMismatch
            | CodeQueryDiagnosticCode::TypestateAnalysisPartial
            | CodeQueryDiagnosticCode::TypestateProviderFailed
            | CodeQueryDiagnosticCode::UnresolvedValueFlowPlanReference
            | CodeQueryDiagnosticCode::ValueFlowRegistrationStale
            | CodeQueryDiagnosticCode::ValueFlowHandleStale
            | CodeQueryDiagnosticCode::ValueFlowRootMismatch
            | CodeQueryDiagnosticCode::ValueFlowAnalysisPartial
            | CodeQueryDiagnosticCode::ValueFlowProviderFailed
            | CodeQueryDiagnosticCode::UnresolvedTaintResultReference
            | CodeQueryDiagnosticCode::TaintRegistrationStale
            | CodeQueryDiagnosticCode::TaintHandleStale
            | CodeQueryDiagnosticCode::TaintRootMismatch
            | CodeQueryDiagnosticCode::TaintPlanReportMismatch
            | CodeQueryDiagnosticCode::TaintProjectionFailed
            | CodeQueryDiagnosticCode::ReceiverAnalysisPartial
            | CodeQueryDiagnosticCode::ReceiverAnalysisFailed
            | CodeQueryDiagnosticCode::CallRelationParseFailed
            | CodeQueryDiagnosticCode::CallRelationCandidatesOmitted
            | CodeQueryDiagnosticCode::CallRelationAnalysisFailed
            | CodeQueryDiagnosticCode::ReferenceAnalysisFailed
            | CodeQueryDiagnosticCode::OccurrenceResolutionIncomplete
            | CodeQueryDiagnosticCode::EnvironmentDerivationIncomplete
            | CodeQueryDiagnosticCode::MaterializationDerivationIncomplete
            | CodeQueryDiagnosticCode::ResolutionTraceIncomplete
            | CodeQueryDiagnosticCode::EdgeAxisUnsupported
            | CodeQueryDiagnosticCode::EdgeDerivationIncomplete
            | CodeQueryDiagnosticCode::PathDerivationIncomplete => {
                Some(QueryOperatorTermination::AnalysisIncomplete)
            }
            CodeQueryDiagnosticCode::InvalidPlan
            | CodeQueryDiagnosticCode::NoEnclosingProcedure
            | CodeQueryDiagnosticCode::CallRelationTargetsAmbiguous
            | CodeQueryDiagnosticCode::ReferenceTargetsAmbiguous
            | CodeQueryDiagnosticCode::UsesTargetsAmbiguous
            | CodeQueryDiagnosticCode::BroadQuery => None,
        };
        if let Some(termination) = termination {
            push_operator_termination(terminations, termination);
        }
    }
}

pub(super) fn cancelled_plan_execution() -> PlanExecution {
    PlanExecution {
        rows: Vec::new(),
        truncated: true,
        cancelled: true,
        pipeline_halted: false,
    }
}
