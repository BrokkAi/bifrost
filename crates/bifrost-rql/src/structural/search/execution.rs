use super::*;

/// Only a proof that every seed is scoped to absent languages can remove a
/// branch's pipeline share. Unknown domains and unscoped seeds keep a share.
/// Walk the plan iteratively, including nested set operands, without changing
/// which branches execute or which diagnostics they produce.
fn branch_has_applicable_language(
    plan: &PhysicalQueryPlan,
    root: PhysicalQueryNodeId,
    scanned_languages: &HashSet<Language>,
) -> bool {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        let languages = match plan.logical_node(node).operator() {
            LogicalQueryOperator::Seed(seed) => &seed.languages,
            LogicalQueryOperator::OccurrenceSeed(seed) => &seed.languages,
            LogicalQueryOperator::ScopeSeed(seed) => &seed.languages,
            LogicalQueryOperator::BindingSeed(seed) => &seed.languages,
            LogicalQueryOperator::GenerationSiteSeed(seed) => &seed.languages,
            LogicalQueryOperator::ExportSeed(seed) => &seed.languages,
            LogicalQueryOperator::PathSeed(seed) => &seed.languages,
            LogicalQueryOperator::Step { .. }
            | LogicalQueryOperator::Limit { .. }
            | LogicalQueryOperator::Set { .. } => {
                pending.extend(plan.node(node).dependencies());
                continue;
            }
            LogicalQueryOperator::ConfigurationFactsSeed(_)
            | LogicalQueryOperator::DependencyEvidenceSeed(_)
            | LogicalQueryOperator::Correlate { .. }
            | LogicalQueryOperator::RequireBoth { .. } => return true,
        };
        if languages.is_empty()
            || languages
                .iter()
                .any(|language| scanned_languages.contains(language))
        {
            return true;
        }
    }
    false
}

struct UnaryPlanContinuation {
    node_id: PhysicalQueryNodeId,
    terminal_cap: Option<usize>,
    invocation_started: Option<Instant>,
    dependency_started: Option<Instant>,
}

struct PlanDependencyExecution {
    execution: PlanExecution,
    elapsed_ns: u64,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute_plan(
    plan: &PhysicalQueryPlan,
    token: QueryToken<'_>,
    node_id: PhysicalQueryNodeId,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    terminal_cap: Option<usize>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    profile_branch: &mut Option<Vec<usize>>,
) -> PlanExecution {
    let mut continuations = Vec::new();
    let mut current_node_id = node_id;
    let caps = plan.terminal_caps(node_id, terminal_cap);
    let mut current_terminal_cap = caps[node_id.index()];
    let chain_diagnostic_start = diagnostics.len();

    loop {
        let node = plan.node(current_node_id);
        let profiling = state.profile.is_some();
        match (
            node.operator(),
            plan.logical_node(current_node_id).operator(),
        ) {
            (PhysicalQueryOperator::PipelineStep, LogicalQueryOperator::Step { .. }) => {
                continuations.push(UnaryPlanContinuation {
                    node_id: current_node_id,
                    terminal_cap: current_terminal_cap,
                    invocation_started: profiling.then(Instant::now),
                    dependency_started: profiling.then(Instant::now),
                });
                current_node_id = node.dependencies()[0];
                current_terminal_cap = caps[current_node_id.index()];
            }
            (PhysicalQueryOperator::Limit, LogicalQueryOperator::Limit { .. }) => {
                let dependency = node.dependencies()[0];
                continuations.push(UnaryPlanContinuation {
                    node_id: current_node_id,
                    terminal_cap: current_terminal_cap,
                    invocation_started: profiling.then(Instant::now),
                    dependency_started: profiling.then(Instant::now),
                });
                current_node_id = dependency;
                current_terminal_cap = caps[dependency.index()];
            }
            _ => break,
        }
    }

    let profiling = state.profile.is_some();
    let mut execution = execute_plan_node(
        plan,
        token,
        current_node_id,
        state,
        limits,
        current_terminal_cap,
        diagnostics,
        profile_branch,
        profiling.then(Instant::now),
        None,
    );
    if !passes_input_rows_through(plan.logical_node(current_node_id).operator()) {
        forget_withheld_rows_paths(&mut diagnostics[chain_diagnostic_start..]);
    }

    while let Some(continuation) = continuations.pop() {
        let elapsed_ns = continuation
            .dependency_started
            .map(elapsed_ns)
            .unwrap_or_default();
        if !passes_input_rows_through(plan.logical_node(continuation.node_id).operator()) {
            forget_withheld_rows_paths(&mut diagnostics[chain_diagnostic_start..]);
        }
        execution = execute_plan_node(
            plan,
            token,
            continuation.node_id,
            state,
            limits,
            continuation.terminal_cap,
            diagnostics,
            profile_branch,
            continuation.invocation_started,
            Some(PlanDependencyExecution {
                execution,
                elapsed_ns,
            }),
        );
    }

    execution
}

/// Whether every row an operator outputs is either one it produced itself or
/// an input row it passed through unchanged (#5451).
///
/// A diagnostic's `withheld_rows_path` is a statement about the rows of the
/// step that raised it. It stays true of the query's rows only while every
/// later operator passes rows through; an operator that derives new rows from
/// its inputs, or keeps some according to another input, can put a gap
/// upstream into rows of any file.
fn passes_input_rows_through(operator: &LogicalQueryOperator) -> bool {
    match operator {
        LogicalQueryOperator::Seed(_)
        | LogicalQueryOperator::OccurrenceSeed(_)
        | LogicalQueryOperator::ScopeSeed(_)
        | LogicalQueryOperator::BindingSeed(_)
        | LogicalQueryOperator::GenerationSiteSeed(_)
        | LogicalQueryOperator::ExportSeed(_)
        | LogicalQueryOperator::PathSeed(_)
        | LogicalQueryOperator::ConfigurationFactsSeed(_)
        | LogicalQueryOperator::DependencyEvidenceSeed(_)
        | LogicalQueryOperator::Limit { .. } => true,
        LogicalQueryOperator::Step { step, .. } => {
            matches!(step, QueryStep::Filter(_) | QueryStep::Project(_))
        }
        LogicalQueryOperator::Set { op, .. } => *op == SetOperator::Union,
        LogicalQueryOperator::Correlate { .. } | LogicalQueryOperator::RequireBoth { .. } => false,
    }
}

/// Withdraw the file attribution of diagnostics whose rows a later operator
/// no longer passes through.
fn forget_withheld_rows_paths(diagnostics: &mut [CodeQueryDiagnostic]) {
    for diagnostic in diagnostics {
        diagnostic.withheld_rows_path = None;
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_plan_node(
    plan: &PhysicalQueryPlan,
    token: QueryToken<'_>,
    node_id: PhysicalQueryNodeId,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    terminal_cap: Option<usize>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    profile_branch: &mut Option<Vec<usize>>,
    invocation_started: Option<Instant>,
    dependency_execution: Option<PlanDependencyExecution>,
) -> PlanExecution {
    let profiling = state.profile.is_some();
    let physical_node = plan.node(node_id);
    let physical_operator = physical_node.operator();
    let logical_operator = plan.logical_node(node_id).operator();
    assert_eq!(
        matches!(
            physical_operator,
            PhysicalQueryOperator::PipelineStep | PhysicalQueryOperator::Limit
        ),
        dependency_execution.is_some(),
        "unary query operators receive exactly one completed dependency"
    );
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
        (
            PhysicalQueryOperator::DependencyEvidenceScan,
            LogicalQueryOperator::DependencyEvidenceSeed(seed),
        ) => {
            let execution =
                execute_dependency_evidence_seed(seed, terminal_cap, state, limits, diagnostics);
            self_truncated = execution.truncated;
            if execution.cancelled {
                disposition = QueryOperatorDisposition::Cancelled;
            }
            execution
        }
        (
            PhysicalQueryOperator::ConfigurationFactsScan,
            LogicalQueryOperator::ConfigurationFactsSeed(seed),
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
                let execution = execute_configuration_facts_seed(
                    seed,
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
            let PlanDependencyExecution {
                execution: child,
                elapsed_ns,
            } = dependency_execution.expect("pipeline step has a completed dependency");
            dependency_execution_ns = dependency_execution_ns.saturating_add(elapsed_ns);
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
                    token,
                    physical_node.derived_layer_request(),
                    physical_node.diagnostic_relation_predicates(),
                    *final_in_authored_suffix,
                    child.rows,
                    state,
                    limits,
                    plan.logical_node(node_id)
                        .operator()
                        .step_output_cap(terminal_cap)
                        .resolve(limits.max_pipeline_rows),
                    diagnostics,
                    instrumentation.as_mut(),
                );
                if let Some(instrumentation) = instrumentation {
                    rows_visited = instrumentation.rows_visited;
                    relation_expansions = instrumentation.relation_expansions;
                    temporary_capacity_bytes_lower_bound =
                        instrumentation.temporary_capacity_bytes_lower_bound;
                }
                // `max_step_outputs` is enforced per step and has no counter
                // of its own; a merge of per-seed executions can only see a
                // per-step truncation if each execution reports what each step
                // emitted. A retried set branch adds to its node's count, which
                // is the honest total of rows that step produced.
                state.step_outputs[node_id.index()] = state.step_outputs[node_id.index()]
                    .saturating_add(u64::try_from(stepped.rows.len()).unwrap_or(u64::MAX));
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
                token,
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
                let applicable: Vec<_> = dependencies
                    .iter()
                    .map(|dependency| {
                        branch_has_applicable_language(plan, *dependency, &state.scanned_languages)
                    })
                    .collect();
                let mut remaining_applicable = applicable.iter().filter(|value| **value).count();
                let mut branch_rows = Vec::with_capacity(dependencies.len());
                // Each branch's diagnostics stay in their own vector until the
                // retry pass below decides which attempt survives; they are
                // appended in branch order afterwards.
                let mut branch_diagnostics: Vec<Vec<CodeQueryDiagnostic>> =
                    Vec::with_capacity(dependencies.len());
                let mut branch_attempts: Vec<BranchAttempt> =
                    Vec::with_capacity(dependencies.len());
                let mut cancelled_child = None;
                let mut complete_prefix = true;
                let mut empty_operand = false;
                for (index, dependency) in dependencies.iter().copied().enumerate() {
                    let mut branch_limits = fair_branch_limits(
                        &state.budget,
                        limits,
                        dependencies.len().saturating_sub(index),
                    );
                    if *op == SetOperator::Union && applicable[index] {
                        assert!(remaining_applicable > 0);
                        let applicable_limits =
                            fair_branch_limits(&state.budget, limits, remaining_applicable);
                        // A smaller divisor cannot shrink an applicable arm's
                        // grant. Caps are absolute cumulative counters, so
                        // rolling unused shares forward cannot spend twice.
                        debug_assert!(
                            applicable_limits.max_pipeline_rows >= branch_limits.max_pipeline_rows
                        );
                        debug_assert!(
                            applicable_limits.max_pipeline_rows <= limits.max_pipeline_rows
                        );
                        branch_limits.max_pipeline_rows = applicable_limits.max_pipeline_rows;
                        remaining_applicable -= 1;
                    }
                    let mut child_diagnostics = Vec::new();
                    if let Some(branch) = profile_branch.as_mut() {
                        branch.push(index);
                    }
                    let dependency_started = profiling.then(Instant::now);
                    let mut child = execute_plan(
                        plan,
                        token,
                        dependency,
                        state,
                        branch_limits,
                        None,
                        &mut child_diagnostics,
                        profile_branch,
                    );
                    debug_assert!(
                        state
                            .budget
                            .pipeline_rows
                            .max(state.budget.provenance_steps)
                            <= limits.max_pipeline_rows,
                        "union branch charges must stay inside the cumulative budget"
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
                    rows_visited = rows_visited.saturating_add(child.rows.len());
                    let prefix_started = profiling.then(Instant::now);
                    prefix_branch_rows(&mut child.rows, index);
                    prefix_branch_diagnostics(&mut child_diagnostics, index);
                    if let Some(started) = prefix_started {
                        merge_ns = merge_ns.saturating_add(elapsed_ns(started));
                    }
                    // Only a branch that exhausted its share of the metered
                    // scan budget can gain from a larger share. A branch that
                    // stopped on a row cap, a relation limit, or missing
                    // analysis reports that instead, and re-running it would
                    // repeat the same work for the same result.
                    let starved = child.truncated
                        && child_diagnostics.iter().any(|diagnostic| {
                            diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
                        });
                    // An empty operand proves the whole result empty only if
                    // every evaluated operand has complete coverage. Otherwise
                    // preserve the ordinary merge and starved-branch retry.
                    complete_prefix &= !child.truncated
                        && !child_diagnostics.iter().any(|diagnostic| {
                            diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete
                        });
                    // A seed-narrowed except is one unit of a whole execution
                    // whose minuend can be non-empty in another file. That
                    // execution evaluates the subtrahends over this file too,
                    // so the unit must, or its summed work and diagnostics
                    // would understate the whole run's.
                    let ends_operator = complete_prefix
                        && !child.cancelled
                        && child.rows.is_empty()
                        && (*op == SetOperator::Intersect
                            || (*op == SetOperator::Except
                                && index == 0
                                && state.scope.seed_files().is_none()));
                    branch_diagnostics.push(child_diagnostics);
                    if child.cancelled {
                        push_operator_termination(
                            &mut terminations,
                            QueryOperatorTermination::DependencyCancelled,
                        );
                        cancelled_child = Some(child);
                        break;
                    }
                    branch_attempts.push(BranchAttempt {
                        limits: branch_limits,
                        truncated: child.truncated,
                        starved,
                    });
                    branch_rows.push(child.rows);
                    if ends_operator {
                        empty_operand = true;
                        if index + 1 < dependencies.len() {
                            push_operator_termination(
                                &mut terminations,
                                QueryOperatorTermination::EmptyOperand,
                            );
                        }
                        break;
                    }
                }
                if cancelled_child.is_none() && !empty_operand {
                    // Branch 0 ran under a share of the leftovers computed
                    // before any branch had run, so a dominant first branch
                    // starves against branches that then leave their share
                    // unused. Offer every truncated branch one more attempt
                    // against the leftovers the whole first pass revealed.
                    // One pass suffices: after it each retried branch has seen
                    // the true leftovers, and a branch is retried at most once,
                    // so the pass terminates.
                    let mut retry_remaining = branch_attempts
                        .iter()
                        .filter(|attempt| attempt.starved)
                        .count();
                    if retry_remaining > 0 {
                        // A truncated seed result is cached and replayed
                        // verbatim, so a retry would re-observe the first
                        // attempt's frontier. Dropping the truncated entries
                        // makes the retry rescan; the seed scan ledger keeps
                        // the files the first attempt already charged free, so
                        // the rescan resumes at the frontier instead of paying
                        // for the whole branch again.
                        state
                            .seed_cache
                            .read_mut(&memo_attribution(state.analyzer), |cache| {
                                cache.retain(|_, cached| !cached.truncated)
                            });
                    }
                    for index in 0..branch_attempts.len() {
                        if !branch_attempts[index].starved {
                            continue;
                        }
                        let retry_limits =
                            fair_branch_limits(&state.budget, limits, retry_remaining);
                        retry_remaining = retry_remaining.saturating_sub(1);
                        if !retry_can_progress(
                            &state.budget,
                            limits,
                            retry_limits,
                            branch_attempts[index].limits,
                        ) {
                            continue;
                        }
                        let mut retry_diagnostics = Vec::new();
                        if let Some(branch) = profile_branch.as_mut() {
                            branch.push(index);
                        }
                        let dependency_started = profiling.then(Instant::now);
                        let mut child = execute_plan(
                            plan,
                            token,
                            dependencies[index],
                            state,
                            retry_limits,
                            None,
                            &mut retry_diagnostics,
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
                        rows_visited = rows_visited.saturating_add(child.rows.len());
                        let prefix_started = profiling.then(Instant::now);
                        prefix_branch_rows(&mut child.rows, index);
                        prefix_branch_diagnostics(&mut retry_diagnostics, index);
                        if let Some(started) = prefix_started {
                            merge_ns = merge_ns.saturating_add(elapsed_ns(started));
                        }
                        if child.cancelled {
                            push_operator_termination(
                                &mut terminations,
                                QueryOperatorTermination::DependencyCancelled,
                            );
                            branch_diagnostics[index] = retry_diagnostics;
                            cancelled_child = Some(child);
                            break;
                        }
                        // The seed scan ledger admits each file's scan charges
                        // once per execution, so a retry resumes at the
                        // truncation frontier; the row lanes are not deduped,
                        // so a retry against an already-spent row budget can
                        // return less than the first attempt did. Keep the
                        // attempt that saw more of the branch.
                        if child.truncated && child.rows.len() <= branch_rows[index].len() {
                            continue;
                        }
                        input_rows = input_rows
                            .saturating_sub(branch_rows[index].len())
                            .saturating_add(child.rows.len());
                        branch_rows[index] = child.rows;
                        branch_diagnostics[index] = retry_diagnostics;
                        branch_attempts[index].truncated = child.truncated;
                        branch_attempts[index].starved = false;
                    }
                }
                let truncated = branch_attempts.iter().any(|attempt| attempt.truncated);
                // A scoped BindingUses query can withhold just the binders
                // whose reference scope is incomplete. Other incomplete
                // exclusion branches have no per-binding coverage, so none
                // of their difference rows can support a negative finding.
                let incomplete_exclusion = if *op != SetOperator::Except {
                    None
                } else if branch_attempts
                    .iter()
                    .skip(1)
                    .any(|attempt| attempt.truncated)
                {
                    Some(false)
                } else {
                    let incomplete = branch_diagnostics
                        .iter()
                        .skip(1)
                        .flatten()
                        .filter(|diagnostic| {
                            diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete
                        })
                        .collect::<Vec<_>>();
                    if incomplete.is_empty() {
                        None
                    } else {
                        let scope_diagnostics = incomplete.iter().all(|diagnostic| {
                            matches!(
                                diagnostic.code,
                                CodeQueryDiagnosticCode::OccurrenceResolutionIncomplete
                                    | CodeQueryDiagnosticCode::OccurrenceRoleUnsupported
                                    | CodeQueryDiagnosticCode::EnvironmentAxisUnsupported
                                    | CodeQueryDiagnosticCode::EnvironmentDerivationIncomplete
                            )
                        });
                        let left_bindings_are_covered = branch_rows.first().is_some_and(|rows| {
                            rows.iter().all(|row| match &row.value {
                                PipelineValue::Binding(binding) => state
                                    .environment_cache
                                    .binding_use_completeness(state.analyzer, binding)
                                    .is_some(),
                                _ => false,
                            })
                        });
                        Some(scope_diagnostics && left_bindings_are_covered)
                    }
                };
                for mut branch in branch_diagnostics {
                    diagnostics.append(&mut branch);
                }
                work_started = profiling.then(|| state_execution_work_snapshot(state));
                cache_started = state.cache_profile;
                own_diagnostic_start = diagnostics.len();
                if let Some(child) = cancelled_child {
                    disposition = QueryOperatorDisposition::Skipped;
                    child
                } else {
                    let merge_started = profiling.then(Instant::now);
                    let (mut rows, merge_measurement) =
                        combine_set_rows(*op, branch_rows, profiling);
                    let incomplete_rows_discarded = match incomplete_exclusion {
                        Some(true) => {
                            let before = rows.len();
                            rows.retain(|row| match &row.value {
                                PipelineValue::Binding(binding) => {
                                    state
                                        .environment_cache
                                        .binding_use_completeness(state.analyzer, binding)
                                        == Some(true)
                                }
                                _ => false,
                            });
                            before.saturating_sub(rows.len())
                        }
                        Some(false) => {
                            let count = rows.len();
                            rows.clear();
                            count
                        }
                        None => 0,
                    };
                    if let Some(started) = merge_started {
                        merge_ns = merge_ns.saturating_add(elapsed_ns(started));
                    }
                    if let Some(merge_measurement) = merge_measurement {
                        rows_discarded = Some(
                            merge_measurement
                                .rows_discarded
                                .saturating_add(incomplete_rows_discarded),
                        );
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
            let PlanDependencyExecution {
                execution: mut child,
                elapsed_ns,
            } = dependency_execution.expect("limit has a completed dependency");
            dependency_execution_ns = dependency_execution_ns.saturating_add(elapsed_ns);
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
        (
            PhysicalQueryOperator::CrossDomainCorrelate
            | PhysicalQueryOperator::CrossDomainRequireBoth,
            LogicalQueryOperator::Correlate { .. } | LogicalQueryOperator::RequireBoth { .. },
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
                // The code input is branch 0 and the configuration input is
                // branch 1, in both row provenance and diagnostics. Each runs
                // under a fair share of the remaining budget, like a set
                // branch, and neither sees the other's rows.
                let dependencies = physical_node.dependencies();
                debug_assert_eq!(dependencies.len(), 2);
                let mut inputs = Vec::with_capacity(2);
                let mut cancelled_child = None;
                for (index, dependency) in dependencies.iter().copied().enumerate() {
                    let branch_limits = fair_branch_limits(
                        &state.budget,
                        limits,
                        dependencies.len().saturating_sub(index),
                    );
                    let mut child_diagnostics = Vec::new();
                    if let Some(branch) = profile_branch.as_mut() {
                        branch.push(index);
                    }
                    let dependency_started = profiling.then(Instant::now);
                    let mut child = execute_plan(
                        plan,
                        token,
                        dependency,
                        state,
                        branch_limits,
                        None,
                        &mut child_diagnostics,
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
                    rows_visited = rows_visited.saturating_add(child.rows.len());
                    prefix_branch_rows(&mut child.rows, index);
                    prefix_branch_diagnostics(&mut child_diagnostics, index);
                    diagnostics.append(&mut child_diagnostics);
                    if child.cancelled {
                        push_operator_termination(
                            &mut terminations,
                            QueryOperatorTermination::DependencyCancelled,
                        );
                        cancelled_child = Some(child);
                        break;
                    }
                    inputs.push(child);
                }
                work_started = profiling.then(|| state_execution_work_snapshot(state));
                cache_started = state.cache_profile;
                own_diagnostic_start = diagnostics.len();
                if let Some(child) = cancelled_child {
                    disposition = QueryOperatorDisposition::Skipped;
                    child
                } else {
                    let configuration = inputs.pop().expect("the configuration input ran");
                    let code = inputs.pop().expect("the code input ran");
                    let execution = match logical_operator {
                        LogicalQueryOperator::Correlate {
                            relation: CrossDomainRelation::DependencyConfiguration(relation),
                            configuration_seeds,
                            ..
                        } => execute_dependency_configuration(
                            relation,
                            configuration_seeds,
                            code,
                            configuration,
                            terminal_cap,
                            state,
                            limits,
                            diagnostics,
                        ),
                        LogicalQueryOperator::Correlate {
                            relation: CrossDomainRelation::ConfigurationKey(relation),
                            configuration_seeds,
                            ..
                        } => execute_correlate_configuration_key(
                            relation,
                            configuration_seeds,
                            code,
                            configuration,
                            terminal_cap,
                            state,
                            limits,
                            diagnostics,
                        ),
                        LogicalQueryOperator::Correlate {
                            relation: CrossDomainRelation::ConfigurationCode(relation),
                            ..
                        } => super::configuration_join::execute(
                            relation,
                            code,
                            configuration,
                            terminal_cap,
                            state,
                            limits,
                            diagnostics,
                        ),
                        LogicalQueryOperator::RequireBoth { .. } => execute_require_both(
                            code,
                            configuration,
                            terminal_cap,
                            state,
                            limits,
                            diagnostics,
                        ),
                        _ => unreachable!("cross-domain physical operators run cross-domain nodes"),
                    };
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

/// One sequential set-operation branch's first-pass outcome, kept so the retry
/// pass can compare the leftovers against the limits the branch actually ran
/// under. `fair_branch_limits` derives its caps from the budget's usage at
/// call time, so they cannot be recomputed after the fact.
struct BranchAttempt {
    limits: CodeQueryExecutionLimits,
    truncated: bool,
    /// The branch truncated against its share of the metered scan budget,
    /// which is the only truncation a larger share can lift.
    starved: bool,
}

/// Whether re-running a truncated branch under `retry` can see more of it than
/// its first attempt under `first` did.
///
/// Two conditions. Every lane of the whole query's `parent` budget must still
/// have room, because a rescan walks the branch from its first file again and
/// stops at the first exhausted lane. And a *scan* lane must be raised: the
/// seed scan ledger admits each file's scan charges once per execution, so a
/// rescan reaches the truncation frontier for free and can spend the raised
/// cap on new files, while the row lanes are charged on every visit and a
/// rescan only re-spends what the first attempt already spent.
fn retry_can_progress(
    budget: &CodeQueryExecutionBudget,
    parent: CodeQueryExecutionLimits,
    retry: CodeQueryExecutionLimits,
    first: CodeQueryExecutionLimits,
) -> bool {
    let has_headroom = budget.scanned_files < parent.max_scanned_files
        && budget.scanned_source_bytes < parent.max_scanned_source_bytes
        && budget.fact_nodes.saturating_add(budget.examined_references) < parent.max_fact_nodes
        && budget.pipeline_rows.max(budget.provenance_steps) < parent.max_pipeline_rows;
    let raises_a_scan_lane = retry.max_scanned_files > first.max_scanned_files
        || retry.max_scanned_source_bytes > first.max_scanned_source_bytes
        || retry.max_fact_nodes > first.max_fact_nodes;
    has_headroom && raises_a_scan_lane
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute_parallel_seed_union(
    plan: &PhysicalQueryPlan,
    token: QueryToken<'_>,
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
    let scope = state.scope.clone();
    let scanned_languages = &state.scanned_languages;
    let receiver_budget_override = state.receiver_budget_override;
    let access_mode = state.access_mode;
    let retained_value_census = state.retained_value_census.clone();
    let structural_index_session = state.structural_index_session.clone();
    let occurrence_cache = state.occurrence_cache.fork_empty();
    let environment_cache = state.environment_cache.fork_empty();
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
                    scope: scope.clone(),
                    scanned_languages: scanned_languages.clone(),
                    step_outputs: vec![0; plan.node_count()],
                    receiver_budget_override,
                    budget: base_budget,
                    seed_cache: CaptureScopedMemo::default(),
                    // Parallel branches dedupe shared per-file charges
                    // through the coordinator ledger, not this one.
                    seed_scan_ledger: SeedScanLedger::default(),
                    indexed_declarations: IndexedDeclarations::default(),
                    reference_cache: ReferenceTraversalCache::default(),
                    occurrence_cache: occurrence_cache.fork_empty(),
                    environment_cache: environment_cache.fork_empty(),
                    configuration_cache: ConfigurationFactsTraversalCache::default(),
                    materialization_cache: materialization::MaterializationTraversalCache::default(
                    ),
                    edge_cache: EdgeTraversalCache::default(),
                    flow_state_cache: FlowStateTraversalCache::default(),
                    control_relation_cache:
                        control_relations::ControlRelationTraversalCache::default(),
                    branch_relation_cache: BranchRelationTraversalCache::default(),
                    cpp_expression_cache: HashMap::default(),
                    cpp_class_fact_cache: HashMap::default(),
                    cpp_class_declaration_cache: HashMap::default(),
                    rust_marker_impls_cache: rust_marker_impls::RustMarkerImplsCache::default(),
                    callable_metrics_cache: HashMap::default(),
                    failure_handler_state_cache: FailureHandlerStateCache::default(),
                    topology_cache: topology_rows::TopologyTraversalCache::default(),
                    rewrite_path_cache: RewritePathTraversalCache::default(),
                    path_cache: PathTraversalCache::default(),
                    call_cache: CallTraversalCache::default(),
                    call_binding_identity_request: state.call_binding_identity_request,
                    comparison_chain_operators: HashMap::default(),
                    receiver_facts: HashMap::default(),
                    receiver_service: None,
                    semantic: None,
                    import_graph: None,
                    import_graph_content: None,
                    direct_import_layer: None,
                    direct_import_layer_content: None,
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
                    token,
                    dependencies[branch],
                    &mut branch_state,
                    limits,
                    None,
                    &mut branch_diagnostics,
                    &mut branch_path,
                );
                lease.finish(branch_state.budget);
                debug_assert!(branch_state.import_graph.is_none());
                debug_assert!(branch_state.import_graph_content.is_none());
                debug_assert!(branch_state.direct_import_layer.is_none());
                debug_assert!(branch_state.direct_import_layer_content.is_none());
                debug_assert!(branch_state.deferred_derived_builds.is_empty());
                debug_assert!(
                    branch_state
                        .reference_cache
                        .inbound
                        .read(&memo_attribution(branch_state.analyzer), |cache| cache
                            .is_empty())
                );
                debug_assert!(
                    branch_state
                        .reference_cache
                        .outbound
                        .read(&memo_attribution(branch_state.analyzer), |cache| cache
                            .is_empty())
                );
                debug_assert!(
                    branch_state
                        .call_cache
                        .incoming
                        .read(&memo_attribution(branch_state.analyzer), |cache| cache
                            .is_empty())
                );
                debug_assert!(
                    branch_state
                        .call_cache
                        .outgoing
                        .read(&memo_attribution(branch_state.analyzer), |cache| cache
                            .is_empty())
                );
                let (operators, access_path) = branch_state.profile.take().map_or_else(
                    || (Vec::new(), QueryAccessPathProfile::default()),
                    |profile| (profile.operators, profile.access_path),
                );
                ParallelSeedBranchResult {
                    execution,
                    diagnostics: branch_diagnostics,
                    seed_cache: branch_state
                        .seed_cache
                        .read_mut(&memo_attribution(branch_state.analyzer), std::mem::take),
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
                state
                    .seed_cache
                    .read_mut(&memo_attribution(state.analyzer), |cache| cache
                        .insert(key, cached))
                    .is_none(),
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
            | CodeQueryDiagnosticCode::ValueFlowWitnessTruncated
            | CodeQueryDiagnosticCode::TypeFlowWitnessTruncated => {
                Some(QueryOperatorTermination::AnalysisLimit)
            }
            CodeQueryDiagnosticCode::TaintFindingTruncated => {
                Some(QueryOperatorTermination::AnalysisLimit)
            }
            CodeQueryDiagnosticCode::UnsupportedStructuralFeature
            | CodeQueryDiagnosticCode::MissingStructuralAdapter
            | CodeQueryDiagnosticCode::UnsupportedImportAnalysis
            | CodeQueryDiagnosticCode::DynamicImportTarget
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
            | CodeQueryDiagnosticCode::MaterializationRowBudgetExhausted
            | CodeQueryDiagnosticCode::EffectBudgetExhausted => {
                Some(QueryOperatorTermination::AnalysisLimit)
            }
            CodeQueryDiagnosticCode::SemanticResultsOmitted
            | CodeQueryDiagnosticCode::SemanticAnalysisPartial
            | CodeQueryDiagnosticCode::SemanticPackAcquisitionPending
            | CodeQueryDiagnosticCode::CallBindingDispatchPartial
            | CodeQueryDiagnosticCode::CallBindingSelectorRejected
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
            | CodeQueryDiagnosticCode::TypeFlowWitnessUnavailable
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
            | CodeQueryDiagnosticCode::PythonHierarchyDerivationIncomplete
            | CodeQueryDiagnosticCode::EdgeAxisUnsupported
            | CodeQueryDiagnosticCode::EdgeDerivationIncomplete
            | CodeQueryDiagnosticCode::FlowStateAxisUnsupported
            | CodeQueryDiagnosticCode::FlowStateDerivationIncomplete
            | CodeQueryDiagnosticCode::RewriteDomainUnsupported
            | CodeQueryDiagnosticCode::RewritePathDerivationIncomplete
            | CodeQueryDiagnosticCode::ControlRelationDerivationIncomplete
            | CodeQueryDiagnosticCode::BranchRelationDerivationIncomplete
            | CodeQueryDiagnosticCode::RecoveredSyntaxIncomplete
            | CodeQueryDiagnosticCode::LoopRelationDerivationIncomplete
            | CodeQueryDiagnosticCode::FailureHandlerDerivationIncomplete
            | CodeQueryDiagnosticCode::StatementReachabilityDerivationIncomplete
            | CodeQueryDiagnosticCode::PendingCleanupFlowDerivationIncomplete
            | CodeQueryDiagnosticCode::ControlRelationExitPartitionPartial
            | CodeQueryDiagnosticCode::TopologyDerivationIncomplete
            | CodeQueryDiagnosticCode::TopologyOwnershipAmbiguous
            | CodeQueryDiagnosticCode::PathDerivationIncomplete
            | CodeQueryDiagnosticCode::EffectDerivationIncomplete
            | CodeQueryDiagnosticCode::ResultContractDerivationIncomplete
            | CodeQueryDiagnosticCode::ResultObligationDerivationIncomplete
            | CodeQueryDiagnosticCode::CallShapeCoverageIncomplete
            | CodeQueryDiagnosticCode::JsxProjectionIncomplete
            | CodeQueryDiagnosticCode::CrossDomainBindingUnproven
            | CodeQueryDiagnosticCode::CrossDomainKeyUnsupported
            | CodeQueryDiagnosticCode::CrossDomainDocumentIncomplete => {
                Some(QueryOperatorTermination::AnalysisIncomplete)
            }
            CodeQueryDiagnosticCode::CrossDomainCorrelationAmbiguous
            | CodeQueryDiagnosticCode::InvalidPlan
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
