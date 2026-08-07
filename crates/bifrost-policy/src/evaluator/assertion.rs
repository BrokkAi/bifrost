use super::*;

/// One subject row: the node an assertion is evaluated at, plus every capture
/// it bound.
#[derive(Debug)]
struct AssertionSubject {
    path: WorkspaceRelativePath,
    location: PolicySourceLocation,
    captures: HashMap<String, Vec<SubjectCapture>>,
    /// A capture that carries no AST id cannot be joined at all. Recorded here
    /// rather than dropped, so the run reports a capability gap instead of an
    /// empty pass.
    captures_without_ast_id: Vec<String>,
}

impl AssertionSubject {
    /// The AST ids bound to one capture name, or `None` when the subject
    /// selector does not bind that capture at all.
    fn ast_ids(&self, name: &str) -> Option<Vec<&str>> {
        self.captures.get(name).map(|captures| {
            captures
                .iter()
                .filter_map(|capture| capture.ast_id.as_deref())
                .collect()
        })
    }
}

/// One capture of one subject row.
#[derive(Debug)]
struct SubjectCapture {
    ast_id: Option<String>,
    /// The captured node's display region, which is what a containment assert
    /// compares a declaring scope against. Absent when the match carried no
    /// node range.
    range: Option<CodeQueryRange>,
}

/// Whether one display region contains another. Both regions address nodes of
/// the same file, so containment is the region order rather than any text.
fn region_contains(outer: CodeQueryRange, inner: CodeQueryRange) -> bool {
    let start = (outer.start_line, outer.start_column) <= (inner.start_line, inner.start_column);
    let end = (inner.end_line, inner.end_column) <= (outer.end_line, outer.end_column);
    start && end
}

pub(super) fn evaluate_assertion_policy(
    policy: &LoadedPolicy,
    spec: &AssertionPolicySpec,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    if let Some(plan) = &spec.relational {
        return evaluate_relational_assertion_policy(policy, plan, context, budget);
    }
    let Some(selector) = policy
        .resolved_selectors()
        .iter()
        .find(|selector| selector.path.as_str() == ASSERTION_SUBJECT_SELECTOR_PATH)
    else {
        return failed_policy_run(
            policy,
            PolicyAnalysisType::Assertion,
            "resolved assertion policy is missing /analysis/subject",
            budget,
        );
    };

    let mut subject_query = selector.query.clone();
    subject_query.result_detail = CodeQueryResultDetail::Full;
    subject_query.limit = budget.query_limits().max_pipeline_rows;
    let subject = execute_code_query_detailed_eager_index(
        context.analyzer,
        &subject_query,
        budget.query_limits(),
        context.cancellation,
    );

    let mut run_incomplete =
        incomplete_reasons(&subject.result.completion(), subject.result.truncated);
    let mut run_failures = failure_reasons(&subject.result.completion());
    let mut query_diagnostics = subject.result.diagnostics.clone();

    let subjects = match collect_assertion_subjects(&subject.result.results, &subject.evidence) {
        Ok(subjects) => subjects,
        Err(message) => {
            return failed_policy_run(policy, PolicyAnalysisType::Assertion, message, budget);
        }
    };

    // Two executions per row family, not one. `occurrences-in` over the subject
    // query would keep a single execution but re-run the subject selector,
    // giving the run two independent completion verdicts for the same rows;
    // scoping fresh seeds to the subject files keeps exactly one soundness
    // accounting per query and charges each file scan once. Each family's
    // query runs only when an assert asks for it, so a policy that never
    // mentions candidates never pays for a resolution trace.
    let mut paths = subjects
        .iter()
        .map(|subject| subject.path.as_str())
        .collect::<Vec<_>>();
    paths.sort_unstable();
    paths.dedup();

    // Every family needs the occurrence rows, not only the occurrence family:
    // an assert about how a token resolves does not apply to a token that is
    // not an occurrence of its role at all, and "the assert does not apply
    // here" must be distinguishable from "the resolver recorded no trace".
    let mut occurrence_roles = asserted_roles(spec, |_| true);
    // The canonical and route families join a *second* capture to occurrence
    // rows, so those roles must be derived (and their adapter gaps reported)
    // exactly like the primary ones.
    for assertion in &spec.asserts {
        match assertion {
            PolicyAssert::Canonical(assertion) => occurrence_roles.push(assertion.equals_role),
            PolicyAssert::Route(assertion) => occurrence_roles.push(assertion.to_role),
            _ => {}
        }
    }
    occurrence_roles.sort();
    occurrence_roles.dedup();
    let candidate_roles = asserted_roles(spec, |assertion| {
        matches!(
            assertion,
            PolicyAssert::Resolution(_) | PolicyAssert::Boundary(_)
        )
    });
    let reaching_roles = asserted_roles(spec, |assertion| {
        matches!(assertion, PolicyAssert::Reaching(_))
    });
    let needs_generation = spec
        .asserts
        .iter()
        .any(|assertion| matches!(assertion, PolicyAssert::Generation(_)));
    let needs_declaration_state = spec
        .asserts
        .iter()
        .any(|assertion| matches!(assertion, PolicyAssert::DeclarationState(_)));

    let mut executed = Vec::new();
    let mut occurrence_rows: Vec<&CodeQueryOccurrence> = Vec::new();
    let mut candidate_rows: Vec<&CodeQueryResolutionCandidate> = Vec::new();
    let mut binding_rows: Vec<&CodeQueryBinding> = Vec::new();
    let mut scope_rows: Vec<&CodeQueryLexicalScope> = Vec::new();
    let mut generation_rows: Vec<&CodeQueryGenerationSite> = Vec::new();

    let mut queries: Vec<CodeQuery> = Vec::new();
    // No subjects means no occurrences for any assert to address: every
    // assert holds vacuously and the verdict is the subject query's own
    // completion. Building the row-family queries anyway would be worse than
    // wasteful -- an empty exact-path list is an unrestricted seed, so a
    // subject-less policy would scan every file in the workspace and inherit
    // completeness verdicts from files it has nothing to say about.
    if !paths.is_empty() && !occurrence_roles.is_empty() {
        match assertion_occurrence_query(&paths, &occurrence_roles, Vec::new(), budget) {
            Ok(query) => queries.push(query),
            Err(message) => {
                return failed_policy_run(policy, PolicyAnalysisType::Assertion, message, budget);
            }
        }
    }
    if !paths.is_empty() && !candidate_roles.is_empty() {
        match assertion_occurrence_query(
            &paths,
            &candidate_roles,
            vec![QueryStep::CandidatesOf(CandidateFilter::default())],
            budget,
        ) {
            Ok(query) => queries.push(query),
            Err(message) => {
                return failed_policy_run(policy, PolicyAnalysisType::Assertion, message, budget);
            }
        }
    }
    if !paths.is_empty() && !reaching_roles.is_empty() {
        match assertion_occurrence_query(
            &paths,
            &reaching_roles,
            vec![QueryStep::ReachingBinding(ReachingBindingOptions::default())],
            budget,
        ) {
            Ok(query) => queries.push(query),
            Err(message) => {
                return failed_policy_run(policy, PolicyAnalysisType::Assertion, message, budget);
            }
        }
        match assertion_scope_query(&paths, budget) {
            Ok(query) => queries.push(query),
            Err(message) => {
                return failed_policy_run(policy, PolicyAnalysisType::Assertion, message, budget);
            }
        }
    }

    for query in &queries {
        let outcome = execute_code_query_detailed_eager_index(
            context.analyzer,
            query,
            budget.query_limits(),
            context.cancellation,
        );
        run_incomplete.extend(incomplete_reasons(
            &outcome.result.completion(),
            outcome.result.truncated,
        ));
        run_failures.extend(failure_reasons(&outcome.result.completion()));
        query_diagnostics.extend(outcome.result.diagnostics.iter().cloned());
        executed.push(outcome);
    }

    if needs_generation {
        let query = match assertion_generation_query(&paths, budget) {
            Ok(query) => query,
            Err(message) => {
                return failed_policy_run(policy, PolicyAnalysisType::Assertion, message, budget);
            }
        };
        let mut outcome = execute_code_query_detailed_eager_index(
            context.analyzer,
            &query,
            budget.query_limits(),
            context.cancellation,
        );
        // A dynamic generation site reports the generated-set axis incomplete
        // at query level, but here that honesty is handled per row: a dynamic
        // site makes exactly the asserts over it inconclusive (or, under
        // :forbid-dynamic, the finding), never the whole run.
        outcome.result.diagnostics.retain(|diagnostic| {
            diagnostic.code != CodeQueryDiagnosticCode::MaterializationDerivationIncomplete
        });
        run_incomplete.extend(incomplete_reasons(
            &outcome.result.completion(),
            outcome.result.truncated,
        ));
        run_failures.extend(failure_reasons(&outcome.result.completion()));
        query_diagnostics.extend(outcome.result.diagnostics.iter().cloned());
        executed.push(outcome);
    }

    for query in &executed {
        for item in &query.result.results {
            match &item.value {
                CodeQueryResultValue::Occurrence { value } => occurrence_rows.push(value),
                CodeQueryResultValue::ResolutionCandidate { value } => candidate_rows.push(value),
                CodeQueryResultValue::Binding { value } => binding_rows.push(value),
                CodeQueryResultValue::LexicalScope { value } => scope_rows.push(value),
                CodeQueryResultValue::GenerationSite { value } => generation_rows.push(value),
                _ => {}
            }
        }
    }

    if subjects
        .iter()
        .any(|subject| !subject.captures_without_ast_id.is_empty())
    {
        run_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
    }

    let mut rows_by_ast_id: HashMap<&str, Vec<&CodeQueryOccurrence>> = HashMap::new();
    for value in occurrence_rows {
        rows_by_ast_id
            .entry(value.ast_id.as_str())
            .or_default()
            .push(value);
    }
    let mut sites_by_ast_id: HashMap<&str, Vec<&CodeQueryGenerationSite>> = HashMap::new();
    for value in &generation_rows {
        if let Some(ast_id) = value.ast_id.as_deref() {
            sites_by_ast_id.entry(ast_id).or_default().push(value);
        }
    }

    // Declaration-state rows are derived directly rather than queried: no
    // seed spans the whole state family, and the rows joined here are exact
    // per-declaration facts whose completeness the derivation itself states.
    let mut state_results: Vec<std::sync::Arc<MaterializationFileResult>> = Vec::new();
    if needs_declaration_state {
        let files_by_rel: HashMap<String, brokk_bifrost_analysis::analyzer::ProjectFile> = context
            .analyzer
            .analyzed_files()
            .into_iter()
            .map(|file| (file.rel_path().to_string_lossy().replace('\\', "/"), file))
            .collect();
        for path in &paths {
            let Some(file) = files_by_rel.get(*path) else {
                run_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
                continue;
            };
            let result = std::sync::Arc::new(materialization_for_file(context.analyzer, file));
            if !result
                .completeness
                .covers(MaterializationAxis::DeclarationState)
            {
                run_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
            }
            state_results.push(result);
        }
    }
    let mut states_by_ast_id: HashMap<String, Vec<&DeclarationStateRow>> = HashMap::new();
    for result in &state_results {
        for row in &result.states {
            if let Some(ast_id) = row.ast_id() {
                states_by_ast_id.entry(ast_id).or_default().push(row);
            }
        }
    }

    let mut candidates_by_ast_id: HashMap<&str, Vec<&CodeQueryResolutionCandidate>> =
        HashMap::new();
    for value in candidate_rows {
        candidates_by_ast_id
            .entry(value.ast_id.as_str())
            .or_default()
            .push(value);
    }
    // A reaching binding is an answer about one occurrence, and the row says
    // which one: the join is that identity, never the binding's name. The
    // identity is path-qualified because a canonical AST id repeats verbatim
    // across files with identical content, and the binding must only join
    // occurrences of its own file.
    let mut bindings_by_occurrence: HashMap<(&str, &str), Vec<&CodeQueryBinding>> = HashMap::new();
    for value in binding_rows {
        if let Some(reached_from) = value.reached_from_ast_id.as_deref() {
            bindings_by_occurrence
                .entry((value.path.as_str(), reached_from))
                .or_default()
                .push(value);
        }
    }
    let mut scopes_by_index: HashMap<(&str, u32), &CodeQueryLexicalScope> = HashMap::new();
    for value in scope_rows {
        scopes_by_index.insert((value.path.as_str(), value.index), value);
    }

    let capability = assertion_capabilities(&query_diagnostics);
    let adapted = adapt_query_diagnostics(&query_diagnostics, budget.max_diagnostics());
    let mut diagnostics = adapted.diagnostics;
    let mut diagnostics_truncated = adapted.truncated;
    if diagnostics_truncated {
        run_incomplete.push(PolicyIncompleteReason::ReportRetentionBudget);
    }
    if adapted.adaptation_failed {
        retain_incomplete_diagnostic(
            &mut diagnostics,
            &mut diagnostics_truncated,
            budget.max_diagnostics(),
            "one or more query diagnostics could not be retained as validated policy diagnostics",
        );
    }

    run_incomplete.sort();
    run_incomplete.dedup();
    run_failures.sort();
    run_failures.dedup();
    let subject_completion = subject.result.completion();
    let row_completions = executed
        .iter()
        .map(|query| query.result.completion())
        .collect::<Vec<_>>();
    let total_work = executed.iter().fold(subject.work, |total, query| {
        total.saturating_add(query.work)
    });
    let work = work_report(total_work, 0, 0);

    if !run_failures.is_empty() {
        return failed_policy_run_with_reason(
            policy,
            PolicyAnalysisType::Assertion,
            Vec::new(),
            run_failures[0],
            "assertion evaluation could not execute a valid query plan",
            work,
            budget,
        );
    }
    // Soundness rule 1: a verdict over an incomplete row set is never a pass
    // and never a clean run, so no findings are assembled at all.
    if !run_incomplete.is_empty() {
        return inconclusive_policy_run_many(
            policy,
            PolicyAnalysisType::Assertion,
            run_incomplete,
            "assertion evaluation could not observe a complete row set",
            work,
            budget,
        );
    }

    let metadata = &policy.definition().metadata;
    let message = match &metadata.message {
        PolicyMessageSpec::Static { text } => text.clone(),
        PolicyMessageSpec::Generated { .. } => {
            return failed_policy_run(
                policy,
                PolicyAnalysisType::Assertion,
                "assertion policy presentation could not be projected into a finding",
                budget,
            );
        }
    };
    let classification = match reduce_finding_classification(
        policy.definition().classification.as_ref(),
        ClassificationProjection::assertion_finding(),
        None,
    ) {
        Ok(classification) => classification,
        Err(_) => {
            return failed_policy_run(
                policy,
                PolicyAnalysisType::Assertion,
                "assertion policy classification could not be reduced",
                budget,
            );
        }
    };
    let severity = finding_severity(&metadata.severity, None);

    let needs_identity_producers = spec.asserts.iter().any(|assertion| {
        matches!(
            assertion,
            PolicyAssert::Canonical(_) | PolicyAssert::Route(_) | PolicyAssert::RoundTrip(_)
        )
    });
    let mut identity_support =
        needs_identity_producers.then(|| IdentityAssertSupport::new(context.analyzer));

    let mut findings = Vec::new();
    // Soundness rule 3: an input a single assert cannot conclude over -- an
    // unattributed tier, a rejection-dependent assert on a selection-only
    // trace, a missing selection -- makes the whole run inconclusive with zero
    // findings, exactly like an incomplete query. The verdicts already
    // assembled are discarded rather than reported beside an admission.
    let mut late_incomplete: Vec<PolicyIncompleteReason> = Vec::new();
    let mut edge_assert_context = EdgeAssertContext::new(context.analyzer, context.cancellation);
    for subject in &subjects {
        for assertion in &spec.asserts {
            // Soundness rule 2: an unbound `:at` is an authoring error, never
            // a vacuous pass.
            let Some(ast_ids) = subject.ast_ids(assertion.at()) else {
                return failed_policy_run_with_reason(
                    policy,
                    PolicyAnalysisType::Assertion,
                    Vec::new(),
                    PolicyFailureReason::InvalidExecutionPlan,
                    &format!(
                        "assert `{}` names capture `{}`, which the subject selector does not bind at {}",
                        assertion.id(),
                        assertion.at(),
                        subject.path.as_str()
                    ),
                    work,
                    budget,
                );
            };
            // A capture that carries no occurrence of the asserted role is not
            // a subject this assert is about. Only the occurrence family, whose
            // whole question is how many such rows exist, evaluates anyway.
            if let Some(role) = assertion.role()
                && !matches!(assertion, PolicyAssert::Occurrence(_))
                && !joined_role_rows(&ast_ids, &rows_by_ast_id, role)
            {
                continue;
            }
            let violation = match assertion {
                PolicyAssert::Occurrence(assertion) => {
                    evaluate_occurrence_assert(assertion, &ast_ids, &rows_by_ast_id)
                }
                PolicyAssert::Resolution(assertion) => evaluate_resolution_assert(
                    assertion,
                    &ast_ids,
                    &candidates_by_ast_id,
                    &mut late_incomplete,
                ),
                PolicyAssert::Boundary(assertion) => evaluate_boundary_assert(
                    assertion,
                    &ast_ids,
                    &candidates_by_ast_id,
                    &mut late_incomplete,
                ),
                PolicyAssert::Generation(assertion) => evaluate_generation_assert(
                    assertion,
                    &ast_ids,
                    &sites_by_ast_id,
                    &mut late_incomplete,
                ),
                PolicyAssert::DeclarationState(assertion) => {
                    evaluate_declaration_state_assert(assertion, &ast_ids, &states_by_ast_id)
                }
                PolicyAssert::EdgeParity(assertion) => evaluate_edge_parity_assert(
                    assertion,
                    &ast_ids,
                    &rows_by_ast_id,
                    &mut edge_assert_context,
                    &mut late_incomplete,
                ),
                PolicyAssert::EdgeClass(assertion) => evaluate_edge_class_assert(
                    assertion,
                    &ast_ids,
                    &rows_by_ast_id,
                    &mut edge_assert_context,
                    &mut late_incomplete,
                ),
                PolicyAssert::Canonical(assertion) => match subject.ast_ids(&assertion.equals) {
                    Some(equals_ids) => evaluate_canonical_assert(
                        assertion,
                        subject,
                        &ast_ids,
                        &equals_ids,
                        identity_support
                            .as_mut()
                            .expect("identity producers exist when a canonical assert does"),
                        context,
                        &mut late_incomplete,
                    ),
                    None => {
                        return failed_policy_run_with_reason(
                            policy,
                            PolicyAnalysisType::Assertion,
                            Vec::new(),
                            PolicyFailureReason::InvalidExecutionPlan,
                            &format!(
                                "assert `{}` names capture `{}`, which the subject selector does not bind at {}",
                                assertion.id,
                                assertion.equals,
                                subject.path.as_str()
                            ),
                            work,
                            budget,
                        );
                    }
                },
                PolicyAssert::Route(assertion) => match subject.ast_ids(&assertion.to) {
                    Some(to_ids) => evaluate_route_assert(
                        assertion,
                        subject,
                        &ast_ids,
                        &to_ids,
                        identity_support
                            .as_mut()
                            .expect("identity producers exist when a route assert does"),
                        context,
                        &mut late_incomplete,
                    ),
                    None => {
                        return failed_policy_run_with_reason(
                            policy,
                            PolicyAnalysisType::Assertion,
                            Vec::new(),
                            PolicyFailureReason::InvalidExecutionPlan,
                            &format!(
                                "assert `{}` names capture `{}`, which the subject selector does not bind at {}",
                                assertion.id,
                                assertion.to,
                                subject.path.as_str()
                            ),
                            work,
                            budget,
                        );
                    }
                },
                PolicyAssert::RoundTrip(assertion) => evaluate_round_trip_assert(
                    assertion,
                    subject,
                    &ast_ids,
                    identity_support
                        .as_mut()
                        .expect("identity producers exist when a round-trip assert does"),
                    context,
                    &mut late_incomplete,
                ),
                PolicyAssert::Reaching(assertion) => {
                    match subject.ast_ids(&assertion.relative_to) {
                        Some(_) => evaluate_reaching_assert(
                            assertion,
                            subject,
                            &ast_ids,
                            &bindings_by_occurrence,
                            &scopes_by_index,
                            &mut late_incomplete,
                        ),
                        None => {
                            return failed_policy_run_with_reason(
                                policy,
                                PolicyAnalysisType::Assertion,
                                Vec::new(),
                                PolicyFailureReason::InvalidExecutionPlan,
                                &format!(
                                    "assert `{}` names capture `{}`, which the subject selector does not bind at {}",
                                    assertion.id,
                                    assertion.relative_to,
                                    subject.path.as_str()
                                ),
                                work,
                                budget,
                            );
                        }
                    }
                }
            };
            let Some(violation) = violation else {
                continue;
            };

            let anchor = super::super::finding_identity::AssertionFindingAnchor::new(
                subject.path.clone(),
                ast_ids.first().copied().unwrap_or(""),
                assertion.id().as_str(),
            );
            let Ok(evidence) = super::super::finding::AssertionFindingEvidence::try_new(
                anchor,
                assertion.kind_label(),
                assertion.role().map_or("declaration", |role| role.label()),
                violation.expected_class,
                violation.expectation.clone(),
                violation.observed.clone(),
                violation.actual_count,
                capability.clone(),
            ) else {
                return failed_policy_run_with_reason(
                    policy,
                    PolicyAnalysisType::Assertion,
                    findings,
                    PolicyFailureReason::InternalInvariant,
                    "a violated assertion could not be projected into validated policy evidence",
                    work,
                    budget,
                );
            };

            let mut related_truncated = false;
            let mut omitted_related = 0_u64;
            let related = match assertion_related_locations(
                subject,
                &violation,
                budget,
                &mut related_truncated,
                &mut omitted_related,
            ) {
                Ok(related) => related,
                Err(()) => {
                    return failed_policy_run_with_reason(
                        policy,
                        PolicyAnalysisType::Assertion,
                        findings,
                        PolicyFailureReason::InternalInvariant,
                        "an evidence row could not be projected into a related policy location",
                        work,
                        budget,
                    );
                }
            };

            let completeness = if related_truncated {
                FindingCompleteness::partial(vec![
                    FindingIncompleteReason::RelatedLocationsTruncated,
                ])
                .expect("one typed finding-incomplete reason is canonical")
            } else {
                FindingCompleteness::Complete
            };
            let proof = ProofMetadata::try_new(
                ProofState::Proven,
                vec![ProofReason::DirectStructuralMatch],
                Vec::new(),
            )
            .expect("a proven direct structural match is a canonical proof");
            let finding = PolicyFinding::try_new(
                metadata.id.clone(),
                policy.semantic_hash(),
                severity,
                message.clone(),
                classification.clone(),
                FindingCertainty::Definite,
                completeness,
                subject.location.clone(),
                related,
                related_truncated,
                omitted_related,
                PolicyFindingEvidence::Assertion { evidence },
                false,
                0,
                None,
                None,
                proof,
                Vec::new(),
                false,
                0,
                budget,
            );
            match finding {
                Ok(finding) => findings.push(finding),
                Err(_) => {
                    return failed_policy_run_with_reason(
                        policy,
                        PolicyAnalysisType::Assertion,
                        findings,
                        PolicyFailureReason::InternalInvariant,
                        "a validated assertion violation could not be retained as a finding",
                        work,
                        budget,
                    );
                }
            }
        }
    }

    if !late_incomplete.is_empty() {
        late_incomplete.sort();
        late_incomplete.dedup();
        return inconclusive_policy_run_many(
            policy,
            PolicyAnalysisType::Assertion,
            late_incomplete,
            "an assertion could not conclude over the rows the analyzer could state",
            work,
            budget,
        );
    }

    let mut completion = PolicyRunCompletion::Complete;
    if let CodeQueryCompletion::ProvenSubset { codes } = &subject_completion {
        completion = PolicyRunCompletion::proven_subset(codes.clone())
            .expect("the detailed subject query declared at least one non-exhaustive omission");
    } else {
        for row_completion in &row_completions {
            if let CodeQueryCompletion::ProvenSubset { codes } = row_completion {
                completion = PolicyRunCompletion::proven_subset(codes.clone())
                    .expect("a detailed row query declared at least one non-exhaustive omission");
                break;
            }
        }
    }
    let work = work_report(total_work, findings.len(), 0);
    finish_assembled_run(
        policy,
        PolicyAnalysisType::Assertion,
        completion,
        findings,
        diagnostics,
        diagnostics_truncated,
        work,
        "assertion evaluation produced an invalid policy run",
        budget,
    )
}

/// Execute a decoded relational assertion plan: run every named query and
/// expansion binding as a CodeQuery, evaluate the bounded join/group/aggregate
/// plan over the returned rows, and assemble each violated group into one
/// finding anchored at exact source ranges.
///
/// Soundness follows the specialized families: a failed query fails the run; a
/// non-exhaustive contributing relation or an exceeded plan limit makes the
/// whole run inconclusive with zero findings, because every supported
/// cardinality can be falsified by unobserved rows.
fn evaluate_relational_assertion_policy(
    policy: &LoadedPolicy,
    plan: &super::super::definition::RelationalAssertionPlan,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    use super::super::assertion_policy::{
        RelationalInput, RelationalViolationRow, evaluate_relational_assertion_rows,
    };
    use super::super::definition::{
        RowBindingName, RowBindingSource, RowExpansionStep, relational_binding_selector_path,
    };

    let mut binding_queries: Vec<CodeQuery> = Vec::with_capacity(plan.bindings.len());
    let mut binding_index_by_name: HashMap<&RowBindingName, usize> = HashMap::new();
    for (index, binding) in plan.bindings.iter().enumerate() {
        let query = match &binding.source {
            RowBindingSource::Query(_) => {
                let selector_path = relational_binding_selector_path(&binding.name);
                let Some(selector) = policy
                    .resolved_selectors()
                    .iter()
                    .find(|selector| selector.path.as_str() == selector_path)
                else {
                    return failed_policy_run(
                        policy,
                        PolicyAnalysisType::Assertion,
                        &format!(
                            "resolved relational policy is missing binding selector `{}`",
                            binding.name
                        ),
                        budget,
                    );
                };
                let mut query = selector.query.clone();
                query.result_detail = CodeQueryResultDetail::Full;
                query.limit = budget.query_limits().max_pipeline_rows;
                query
            }
            RowBindingSource::Expansion { from, step } => {
                let Some(&source_index) = binding_index_by_name.get(from) else {
                    return failed_policy_run(
                        policy,
                        PolicyAnalysisType::Assertion,
                        &format!(
                            "relational binding `{}` expands `{from}` before it is declared",
                            binding.name
                        ),
                        budget,
                    );
                };
                let projection = match step {
                    RowExpansionStep::ReceiverOutcome => QueryStep::ReceiverOutcome,
                    RowExpansionStep::ReceiverEvidence => QueryStep::ReceiverEvidence,
                    RowExpansionStep::MemberSelection => {
                        // The member-selection projection consumes occurrence
                        // rows directly; no receiver-analysis lowering exists
                        // or is needed for it.
                        let mut query = binding_queries[source_index].clone();
                        query.plan.steps.push(QueryStep::MemberSelection);
                        binding_index_by_name.insert(&binding.name, index);
                        binding_queries.push(query);
                        continue;
                    }
                    RowExpansionStep::DispatchOutcome | RowExpansionStep::DispatchTargets => {
                        // Both dispatch steps consume the same site rows the
                        // source binding already produced, so the expansion is
                        // one appended step, not a second query.
                        let mut query = binding_queries[source_index].clone();
                        query.plan.steps.push(match step {
                            RowExpansionStep::DispatchOutcome => QueryStep::DispatchOutcome,
                            _ => QueryStep::DispatchTargets,
                        });
                        binding_index_by_name.insert(&binding.name, index);
                        binding_queries.push(query);
                        continue;
                    }
                    RowExpansionStep::MemberFamily | RowExpansionStep::FamilyEdges => {
                        // Both family steps consume the member declaration rows
                        // the source binding already produced, so the expansion
                        // is one appended step rather than a second query.
                        let mut query = binding_queries[source_index].clone();
                        query.plan.steps.push(match step {
                            RowExpansionStep::MemberFamily => QueryStep::MemberFamily,
                            _ => QueryStep::FamilyEdges,
                        });
                        binding_index_by_name.insert(&binding.name, index);
                        binding_queries.push(query);
                        continue;
                    }
                    RowExpansionStep::CandidateHierarchy => {
                        // The hierarchy-hop projection consumes the same
                        // occurrence rows the candidate trace consumes, for
                        // the same reason.
                        let mut query = binding_queries[source_index].clone();
                        query.plan.steps.push(QueryStep::CandidateHierarchy);
                        binding_index_by_name.insert(&binding.name, index);
                        binding_queries.push(query);
                        continue;
                    }
                    other => {
                        return failed_policy_run(
                            policy,
                            PolicyAnalysisType::Assertion,
                            &format!(
                                "row expansion `{}` has no executable row domain yet",
                                other.label()
                            ),
                            budget,
                        );
                    }
                };
                let mut query = binding_queries[source_index].clone();
                // The receiver row projections consume a receiver analysis. A
                // source binding that is not already a receiver analysis is
                // lowered through the production receiver analysis first, so
                // the expansion rows are projections of the same solver run
                // the ordinary receiver queries use.
                let source_is_receiver_analysis = query
                    .validate_steps()
                    .map(|kind| kind == QueryValueKind::ReceiverAnalysis)
                    .unwrap_or(false);
                if !source_is_receiver_analysis {
                    query
                        .plan
                        .steps
                        .push(QueryStep::ReceiverTargets(Default::default()));
                }
                query.plan.steps.push(projection);
                query
            }
        };
        binding_index_by_name.insert(&binding.name, index);
        binding_queries.push(query);
    }

    let mut run_incomplete: Vec<PolicyIncompleteReason> = Vec::new();
    let mut run_failures: Vec<PolicyFailureReason> = Vec::new();
    let mut query_diagnostics: Vec<CodeQueryDiagnostic> = Vec::new();
    let mut executed = Vec::with_capacity(binding_queries.len());
    let mut total_work: Option<CodeQueryExecutionWork> = None;
    for query in &binding_queries {
        // A binding that expands into a semantic row family (the #1477
        // dispatch rows) needs the generation-bound workspace oracles. Use
        // them whenever the evaluation context carries a workspace; the
        // analyzer-only path stays exactly as it was otherwise.
        let outcome = match context.workspace {
            Some(workspace) => execute_code_query_detailed_eager_index_workspace(
                workspace,
                query,
                budget.query_limits(),
                context.cancellation,
            ),
            None => execute_code_query_detailed_eager_index(
                context.analyzer,
                query,
                budget.query_limits(),
                context.cancellation,
            ),
        };
        run_incomplete.extend(incomplete_reasons(
            &outcome.result.completion(),
            outcome.result.truncated,
        ));
        run_failures.extend(failure_reasons(&outcome.result.completion()));
        query_diagnostics.extend(outcome.result.diagnostics.iter().cloned());
        total_work = Some(match total_work {
            Some(work) => work.saturating_add(outcome.work),
            None => outcome.work,
        });
        executed.push(outcome);
    }
    let total_work = total_work.expect("a validated relational plan has at least one binding");
    let work = work_report(total_work, 0, 0);

    run_failures.sort();
    run_failures.dedup();
    if !run_failures.is_empty() {
        return failed_policy_run_with_reason(
            policy,
            PolicyAnalysisType::Assertion,
            Vec::new(),
            run_failures[0],
            "relational assertion evaluation could not execute a valid query plan",
            work,
            budget,
        );
    }
    for outcome in &executed {
        if outcome.result.results.len() != outcome.evidence.len() {
            return failed_policy_run_with_reason(
                policy,
                PolicyAnalysisType::Assertion,
                Vec::new(),
                PolicyFailureReason::InternalInvariant,
                "relational binding rows and their detailed evidence disagree",
                work,
                budget,
            );
        }
    }

    let inputs = plan
        .bindings
        .iter()
        .zip(&executed)
        .map(|(binding, outcome)| RelationalInput {
            binding: &binding.name,
            rows: &outcome.result.results,
            exhaustive: matches!(outcome.result.completion(), CodeQueryCompletion::Complete)
                && !outcome.result.truncated,
        })
        .collect::<Vec<_>>();
    let evaluation = match evaluate_relational_assertion_rows(plan, &inputs) {
        Ok(evaluation) => evaluation,
        Err(error) => {
            return failed_policy_run_with_reason(
                policy,
                PolicyAnalysisType::Assertion,
                Vec::new(),
                PolicyFailureReason::InvalidExecutionPlan,
                &format!("relational assertion evaluation could not conclude: {error:?}"),
                work,
                budget,
            );
        }
    };

    let capability = assertion_capabilities(&query_diagnostics);
    let adapted = adapt_query_diagnostics(&query_diagnostics, budget.max_diagnostics());
    let mut diagnostics = adapted.diagnostics;
    let mut diagnostics_truncated = adapted.truncated;
    if diagnostics_truncated {
        run_incomplete.push(PolicyIncompleteReason::ReportRetentionBudget);
    }
    if adapted.adaptation_failed {
        retain_incomplete_diagnostic(
            &mut diagnostics,
            &mut diagnostics_truncated,
            budget.max_diagnostics(),
            "one or more query diagnostics could not be retained as validated policy diagnostics",
        );
    }

    if evaluation.limit_exceeded {
        run_incomplete.push(PolicyIncompleteReason::PipelineRowBudget);
    }
    if !evaluation.exhaustive && run_incomplete.is_empty() {
        run_incomplete.push(PolicyIncompleteReason::PartialDiscovery);
    }
    run_incomplete.sort();
    run_incomplete.dedup();
    if !run_incomplete.is_empty() {
        return inconclusive_policy_run_many(
            policy,
            PolicyAnalysisType::Assertion,
            run_incomplete,
            "relational assertion evaluation could not observe a complete row set",
            work,
            budget,
        );
    }

    let metadata = &policy.definition().metadata;
    let message = match &metadata.message {
        PolicyMessageSpec::Static { text } => text.clone(),
        PolicyMessageSpec::Generated { .. } => {
            return failed_policy_run(
                policy,
                PolicyAnalysisType::Assertion,
                "assertion policy presentation could not be projected into a finding",
                budget,
            );
        }
    };
    let classification = match reduce_finding_classification(
        policy.definition().classification.as_ref(),
        ClassificationProjection::assertion_finding(),
        None,
    ) {
        Ok(classification) => classification,
        Err(_) => {
            return failed_policy_run(
                policy,
                PolicyAnalysisType::Assertion,
                "assertion policy classification could not be reduced",
                budget,
            );
        }
    };
    let severity = finding_severity(&metadata.severity, None);

    let row_location = |row: &RelationalViolationRow| -> Option<PolicySourceLocation> {
        let index = *binding_index_by_name.get(&row.binding)?;
        let outcome = &executed[index];
        let item = outcome.result.results.get(row.row)?;
        let evidence = outcome.evidence.get(row.row)?;
        let path = WorkspaceRelativePath::try_from_path(evidence.file.rel_path()).ok()?;
        match (evidence.byte_span.as_ref(), item.value.display_range()) {
            (Some(byte_span), Some(range)) => policy_span_location(path, byte_span, range).ok(),
            _ => Some(PolicySourceLocation::artifact(path)),
        }
    };

    let mut findings = Vec::new();
    for violation in &evaluation.violations {
        let assertion = plan
            .assertions
            .iter()
            .find(|assertion| assertion.id == violation.assertion)
            .expect("a violation always references an assertion of its own plan");
        let Some(primary_row) = violation
            .representatives
            .first()
            .and_then(|tuple| tuple.first())
        else {
            return failed_policy_run_with_reason(
                policy,
                PolicyAnalysisType::Assertion,
                findings,
                PolicyFailureReason::InternalInvariant,
                "a violated relational group retained no contributing row",
                work,
                budget,
            );
        };
        let Some(primary_location) = row_location(primary_row) else {
            return failed_policy_run_with_reason(
                policy,
                PolicyAnalysisType::Assertion,
                findings,
                PolicyFailureReason::InternalInvariant,
                "a relational violation row could not be projected into a source location",
                work,
                budget,
            );
        };
        let key_text = render_relational_key(&violation.key);

        let mut related = Vec::new();
        let mut related_truncated = false;
        let mut omitted_related = 0_u64;
        for (tuple_index, tuple) in violation.representatives.iter().enumerate() {
            for (row_index, row) in tuple.iter().enumerate() {
                let relationship = if tuple_index == 0 && row_index == 0 {
                    PolicyLocationRelationship::Subject
                } else {
                    PolicyLocationRelationship::Evidence
                };
                if related.len() == budget.max_related_locations_per_finding() {
                    related_truncated = true;
                    omitted_related = omitted_related.saturating_add(1);
                    continue;
                }
                let Some(location) = row_location(row) else {
                    return failed_policy_run_with_reason(
                        policy,
                        PolicyAnalysisType::Assertion,
                        findings,
                        PolicyFailureReason::InternalInvariant,
                        "a relational violation row could not be projected into a source location",
                        work,
                        budget,
                    );
                };
                let Ok(entry) = RelatedPolicyLocation::try_new(relationship, location, Vec::new())
                else {
                    return failed_policy_run_with_reason(
                        policy,
                        PolicyAnalysisType::Assertion,
                        findings,
                        PolicyFailureReason::InternalInvariant,
                        "an evidence row could not be projected into a related policy location",
                        work,
                        budget,
                    );
                };
                related.push(entry);
            }
        }

        let Ok(anchor_path) = WorkspaceRelativePath::new(primary_location.path()) else {
            return failed_policy_run_with_reason(
                policy,
                PolicyAnalysisType::Assertion,
                findings,
                PolicyFailureReason::InternalInvariant,
                "a relational violation location has no workspace-relative path",
                work,
                budget,
            );
        };
        let anchor = super::super::finding_identity::AssertionFindingAnchor::new(
            anchor_path,
            &key_text,
            assertion.id.as_str(),
        );
        let expectation = format!(
            "({} {})",
            assertion.cardinality.label(),
            assertion.cardinality.count()
        );
        let observed = format!(
            "aggregate `{}.{}` over group key `{key_text}` = {}",
            assertion.group, assertion.aggregate, violation.actual
        );
        let Ok(evidence) = super::super::finding::AssertionFindingEvidence::try_new(
            anchor,
            "relational",
            "row",
            violation.group.as_str(),
            expectation,
            Some(observed),
            violation.actual,
            capability.clone(),
        ) else {
            return failed_policy_run_with_reason(
                policy,
                PolicyAnalysisType::Assertion,
                findings,
                PolicyFailureReason::InternalInvariant,
                "a violated assertion could not be projected into validated policy evidence",
                work,
                budget,
            );
        };

        let completeness = if related_truncated {
            FindingCompleteness::partial(vec![FindingIncompleteReason::RelatedLocationsTruncated])
                .expect("one typed finding-incomplete reason is canonical")
        } else {
            FindingCompleteness::Complete
        };
        let proof = ProofMetadata::try_new(
            ProofState::Proven,
            vec![ProofReason::DirectStructuralMatch],
            Vec::new(),
        )
        .expect("a proven direct structural match is a canonical proof");
        let finding = PolicyFinding::try_new(
            metadata.id.clone(),
            policy.semantic_hash(),
            severity,
            message.clone(),
            classification.clone(),
            FindingCertainty::Definite,
            completeness,
            primary_location,
            related,
            related_truncated,
            omitted_related,
            PolicyFindingEvidence::Assertion { evidence },
            false,
            0,
            None,
            None,
            proof,
            Vec::new(),
            false,
            0,
            budget,
        );
        match finding {
            Ok(finding) => findings.push(finding),
            Err(_) => {
                return failed_policy_run_with_reason(
                    policy,
                    PolicyAnalysisType::Assertion,
                    findings,
                    PolicyFailureReason::InternalInvariant,
                    "a validated assertion violation could not be retained as a finding",
                    work,
                    budget,
                );
            }
        }
    }

    let work = work_report(total_work, findings.len(), 0);
    finish_assembled_run(
        policy,
        PolicyAnalysisType::Assertion,
        PolicyRunCompletion::Complete,
        findings,
        diagnostics,
        diagnostics_truncated,
        work,
        "relational assertion evaluation produced an invalid policy run",
        budget,
    )
}

/// Render one group key as a stable, human-readable correlation string. Group
/// keys are stable row scalars, so this rendering is content-scoped exactly
/// when the authored key fields are.
fn render_relational_key(key: &[Option<super::super::assertion_policy::RowScalar>]) -> String {
    use super::super::assertion_policy::RowScalar;
    key.iter()
        .map(|scalar| match scalar {
            None => "<null>".to_string(),
            Some(RowScalar::StableId(value))
            | Some(RowScalar::String(value))
            | Some(RowScalar::ConstrainedEnum(value))
            | Some(RowScalar::DeclarationIdentity(value)) => value.clone(),
            Some(RowScalar::Integer(value)) => value.to_string(),
            Some(RowScalar::Boolean(value)) => value.to_string(),
        })
        .collect::<Vec<_>>()
        .join("|")
}

/// The roles asserted by one family of asserts, deduplicated. Capability
/// reporting narrows to exactly these, so an adapter gap in a role no assert
/// mentions cannot make the run unreliable.
fn asserted_roles(
    spec: &AssertionPolicySpec,
    selects: impl Fn(&PolicyAssert) -> bool,
) -> Vec<OccurrenceRole> {
    let mut roles = spec
        .asserts
        .iter()
        .filter(|assertion| selects(assertion))
        .filter_map(PolicyAssert::role)
        .collect::<Vec<_>>();
    roles.sort();
    roles.dedup();
    roles
}

/// Whether any occurrence row of one role joined to a subject capture.
fn joined_role_rows(
    ast_ids: &[&str],
    rows_by_ast_id: &HashMap<&str, Vec<&CodeQueryOccurrence>>,
    role: OccurrenceRole,
) -> bool {
    ast_ids.iter().any(|ast_id| {
        rows_by_ast_id
            .get(ast_id)
            .is_some_and(|rows| rows.iter().any(|row| row.role == role.label()))
    })
}

/// What one violated assert observed, in the shape the finding needs.
struct AssertionViolation<'rows> {
    /// The occurrence class the joined rows must carry.
    expected_class: &'static str,
    expectation: String,
    observed: Option<String>,
    actual_count: u64,
    /// Occurrence rows that joined, listed as actual occurrences.
    occurrences: Vec<&'rows CodeQueryOccurrence>,
    /// Candidate rows the resolver considered, listed as considered
    /// candidates. The selected ones lead.
    candidates: Vec<&'rows CodeQueryResolutionCandidate>,
    /// The binding a reaching assert reached, listed as the reaching binding.
    binding: Option<&'rows CodeQueryBinding>,
    /// The scope the binding is declared in.
    declaring_scope: Option<&'rows CodeQueryLexicalScope>,
    /// Generation-site rows a generation assert fired on; the site and each
    /// generated declaration's naming argument become related locations.
    generation_sites: Vec<&'rows CodeQueryGenerationSite>,
    /// Prebuilt locations for edge-assert evidence: the unmatched edge's site
    /// and target files. Built at evaluation time because edge rows are
    /// derivation rows, not wire rows.
    edge_locations: Vec<PolicySourceLocation>,
    /// Producer-derived evidence locations (route provenance, compared
    /// tokens, terminal declarations), already shaped as policy locations
    /// because their rows never travelled through a query.
    extra_locations: Vec<(PolicyLocationRelationship, PolicySourceLocation)>,
}

impl<'rows> AssertionViolation<'rows> {
    fn new(expected_class: &'static str, expectation: String, observed: Option<String>) -> Self {
        Self {
            expected_class,
            expectation,
            observed,
            actual_count: 0,
            occurrences: Vec::new(),
            candidates: Vec::new(),
            binding: None,
            declaring_scope: None,
            generation_sites: Vec::new(),
            edge_locations: Vec::new(),
            extra_locations: Vec::new(),
        }
    }
}

fn evaluate_occurrence_assert<'rows>(
    assertion: &OccurrenceAssert,
    ast_ids: &[&str],
    rows_by_ast_id: &HashMap<&str, Vec<&'rows CodeQueryOccurrence>>,
) -> Option<AssertionViolation<'rows>> {
    let mut actual: Vec<&CodeQueryOccurrence> = Vec::new();
    for ast_id in ast_ids {
        let Some(rows) = rows_by_ast_id.get(ast_id) else {
            continue;
        };
        actual.extend(
            rows.iter()
                .copied()
                .filter(|row| assertion_row_matches(assertion, row)),
        );
    }
    if assertion
        .cardinality
        .satisfied_by(u32::try_from(actual.len()).unwrap_or(u32::MAX))
    {
        return None;
    }
    let mut violation = AssertionViolation::new(
        assertion.expect.label(),
        assertion.cardinality.to_string(),
        None,
    );
    violation.actual_count = u64::try_from(actual.len()).unwrap_or(u64::MAX);
    violation.occurrences = actual;
    Some(violation)
}

/// The candidate rows joined to one subject capture, in row order.
fn joined_candidates<'rows>(
    ast_ids: &[&str],
    candidates_by_ast_id: &HashMap<&str, Vec<&'rows CodeQueryResolutionCandidate>>,
) -> Vec<&'rows CodeQueryResolutionCandidate> {
    let mut rows = Vec::new();
    for ast_id in ast_ids {
        if let Some(joined) = candidates_by_ast_id.get(ast_id) {
            rows.extend(joined.iter().copied());
        }
    }
    rows
}

const SELECTED_OUTCOME: &str = "selected";
const SELECTION_ONLY_TRACE: &str = "selection_only";
const NAME_ONLY_FALLBACK_TIER: &str = "name_only_fallback";

/// Per-run memo of edge derivations for the edge assert families.
///
/// The derivation layer is consulted directly rather than through internal
/// queries: the asserts need the canonical rows' `CodeUnit` targets and typed
/// completeness, and both are first-class on the derivation result while the
/// wire rows re-render them.
struct EdgeAssertContext<'a> {
    analyzer: &'a dyn IAnalyzer,
    cancellation: Option<&'a CancellationToken>,
    inverse: HashMap<CodeUnit, Arc<EdgeDerivationResult>>,
    forward: HashMap<ProjectFile, Option<Arc<EdgeDerivationResult>>>,
}

impl<'a> EdgeAssertContext<'a> {
    fn new(analyzer: &'a dyn IAnalyzer, cancellation: Option<&'a CancellationToken>) -> Self {
        Self {
            analyzer,
            cancellation,
            inverse: HashMap::new(),
            forward: HashMap::new(),
        }
    }

    fn file(&self, rel_path: &str) -> ProjectFile {
        ProjectFile::new(self.analyzer.project().root().to_path_buf(), rel_path)
    }

    fn inverse_for(&mut self, declaration: &CodeUnit) -> Arc<EdgeDerivationResult> {
        if let Some(cached) = self.inverse.get(declaration) {
            return Arc::clone(cached);
        }
        let derived = Arc::new(inverse_edges_for_declaration(
            self.analyzer,
            declaration,
            self.cancellation,
        ));
        self.inverse
            .insert(declaration.clone(), Arc::clone(&derived));
        derived
    }

    /// `None` only on cancellation.
    fn forward_for(&mut self, file: &ProjectFile) -> Option<Arc<EdgeDerivationResult>> {
        if let Some(cached) = self.forward.get(file) {
            return cached.clone();
        }
        let token = self.cancellation.cloned().unwrap_or_default();
        let derived = forward_edges_for_file(self.analyzer, file, &token)
            .ok()
            .map(Arc::new);
        self.forward.insert(file.clone(), derived.clone());
        derived
    }
}

/// The classification axes a parity comparison depends on. Site identity and
/// the projection axes themselves are checked separately per direction.
const EDGE_PARITY_CLASSIFICATION_AXES: &[EdgeAxis] = &[
    EdgeAxis::KindClassification,
    EdgeAxis::ProofAttribution,
    EdgeAxis::OwnerClassification,
];

fn edge_result_covers(result: &EdgeDerivationResult, projection: EdgeAxis) -> bool {
    result.covers(projection)
        && EDGE_PARITY_CLASSIFICATION_AXES
            .iter()
            .all(|axis| result.covers(*axis))
}

/// Forward coverage scoped to the asserted role: occurrence incompleteness in
/// an unrelated role must not decide an unrelated verdict (the #1474 M6
/// lesson, applied to edges).
fn forward_covers_for_role(result: &EdgeDerivationResult, role: OccurrenceRole) -> bool {
    result.covers_forward_role(role)
        && EDGE_PARITY_CLASSIFICATION_AXES
            .iter()
            .all(|axis| result.covers(*axis))
}

fn edge_surface_admits(surface: Option<UsageHitSurface>, row: &ReferenceEdgeRow) -> bool {
    surface.is_none_or(|surface| row.included_in(surface))
}

/// The site identity two producers must agree on: the file plus the exact byte
/// interval, and the AST identity whenever both producers state one.
fn edge_sites_match(left: &ReferenceEdgeRow, right: &ReferenceEdgeRow) -> bool {
    left.site.file == right.site.file
        && left.site.range.start_byte == right.site.range.start_byte
        && left.site.range.end_byte == right.site.range.end_byte
        && match (&left.site.ast_id, &right.site.ast_id) {
            (Some(left), Some(right)) => left == right,
            _ => true,
        }
}

/// The explicit field-for-field comparison. Returns the labels of the fields
/// that disagree; empty means parity.
fn edge_field_mismatches(left: &ReferenceEdgeRow, right: &ReferenceEdgeRow) -> Vec<String> {
    let mut mismatches = Vec::new();
    if left.reference_kind != right.reference_kind {
        mismatches.push(format!(
            "reference_kind {} != {}",
            edge_kind_label(left),
            edge_kind_label(right)
        ));
    }
    if left.proof != right.proof {
        mismatches.push("proof".to_string());
    }
    // usage_kind is deliberately NOT a compared field: the forward producer
    // cannot classify usage kinds (it states `reference` unconditionally), so
    // a raw comparison would fire on every self call and import. Usage-surface
    // classification is compared explicitly instead, through the assert's
    // :surface option: a row that belongs to the compared surface on one side
    // and not the other is a missing counterpart, which is the honest form of
    // the disagreement.
    if left.site_class != right.site_class {
        mismatches.push(format!(
            "site_class {} != {}",
            left.site_class.label(),
            right.site_class.label()
        ));
    }
    if left.owner_relation != right.owner_relation {
        mismatches.push(format!(
            "owner_relation {} != {}",
            left.owner_relation.label(),
            right.owner_relation.label()
        ));
    }
    mismatches
}

fn edge_kind_label(row: &ReferenceEdgeRow) -> &'static str {
    row.reference_kind.map_or("unclassified", |kind| {
        brokk_bifrost_analysis::analyzer::structural::query::schema::reference_kind_label(kind)
    })
}

/// One human-readable statement of an edge, used in observed text so a finding
/// names the unmatched edge exactly.
fn edge_description(row: &ReferenceEdgeRow) -> String {
    format!(
        "{}:{}..{} -> {} [{}; {}; {}; {}; {}]",
        row.site.file.rel_path().display(),
        row.site.range.start_byte,
        row.site.range.end_byte,
        row.target.fq_name(),
        edge_kind_label(row),
        if row.proof == UsageProof::Proven {
            "proven"
        } else {
            "unproven"
        },
        row.usage_kind.wire_label(),
        row.site_class.label(),
        row.owner_relation.label(),
    )
}

fn edge_location(file: &ProjectFile) -> Option<PolicySourceLocation> {
    WorkspaceRelativePath::new(file.rel_path().to_string_lossy())
        .ok()
        .map(PolicySourceLocation::artifact)
}

/// The subject occurrence rows an edge assert is about.
fn edge_subject_rows<'rows>(
    role: OccurrenceRole,
    ast_ids: &[&str],
    rows_by_ast_id: &HashMap<&str, Vec<&'rows CodeQueryOccurrence>>,
) -> Vec<&'rows CodeQueryOccurrence> {
    let mut rows = Vec::new();
    for ast_id in ast_ids {
        if let Some(joined) = rows_by_ast_id.get(ast_id) {
            rows.extend(
                joined
                    .iter()
                    .copied()
                    .filter(|row| row.role == role.label()),
            );
        }
    }
    rows
}

/// The forward edges whose site is exactly one subject token.
fn forward_edges_at_token(
    result: &EdgeDerivationResult,
    token: &CodeQueryOccurrence,
) -> Vec<ReferenceEdgeRow> {
    result
        .edges
        .iter()
        .filter(|row| row.site.ast_id.as_deref() == Some(token.ast_id.as_str()))
        .cloned()
        .collect()
}

/// The declaration a declaration-name token names, addressed by containment of
/// the token in the declaration's range.
fn declaration_of_token(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    token: &CodeQueryOccurrence,
) -> Option<CodeUnit> {
    analyzer.enclosing_code_unit(
        file,
        &AnalyzerRange {
            start_byte: token.start_byte,
            end_byte: token.end_byte,
            start_line: token.range.start_line,
            end_line: token.range.end_line,
        },
    )
}

fn evaluate_edge_parity_assert<'rows>(
    assertion: &EdgeParityAssert,
    ast_ids: &[&str],
    rows_by_ast_id: &HashMap<&str, Vec<&'rows CodeQueryOccurrence>>,
    edges: &mut EdgeAssertContext<'_>,
    late_incomplete: &mut Vec<PolicyIncompleteReason>,
) -> Option<AssertionViolation<'rows>> {
    let tokens = edge_subject_rows(assertion.role, ast_ids, rows_by_ast_id);
    let mut unmatched: Vec<String> = Vec::new();
    let mut locations: Vec<PolicySourceLocation> = Vec::new();
    let mut count = 0u64;

    for token in &tokens {
        let file = edges.file(&token.path);
        if assertion.role == OccurrenceRole::DeclarationName {
            // Inverse direction: every inverse edge of the declaration this
            // token names must have a field-identical forward counterpart in
            // the file that spelled the site.
            let Some(unit) = declaration_of_token(edges.analyzer, &file, token) else {
                late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
                return None;
            };
            let inverse = edges.inverse_for(&unit);
            if !edge_result_covers(&inverse, EdgeAxis::InverseProjection) {
                late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
                return None;
            }
            for edge in &inverse.edges {
                if !edge_surface_admits(assertion.surface, edge) {
                    continue;
                }
                let Some(forward) = edges.forward_for(&edge.site.file) else {
                    late_incomplete.push(PolicyIncompleteReason::Cancelled);
                    return None;
                };
                if !edge_result_covers(&forward, EdgeAxis::ForwardProjection) {
                    late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
                    return None;
                }
                if forward.generation != inverse.generation {
                    // Two generations cannot be compared; refusing is the
                    // contract, not a finding and not a pass.
                    late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
                    return None;
                }
                // The counterpart must belong to the compared surface too: a
                // surface-scoped parity claim compares the two surface
                // projections, not one projection against the complete set.
                let counterpart = forward.edges.iter().find(|candidate| {
                    edge_surface_admits(assertion.surface, candidate)
                        && edge_sites_match(candidate, edge)
                        && candidate.target == edge.target
                });
                match counterpart {
                    None => {
                        count += 1;
                        unmatched.push(format!(
                            "inverse edge {} has no forward counterpart",
                            edge_description(edge)
                        ));
                        locations.extend(edge_location(&edge.site.file));
                    }
                    Some(counterpart) => {
                        let mismatches = edge_field_mismatches(counterpart, edge);
                        if !mismatches.is_empty() {
                            count += 1;
                            unmatched.push(format!(
                                "edge {} disagrees across producers on {}",
                                edge_description(edge),
                                mismatches.join(", ")
                            ));
                            locations.extend(edge_location(&edge.site.file));
                        }
                    }
                }
            }
        } else {
            // Forward direction: every forward edge the resolver states at
            // this token must appear, field-identical, in its target's
            // inverse listing.
            let Some(forward) = edges.forward_for(&file) else {
                late_incomplete.push(PolicyIncompleteReason::Cancelled);
                return None;
            };
            if !forward_covers_for_role(&forward, assertion.role) {
                late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
                return None;
            }
            for edge in forward_edges_at_token(&forward, token) {
                if !edge_surface_admits(assertion.surface, &edge) {
                    continue;
                }
                let inverse = edges.inverse_for(&edge.target);
                if !edge_result_covers(&inverse, EdgeAxis::InverseProjection) {
                    late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
                    return None;
                }
                if forward.generation != inverse.generation {
                    late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
                    return None;
                }
                let counterpart = inverse.edges.iter().find(|candidate| {
                    edge_surface_admits(assertion.surface, candidate)
                        && edge_sites_match(candidate, &edge)
                        && candidate.target == edge.target
                });
                match counterpart {
                    None => {
                        count += 1;
                        unmatched.push(format!(
                            "forward edge {} has no inverse counterpart",
                            edge_description(&edge)
                        ));
                        locations.extend(edge_location(edge.target.source()));
                    }
                    Some(counterpart) => {
                        let mismatches = edge_field_mismatches(&edge, counterpart);
                        if !mismatches.is_empty() {
                            count += 1;
                            unmatched.push(format!(
                                "edge {} disagrees across producers on {}",
                                edge_description(&edge),
                                mismatches.join(", ")
                            ));
                            locations.extend(edge_location(edge.target.source()));
                        }
                    }
                }
            }
        }
    }

    if unmatched.is_empty() {
        return None;
    }
    let mut violation = AssertionViolation::new(
        "reference",
        assertion.expectation(),
        Some(unmatched.join("; ")),
    );
    violation.actual_count = count;
    violation.occurrences = tokens;
    violation.edge_locations = locations;
    Some(violation)
}

fn evaluate_edge_class_assert<'rows>(
    assertion: &EdgeClassAssert,
    ast_ids: &[&str],
    rows_by_ast_id: &HashMap<&str, Vec<&'rows CodeQueryOccurrence>>,
    edges: &mut EdgeAssertContext<'_>,
    late_incomplete: &mut Vec<PolicyIncompleteReason>,
) -> Option<AssertionViolation<'rows>> {
    let tokens = edge_subject_rows(assertion.role, ast_ids, rows_by_ast_id);
    let mut offending: Vec<String> = Vec::new();
    let mut locations: Vec<PolicySourceLocation> = Vec::new();
    let mut count = 0u64;

    for token in &tokens {
        let file = edges.file(&token.path);
        let rows: Vec<ReferenceEdgeRow> = if assertion.role == OccurrenceRole::DeclarationName {
            let Some(unit) = declaration_of_token(edges.analyzer, &file, token) else {
                late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
                return None;
            };
            let inverse = edges.inverse_for(&unit);
            if !edge_result_covers(&inverse, EdgeAxis::InverseProjection) {
                late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
                return None;
            }
            inverse.edges.clone()
        } else {
            let Some(forward) = edges.forward_for(&file) else {
                late_incomplete.push(PolicyIncompleteReason::Cancelled);
                return None;
            };
            if !forward_covers_for_role(&forward, assertion.role) {
                late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
                return None;
            }
            forward_edges_at_token(&forward, token)
        };
        for edge in rows {
            if !edge_surface_admits(assertion.surface, &edge) {
                continue;
            }
            let verdict = edge_class_verdict(&assertion.constraint, &edge);
            match verdict {
                EdgeClassVerdict::Satisfied => {}
                EdgeClassVerdict::Undecidable => {
                    // The constrained axis is `unknown` on this row; unknown
                    // can neither satisfy nor violate a classification.
                    late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
                    return None;
                }
                EdgeClassVerdict::Violated(reason) => {
                    count += 1;
                    offending.push(format!("edge {} {reason}", edge_description(&edge)));
                    locations.extend(edge_location(&edge.site.file));
                }
            }
        }
    }

    if offending.is_empty() {
        return None;
    }
    let mut violation = AssertionViolation::new(
        "reference",
        assertion.expectation(),
        Some(offending.join("; ")),
    );
    violation.actual_count = count;
    violation.occurrences = tokens;
    violation.edge_locations = locations;
    Some(violation)
}

enum EdgeClassVerdict {
    Satisfied,
    Violated(String),
    Undecidable,
}

fn edge_class_verdict(
    constraint: &EdgeClassConstraint,
    edge: &ReferenceEdgeRow,
) -> EdgeClassVerdict {
    fn check<T: PartialEq + Copy>(
        value: T,
        require: &[T],
        forbid: &[T],
        label: impl Fn(T) -> String,
    ) -> EdgeClassVerdict {
        if forbid.contains(&value) {
            return EdgeClassVerdict::Violated(format!("carries forbidden value {}", label(value)));
        }
        if !require.is_empty() && !require.contains(&value) {
            return EdgeClassVerdict::Violated(format!(
                "carries {} outside the required set",
                label(value)
            ));
        }
        EdgeClassVerdict::Satisfied
    }
    match constraint {
        EdgeClassConstraint::Relation { require, forbid } => {
            if edge.owner_relation == OwnerRelation::Unknown
                && !forbid.contains(&OwnerRelation::Unknown)
                && !require.contains(&OwnerRelation::Unknown)
            {
                return EdgeClassVerdict::Undecidable;
            }
            check(edge.owner_relation, require, forbid, |value| {
                value.label().to_string()
            })
        }
        EdgeClassConstraint::Usage { require, forbid } => {
            check(edge.usage_kind, require, forbid, |value| {
                value.wire_label().to_string()
            })
        }
        EdgeClassConstraint::SiteClass { require, forbid } => {
            check(edge.site_class, require, forbid, |value| {
                value.label().to_string()
            })
        }
        EdgeClassConstraint::Kind { require, forbid } => match edge.reference_kind {
            // An unclassified kind is not a kind; it can neither satisfy a
            // requirement nor trip a prohibition.
            None => EdgeClassVerdict::Undecidable,
            Some(kind) => check(kind, require, forbid, |value| {
                brokk_bifrost_analysis::analyzer::structural::query::schema::reference_kind_label(
                    value,
                )
                .to_string()
            }),
        },
    }
}

fn evaluate_resolution_assert<'rows>(
    assertion: &ResolutionAssert,
    ast_ids: &[&str],
    candidates_by_ast_id: &HashMap<&str, Vec<&'rows CodeQueryResolutionCandidate>>,
    late_incomplete: &mut Vec<PolicyIncompleteReason>,
) -> Option<AssertionViolation<'rows>> {
    let considered = joined_candidates(ast_ids, candidates_by_ast_id);
    let selected = considered
        .iter()
        .copied()
        .filter(|row| row.outcome == SELECTED_OUTCOME)
        .collect::<Vec<_>>();
    // Nothing was selected, so there is no tier to compare. That is an absent
    // verdict, not a satisfied one and not a violated one.
    if selected.is_empty() {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    }
    // An absent tier means the recording seam could not name one. It is never
    // the weakest tier, so it can neither pass nor fail a tier comparison.
    if selected.iter().any(|row| row.tier.is_none()) {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    }
    // Uniqueness is a claim about the whole considered set, which a trace that
    // records no rejections does not state.
    if assertion.require_unique
        && considered
            .iter()
            .any(|row| row.trace_completeness == SELECTION_ONLY_TRACE)
    {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    }

    let unique_violated = assertion.require_unique && selected.len() > 1;
    let tier_violated = selected.iter().any(|row| {
        row.tier
            .and_then(PrecedenceTier::from_label)
            .is_some_and(|tier| !assertion.accepts(tier))
    });
    if !unique_violated && !tier_violated {
        return None;
    }

    let observed = selected
        .iter()
        .filter_map(|row| row.tier)
        .collect::<Vec<_>>()
        .join(", ");
    let mut violation = AssertionViolation::new(
        "reference",
        assertion.expectation(),
        Some(format!(
            "{} selected candidate(s) at tier(s) {observed}",
            selected.len()
        )),
    );
    violation.actual_count = u64::try_from(selected.len()).unwrap_or(u64::MAX);
    violation.candidates = ordered_candidates(&selected, &considered);
    Some(violation)
}

fn evaluate_boundary_assert<'rows>(
    assertion: &BoundaryAssert,
    ast_ids: &[&str],
    candidates_by_ast_id: &HashMap<&str, Vec<&'rows CodeQueryResolutionCandidate>>,
    _late_incomplete: &mut Vec<PolicyIncompleteReason>,
) -> Option<AssertionViolation<'rows>> {
    let considered = joined_candidates(ast_ids, candidates_by_ast_id);
    let selected = considered
        .iter()
        .copied()
        .filter(|row| row.outcome == SELECTED_OUTCOME)
        .collect::<Vec<_>>();
    // Unlike the tier assert, this one is a pure prohibition: nothing selected
    // is nothing selected by bare name, which satisfies it. Requiring a
    // selection here would report a boundary the resolver correctly refused to
    // cross as an unanswerable question.
    let offending = selected
        .iter()
        .copied()
        .filter(|row| {
            row.tier == Some(NAME_ONLY_FALLBACK_TIER)
                && BoundaryStatus::from_label(row.boundary)
                    .is_some_and(|status| assertion.forbid_fallback_past.reached_by(status))
        })
        .collect::<Vec<_>>();
    if offending.is_empty() {
        return None;
    }
    let observed = offending
        .iter()
        .map(|row| row.boundary)
        .collect::<Vec<_>>()
        .join(", ");
    let mut violation = AssertionViolation::new(
        "reference",
        assertion.expectation(),
        Some(format!(
            "name_only_fallback selected at boundary(s) {observed}"
        )),
    );
    violation.actual_count = u64::try_from(offending.len()).unwrap_or(u64::MAX);
    violation.candidates = ordered_candidates(&offending, &considered);
    Some(violation)
}

fn evaluate_generation_assert<'rows>(
    assertion: &GenerationAssert,
    ast_ids: &[&str],
    sites_by_ast_id: &HashMap<&str, Vec<&'rows CodeQueryGenerationSite>>,
    late_incomplete: &mut Vec<PolicyIncompleteReason>,
) -> Option<AssertionViolation<'rows>> {
    let joined: Vec<&CodeQueryGenerationSite> = ast_ids
        .iter()
        .filter_map(|ast_id| sites_by_ast_id.get(ast_id))
        .flatten()
        .copied()
        .filter(|row| assertion.kind.is_none_or(|kind| row.kind == kind.label()))
        .collect();
    // A capture that addresses no generation site is not a subject this
    // assert is about, exactly as a role-less token is not a subject of a
    // resolution assert.
    if joined.is_empty() {
        return None;
    }
    for row in &joined {
        if row.input == "dynamic" {
            if assertion.forbid_dynamic {
                let mut violation = AssertionViolation::new(
                    "generation_site",
                    assertion.expectation(),
                    Some("a generation site with dynamic inputs".to_string()),
                );
                violation.actual_count = 1;
                violation.generation_sites = vec![row];
                return Some(violation);
            }
            // The generated set of a dynamic site is honestly unknown, so a
            // cardinality over it can neither pass nor fail.
            late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
            continue;
        }
        if let Some(cardinality) = assertion.cardinality {
            let actual = u32::try_from(row.generated_count).unwrap_or(u32::MAX);
            if !cardinality.satisfied_by(actual) {
                let mut violation = AssertionViolation::new(
                    "generation_site",
                    assertion.expectation(),
                    Some(format!(
                        "{} generated declaration(s): {}",
                        row.generated_count,
                        row.generated
                            .iter()
                            .map(|generated| generated.fq_name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                );
                violation.actual_count = u64::from(actual);
                violation.generation_sites = vec![row];
                return Some(violation);
            }
        }
    }
    None
}

fn evaluate_declaration_state_assert<'rows>(
    assertion: &DeclarationStateAssert,
    ast_ids: &[&str],
    states_by_ast_id: &HashMap<String, Vec<&'rows DeclarationStateRow>>,
) -> Option<AssertionViolation<'rows>> {
    let joined: Vec<&DeclarationStateRow> = ast_ids
        .iter()
        .filter_map(|ast_id| states_by_ast_id.get(*ast_id))
        .flatten()
        .copied()
        .collect();
    // A capture whose node anchors no state row is not a subject this assert
    // is about.
    if joined.is_empty() {
        return None;
    }
    for row in &joined {
        let origin_ok = assertion
            .expect_origin
            .is_none_or(|origin| row.origin == origin);
        let declaration_only_ok = assertion
            .declaration_only
            .is_none_or(|expected| row.declaration_only == expected);
        let config_gated_ok = assertion
            .config_gated
            .is_none_or(|expected| row.config_gated == expected);
        if origin_ok && declaration_only_ok && config_gated_ok {
            continue;
        }
        let mut violation = AssertionViolation::new(
            "declaration_state",
            assertion.expectation(),
            Some(format!(
                "{} is {}{}{}",
                row.unit.fq_name(),
                row.origin.label(),
                if row.declaration_only {
                    ", declaration-only"
                } else {
                    ""
                },
                if row.config_gated {
                    ", config-gated"
                } else {
                    ""
                },
            )),
        );
        violation.actual_count = 1;
        return Some(violation);
    }
    None
}

/// Selected rows first, then every other considered row, so a reader sees the
/// answer before the alternatives it beat.
fn ordered_candidates<'rows>(
    leading: &[&'rows CodeQueryResolutionCandidate],
    considered: &[&'rows CodeQueryResolutionCandidate],
) -> Vec<&'rows CodeQueryResolutionCandidate> {
    let mut rows = leading.to_vec();
    for row in considered {
        if !rows.iter().any(|kept| kept.id == row.id) {
            rows.push(row);
        }
    }
    rows
}

fn evaluate_reaching_assert<'rows>(
    assertion: &ReachingAssert,
    subject: &AssertionSubject,
    ast_ids: &[&str],
    bindings_by_occurrence: &HashMap<(&str, &str), Vec<&'rows CodeQueryBinding>>,
    scopes_by_index: &HashMap<(&str, u32), &'rows CodeQueryLexicalScope>,
    late_incomplete: &mut Vec<PolicyIncompleteReason>,
) -> Option<AssertionViolation<'rows>> {
    let mut reached: Vec<&CodeQueryBinding> = Vec::new();
    for ast_id in ast_ids {
        if let Some(rows) = bindings_by_occurrence.get(&(subject.path.as_str(), *ast_id)) {
            reached.extend(rows.iter().copied().filter(|row| !row.shadowed));
        }
    }
    // "No binding of this name is in effect here" is a complete answer, not an
    // incomplete one: the name resolves to something other than a lexical
    // binding, so there is no declaring scope for a containment requirement to
    // constrain. An environment that could not state its intervals is a
    // different case and has already made the run inconclusive through the
    // query's own diagnostics.
    let binding = reached.first().copied()?;
    let Some(scope) = scopes_by_index
        .get(&(binding.path.as_str(), binding.declaring_scope_index))
        .copied()
    else {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    };
    // A capture with no node range cannot bound anything, and guessing one
    // from the subject's own span would be answering a different question.
    let Some(related) = subject
        .captures
        .get(&assertion.relative_to)
        .and_then(|captures| captures.iter().find_map(|capture| capture.range))
    else {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    };
    // Containment is a comparison of two display regions, which means anything
    // at all only within one file. The binding was reached from an occurrence
    // this subject row captured, and the related capture belongs to the same
    // structural match, so both address nodes of the subject's file by
    // construction. State it rather than assume it: a coordinate comparison
    // across two files would answer confidently and wrongly.
    assert_eq!(
        binding.path.as_str(),
        subject.path.as_str(),
        "a reaching binding must belong to the file of the occurrence it was reached from"
    );
    assert_eq!(
        scope.path.as_str(),
        subject.path.as_str(),
        "a declaring scope must belong to the file of the binding that names it"
    );
    let contained = region_contains(related, scope.range);
    if assertion.containment.satisfied_by(contained) {
        return None;
    }
    let mut violation = AssertionViolation::new(
        "reference",
        assertion.expectation(),
        Some(format!(
            "binding `{}` is declared {} capture `{}`",
            binding.name,
            if contained { "inside" } else { "outside" },
            assertion.relative_to
        )),
    );
    violation.actual_count = 1;
    violation.binding = Some(binding);
    violation.declaring_scope = Some(scope);
    Some(violation)
}

fn collect_assertion_subjects(
    results: &[CodeQueryResultItem],
    evidence: &[DetailedCodeQueryEvidence],
) -> Result<Vec<AssertionSubject>, &'static str> {
    if results.len() != evidence.len() {
        return Err("assertion subject rows and their detailed evidence disagree");
    }
    let mut subjects = Vec::with_capacity(results.len());
    for (item, evidence) in results.iter().zip(evidence) {
        let CodeQueryResultValue::StructuralMatch { value } = &item.value else {
            return Err(
                "an assertion subject selector must produce structural matches carrying captures",
            );
        };
        let Ok(path) = WorkspaceRelativePath::try_from_path(evidence.file.rel_path()) else {
            return Err("an assertion subject row has no workspace-relative path");
        };
        let (Some(byte_span), Some(range)) = (evidence.byte_span.as_ref(), value.node_range) else {
            return Err("an assertion subject row is missing its exact source span");
        };
        let Ok(location) = policy_span_location(path.clone(), byte_span, range) else {
            return Err("an assertion subject row span could not be projected");
        };
        let mut captures: HashMap<String, Vec<SubjectCapture>> = HashMap::new();
        let mut captures_without_ast_id = Vec::new();
        for capture in &value.captures {
            if capture.ast_id.is_none() {
                captures_without_ast_id.push(capture.name.clone());
            }
            captures
                .entry(capture.name.clone())
                .or_default()
                .push(SubjectCapture {
                    ast_id: capture.ast_id.clone(),
                    range: capture.range,
                });
        }
        subjects.push(AssertionSubject {
            path,
            location,
            captures,
            captures_without_ast_id,
        });
    }
    Ok(subjects)
}

fn assertion_occurrence_query(
    paths: &[&str],
    roles: &[OccurrenceRole],
    steps: Vec<QueryStep>,
    budget: &PolicyBudget,
) -> Result<CodeQuery, &'static str> {
    // An empty exact-path list is an unrestricted seed; a caller with no
    // subject files must skip the query instead of scanning the workspace.
    assert!(
        !paths.is_empty(),
        "assertion row queries require subject paths"
    );
    let Ok(seed) = OccurrenceSeed::for_exact_paths(paths.iter().copied(), roles.to_vec()) else {
        return Err("an assertion subject path is not a valid scan pattern");
    };
    Ok(CodeQuery {
        schema_version: SCHEMA_VERSION,
        plan: CodeQueryPlan {
            source: CodeQueryPlanSource::Occurrences(Box::new(seed)),
            steps,
        },
        limit: budget.query_limits().max_pipeline_rows,
        // Full detail is what emits `ast_id`, which is the whole join.
        result_detail: CodeQueryResultDetail::Full,
        execution_mode: Default::default(),
    })
}

/// Every scope of the subject files, so a binding's declaring scope index can
/// be projected to the interval a containment assert compares against.
fn assertion_scope_query(paths: &[&str], budget: &PolicyBudget) -> Result<CodeQuery, &'static str> {
    assert!(
        !paths.is_empty(),
        "assertion scope queries require subject paths"
    );
    let Ok(seed) = ScopeSeed::for_exact_paths(paths.iter().copied()) else {
        return Err("an assertion subject path is not a valid scan pattern");
    };
    Ok(CodeQuery {
        schema_version: SCHEMA_VERSION,
        plan: CodeQueryPlan {
            source: CodeQueryPlanSource::Scopes(Box::new(seed)),
            steps: Vec::new(),
        },
        limit: budget.query_limits().max_pipeline_rows,
        result_detail: CodeQueryResultDetail::Full,
        execution_mode: Default::default(),
    })
}

/// Every generation site of the subject files, joined to captures by the
/// site's own AST identity (#1476).
fn assertion_generation_query(
    paths: &[&str],
    budget: &PolicyBudget,
) -> Result<CodeQuery, &'static str> {
    let Ok(seed) = GenerationSiteSeed::for_exact_paths(paths.iter().copied()) else {
        return Err("an assertion subject path is not a valid scan pattern");
    };
    Ok(CodeQuery {
        schema_version: SCHEMA_VERSION,
        plan: CodeQueryPlan {
            source: CodeQueryPlanSource::GenerationSites(Box::new(seed)),
            steps: Vec::new(),
        },
        limit: budget.query_limits().max_pipeline_rows,
        result_detail: CodeQueryResultDetail::Full,
        execution_mode: Default::default(),
    })
}

fn assertion_related_locations(
    subject: &AssertionSubject,
    violation: &AssertionViolation<'_>,
    budget: &PolicyBudget,
    related_truncated: &mut bool,
    omitted_related: &mut u64,
) -> Result<Vec<RelatedPolicyLocation>, ()> {
    let mut related = vec![
        RelatedPolicyLocation::try_new(
            PolicyLocationRelationship::Subject,
            subject.location.clone(),
            Vec::new(),
        )
        .map_err(|_| ())?,
    ];
    if violation.occurrences.is_empty()
        && violation.candidates.is_empty()
        && violation.binding.is_none()
        && violation.generation_sites.is_empty()
        && violation.extra_locations.is_empty()
    {
        // An absence violation has no offending row to point at, so the place
        // the row was expected is the subject node itself.
        related.push(
            RelatedPolicyLocation::try_new(
                PolicyLocationRelationship::ExpectedOccurrence,
                subject.location.clone(),
                Vec::new(),
            )
            .map_err(|_| ())?,
        );
    }
    let mut push = |relationship: PolicyLocationRelationship,
                    location: PolicySourceLocation,
                    related: &mut Vec<RelatedPolicyLocation>|
     -> Result<(), ()> {
        if related.len() >= budget.max_related_locations_per_finding() {
            *related_truncated = true;
            *omitted_related = omitted_related.saturating_add(1);
            return Ok(());
        }
        related.push(
            RelatedPolicyLocation::try_new(relationship, location, Vec::new()).map_err(|_| ())?,
        );
        Ok(())
    };
    for row in &violation.occurrences {
        let location = occurrence_row_location(&subject.path, row)?;
        push(
            PolicyLocationRelationship::ActualOccurrence,
            location,
            &mut related,
        )?;
    }
    for (index, row) in violation.candidates.iter().enumerate() {
        let relationship = if index == 0 && row.outcome == SELECTED_OUTCOME {
            PolicyLocationRelationship::SelectedCandidate
        } else {
            PolicyLocationRelationship::ConsideredCandidate
        };
        push(relationship, candidate_row_location(row)?, &mut related)?;
    }
    for row in &violation.generation_sites {
        let path = WorkspaceRelativePath::new(&row.path).map_err(|_| ())?;
        push(
            PolicyLocationRelationship::GenerationSite,
            policy_span_location(path.clone(), &(row.start_byte..row.end_byte), row.range)?,
            &mut related,
        )?;
        for generated in &row.generated {
            push(
                PolicyLocationRelationship::GeneratedDeclaration,
                policy_span_location(
                    path.clone(),
                    &(generated.argument_start_byte..generated.argument_end_byte),
                    generated.argument_range,
                )?,
                &mut related,
            )?;
        }
    }
    for location in &violation.edge_locations {
        push(
            PolicyLocationRelationship::Evidence,
            location.clone(),
            &mut related,
        )?;
    }
    if let Some(binding) = violation.binding {
        push(
            PolicyLocationRelationship::ReachingBinding,
            binding_row_location(binding)?,
            &mut related,
        )?;
    }
    if let Some(scope) = violation.declaring_scope {
        push(
            PolicyLocationRelationship::DeclaringScope,
            scope_row_location(scope)?,
            &mut related,
        )?;
    }
    for (relationship, location) in &violation.extra_locations {
        push(*relationship, location.clone(), &mut related)?;
    }
    Ok(related)
}

/// Producer access for the canonical, route, and round-trip families, which
/// read the analyzer's identity producers directly rather than query rows:
/// their inputs are `CodeUnit`s, which no serialized row carries. Occurrence
/// derivations are memoised per file, and a policy without these families
/// never constructs this at all.
struct IdentityAssertSupport {
    files_by_path: HashMap<String, ProjectFile>,
    occurrences: HashMap<String, std::sync::Arc<OccurrenceFileResult>>,
}

impl IdentityAssertSupport {
    fn new(analyzer: &dyn IAnalyzer) -> Self {
        let mut files_by_path = HashMap::new();
        for file in analyzer.analyzed_files() {
            files_by_path.insert(workspace_relative_key(&file), file);
        }
        Self {
            files_by_path,
            occurrences: HashMap::new(),
        }
    }

    fn file(&self, path: &WorkspaceRelativePath) -> Option<&ProjectFile> {
        self.files_by_path.get(path.as_str())
    }

    /// The internal occurrence rows of one file. `None` on cancellation or an
    /// unknown path; a caller records the gap rather than passing silently.
    fn rows(
        &mut self,
        analyzer: &dyn IAnalyzer,
        path: &WorkspaceRelativePath,
        cancellation: Option<&CancellationToken>,
    ) -> Option<std::sync::Arc<OccurrenceFileResult>> {
        if let Some(cached) = self.occurrences.get(path.as_str()) {
            return Some(std::sync::Arc::clone(cached));
        }
        let file = self.files_by_path.get(path.as_str())?.clone();
        let token = cancellation.cloned().unwrap_or_default();
        let derived = occurrences_for_file(analyzer, &file, &token).ok()?;
        let derived = std::sync::Arc::new(derived);
        self.occurrences
            .insert(path.as_str().to_string(), std::sync::Arc::clone(&derived));
        Some(derived)
    }
}

/// The stable workspace-relative key an analyzed file is addressed by: path
/// components joined with `/`, matching how subject paths are rendered.
fn workspace_relative_key(file: &ProjectFile) -> String {
    file.rel_path()
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// The declarations one internal occurrence row names: its resolved targets
/// for a reference-class token, or the declared unit itself for a
/// declaration-name token.
fn row_declarations(row: &InternalOccurrenceRow) -> Option<Vec<CodeUnit>> {
    match &row.target {
        InternalOccurrenceTarget::Resolved(units) => Some(units.clone()),
        InternalOccurrenceTarget::None => row
            .enclosing
            .as_ref()
            .map(|unit| vec![unit.clone()])
            .filter(|_| row.class == InternalOccurrenceClass::Declaration),
        InternalOccurrenceTarget::Lexical(_) | InternalOccurrenceTarget::Unresolved(_) => None,
    }
}

/// The internal row of one role joined to one capture's AST ids.
fn internal_row_by_ast<'rows>(
    rows: &'rows OccurrenceFileResult,
    ast_ids: &[&str],
    role: OccurrenceRole,
) -> Option<&'rows InternalOccurrenceRow> {
    rows.rows
        .iter()
        .find(|row| row.role == role && ast_ids.contains(&row.ast_id().as_str()))
}

fn evaluate_canonical_assert<'rows>(
    assertion: &CanonicalAssert,
    subject: &AssertionSubject,
    ast_ids: &[&str],
    equals_ids: &[&str],
    support: &mut IdentityAssertSupport,
    context: &PolicyEvaluationContext<'_>,
    late_incomplete: &mut Vec<PolicyIncompleteReason>,
) -> Option<AssertionViolation<'rows>> {
    let Some(rows) = support.rows(context.analyzer, &subject.path, context.cancellation) else {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    };
    let subject_row = internal_row_by_ast(&rows, ast_ids, assertion.role)?;
    // The compared capture without a row of its role is not a pair this
    // assert is about; a resolver that could not answer either token is.
    let compared_row = internal_row_by_ast(&rows, equals_ids, assertion.equals_role)?;
    let (Some(subject_units), Some(compared_units)) = (
        row_declarations(subject_row),
        row_declarations(compared_row),
    ) else {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    };
    let subject_identities: Vec<_> = subject_units
        .iter()
        .map(|unit| canonical_identity_of(context.analyzer, unit))
        .collect();
    let compared_identities: Vec<_> = compared_units
        .iter()
        .map(|unit| canonical_identity_of(context.analyzer, unit))
        .collect();
    let shared = subject_identities
        .iter()
        .any(|identity| compared_identities.contains(identity));
    let violated = if assertion.distinct { shared } else { !shared };
    if !violated {
        return None;
    }
    let mut violation = AssertionViolation::new(
        "reference",
        assertion.expectation(),
        Some(format!(
            "subject resolves to [{}]; `{}` resolves to [{}]",
            identity_renderings(&subject_identities),
            assertion.equals,
            identity_renderings(&compared_identities),
        )),
    );
    violation.actual_count = u64::try_from(subject_identities.len()).unwrap_or(u64::MAX);
    if let Ok(location) = internal_row_location(&subject.path, compared_row) {
        violation
            .extra_locations
            .push((PolicyLocationRelationship::Evidence, location));
    }
    Some(violation)
}

fn identity_renderings(identities: &[CanonicalIdentity]) -> String {
    identities
        .iter()
        .map(|identity| {
            format!(
                "{} {} {}",
                identity.namespace.label(),
                identity.diagnostic_rendering(),
                match identity.generic_arity {
                    Some(arity) => format!("<{arity}>"),
                    None => String::new(),
                }
            )
            .trim_end()
            .to_string()
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn internal_row_location(
    path: &WorkspaceRelativePath,
    row: &InternalOccurrenceRow,
) -> Result<PolicySourceLocation, ()> {
    policy_span_location(
        path.clone(),
        &(row.range.start_byte..row.range.end_byte),
        CodeQueryRange {
            start_line: row.range.start_line,
            start_column: 1,
            end_line: row.range.end_line,
            end_column: 1,
        },
    )
}

fn evaluate_route_assert<'rows>(
    assertion: &RouteAssert,
    subject: &AssertionSubject,
    ast_ids: &[&str],
    to_ids: &[&str],
    support: &mut IdentityAssertSupport,
    context: &PolicyEvaluationContext<'_>,
    late_incomplete: &mut Vec<PolicyIncompleteReason>,
) -> Option<AssertionViolation<'rows>> {
    let Some(rows) = support.rows(context.analyzer, &subject.path, context.cancellation) else {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    };
    let subject_row = internal_row_by_ast(&rows, ast_ids, assertion.role)?;
    let target_row = internal_row_by_ast(&rows, to_ids, assertion.to_role)?;
    let Some(targets) = row_declarations(target_row) else {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    };
    let Some(file) = support.file(&subject.path).cloned() else {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    };

    // An adapter that supplies no route relations at all cannot state the
    // absence of a route, so a missing route there is a capability gap.
    if !file_supplies_route_relations(&file) {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    }

    // The traversal follows the identity-preserving hops plus whatever `:via`
    // names explicitly: a route is about one identity flowing, and letting the
    // walk wander through projection hops (nested owners, partial parts) would
    // terminate it at a *different* identity than the one the site names --
    // the same trap the round-trip check documents.
    let mut allowed: Vec<RouteHopKind> = IDENTITY_PRESERVING_HOPS.to_vec();
    if let Some(via) = assertion.via
        && !allowed.contains(&via)
    {
        allowed.push(via);
    }
    if let Some(forbidden) = assertion.forbid {
        allowed.retain(|kind| *kind != forbidden);
    }
    let allowed = Some(allowed);
    // Relation rows anchor at import/export sites; every other token's route
    // starts at what it resolves to. A site with no outgoing rows is not
    // evidence of no route, so both starts are walked: the site's own rows
    // where they exist, and the resolved declarations' otherwise.
    let mut starts = vec![RouteEndpoint::Site {
        file,
        range: subject_row.range,
        name: subject_row.effective_spelling().to_owned(),
    }];
    if let Some(subject_units) = row_declarations(subject_row) {
        for unit in subject_units {
            starts.push(RouteEndpoint::Declaration(unit));
        }
    }
    let token = context.cancellation.cloned().unwrap_or_default();
    let mut routes = Vec::new();
    for start in &starts {
        let Ok(mut from_start) =
            identity_routes_from(context.analyzer, start, allowed.as_deref(), &token)
        else {
            late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
            return None;
        };
        routes.append(&mut from_start);
    }

    let matched = routes.iter().any(|route| {
        route
            .terminal_declaration()
            .is_some_and(|terminal| targets.contains(terminal))
            && assertion
                .via
                .is_none_or(|via| route.hops.iter().any(|hop| hop.kind == via))
    });
    if matched {
        return None;
    }
    // A traversal that could not run to completion is not evidence of absence.
    if routes.iter().any(|route| {
        matches!(
            route.termination,
            RouteTermination::Cycle
                | RouteTermination::FanOutTruncated
                | RouteTermination::DepthTruncated
                | RouteTermination::Incomplete
        )
    }) {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    }

    let mut violation = AssertionViolation::new(
        "reference",
        assertion.expectation(),
        Some(format!(
            "{} terminal route(s) observed, none reaching the target through the required hops",
            routes
                .iter()
                .filter(|route| route.termination == RouteTermination::Terminal)
                .count()
        )),
    );
    if let Ok(location) = internal_row_location(&subject.path, target_row) {
        violation
            .extra_locations
            .push((PolicyLocationRelationship::Evidence, location));
    }
    Some(violation)
}

fn evaluate_round_trip_assert<'rows>(
    assertion: &RoundTripAssert,
    subject: &AssertionSubject,
    ast_ids: &[&str],
    support: &mut IdentityAssertSupport,
    context: &PolicyEvaluationContext<'_>,
    late_incomplete: &mut Vec<PolicyIncompleteReason>,
) -> Option<AssertionViolation<'rows>> {
    let Some(rows) = support.rows(context.analyzer, &subject.path, context.cancellation) else {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    };
    let subject_row = internal_row_by_ast(&rows, ast_ids, assertion.role)?;
    let Some(file) = support.file(&subject.path).cloned() else {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    };
    let token = context.cancellation.cloned().unwrap_or_default();
    let start = RouteEndpoint::Site {
        file: file.clone(),
        range: subject_row.range,
        name: subject_row.effective_spelling().to_owned(),
    };
    // The inverse enumeration needs every file a forward terminal lives in:
    // a facade's origin is in another file, and inverse edges over the
    // subject file alone could never reach back across it.
    let Ok(forward) = identity_routes_from(
        context.analyzer,
        &start,
        Some(IDENTITY_PRESERVING_HOPS),
        &token,
    ) else {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    };
    let mut scope = vec![file.clone()];
    for route in &forward {
        if let Some(terminal) = route.terminal_declaration()
            && !scope.contains(terminal.source())
        {
            scope.push(terminal.source().clone());
        }
    }
    let outcome = round_trip_from_site(
        context.analyzer,
        &file,
        subject_row.range,
        subject_row.effective_spelling(),
        &scope,
        &token,
    );
    match outcome {
        Ok(RoundTripOutcome::Holds { .. }) => None,
        Ok(RoundTripOutcome::ForwardInconclusive) | Err(_) => {
            late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
            None
        }
        Ok(RoundTripOutcome::InverseMisses { terminal }) => {
            let mut violation = AssertionViolation::new(
                "reference",
                assertion.expectation(),
                Some(format!(
                    "forward resolution reaches `{}`, which inverse enumeration cannot walk back to the site",
                    terminal.fq_name()
                )),
            );
            violation.actual_count = 1;
            let terminal_path =
                WorkspaceRelativePath::new(workspace_relative_key(terminal.source()));
            if let Ok(terminal_path) = terminal_path {
                violation.extra_locations.push((
                    PolicyLocationRelationship::Declaration,
                    PolicySourceLocation::artifact(terminal_path),
                ));
            }
            Some(violation)
        }
    }
}

fn assertion_row_matches(assertion: &OccurrenceAssert, row: &CodeQueryOccurrence) -> bool {
    if row.role != assertion.role.label() {
        return false;
    }
    if let Some(namespace) = assertion.namespace
        && row.namespace != namespace.label()
    {
        return false;
    }
    if assertion.require_target && !matches!(row.target, CodeQueryOccurrenceTarget::Resolved { .. })
    {
        return false;
    }
    true
}

/// A candidate row's location.
///
/// The row itself carries the *reference's* span, which is the position whose
/// resolution the candidate explains. A unit-backed candidate additionally
/// names the file its declaration lives in, and that file is a more useful
/// answer than repeating the reference, so it is used where it exists. It is
/// file-only because a candidate declaration carries no byte span.
fn candidate_row_location(row: &CodeQueryResolutionCandidate) -> Result<PolicySourceLocation, ()> {
    if let CodeQueryCandidateRef::Unit { unit } = &row.candidate
        && let Ok(path) = WorkspaceRelativePath::new(&unit.path)
    {
        return Ok(PolicySourceLocation::artifact(path));
    }
    let path = WorkspaceRelativePath::new(&row.path).map_err(|_| ())?;
    policy_span_location(path, &(row.start_byte..row.end_byte), row.range)
}

fn binding_row_location(row: &CodeQueryBinding) -> Result<PolicySourceLocation, ()> {
    let path = WorkspaceRelativePath::new(&row.path).map_err(|_| ())?;
    policy_span_location(path, &(row.start_byte..row.end_byte), row.range)
}

fn scope_row_location(row: &CodeQueryLexicalScope) -> Result<PolicySourceLocation, ()> {
    let path = WorkspaceRelativePath::new(&row.path).map_err(|_| ())?;
    policy_span_location(path, &(row.start_byte..row.end_byte), row.range)
}

fn occurrence_row_location(
    path: &WorkspaceRelativePath,
    row: &CodeQueryOccurrence,
) -> Result<PolicySourceLocation, ()> {
    policy_span_location(path.clone(), &(row.start_byte..row.end_byte), row.range)
}

fn assertion_capabilities(diagnostics: &[CodeQueryDiagnostic]) -> Vec<PolicyCapability> {
    let mut capabilities = Vec::new();
    for diagnostic in diagnostics {
        if diagnostic.impact != CodeQueryDiagnosticImpact::Incomplete {
            continue;
        }
        if let Ok(capability) =
            PolicyCapability::query_feature(diagnostic.language, diagnostic.code.as_str())
        {
            capabilities.push(capability);
        }
    }
    capabilities.sort();
    capabilities.dedup();
    capabilities
}
