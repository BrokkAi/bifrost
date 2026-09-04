use brokk_bifrost_analysis::analyzer::usages::UsageHitKind;
use brokk_bifrost_rql::structural::CodeQueryRowScalarRef;
use brokk_bifrost_rql::structural::edges::EdgeProvenance;
use brokk_bifrost_rql::structural::search::{DetailedCodeQueryResult, MergedUnitRows};
use std::collections::HashSet;

use super::super::units::AssertFileProduct;
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

    /// Whether one capture of this name binds a node that is not an
    /// identifier -- a field access, for example -- and therefore never has
    /// an identifier-occurrence row of any role.
    fn binds_non_identifier(&self, name: &str) -> bool {
        self.captures.get(name).is_some_and(|captures| {
            captures.iter().any(|capture| {
                capture
                    .kind
                    .as_deref()
                    .is_some_and(|kind| kind != "identifier")
            })
        })
    }
}

/// One capture of one subject row.
#[derive(Debug)]
struct SubjectCapture {
    ast_id: Option<String>,
    /// The captured node's normalized kind, which says whether the capture is
    /// an identifier occurrence at all.
    kind: Option<Box<str>>,
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

/// One query's rows, however this run obtained them.
///
/// A whole run projects one workspace-wide execution into this; a sliced run
/// merges one execution per seed file into it. Everything after this point is
/// the same code either way, which is what makes the two runs answer alike by
/// construction rather than by comparison. An assertion policy's subject
/// selector and each binding of a relational plan are both one query, so both
/// arrive here.
struct ExecutedQueryRows {
    items: Vec<UnitRowItem>,
    evidence: Vec<UnitRowEvidence>,
    completion: CodeQueryCompletion,
    truncated: bool,
    diagnostics: Vec<CodeQueryDiagnostic>,
    work: CodeQueryExecutionWork,
}

impl ExecutedQueryRows {
    /// One whole execution's rendered rows, projected into exactly the product
    /// a unit publishes, so no consumer can tell which path produced them.
    fn of_detailed(detailed: DetailedCodeQueryResult) -> Self {
        Self {
            items: detailed
                .result
                .results
                .iter()
                .map(UnitRowItem::project)
                .collect(),
            evidence: detailed
                .evidence
                .iter()
                .map(UnitRowEvidence::project)
                .collect(),
            completion: detailed.result.completion(),
            truncated: detailed.result.truncated,
            diagnostics: detailed.result.diagnostics,
            work: detailed.work,
        }
    }

    /// The rows several units produced, merged in seed order.
    fn of_merged(merged: MergedUnitRows) -> Self {
        Self {
            completion: merged.completion(),
            truncated: merged.truncated,
            diagnostics: merged.diagnostics,
            work: merged.work,
            items: merged.items,
            evidence: merged.evidence,
        }
    }
}

/// The row-family executor one assertion run uses for every file.
///
/// Chosen once per run from the asserts: deriving an occurrence row's resolved
/// target is one definition resolution per reference-class row, and only the
/// occurrence family's `:require-target` reads it (#1452).
type AssertRowQueryExecutor = fn(
    &dyn IAnalyzer,
    &CodeQuery,
    brokk_bifrost_rql::structural::CodeQueryExecutionLimits,
    Option<&CancellationToken>,
) -> brokk_bifrost_rql::structural::search::DetailedCodeQueryResult;

/// Everything one assert-file iteration reads that the run computed once from
/// the policy alone.
///
/// None of it depends on which file is being evaluated, which is exactly why a
/// file's iteration is a pure function of its own subject slice plus this.
struct AssertRunPlan<'a> {
    spec: &'a AssertionPolicySpec,
    occurrence_roles: Vec<OccurrenceRole>,
    candidate_roles: Vec<OccurrenceRole>,
    value_origin_roles: Vec<OccurrenceRole>,
    binding_row_roles: Vec<OccurrenceRole>,
    origin_shape_asserts: Vec<&'a OriginShapeAssert>,
    needs_generation: bool,
    needs_declaration_state: bool,
    needs_identity_producers: bool,
    execute_row_query: AssertRowQueryExecutor,
    severity: FindingSeverity,
    message: String,
    classification: super::super::classification::FindingClassification,
}

impl<'a> AssertRunPlan<'a> {
    /// Derive the plan, or state why this policy cannot be evaluated at all.
    fn build(
        policy: &'a LoadedPolicy,
        spec: &'a AssertionPolicySpec,
    ) -> Result<Self, &'static str> {
        // Every family needs the occurrence rows, not only the occurrence
        // family: an assert about how a token resolves does not apply to a
        // token that is not an occurrence of its role at all, and "the assert
        // does not apply here" must be distinguishable from "the resolver
        // recorded no trace".
        let mut occurrence_roles = asserted_roles(spec, |_| true);
        // The canonical and route families join a *second* capture to
        // occurrence rows, so those roles must be derived (and their adapter
        // gaps reported) exactly like the primary ones.
        for assertion in &spec.asserts {
            match assertion {
                PolicyAssert::Canonical(assertion) => occurrence_roles.push(assertion.equals_role),
                PolicyAssert::Route(assertion) => occurrence_roles.push(assertion.to_role),
                // Origin-shape reports role() as None so the generic anchor
                // gates stay out of its way; its iterable join still needs the
                // role's occurrence and binding rows.
                PolicyAssert::OriginShape(assertion) => occurrence_roles.push(assertion.role),
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
        let value_origin_roles = asserted_roles(spec, |assertion| {
            matches!(assertion, PolicyAssert::ValueOrigin(_))
        });
        // Both families read the same binding-of rows, keyed by the role each
        // assert names. The value-origin family needs one more role --
        // `value_reference`, the class an assignment's left operand carries --
        // but only for a file that actually has an assignment inside a
        // subject's region. That is decided per file, after the assignment
        // query runs.
        let mut binding_row_roles = asserted_roles(spec, |assertion| {
            matches!(
                assertion,
                PolicyAssert::BindingScope(_) | PolicyAssert::ValueOrigin(_)
            )
        });
        for assertion in &spec.asserts {
            if let PolicyAssert::OriginShape(assertion) = assertion {
                binding_row_roles.push(assertion.role);
            }
        }
        binding_row_roles.sort();
        binding_row_roles.dedup();
        let origin_shape_asserts: Vec<&OriginShapeAssert> = spec
            .asserts
            .iter()
            .filter_map(|assertion| match assertion {
                PolicyAssert::OriginShape(assertion) => Some(assertion),
                _ => None,
            })
            .collect();
        let needs_occurrence_targets = spec.asserts.iter().any(|assertion| {
            matches!(assertion, PolicyAssert::Occurrence(assertion) if assertion.require_target)
        });
        let execute_row_query: AssertRowQueryExecutor = if needs_occurrence_targets {
            execute_code_query_detailed_eager_index
        } else {
            execute_code_query_detailed_eager_index_without_targets
        };
        let metadata = &policy.definition().metadata;
        let PolicyMessageSpec::Static { text } = &metadata.message else {
            return Err("assertion policy presentation could not be projected into a finding");
        };
        let Ok(classification) = reduce_finding_classification(
            policy.definition().classification.as_ref(),
            ClassificationProjection::assertion_finding(),
            None,
        ) else {
            return Err("assertion policy classification could not be reduced");
        };
        Ok(Self {
            spec,
            occurrence_roles,
            candidate_roles,
            value_origin_roles,
            binding_row_roles,
            origin_shape_asserts,
            needs_generation: spec
                .asserts
                .iter()
                .any(|assertion| matches!(assertion, PolicyAssert::Generation(_))),
            needs_declaration_state: spec
                .asserts
                .iter()
                .any(|assertion| matches!(assertion, PolicyAssert::DeclarationState(_))),
            needs_identity_producers: spec.asserts.iter().any(|assertion| {
                matches!(
                    assertion,
                    PolicyAssert::Canonical(_)
                        | PolicyAssert::Route(_)
                        | PolicyAssert::RoundTrip(_)
                )
            }),
            execute_row_query,
            severity: finding_severity(&metadata.severity, None),
            message: text.clone(),
            classification,
        })
    }

    /// Whether this policy states a property of a file set rather than of its
    /// subject rows.
    ///
    /// The termination family anchors on the min-by-(path, span) subject across
    /// the whole run and, with no scope, enumerates the workspace, so no
    /// per-file partition of it exists: a policy containing one is evaluated
    /// whole.
    fn asserts_over_a_file_set(spec: &AssertionPolicySpec) -> bool {
        spec.asserts
            .iter()
            .any(|assertion| matches!(assertion, PolicyAssert::RewriteTermination(_)))
    }

    fn presentation<'p>(&'p self, policy: &'p LoadedPolicy) -> AssertionFindingPresentation<'p> {
        AssertionFindingPresentation {
            policy,
            policy_id: &policy.definition().metadata.id,
            severity: self.severity,
            message: &self.message,
            classification: &self.classification,
        }
    }
}

/// The four memo caches an assert-file iteration reads through.
///
/// Every one of them is a memo keyed by a declaration, a file or a path -- an
/// answer that does not depend on which files were asked about before -- so a
/// unit that starts with empty caches computes exactly what a whole run's
/// shared caches would have answered. That is what lets a sliced run give each
/// unit its own set.
struct AssertFileCaches<'a> {
    identity: Option<IdentityAssertSupport>,
    edge: EdgeAssertContext<'a>,
    flow: FlowStateAssertContext<'a>,
}

impl<'a> AssertFileCaches<'a> {
    fn new(
        plan: &AssertRunPlan<'_>,
        context: &'a PolicyEvaluationContext<'a>,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Self {
        Self {
            identity: plan
                .needs_identity_producers
                .then(|| IdentityAssertSupport::new(context.analyzer)),
            edge: EdgeAssertContext::new(context.analyzer, context.cancellation),
            flow: FlowStateAssertContext::new(
                context.workspace,
                context.cancellation,
                active_semantic_model_snapshot,
            ),
        }
    }
}

/// Why one assert-file iteration could not conclude, and what the run reports
/// when it does not.
///
/// Three shapes, because the three failures state different things: a plan
/// error reports no findings and no work at all, a failed row query reports the
/// typed reason its execution gave, and a projection failure reports every
/// finding the run had assembled including this file's.
enum AssertFileFailure {
    QueryPlan(&'static str),
    Run {
        reason: PolicyFailureReason,
        message: String,
        work: CodeQueryExecutionWork,
    },
    Projection {
        message: &'static str,
        findings: Vec<PolicyFinding>,
        work: CodeQueryExecutionWork,
    },
}

/// What the per-file iterations contribute to the run.
///
/// One accumulator per thing the run finishes with, filled in path order.
/// A sliced run fills it from published products and a whole run from products
/// it just computed; neither can tell the difference, which is the whole claim.
struct AssertionRunTotals {
    findings: Vec<PolicyFinding>,
    unconcluded_files: Vec<(String, Vec<PolicyIncompleteReason>)>,
    row_completions: Vec<CodeQueryCompletion>,
    query_diagnostics: Vec<CodeQueryDiagnostic>,
    work: CodeQueryExecutionWork,
}

impl AssertionRunTotals {
    /// The totals a run starts from: what the subject query itself cost and
    /// said.
    fn of_subject(rows: &ExecutedQueryRows) -> Self {
        Self {
            findings: Vec::new(),
            unconcluded_files: Vec::new(),
            row_completions: Vec::new(),
            query_diagnostics: rows.diagnostics.clone(),
            work: rows.work,
        }
    }

    /// Merge one file's product, exactly as the per-file loop appended it.
    fn merge(&mut self, path: &str, product: AssertFileProduct) {
        debug_assert!(
            product.findings.is_empty() || product.unconcluded.is_empty(),
            "a file that could not be concluded reports no findings"
        );
        self.findings.extend(product.findings);
        if !product.unconcluded.is_empty() {
            self.unconcluded_files
                .push((path.to_string(), product.unconcluded));
        }
        self.row_completions.extend(product.row_completions);
        self.query_diagnostics.extend(product.diagnostics);
        self.work = self.work.saturating_add(product.work);
    }
}

/// The run-level values every subject file's iteration reads.
struct AssertionRun<'a> {
    plan: AssertRunPlan<'a>,
    subjects: Vec<AssertionSubject>,
    subject_diagnostics: Vec<CodeQueryDiagnostic>,
    subject_completion: CodeQueryCompletion,
    files_by_rel: HashMap<String, brokk_bifrost_analysis::analyzer::ProjectFile>,
}

impl<'a> AssertionRun<'a> {
    /// This run's subject files, in path order, each with the subject rows it
    /// carries.
    ///
    /// Sorted because the merge appends in this order and two runs that walked
    /// the files differently would assemble the same findings into different
    /// reports.
    fn subjects_by_path(&self) -> Vec<(&str, Vec<&AssertionSubject>)> {
        let mut by_path: HashMap<&str, Vec<&AssertionSubject>> = HashMap::new();
        for subject in &self.subjects {
            by_path
                .entry(subject.path.as_str())
                .or_default()
                .push(subject);
        }
        let mut paths = by_path.keys().copied().collect::<Vec<_>>();
        paths.sort_unstable();
        paths
            .into_iter()
            .map(|path| {
                let subjects = by_path
                    .remove(path)
                    .expect("every listed path has subjects");
                (path, subjects)
            })
            .collect()
    }
}

pub(super) fn evaluate_assertion_policy(
    policy: &LoadedPolicy,
    spec: &AssertionPolicySpec,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
) -> Result<PolicyRun, PolicyRunError> {
    if let Some(plan) = &spec.relational {
        // A relational plan is sliced by its own bindings, and records its own
        // reuse review while doing it.
        return evaluate_relational_assertion_policy(policy, plan, context, budget);
    }
    let subject_query = match assertion_subject_query(policy, budget) {
        Ok(query) => query,
        Err(message) => {
            return failed_policy_run(policy, PolicyAnalysisType::Assertion, message, budget);
        }
    };

    let Some(incremental) = context.incremental else {
        return whole_assertion_run(
            policy,
            spec,
            &subject_query,
            context,
            budget,
            active_semantic_model_snapshot,
        );
    };
    let mut attempt = UnitAttempt::default();
    let sliced = sliced_assertion_run(
        policy,
        spec,
        &subject_query,
        incremental,
        context,
        budget,
        active_semantic_model_snapshot.clone(),
        &mut attempt,
    );
    let (run, reason) = match sliced {
        Ok(run) => (run, None),
        Err(reason) => (
            whole_assertion_run(
                policy,
                spec,
                &subject_query,
                context,
                budget,
                active_semantic_model_snapshot,
            ),
            Some(reason),
        ),
    };
    let review = attempt.into_run(policy.definition().metadata.id.clone(), reason);
    note_incremental_run(&review, incremental);
    incremental.record_run(review);
    run
}

/// The exact query an assertion policy's subject selector executes.
///
/// Every path an assertion policy takes -- one whole execution, or one per seed
/// file -- runs this query and no other, so a sliced run and a whole run cannot
/// differ by their result detail or their row limit.
fn assertion_subject_query(
    policy: &LoadedPolicy,
    budget: &PolicyBudget,
) -> Result<CodeQuery, &'static str> {
    let Some(selector) = policy
        .resolved_selectors()
        .iter()
        .find(|selector| selector.path.as_str() == ASSERTION_SUBJECT_SELECTOR_PATH)
    else {
        return Err("resolved assertion policy is missing /analysis/subject");
    };
    let Some((_, query)) = selector.as_query() else {
        return Err("assertion subjects require a query selector; row selectors are endpoint-only");
    };
    let mut subject_query = query.clone();
    subject_query.result_detail = CodeQueryResultDetail::Full;
    subject_query.limit = budget.query_limits().max_pipeline_rows;
    Ok(subject_query)
}

/// Evaluate one assertion policy as the merge of its units.
///
/// Two unit kinds, and the same algorithm for both. The subject selector is a
/// query like any other, so it runs through the shared per-seed-file path; each
/// subject file is then an assert unit keyed by that file, its blob, and the
/// digest of the subject rows it asserts over, whose product is one iteration
/// of the per-file loop. The merge appends products in path order into the same
/// accumulators a whole run fills, and the run finishes identically.
///
/// `Err` is the demand to evaluate the whole policy instead, with the reason
/// that demand exists.
#[allow(clippy::too_many_arguments)]
fn sliced_assertion_run(
    policy: &LoadedPolicy,
    spec: &AssertionPolicySpec,
    subject_query: &CodeQuery,
    incremental: &PolicyIncrementalContext<'_>,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    attempt: &mut UnitAttempt,
) -> Result<Result<PolicyRun, PolicyRunError>, WidenReason> {
    // The termination family states a property of a file set: it anchors on the
    // min-by-(path, span) subject across the whole run and, with no scope,
    // enumerates the workspace. No per-file partition of that exists, so a
    // policy containing one is evaluated whole.
    if AssertRunPlan::asserts_over_a_file_set(spec) {
        return Err(WidenReason::WholePolicyFamily);
    }

    let limits = budget.query_limits();
    let workspace_files = context.analyzer.analyzed_files();
    let execution = UnitQueryExecution {
        analyzer: context.analyzer,
        // The whole subject execution is analyzer-only, so its units are too.
        workspace: None,
        cancellation: context.cancellation,
        limits,
        workspace_files: &workspace_files,
    };
    let mut reuse = UnitReuse::new(policy, incremental, budget);
    let subject_units = sliced_query_units(
        policy,
        subject_query,
        &mut reuse,
        &execution,
        SeedPartition::seed,
        attempt,
    )?;
    let rows = ExecutedQueryRows::of_merged(subject_units.merged);
    let run = match assertion_run(policy, spec, &rows, context) {
        Ok(run) => run,
        Err(refusal) => return Ok(refusal.into_run(policy, budget)),
    };

    // Every unit key this policy will ask about, in one batch before the first
    // lookup, exactly as the query path prefetches its own.
    let subjects_by_path = run.subjects_by_path();
    let files_by_rel = analyzed_files_by_rel_path(context);
    let mut keys = subject_units.keys;
    let mut assert_keys = Vec::with_capacity(subjects_by_path.len());
    for (path, file_subjects) in &subjects_by_path {
        let Some(file) = files_by_rel.get(*path) else {
            // A subject row named a path the head does not analyze, so there is
            // no content identity to key its unit by.
            return Err(WidenReason::ReverseDependencyEvidenceMissing);
        };
        let language = language_for_file(file);
        let Some(blob) = incremental.changed().head_blob(language, path) else {
            return Err(WidenReason::ReverseDependencyEvidenceMissing);
        };
        assert_keys.push(incremental.inputs().unit_key(
            policy,
            UnitPartition::AssertFile {
                language,
                rel_path: Box::from(*path),
                blob,
                subjects: subject_rows_digest(&rows, file_subjects.len(), path),
            },
        ));
    }
    attempt.enumerated(assert_keys.len());
    reuse.prefetch(&assert_keys)?;

    let mut totals = AssertionRunTotals::of_subject(&rows);
    let presentation = run.plan.presentation(policy);
    for ((path, file_subjects), key) in subjects_by_path.iter().zip(assert_keys.iter()) {
        let product = match reuse.published(key)? {
            Some(product) => {
                attempt.reused();
                let Some(product) = product.into_assert_file() else {
                    // One key names one product shape; anything else is a store
                    // that answered a different question.
                    return Err(WidenReason::ProductLoadFailed);
                };
                check_exhaustive_assert_file(&product)?;
                product
            }
            None => {
                attempt.recomputed();
                // Each unit gets its own caches. Every one of them is a memo
                // keyed by a declaration, a file or a path, so starting empty
                // computes exactly what a whole run's shared caches would have
                // answered; only the memo hits are lost.
                let mut caches = AssertFileCaches::new(
                    &run.plan,
                    context,
                    active_semantic_model_snapshot.clone(),
                );
                let (product, reads) = recompute_unit(context.analyzer, || {
                    evaluate_assert_file(
                        path,
                        file_subjects,
                        &run.plan,
                        &presentation,
                        &run.subject_diagnostics,
                        &run.files_by_rel,
                        &mut caches,
                        context,
                        budget,
                    )
                });
                let product = match product {
                    Ok(product) => product,
                    // A file that cannot be evaluated fails the whole run,
                    // exactly as it does today; it is not a widening.
                    Err(failure) => {
                        return Ok(assert_file_failure_run(
                            policy,
                            *failure,
                            &mut totals,
                            budget,
                        ));
                    }
                };
                let Some(reads) = reads else {
                    attempt.unbounded();
                    return Err(WidenReason::UnitUnbounded);
                };
                check_exhaustive_assert_file(&product)?;
                reuse.publish(
                    key.clone(),
                    PolicyUnitProduct::AssertFile(product.clone()),
                    reads,
                );
                product
            }
        };
        totals.merge(path, product);
    }

    keys.extend(assert_keys);
    // Every unit of this policy is published and merged, so this list is what
    // another run replays to reproduce the product without executing anything.
    incremental.record_units(policy.definition().metadata.id.clone(), keys);
    Ok(finish_assertion_run(
        policy,
        &run.subject_completion,
        totals,
        budget,
    ))
}

/// A published assert unit is a partition of a whole run only when its own
/// iteration concluded cleanly.
///
/// A file whose row queries raised a diagnostic is one whose capability gaps
/// the run reports, and diagnostics are not additive across partitions; a file
/// the run could not conclude is a legitimate product and merges, because the
/// whole run records exactly the same unconcluded entry for it.
fn check_exhaustive_assert_file(product: &AssertFileProduct) -> Result<(), WidenReason> {
    if product.diagnostics.is_empty() {
        return Ok(());
    }
    Err(WidenReason::UnitDiagnostics)
}

/// The digest of one file's subject rows, as the assert unit's key carries it.
///
/// The rows themselves, in the order the merge produced them: a subject
/// selector that bound different rows in the same bytes asked a different
/// question of the same file, and the digest is what makes that a different
/// unit rather than a wrong answer.
fn subject_rows_digest(
    rows: &ExecutedQueryRows,
    expected: usize,
    path: &str,
) -> brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest {
    let mut digested = 0_usize;
    let mut material = String::new();
    for (item, evidence) in rows.items.iter().zip(&rows.evidence) {
        if evidence.rel_path.as_ref() != path {
            continue;
        }
        digested += 1;
        material.push_str(
            &serde_json::to_string(&(item, evidence))
                .expect("a projected subject row renders as canonical JSON"),
        );
        material.push('\u{1}');
    }
    assert_eq!(
        digested, expected,
        "every subject of `{path}` is one of its own file's rows"
    );
    brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest::sha256(material)
}

/// Every analyzed file of the head, by its workspace-relative path.
///
/// A sliced run needs one for every subject path -- the language and the blob
/// its unit is keyed by -- which is a different question from the
/// declaration-state family's map and is computed whether or not that family
/// runs.
fn analyzed_files_by_rel_path(
    context: &PolicyEvaluationContext<'_>,
) -> HashMap<String, brokk_bifrost_analysis::analyzer::ProjectFile> {
    context
        .analyzer
        .analyzed_files()
        .into_iter()
        .map(|file| (workspace_relative_key(&file), file))
        .collect()
}

/// Evaluate one assertion policy over the whole workspace.
fn whole_assertion_run(
    policy: &LoadedPolicy,
    spec: &AssertionPolicySpec,
    subject_query: &CodeQuery,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
) -> Result<PolicyRun, PolicyRunError> {
    let rows = ExecutedQueryRows::of_detailed(execute_code_query_detailed_eager_index(
        context.analyzer,
        subject_query,
        budget.query_limits(),
        context.cancellation,
    ));
    let run = match assertion_run(policy, spec, &rows, context) {
        Ok(run) => run,
        Err(refusal) => return refusal.into_run(policy, budget),
    };

    let mut totals = AssertionRunTotals::of_subject(&rows);
    let presentation = run.plan.presentation(policy);
    let mut caches = AssertFileCaches::new(&run.plan, context, active_semantic_model_snapshot);
    for (path, file_subjects) in run.subjects_by_path() {
        match evaluate_assert_file(
            path,
            &file_subjects,
            &run.plan,
            &presentation,
            &run.subject_diagnostics,
            &run.files_by_rel,
            &mut caches,
            context,
            budget,
        ) {
            Ok(product) => totals.merge(path, product),
            Err(failure) => {
                return assert_file_failure_run(policy, *failure, &mut totals, budget);
            }
        }
    }

    let mut rewrite_assert_context =
        RewriteAssertContext::new(context.analyzer, context.cancellation);
    // The termination family states a property of a *file set*, not of one
    // captured node, so it is evaluated once per run rather than once per
    // subject row, and one assert produces at most one finding: "these chases
    // cycle" is a single statement whose evidence is an ordered list, not one
    // finding per offending import. Its accounting joins the same per-file
    // ledger every other family uses, so an unreliable file degrades exactly
    // itself.
    for assertion in &run.plan.spec.asserts {
        let PolicyAssert::RewriteTermination(assertion) = assertion else {
            continue;
        };
        let work = work_report(totals.work, totals.findings.len(), 0);
        // The finding is anchored at a subject row, exactly as every other
        // family's is: an assertion finding's identity is its subject node,
        // and the offending chases are stated as evidence beside it. The
        // deterministic choice is the first subject in path order.
        let anchor_subject = run
            .subjects
            .iter()
            .filter(|subject| {
                assertion
                    .scope
                    .as_ref()
                    .is_none_or(|capture| subject.captures.contains_key(capture))
            })
            .min_by_key(|subject| {
                (
                    subject.path.as_str(),
                    subject
                        .location
                        .byte_span()
                        .map_or(u64::MAX, |span| span.start()),
                )
            });
        let files = match &assertion.scope {
            // Without a scope the assert is about the domain itself, which is
            // a workspace property: the mined regression was a chase over the
            // workspace's own imports, not over a captured token.
            None => rewrite_assert_context.workspace_files().to_vec(),
            Some(capture) => {
                let mut paths = run
                    .subjects
                    .iter()
                    .filter(|subject| subject.captures.contains_key(capture))
                    .map(|subject| subject.path.as_str())
                    .collect::<Vec<_>>();
                if paths.is_empty() {
                    return failed_policy_run_with_reason(
                        policy,
                        PolicyAnalysisType::Assertion,
                        std::mem::take(&mut totals.findings),
                        PolicyFailureReason::InvalidExecutionPlan,
                        &format!(
                            "assert `{}` scopes to capture `{}`, which the subject selector does not bind anywhere",
                            assertion.id, capture
                        ),
                        work,
                        budget,
                    );
                }
                paths.sort_unstable();
                paths.dedup();
                paths
                    .into_iter()
                    .map(|path| {
                        ProjectFile::new(
                            context.analyzer.project().root().to_path_buf(),
                            path.to_string(),
                        )
                    })
                    .collect()
            }
        };

        let mut cycles: Vec<String> = Vec::new();
        let mut origins: Vec<PolicySourceLocation> = Vec::new();
        for file in files {
            let derived = rewrite_assert_context.for_file(&file);
            let key = workspace_relative_key(&file);
            if !derived.completeness.covers(assertion.domain) {
                totals.unconcluded_files.push((
                    key,
                    derived
                        .completeness
                        .reasons()
                        .iter()
                        .map(|reason| match reason {
                            RewritePathIncompleteReason::Cancelled => {
                                PolicyIncompleteReason::Cancelled
                            }
                            RewritePathIncompleteReason::NoDomainAnalyzer(_)
                            | RewritePathIncompleteReason::NoIndexedSource => {
                                PolicyIncompleteReason::CapabilityIncomplete
                            }
                        })
                        .collect(),
                ));
                continue;
            }
            for path in derived
                .paths
                .iter()
                .filter(|path| path.domain == assertion.domain)
            {
                match termination_verdict(&path.outcome) {
                    TerminationVerdict::Satisfied => continue,
                    // Absence of evidence: the chase stopped without deciding,
                    // so this file concludes nothing in either direction. It
                    // is never a finding and never a pass.
                    TerminationVerdict::Inconclusive => {
                        totals
                            .unconcluded_files
                            .push((key.clone(), vec![PolicyIncompleteReason::PartialDiscovery]));
                        continue;
                    }
                    TerminationVerdict::Counterexample => {}
                }
                let witness = path.outcome.witness();
                cycles.push(format!(
                    "the chase from `{}` at {}:{} repeats a semantic state; witness: {} (declared bound {}, {} step(s))",
                    path.origin.specifier,
                    key,
                    path.origin.range.start_line,
                    witness.join(" -> "),
                    path.declared_bound,
                    path.steps.len(),
                ));
                if let Ok(origin_path) = WorkspaceRelativePath::new(key.as_str()) {
                    origins.push(PolicySourceLocation::artifact(origin_path));
                } else {
                    return failed_policy_run_with_reason(
                        policy,
                        PolicyAnalysisType::Assertion,
                        std::mem::take(&mut totals.findings),
                        PolicyFailureReason::InternalInvariant,
                        "a rewrite origin could not be projected into a workspace-relative path",
                        work,
                        budget,
                    );
                }
            }
        }

        if cycles.is_empty() {
            continue;
        }
        // Nothing to anchor the finding to: the subject selector chose no row
        // this assert applies to, which is the same vacuous shape every other
        // family has and not a verdict of its own.
        let Some(anchor_subject) = anchor_subject else {
            continue;
        };
        let count = u64::try_from(cycles.len()).unwrap_or(u64::MAX);
        let anchor = super::super::finding_identity::AssertionFindingAnchor::new(
            anchor_subject.path.clone(),
            assertion
                .scope
                .as_ref()
                .and_then(|capture| anchor_subject.ast_ids(capture))
                .and_then(|ids| ids.first().copied())
                .unwrap_or(""),
            assertion.id.as_str(),
        );
        let Ok(evidence) = super::super::finding::AssertionFindingEvidence::try_new(
            anchor,
            "rewrite_termination",
            "declaration",
            "rewrite_path",
            assertion.expectation(),
            Some(cycles.join("; ")),
            count,
            // This family reads no occurrence rows, so there is no adapter
            // role gap for it to report.
            Vec::new(),
        ) else {
            return failed_policy_run_with_reason(
                policy,
                PolicyAnalysisType::Assertion,
                std::mem::take(&mut totals.findings),
                PolicyFailureReason::InternalInvariant,
                "a violated assertion could not be projected into validated policy evidence",
                work,
                budget,
            );
        };
        let Ok(related) = std::iter::once((
            PolicyLocationRelationship::Subject,
            anchor_subject.location.clone(),
        ))
        .chain(
            origins
                .into_iter()
                .map(|origin| (PolicyLocationRelationship::Evidence, origin)),
        )
        .map(|(relationship, location)| {
            RelatedPolicyLocation::try_new(relationship, location, Vec::new())
        })
        .collect::<Result<Vec<_>, _>>() else {
            return failed_policy_run_with_reason(
                policy,
                PolicyAnalysisType::Assertion,
                std::mem::take(&mut totals.findings),
                PolicyFailureReason::InternalInvariant,
                "an evidence row could not be projected into a related policy location",
                work,
                budget,
            );
        };
        match presentation.assemble(
            anchor_subject.location.clone(),
            related,
            false,
            0,
            evidence,
            budget,
        ) {
            Ok(finding) => totals.findings.push(finding),
            Err(()) => {
                return failed_policy_run_with_reason(
                    policy,
                    PolicyAnalysisType::Assertion,
                    std::mem::take(&mut totals.findings),
                    PolicyFailureReason::InternalInvariant,
                    "a validated assertion violation could not be retained as a finding",
                    work,
                    budget,
                );
            }
        }
    }
    finish_assertion_run(policy, &run.subject_completion, totals, budget)
}

/// Everything one run computes between its subject rows and its per-file
/// iterations, or the refusal that stops it.
fn assertion_run<'a>(
    policy: &'a LoadedPolicy,
    spec: &'a AssertionPolicySpec,
    rows: &ExecutedQueryRows,
    context: &PolicyEvaluationContext<'_>,
) -> Result<AssertionRun<'a>, Box<AssertionRunRefusal>> {
    // Subject discovery is the one run-level completeness question left: if the
    // selector could not enumerate its subjects, the evaluator does not even
    // know which files it failed to consider, so per-file attribution is
    // impossible by construction and the whole run is inconclusive.
    let run_failures = failure_reasons(&rows.completion);
    let subject_incomplete = incomplete_reasons(&rows.completion, rows.truncated);
    let subjects = match collect_assertion_subjects(&rows.items, &rows.evidence) {
        Ok(subjects) => subjects,
        Err(message) => return Err(Box::new(AssertionRunRefusal::Failed(message))),
    };
    if !run_failures.is_empty() {
        return Err(Box::new(AssertionRunRefusal::QueryFailed {
            reason: run_failures[0],
            work: rows.work,
        }));
    }
    if !subject_incomplete.is_empty() {
        return Err(Box::new(AssertionRunRefusal::SubjectsIncomplete {
            reasons: subject_incomplete,
            work: rows.work,
        }));
    }
    let plan = match AssertRunPlan::build(policy, spec) {
        Ok(plan) => plan,
        Err(message) => return Err(Box::new(AssertionRunRefusal::Failed(message))),
    };
    // Declaration-state rows are derived directly rather than queried: no seed
    // spans the whole state family, and the rows joined here are exact
    // per-declaration facts whose completeness the derivation itself states.
    let files_by_rel = if plan.needs_declaration_state {
        context
            .analyzer
            .analyzed_files()
            .into_iter()
            .map(|file| (workspace_relative_key(&file), file))
            .collect()
    } else {
        HashMap::new()
    };
    Ok(AssertionRun {
        plan,
        subjects,
        subject_diagnostics: rows.diagnostics.clone(),
        subject_completion: rows.completion.clone(),
        files_by_rel,
    })
}

/// Why a run stopped before it evaluated a single file.
enum AssertionRunRefusal {
    Failed(&'static str),
    QueryFailed {
        reason: PolicyFailureReason,
        work: CodeQueryExecutionWork,
    },
    SubjectsIncomplete {
        reasons: Vec<PolicyIncompleteReason>,
        work: CodeQueryExecutionWork,
    },
}

impl AssertionRunRefusal {
    fn into_run(
        self,
        policy: &LoadedPolicy,
        budget: &PolicyBudget,
    ) -> Result<PolicyRun, PolicyRunError> {
        match self {
            Self::Failed(message) => {
                failed_policy_run(policy, PolicyAnalysisType::Assertion, message, budget)
            }
            Self::QueryFailed { reason, work } => failed_policy_run_with_reason(
                policy,
                PolicyAnalysisType::Assertion,
                Vec::new(),
                reason,
                "assertion evaluation could not execute a valid query plan",
                work_report(work, 0, 0),
                budget,
            ),
            Self::SubjectsIncomplete { reasons, work } => inconclusive_policy_run_many(
                policy,
                PolicyAnalysisType::Assertion,
                reasons,
                "assertion evaluation could not observe a complete row set",
                work_report(work, 0, 0),
                budget,
            ),
        }
    }
}

/// The failed run one refused assert-file iteration produces.
fn assert_file_failure_run(
    policy: &LoadedPolicy,
    failure: AssertFileFailure,
    totals: &mut AssertionRunTotals,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    match failure {
        AssertFileFailure::QueryPlan(message) => {
            failed_policy_run(policy, PolicyAnalysisType::Assertion, message, budget)
        }
        AssertFileFailure::Run {
            reason,
            message,
            work,
        } => failed_policy_run_with_reason(
            policy,
            PolicyAnalysisType::Assertion,
            Vec::new(),
            reason,
            &message,
            work_report(totals.work.saturating_add(work), 0, 0),
            budget,
        ),
        AssertFileFailure::Projection {
            message,
            findings,
            work,
        } => {
            let charged = totals.work.saturating_add(work);
            let mut assembled = std::mem::take(&mut totals.findings);
            assembled.extend(findings);
            failed_policy_run_with_reason(
                policy,
                PolicyAnalysisType::Assertion,
                assembled,
                PolicyFailureReason::InternalInvariant,
                message,
                work_report(charged, 0, 0),
                budget,
            )
        }
    }
}

/// Assemble the run every assertion evaluation ends with.
fn finish_assertion_run(
    policy: &LoadedPolicy,
    subject_completion: &CodeQueryCompletion,
    totals: AssertionRunTotals,
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    let adapted = adapt_query_diagnostics(&totals.query_diagnostics, budget.max_diagnostics());
    let mut diagnostics = adapted.diagnostics;
    let mut diagnostics_truncated = adapted.truncated;
    let mut run_incomplete: Vec<PolicyIncompleteReason> = totals
        .unconcluded_files
        .iter()
        .flat_map(|(_, reasons)| reasons.iter().copied())
        .collect();
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
    if !totals.unconcluded_files.is_empty() {
        retain_unconcluded_files_diagnostic(
            &totals.unconcluded_files,
            &mut diagnostics,
            &mut diagnostics_truncated,
            budget.max_diagnostics(),
        );
    }
    run_incomplete.sort();
    run_incomplete.dedup();

    let completion = if run_incomplete.is_empty() {
        let mut completion = PolicyRunCompletion::Complete;
        if let CodeQueryCompletion::ProvenSubset { codes } = &subject_completion {
            completion = PolicyRunCompletion::proven_subset(codes.clone())
                .expect("the detailed subject query declared at least one non-exhaustive omission");
        } else {
            for row_completion in &totals.row_completions {
                if let CodeQueryCompletion::ProvenSubset { codes } = row_completion {
                    completion = PolicyRunCompletion::proven_subset(codes.clone()).expect(
                        "a detailed row query declared at least one non-exhaustive omission",
                    );
                    break;
                }
            }
        }
        completion
    } else {
        PolicyRunCompletion::inconclusive(run_incomplete)
            .expect("typed per-file incomplete reasons are canonical")
    };
    let work = work_report(totals.work, totals.findings.len(), 0);
    finish_assembled_run(
        policy,
        PolicyAnalysisType::Assertion,
        completion,
        totals.findings,
        diagnostics,
        diagnostics_truncated,
        work,
        "assertion evaluation produced an invalid policy run",
        budget,
    )
}

/// Evaluate one subject file's row families and asserts.
///
/// This is one iteration of the per-file loop, and it is a pure function of its
/// inputs plus the memo caches: the file's subject slice, the run-level plan,
/// and the caches, which are memos rather than accumulators. That is what makes
/// a subject file an evaluation unit -- the same inputs give the same product,
/// whichever run computes it and whatever order the files were walked in.
#[allow(clippy::too_many_arguments)]
fn evaluate_assert_file(
    path: &str,
    file_subjects: &[&AssertionSubject],
    plan: &AssertRunPlan<'_>,
    presentation: &AssertionFindingPresentation<'_>,
    subject_diagnostics: &[CodeQueryDiagnostic],
    files_by_rel: &HashMap<String, brokk_bifrost_analysis::analyzer::ProjectFile>,
    caches: &mut AssertFileCaches<'_>,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
) -> Result<AssertFileProduct, Box<AssertFileFailure>> {
    let mut file_work = CodeQueryExecutionWork::default();
    let mut file_failures: Vec<PolicyFailureReason> = Vec::new();
    let mut file_diagnostics: Vec<CodeQueryDiagnostic> = Vec::new();
    let mut row_completions: Vec<CodeQueryCompletion> = Vec::new();
    let file_paths = [path];
    let mut file_incomplete: Vec<PolicyIncompleteReason> = Vec::new();

    // The assignment family runs *before* the other row families, because
    // its answer decides whether they need the `value_reference` role at
    // all. Only an assignment written inside a region some value-origin
    // assert compares against can exempt anything, so a file with none --
    // which is most files -- never pays for reaching a binding from every
    // plain value position in it. The verdict is unchanged either way:
    // with no in-region assignment the exemption is false for every
    // subject, which is exactly what the skipped rows would have said.
    let mut assignment_outcome = None;
    if !plan.value_origin_roles.is_empty() {
        let query = match assertion_assignment_query(&file_paths, budget) {
            Ok(query) => query,
            Err(message) => {
                return Err(Box::new(AssertFileFailure::QueryPlan(message)));
            }
        };
        let outcome = (plan.execute_row_query)(
            context.analyzer,
            &query,
            budget.query_limits(),
            context.cancellation,
        );
        file_incomplete.extend(incomplete_reasons(
            &outcome.result.completion(),
            outcome.result.truncated,
        ));
        file_failures.extend(failure_reasons(&outcome.result.completion()));
        file_diagnostics.extend(outcome.result.diagnostics.iter().cloned());
        file_work = file_work.saturating_add(outcome.work);
        row_completions.push(outcome.result.completion());
        assignment_outcome = Some(outcome);
    }
    let value_origin_regions = value_origin_regions(plan.spec, file_subjects);
    let assignments_in_region = assignment_outcome.as_ref().is_some_and(|outcome| {
        assigned_left_operands(&outcome.result.results)
            .any(|(_, range)| region_contains_any(&value_origin_regions, range))
    });
    let mut binding_row_roles = plan.binding_row_roles.clone();
    if assignments_in_region {
        binding_row_roles.push(OccurrenceRole::ValueReference);
        binding_row_roles.sort();
        binding_row_roles.dedup();
    }

    let mut queries: Vec<CodeQuery> = Vec::new();
    if !plan.occurrence_roles.is_empty() {
        match assertion_occurrence_query(&file_paths, &plan.occurrence_roles, Vec::new(), budget) {
            Ok(query) => queries.push(query),
            Err(message) => {
                return Err(Box::new(AssertFileFailure::QueryPlan(message)));
            }
        }
    }
    if !plan.candidate_roles.is_empty() {
        match assertion_occurrence_query(
            &file_paths,
            &plan.candidate_roles,
            vec![QueryStep::CandidatesOf(CandidateFilter::default())],
            budget,
        ) {
            Ok(query) => queries.push(query),
            Err(message) => {
                return Err(Box::new(AssertFileFailure::QueryPlan(message)));
            }
        }
    }
    if !binding_row_roles.is_empty() {
        match assertion_occurrence_query(
            &file_paths,
            &binding_row_roles,
            vec![QueryStep::BindingOf(BindingOfOptions::default())],
            budget,
        ) {
            Ok(query) => queries.push(query),
            Err(message) => {
                return Err(Box::new(AssertFileFailure::QueryPlan(message)));
            }
        }
        match assertion_scope_query(&file_paths, budget) {
            Ok(query) => queries.push(query),
            Err(message) => {
                return Err(Box::new(AssertFileFailure::QueryPlan(message)));
            }
        }
    }

    if !plan.origin_shape_asserts.is_empty() {
        match origin_shape_iterable_query(&file_paths, budget) {
            Ok(query) => queries.push(query),
            Err(message) => {
                return Err(Box::new(AssertFileFailure::QueryPlan(message)));
            }
        }
        match origin_shape_assignment_query(&file_paths, budget) {
            Ok(query) => queries.push(query),
            Err(message) => {
                return Err(Box::new(AssertFileFailure::QueryPlan(message)));
            }
        }
        let mut maxes: Vec<u32> = plan
            .origin_shape_asserts
            .iter()
            .map(|assertion| assertion.max_elements)
            .collect();
        maxes.sort_unstable();
        maxes.dedup();
        for max in maxes {
            match origin_shape_literal_query(&file_paths, max, budget) {
                Ok(query) => queries.push(query),
                Err(message) => {
                    return Err(Box::new(AssertFileFailure::QueryPlan(message)));
                }
            }
        }
    }

    let mut executed = Vec::new();
    for query in &queries {
        let outcome = (plan.execute_row_query)(
            context.analyzer,
            query,
            budget.query_limits(),
            context.cancellation,
        );
        file_incomplete.extend(incomplete_reasons(
            &outcome.result.completion(),
            outcome.result.truncated,
        ));
        file_failures.extend(failure_reasons(&outcome.result.completion()));
        file_diagnostics.extend(outcome.result.diagnostics.iter().cloned());
        file_work = file_work.saturating_add(outcome.work);
        row_completions.push(outcome.result.completion());
        executed.push(outcome);
    }

    if plan.needs_generation {
        let query = match assertion_generation_query(&file_paths, budget) {
            Ok(query) => query,
            Err(message) => {
                return Err(Box::new(AssertFileFailure::QueryPlan(message)));
            }
        };
        let mut outcome = execute_code_query_detailed_eager_index(
            context.analyzer,
            &query,
            budget.query_limits(),
            context.cancellation,
        );
        // A dynamic generation site reports the generated-set axis
        // incomplete at query level, but here that honesty is handled per
        // row: a dynamic site makes exactly the asserts over it
        // inconclusive (or, under :forbid-dynamic, the finding), never the
        // whole file.
        outcome.result.diagnostics.retain(|diagnostic| {
            diagnostic.code != CodeQueryDiagnosticCode::MaterializationDerivationIncomplete
        });
        file_incomplete.extend(incomplete_reasons(
            &outcome.result.completion(),
            outcome.result.truncated,
        ));
        file_failures.extend(failure_reasons(&outcome.result.completion()));
        file_diagnostics.extend(outcome.result.diagnostics.iter().cloned());
        file_work = file_work.saturating_add(outcome.work);
        row_completions.push(outcome.result.completion());
        executed.push(outcome);
    }

    if !file_failures.is_empty() {
        return Err(Box::new(AssertFileFailure::Run {
            reason: file_failures[0],
            message: "assertion evaluation could not execute a valid query plan".to_string(),
            work: file_work,
        }));
    }

    let mut state_results: Vec<std::sync::Arc<MaterializationFileResult>> = Vec::new();
    if plan.needs_declaration_state {
        match files_by_rel.get(path) {
            None => file_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete),
            Some(file) => {
                let result = std::sync::Arc::new(materialization_for_file(context.analyzer, file));
                if !result
                    .completeness
                    .covers(MaterializationAxis::DeclarationState)
                {
                    file_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
                }
                state_results.push(result);
            }
        }
    }

    if file_subjects
        .iter()
        .any(|subject| !subject.captures_without_ast_id.is_empty())
    {
        file_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
    }

    // Soundness rule 1, per file: a verdict over an incomplete row set is
    // never a pass and never a finding, so this file's asserts are not
    // evaluated at all and the file is reported as unconcluded.
    if !file_incomplete.is_empty() {
        file_incomplete.sort();
        file_incomplete.dedup();
        return Ok(AssertFileProduct {
            findings: Vec::new(),
            unconcluded: file_incomplete,
            row_completions,
            diagnostics: file_diagnostics,
            work: file_work,
        });
    }

    let mut rows_by_ast_id: HashMap<&str, Vec<&CodeQueryOccurrence>> = HashMap::new();
    let mut candidates_by_ast_id: HashMap<&str, Vec<&CodeQueryResolutionCandidate>> =
        HashMap::new();
    // A binding-of answer is an answer about one occurrence, and the row
    // says which one: the join is that identity, never the binding's name.
    // The identity is path-qualified because a canonical AST id repeats
    // verbatim across files with identical content, and the binding must
    // only join occurrences of its own file.
    let mut bindings_by_occurrence: HashMap<(&str, &str), Vec<&CodeQueryBinding>> = HashMap::new();
    let mut scopes_by_index: HashMap<(&str, u32), &CodeQueryLexicalScope> = HashMap::new();
    let mut sites_by_ast_id: HashMap<&str, Vec<&CodeQueryGenerationSite>> = HashMap::new();
    // Every assignment in this file whose left operand is a named value
    // *and* is written inside a region some value-origin assert compares
    // against, as (left-operand AST id, left-operand region). Filtering
    // here rather than at each subject keeps the per-subject scan to the
    // assignments that can possibly exempt anything, and it is the same
    // predicate the assert applies.
    let assigned_positions: Vec<(&str, CodeQueryRange)> = assignment_outcome
        .as_ref()
        .map(|outcome| {
            assigned_left_operands(&outcome.result.results)
                .filter(|(_, range)| region_contains_any(&value_origin_regions, *range))
                .collect()
        })
        .unwrap_or_default();
    for query in &executed {
        for item in &query.result.results {
            match &item.value {
                CodeQueryResultValue::Occurrence { value } => rows_by_ast_id
                    .entry(value.ast_id.as_str())
                    .or_default()
                    .push(value),
                CodeQueryResultValue::ResolutionCandidate { value } => candidates_by_ast_id
                    .entry(value.ast_id.as_str())
                    .or_default()
                    .push(value),
                CodeQueryResultValue::Binding { value } => {
                    if let Some(reached_from) = value.reached_from_ast_id.as_deref() {
                        bindings_by_occurrence
                            .entry((value.path.as_str(), reached_from))
                            .or_default()
                            .push(value);
                    }
                }
                CodeQueryResultValue::LexicalScope { value } => {
                    scopes_by_index.insert((value.path.as_str(), value.index), value);
                }
                CodeQueryResultValue::GenerationSite { value } => {
                    if let Some(ast_id) = value.ast_id.as_deref() {
                        sites_by_ast_id.entry(ast_id).or_default().push(value);
                    }
                }
                _ => {}
            }
        }
    }
    // Origin-shape row material: every assignment's (left, right) capture
    // pair, and per element bound the collection-literal facts within it.
    // A right operand without an AST id is unjoinable and is kept as
    // `None`: it can establish a binding but can never prove the literal
    // shape, which is exactly the conservative direction this family
    // fails in.
    let mut origin_assignments: Vec<(&str, Option<&str>)> = Vec::new();
    let mut origin_literals: HashMap<u32, HashSet<&str>> = HashMap::new();
    // Which expression each for-each loop iterates, joined by the loop
    // node's AST identity. A loop absent from this map -- a while loop, a
    // counting for, or a for-each whose iterable carried no identity --
    // has an unknown iteration source, which the assert reports.
    let mut origin_iterables: HashMap<&str, Vec<&str>> = HashMap::new();
    for query in &executed {
        for item in &query.result.results {
            let CodeQueryResultValue::StructuralMatch { value } = &item.value else {
                continue;
            };
            let mut left: Option<&str> = None;
            let mut right: Option<Option<&str>> = None;
            let mut loop_node: Option<&str> = None;
            let mut iterable: Option<&str> = None;
            for capture in &value.captures {
                if capture.name == ORIGIN_LEFT_CAPTURE {
                    left = capture.ast_id.as_deref();
                } else if capture.name == ORIGIN_RIGHT_CAPTURE {
                    right = Some(capture.ast_id.as_deref());
                } else if capture.name == ORIGIN_LOOP_CAPTURE {
                    loop_node = capture.ast_id.as_deref();
                } else if capture.name == ORIGIN_ITERABLE_CAPTURE {
                    iterable = capture.ast_id.as_deref();
                } else if let Some(max) = capture
                    .name
                    .strip_prefix(ORIGIN_LITERAL_CAPTURE_PREFIX)
                    .and_then(|suffix| suffix.parse::<u32>().ok())
                    && let Some(ast_id) = capture.ast_id.as_deref()
                {
                    origin_literals.entry(max).or_default().insert(ast_id);
                }
            }
            if let (Some(left), Some(right)) = (left, right) {
                origin_assignments.push((left, right));
            }
            if let (Some(loop_node), Some(iterable)) = (loop_node, iterable) {
                origin_iterables
                    .entry(loop_node)
                    .or_default()
                    .push(iterable);
            }
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

    // Capability reporting on this file's findings depends on the subject
    // query plus this file's own row queries, not on gaps another file
    // surfaced.
    let mut capability_diagnostics = subject_diagnostics.to_vec();
    for query in &executed {
        capability_diagnostics.extend(query.result.diagnostics.iter().cloned());
    }
    if let Some(outcome) = assignment_outcome.as_ref() {
        capability_diagnostics.extend(outcome.result.diagnostics.iter().cloned());
    }
    let capability = assertion_capabilities(&capability_diagnostics);

    let mut file_findings: Vec<PolicyFinding> = Vec::new();
    // Soundness rule 3, per file: an input a single assert cannot conclude
    // over -- an unattributed tier, a rejection-dependent assert on a
    // selection-only trace, a missing selection -- makes this *file*
    // inconclusive with zero findings, exactly like an incomplete query.
    // The file's assembled verdicts are discarded rather than reported
    // beside an admission; other files' verdicts stand.
    let mut late_incomplete: Vec<PolicyIncompleteReason> = Vec::new();
    for subject in file_subjects.iter().copied() {
        for assertion in &plan.spec.asserts {
            // Soundness rule 2: an unbound `:at` is an authoring error,
            // never a vacuous pass.
            // The termination family is about a file set rather than one
            // captured node, so it binds no subject capture and is
            // evaluated once per run, after this loop.
            let Some(at) = assertion.at() else {
                continue;
            };
            let Some(ast_ids) = subject.ast_ids(at) else {
                return Err(Box::new(AssertFileFailure::Run {
                    reason: PolicyFailureReason::InvalidExecutionPlan,
                    message: format!(
                        "assert `{}` names capture `{}`, which the subject selector does not bind at {}",
                        assertion.id(),
                        at,
                        subject.path.as_str()
                    ),
                    work: file_work,
                }));
            };
            // A capture that carries no occurrence of the asserted role is
            // not a subject this assert is about. The occurrence family,
            // whose whole question is how many such rows exist, evaluates
            // anyway. The flow family also evaluates when the capture
            // binds a non-identifier node: its join is the state-event
            // row, and a property read anchors on the whole field access,
            // which has no identifier-occurrence row of any role (#2015).
            // An identifier capture of the wrong role stays skipped for
            // it like for every other family.
            let non_identifier_flow_subject =
                matches!(assertion, PolicyAssert::FlowEstablishment(_))
                    && subject.binds_non_identifier(at);
            if let Some(role) = assertion.role()
                && !matches!(assertion, PolicyAssert::Occurrence(_))
                && !non_identifier_flow_subject
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
                    &mut caches.edge,
                    &mut late_incomplete,
                ),
                PolicyAssert::EdgeClass(assertion) => evaluate_edge_class_assert(
                    assertion,
                    &ast_ids,
                    &rows_by_ast_id,
                    &mut caches.edge,
                    &mut late_incomplete,
                ),
                PolicyAssert::FlowEstablishment(assertion) => evaluate_flow_establishment_assert(
                    assertion,
                    subject,
                    &ast_ids,
                    &mut caches.flow,
                    &mut late_incomplete,
                ),
                // Evaluated once per run, below; the subject loop skipped
                // it at the `:at` check above.
                PolicyAssert::RewriteTermination(_) => None,
                PolicyAssert::Canonical(assertion) => match subject.ast_ids(&assertion.equals) {
                    Some(equals_ids) => evaluate_canonical_assert(
                        assertion,
                        subject,
                        &ast_ids,
                        &equals_ids,
                        caches
                            .identity
                            .as_mut()
                            .expect("identity producers exist when a canonical assert does"),
                        context,
                        &mut late_incomplete,
                    ),
                    None => {
                        return Err(Box::new(AssertFileFailure::Run {
                            reason: PolicyFailureReason::InvalidExecutionPlan,
                            message: format!(
                                "assert `{}` names capture `{}`, which the subject selector does not bind at {}",
                                assertion.id,
                                assertion.equals,
                                subject.path.as_str()
                            ),
                            work: file_work,
                        }));
                    }
                },
                PolicyAssert::Route(assertion) => match subject.ast_ids(&assertion.to) {
                    Some(to_ids) => evaluate_route_assert(
                        assertion,
                        subject,
                        &ast_ids,
                        &to_ids,
                        caches
                            .identity
                            .as_mut()
                            .expect("identity producers exist when a route assert does"),
                        context,
                        &mut late_incomplete,
                    ),
                    None => {
                        return Err(Box::new(AssertFileFailure::Run {
                            reason: PolicyFailureReason::InvalidExecutionPlan,
                            message: format!(
                                "assert `{}` names capture `{}`, which the subject selector does not bind at {}",
                                assertion.id,
                                assertion.to,
                                subject.path.as_str()
                            ),
                            work: file_work,
                        }));
                    }
                },
                PolicyAssert::RoundTrip(assertion) => evaluate_round_trip_assert(
                    assertion,
                    subject,
                    &ast_ids,
                    caches
                        .identity
                        .as_mut()
                        .expect("identity producers exist when a round-trip assert does"),
                    context,
                    &mut late_incomplete,
                ),
                PolicyAssert::OriginShape(assertion) => evaluate_origin_shape_assert(
                    assertion,
                    subject,
                    &bindings_by_occurrence,
                    &origin_iterables,
                    &origin_assignments,
                    &origin_literals,
                ),
                PolicyAssert::ValueOrigin(assertion) => {
                    match subject.ast_ids(&assertion.relative_to) {
                        Some(_) => evaluate_value_origin_assert(
                            assertion,
                            subject,
                            &ast_ids,
                            &bindings_by_occurrence,
                            &scopes_by_index,
                            &assigned_positions,
                            &mut late_incomplete,
                        ),
                        None => {
                            return Err(Box::new(AssertFileFailure::Run {
                                reason: PolicyFailureReason::InvalidExecutionPlan,
                                message: format!(
                                    "assert `{}` names capture `{}`, which the subject selector does not bind at {}",
                                    assertion.id,
                                    assertion.relative_to,
                                    subject.path.as_str()
                                ),
                                work: file_work,
                            }));
                        }
                    }
                }
                PolicyAssert::BindingScope(assertion) => {
                    match subject.ast_ids(&assertion.relative_to) {
                        Some(_) => evaluate_binding_scope_assert(
                            assertion,
                            subject,
                            &ast_ids,
                            &bindings_by_occurrence,
                            &scopes_by_index,
                            &mut late_incomplete,
                        ),
                        None => {
                            return Err(Box::new(AssertFileFailure::Run {
                                reason: PolicyFailureReason::InvalidExecutionPlan,
                                message: format!(
                                    "assert `{}` names capture `{}`, which the subject selector does not bind at {}",
                                    assertion.id,
                                    assertion.relative_to,
                                    subject.path.as_str()
                                ),
                                work: file_work,
                            }));
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
                match assertion {
                    // role() is None for this family so the generic gates
                    // join on the anchor, but the evidence names the role
                    // its iterable join actually used.
                    PolicyAssert::OriginShape(assertion) => assertion.role.label(),
                    _ => assertion.role().map_or("declaration", |role| role.label()),
                },
                violation.expected_class,
                violation.expectation.clone(),
                violation.observed.clone(),
                violation.actual_count,
                capability.clone(),
            ) else {
                return Err(Box::new(AssertFileFailure::Projection {
                    message: "a violated assertion could not be projected into validated policy evidence",
                    findings: file_findings,
                    work: file_work,
                }));
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
                    return Err(Box::new(AssertFileFailure::Projection {
                        message: "an evidence row could not be projected into a related policy location",
                        findings: file_findings,
                        work: file_work,
                    }));
                }
            };

            let finding = presentation.assemble(
                subject.location.clone(),
                related,
                related_truncated,
                omitted_related,
                evidence,
                budget,
            );
            match finding {
                Ok(finding) => file_findings.push(finding),
                Err(_) => {
                    return Err(Box::new(AssertFileFailure::Projection {
                        message: "a validated assertion violation could not be retained as a finding",
                        findings: file_findings,
                        work: file_work,
                    }));
                }
            }
        }
    }

    // Soundness rule 3 again, stated as the product's shape: a file whose
    // asserts could not conclude reports no findings at all, so the two
    // halves of the product are never both populated.
    if late_incomplete.is_empty() {
        return Ok(AssertFileProduct {
            findings: file_findings,
            unconcluded: Vec::new(),
            row_completions,
            diagnostics: file_diagnostics,
            work: file_work,
        });
    }
    late_incomplete.sort();
    late_incomplete.dedup();
    Ok(AssertFileProduct {
        findings: Vec::new(),
        unconcluded: late_incomplete,
        row_completions,
        diagnostics: file_diagnostics,
        work: file_work,
    })
}

/// The presentation values every assertion finding of one run shares.
///
/// Two producers build assertion findings: the per-subject loop, and the
/// termination family, which is about a file set rather than a captured node
/// and therefore runs once per policy run. They must project identically, so
/// the projection lives here rather than being written twice.
struct AssertionFindingPresentation<'presentation> {
    policy: &'presentation LoadedPolicy,
    policy_id: &'presentation super::super::definition::PolicyId,
    severity: FindingSeverity,
    message: &'presentation str,
    classification: &'presentation super::super::classification::FindingClassification,
}

impl AssertionFindingPresentation<'_> {
    fn assemble(
        &self,
        location: PolicySourceLocation,
        related: Vec<RelatedPolicyLocation>,
        related_truncated: bool,
        omitted_related: u64,
        evidence: super::super::finding::AssertionFindingEvidence,
        budget: &PolicyBudget,
    ) -> Result<PolicyFinding, ()> {
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
        PolicyFinding::try_new(
            self.policy_id.clone(),
            self.policy.semantic_hash(),
            self.severity,
            self.message.to_string(),
            self.classification.clone(),
            FindingCertainty::Definite,
            completeness,
            location,
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
        )
        .map_err(|_| ())
    }
}

/// Retain one diagnostic that names every file whose verdict this run could
/// not conclude, with each file's typed reasons. The complete set is listed
/// unless the report prose bound forces a tail count.
fn retain_unconcluded_files_diagnostic(
    unconcluded_files: &[(String, Vec<PolicyIncompleteReason>)],
    diagnostics: &mut Vec<PolicyDiagnostic>,
    diagnostics_truncated: &mut bool,
    max_diagnostics: usize,
) {
    if diagnostics.len() >= max_diagnostics {
        *diagnostics_truncated = true;
        return;
    }
    // The policy-report prose bound is 4096 bytes; leave room for the tail
    // note so the message always validates.
    const MESSAGE_BYTE_BUDGET: usize = 3_900;
    let mut message = String::from("assertion evaluation could not conclude these subject files: ");
    let mut listed = 0_usize;
    for (path, reasons) in unconcluded_files {
        let entry = format!("{}{path} {reasons:?}", if listed == 0 { "" } else { "; " });
        if message.len() + entry.len() > MESSAGE_BYTE_BUDGET {
            break;
        }
        message.push_str(&entry);
        listed += 1;
    }
    let omitted = unconcluded_files.len() - listed;
    if omitted > 0 {
        message.push_str(&format!(" ... and {omitted} more unconcluded files"));
    }
    match PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        &message,
        None,
        Vec::new(),
    ) {
        Ok(diagnostic) => diagnostics.push(diagnostic),
        Err(_) => *diagnostics_truncated = true,
    }
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
                let Some((_, query)) = selector.as_query() else {
                    return failed_policy_run(
                        policy,
                        PolicyAnalysisType::Assertion,
                        &format!(
                            "relational binding `{}` requires a query selector; nested row selectors are unsupported",
                            binding.name
                        ),
                        budget,
                    );
                };
                let mut query = query.clone();
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

    let Some(incremental) = context.incremental else {
        let executed = whole_relational_bindings(&binding_queries, context, budget);
        return relational_run(policy, plan, &binding_index_by_name, &executed, budget);
    };
    let mut attempt = UnitAttempt::default();
    let sliced = sliced_relational_bindings(
        policy,
        plan,
        &binding_queries,
        incremental,
        context,
        budget,
        &mut attempt,
    );
    let (executed, reason) = match sliced {
        Ok(executed) => (executed, None),
        Err(reason) => (
            whole_relational_bindings(&binding_queries, context, budget),
            Some(reason),
        ),
    };
    let review = attempt.into_run(policy.definition().metadata.id.clone(), reason);
    note_incremental_run(&review, incremental);
    incremental.record_run(review);
    relational_run(policy, plan, &binding_index_by_name, &executed, budget)
}

/// Execute every row binding of a relational plan over the whole workspace.
///
/// A binding that expands into a semantic row family (the #1477 dispatch rows)
/// needs the generation-bound workspace oracles; the analyzer-only path serves
/// an evaluation context that carries no workspace.
fn whole_relational_bindings(
    queries: &[CodeQuery],
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
) -> Vec<ExecutedQueryRows> {
    queries
        .iter()
        .map(|query| {
            ExecutedQueryRows::of_detailed(match context.workspace {
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
            })
        })
        .collect()
}

/// Execute every row binding as the merge of one execution per seed file.
///
/// One binding is one query, so it is sliced by exactly the shared path a match
/// selector and an assertion subject selector take; the only thing this adds is
/// the binding's own name in the partition, because one relational policy runs
/// one query per binding over the same seed files.
///
/// The merged row vector is the vector a whole execution would have built, in
/// the same order, which is what the plan evaluation needs: a violation's
/// contributors are positional indices into it and a finding anchors at the
/// first representative row.
///
/// `Err` is the demand to evaluate the whole policy instead, with the reason
/// that demand exists.
fn sliced_relational_bindings(
    policy: &LoadedPolicy,
    plan: &super::super::definition::RelationalAssertionPlan,
    queries: &[CodeQuery],
    incremental: &PolicyIncrementalContext<'_>,
    context: &PolicyEvaluationContext<'_>,
    budget: &PolicyBudget,
    attempt: &mut UnitAttempt,
) -> Result<Vec<ExecutedQueryRows>, WidenReason> {
    let limits = budget.query_limits();
    let workspace_files = context.analyzer.analyzed_files();
    let execution = UnitQueryExecution {
        analyzer: context.analyzer,
        workspace: context.workspace,
        cancellation: context.cancellation,
        limits,
        workspace_files: &workspace_files,
    };
    let mut reuse = UnitReuse::new(policy, incremental, budget);
    let mut executed = Vec::with_capacity(queries.len());
    let mut keys = Vec::new();
    assert_eq!(
        plan.bindings.len(),
        queries.len(),
        "one executable query is built for every declared row binding"
    );
    for (binding, query) in plan.bindings.iter().zip(queries) {
        let name = binding.name.as_str();
        let sliced = sliced_query_units(
            policy,
            query,
            &mut reuse,
            &execution,
            |seed| seed.binding(name),
            attempt,
        )?;
        keys.extend(sliced.keys);
        executed.push(ExecutedQueryRows::of_merged(sliced.merged));
    }
    // Every unit of this policy is published and merged, so this list is what
    // another run replays to reproduce the product without executing anything.
    incremental.record_units(policy.definition().metadata.id.clone(), keys);
    Ok(executed)
}

/// Evaluate one relational plan over the rows its bindings produced.
///
/// Everything from here is the same code whichever path produced those rows,
/// which is what makes a sliced run and a whole run answer alike by
/// construction rather than by comparison.
fn relational_run(
    policy: &LoadedPolicy,
    plan: &super::super::definition::RelationalAssertionPlan,
    binding_index_by_name: &HashMap<&super::super::definition::RowBindingName, usize>,
    executed: &[ExecutedQueryRows],
    budget: &PolicyBudget,
) -> Result<PolicyRun, PolicyRunError> {
    use super::super::assertion_policy::{
        RelationalInput, RelationalViolationRow, evaluate_relational_assertion_rows,
    };
    use super::super::relational::RelationCoverage;

    let mut run_incomplete: Vec<PolicyIncompleteReason> = Vec::new();
    let mut run_failures: Vec<PolicyFailureReason> = Vec::new();
    let mut query_diagnostics: Vec<CodeQueryDiagnostic> = Vec::new();
    let mut binding_coverage: Vec<RelationCoverage> = Vec::with_capacity(executed.len());
    let mut total_work: Option<CodeQueryExecutionWork> = None;

    /// Whether this row states that the producer suppressed the row *set* it
    /// heads, which is a different question from whether one of its fields is
    /// unknown.
    ///
    /// A relational assertion counts rows, so it is sensitive to a set that is
    /// empty because nobody could read it rather than because it is genuinely
    /// empty. A call shape whose coverage is not `exact` is exactly that case:
    /// the derivation deliberately emits zero argument-group and zero argument
    /// rows for it (#1478 Milestone 1) so that a macro-expanded argument list
    /// can never be byte-identical to a real zero-argument call. Counting those
    /// absent rows and passing an exact cardinality would report the confident
    /// answer the coverage field exists to prevent, so the run is inconclusive
    /// instead.
    ///
    /// This is deliberately *not* the same judgement as the match-selector
    /// path's per-row `selected_site_quality`. A row whose own coverage is
    /// partial about the world it describes -- an open member-selection
    /// candidate set, an undecided candidate verdict, an `unknown_shape`
    /// overload summary -- still publishes exact values in its own fields and
    /// still emits every row it heads, and poisoning a whole run because one
    /// site in the file was undecidable would make almost every relational
    /// policy inconclusive. A policy that must exclude undecided rows filters
    /// them with `:where`, which is what the winning-tier sugar lowers to.
    fn suppressed_row_set(item: &UnitRowItem) -> bool {
        if item.domain != DetailedCodeQueryDomain::CallShape {
            return false;
        }
        row_text(item, "coverage").expect("every call-shape row states its coverage") != "exact"
    }

    for rows in executed {
        let reasons = incomplete_reasons(&rows.completion, rows.truncated);
        run_incomplete.extend(reasons.iter().copied());
        // One binding's rows, one coverage. This is the mapping issue 2435 is
        // about: `ProvenSubset` is not "not exhaustive", and a suppressed row
        // set is not a partial one -- it is a relation the producer refused to
        // describe at all.
        let coverage = if rows.items.iter().any(suppressed_row_set) {
            run_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
            RelationCoverage::unsupported_row_set()
        } else {
            match &rows.completion {
                CodeQueryCompletion::Complete if !rows.truncated => RelationCoverage::Exhaustive,
                CodeQueryCompletion::ProvenSubset { .. } => RelationCoverage::ProvenSubset,
                CodeQueryCompletion::Complete
                | CodeQueryCompletion::Incomplete { .. }
                | CodeQueryCompletion::Cancelled
                | CodeQueryCompletion::Invalid { .. } => RelationCoverage::incomplete(reasons),
            }
        };
        binding_coverage.push(coverage);
        run_failures.extend(failure_reasons(&rows.completion));
        query_diagnostics.extend(rows.diagnostics.iter().cloned());
        total_work = Some(match total_work {
            Some(work) => work.saturating_add(rows.work),
            None => rows.work,
        });
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
    for rows in executed {
        if rows.items.len() != rows.evidence.len() {
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
        .zip(executed)
        .zip(&binding_coverage)
        .map(|((binding, rows), coverage)| RelationalInput {
            binding: &binding.name,
            rows: &rows.items,
            coverage: coverage.clone(),
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
    let work = relational_work_report(total_work, evaluation.work, 0, 0);

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
    // An assertion whose verdict the coverage rules blocked makes the run
    // non-reliable, which is what keeps status 0 impossible. It does not
    // discard the verdicts the same evaluation did prove.
    for obligation in &evaluation.unmet_obligations {
        run_incomplete.extend(obligation.reasons.iter().copied());
    }
    if !evaluation.exhaustive && run_incomplete.is_empty() {
        run_incomplete.push(PolicyIncompleteReason::PartialDiscovery);
    }
    run_incomplete.sort();
    run_incomplete.dedup();
    let completion = if run_incomplete.is_empty() {
        PolicyRunCompletion::Complete
    } else {
        retain_incomplete_run_diagnostic(
            &mut diagnostics,
            &mut diagnostics_truncated,
            budget.max_diagnostics(),
            "relational assertion evaluation could not observe a complete row set",
        );
        // One diagnostic per blocked verdict, so a reader sees which
        // assertion could not conclude and why, not only that something
        // could not. Every obligation states at least one reason, so this
        // list is non-empty exactly when the run is inconclusive, which is
        // the completion a `RunIncomplete` diagnostic requires.
        retain_relational_obligation_diagnostics(
            &mut diagnostics,
            &mut diagnostics_truncated,
            budget.max_diagnostics(),
            &evaluation,
        );
        PolicyRunCompletion::inconclusive(run_incomplete)
            .expect("typed relational incomplete reasons are canonical")
    };

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
        let rows = &executed[index];
        let item = rows.items.get(row.row)?;
        let evidence = rows.evidence.get(row.row)?;
        let path = WorkspaceRelativePath::new(evidence.rel_path.as_ref()).ok()?;
        match (evidence.byte_span.as_ref(), item.range) {
            (Some(byte_span), Some(range)) => policy_span_location(path, byte_span, range).ok(),
            _ => Some(PolicySourceLocation::artifact(path)),
        }
    };
    // A conflict row states two access sites beside its own anchor, and both
    // are read from the row's declared field surface: the projected row is
    // what every path carries, and the surface is what the row publishes.
    let row_endpoint_locations =
        |row: &RelationalViolationRow| -> Option<Vec<PolicySourceLocation>> {
            let index = *binding_index_by_name.get(&row.binding)?;
            let item = executed[index].items.get(row.row)?;
            if item.domain != DetailedCodeQueryDomain::ConcurrentAccessConflict {
                return Some(Vec::new());
            }
            let endpoint = |site: &str| -> Option<PolicySourceLocation> {
                let path =
                    WorkspaceRelativePath::new(row_text(item, &format!("{site}_path"))?).ok()?;
                let byte_span = PolicyByteSpan::new(
                    row_number(item, &format!("{site}_start_byte"))?,
                    row_number(item, &format!("{site}_end_byte"))?,
                )
                .ok()?;
                let region = PolicyDisplayRegion::new(
                    row_number(item, &format!("{site}_start_line"))?,
                    row_number(item, &format!("{site}_start_column"))?,
                    row_number(item, &format!("{site}_end_line"))?,
                    row_number(item, &format!("{site}_end_column"))?,
                )
                .ok()?;
                Some(PolicySourceLocation::span(path, byte_span, region))
            };
            Some(vec![endpoint("first")?, endpoint("second")?])
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
                let Some(endpoint_locations) = row_endpoint_locations(row) else {
                    return failed_policy_run_with_reason(
                        policy,
                        PolicyAnalysisType::Assertion,
                        findings,
                        PolicyFailureReason::InternalInvariant,
                        "a concurrent access row could not project its endpoint locations",
                        work,
                        budget,
                    );
                };
                for location in endpoint_locations {
                    if related.iter().any(|entry| entry.location() == &location) {
                        continue;
                    }
                    if related.len() == budget.max_related_locations_per_finding() {
                        related_truncated = true;
                        omitted_related = omitted_related.saturating_add(1);
                        continue;
                    }
                    let Ok(entry) = RelatedPolicyLocation::try_new(
                        PolicyLocationRelationship::Evidence,
                        location,
                        Vec::new(),
                    ) else {
                        return failed_policy_run_with_reason(
                            policy,
                            PolicyAnalysisType::Assertion,
                            findings,
                            PolicyFailureReason::InternalInvariant,
                            "a concurrent access endpoint could not be retained as finding evidence",
                            work,
                            budget,
                        );
                    };
                    related.push(entry);
                }
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

    let work = relational_work_report(total_work, evaluation.work, findings.len(), 0);
    let mut run = finish_assembled_run(
        policy,
        PolicyAnalysisType::Assertion,
        completion,
        findings,
        diagnostics,
        diagnostics_truncated,
        work,
        "relational assertion evaluation produced an invalid policy run",
        budget,
    )?;
    attach_relational_obligations(&mut run, &evaluation, budget);
    Ok(run)
}

/// One text scalar of a projected row, by the field name its domain declares.
///
/// `None` for a field the domain does not declare and for one whose declared
/// type is not textual, which are both reader errors rather than row states;
/// every caller here reads a field its own domain declares as required.
fn row_text<'a>(item: &'a UnitRowItem, field: &str) -> Option<&'a str> {
    match item.field(field).ok()?? {
        CodeQueryRowScalarRef::StableId(value)
        | CodeQueryRowScalarRef::String(value)
        | CodeQueryRowScalarRef::ConstrainedEnum(value)
        | CodeQueryRowScalarRef::DeclarationIdentity(value) => Some(value),
        CodeQueryRowScalarRef::Integer(_) | CodeQueryRowScalarRef::Boolean(_) => None,
    }
}

/// One integer scalar of a projected row, read like [`row_text`].
fn row_number(item: &UnitRowItem, field: &str) -> Option<u64> {
    match item.field(field).ok()?? {
        CodeQueryRowScalarRef::Integer(value) => Some(value),
        CodeQueryRowScalarRef::StableId(_)
        | CodeQueryRowScalarRef::String(_)
        | CodeQueryRowScalarRef::ConstrainedEnum(_)
        | CodeQueryRowScalarRef::DeclarationIdentity(_)
        | CodeQueryRowScalarRef::Boolean(_) => None,
    }
}

/// Publish every unmet obligation as structured report data beside the
/// diagnostics that already name it.
///
/// The diagnostics are the human-visible summary channel and stay exactly as
/// they were; this list is what an agent reads. Both are built from the same
/// evaluation in the same order, so they can never disagree about which
/// verdict was blocked.
///
/// Nothing here can make a run more trustworthy: obligations are attached only
/// to an `Inconclusive` run, and a run whose assembly degraded to `Failed`
/// published no verdict at all, so it carries none. The retained-bytes bound
/// is respected by dropping obligations from the end of the deterministic
/// order and recording the loss in the truncation pair.
fn attach_relational_obligations(
    run: &mut PolicyRun,
    evaluation: &super::super::assertion_policy::RelationalAssertionEvaluation,
    budget: &PolicyBudget,
) {
    use super::super::finding::PolicyObligation;

    if !matches!(run.completion(), PolicyRunCompletion::Inconclusive { .. }) {
        return;
    }
    let mut obligations = Vec::new();
    let mut truncated = evaluation.obligations_truncated;
    let mut omitted = evaluation.omitted_obligations_lower_bound;
    for obligation in &evaluation.unmet_obligations {
        if obligations.len() >= budget.max_obligations_per_run() {
            truncated = true;
            omitted = omitted.saturating_add(1);
            continue;
        }
        let key = render_relational_key(&obligation.key);
        let projected = PolicyObligation::try_new(
            obligation.assertion.as_str(),
            policy_obligation_kind(obligation.kind),
            obligation.group.as_str(),
            (!key.is_empty()).then_some(key.as_str()),
            obligation.reasons.clone(),
        );
        match projected {
            Ok(projected) => obligations.push(projected),
            Err(_) => {
                truncated = true;
                omitted = omitted.saturating_add(1);
            }
        }
    }
    // `omitted > 0` without `truncated` is unrepresentable, and so is the
    // reverse; the evaluation's own pair already agrees, and every increment
    // above sets both.
    if truncated && omitted == 0 {
        omitted = 1;
    }
    loop {
        if run
            .set_obligations(&obligations, truncated, omitted, budget)
            .is_ok()
        {
            return;
        }
        if obligations.pop().is_none() {
            return;
        }
        truncated = true;
        omitted = omitted.saturating_add(1);
    }
}

/// The report's published spelling of one evaluator obligation kind.
const fn policy_obligation_kind(
    kind: super::super::relational::RelationalObligationKind,
) -> super::super::finding::PolicyObligationKind {
    use super::super::finding::PolicyObligationKind;
    use super::super::relational::RelationalObligationKind;
    match kind {
        RelationalObligationKind::AbsenceRequiresExhaustiveCoverage => {
            PolicyObligationKind::AbsenceRequiresExhaustiveCoverage
        }
        RelationalObligationKind::VerdictRequiresWitnessedRows => {
            PolicyObligationKind::VerdictRequiresWitnessedRows
        }
    }
}

/// Retain the one diagnostic that says this relational run could not observe
/// everything it needed to.
///
/// Separate from `retain_incomplete_diagnostic` because that helper reports a
/// retention-budget cause; this one reports an evaluation cause, which is the
/// code the inconclusive relational path has always published.
fn retain_incomplete_run_diagnostic(
    diagnostics: &mut Vec<PolicyDiagnostic>,
    diagnostics_truncated: &mut bool,
    max_diagnostics: usize,
    message: &str,
) {
    if diagnostics.len() >= max_diagnostics {
        *diagnostics_truncated = true;
        return;
    }
    match PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        message,
        None,
        Vec::new(),
    ) {
        Ok(diagnostic) => diagnostics.push(diagnostic),
        Err(_) => *diagnostics_truncated = true,
    }
}

/// Name every unmet proof obligation on the run's diagnostics.
///
/// One diagnostic per blocked verdict, in the evaluation's own deterministic
/// order, bounded by the same per-policy diagnostic cap every other channel
/// respects. The reason family is the obligation kind rather than the whole
/// message, so a capped list still reports how many verdicts each kind
/// blocked (#2356); the message carries the assertion, the group and the group
/// key, which is what makes the blocked claim addressable.
///
/// Truncation is recorded, never silent: the run's typed incomplete reasons
/// are folded in before this runs, so a dropped diagnostic costs detail and
/// never soundness.
fn retain_relational_obligation_diagnostics(
    diagnostics: &mut Vec<PolicyDiagnostic>,
    diagnostics_truncated: &mut bool,
    max_diagnostics: usize,
    evaluation: &super::super::assertion_policy::RelationalAssertionEvaluation,
) {
    if evaluation.obligations_truncated {
        *diagnostics_truncated = true;
    }
    for obligation in &evaluation.unmet_obligations {
        if diagnostics.len() >= max_diagnostics {
            *diagnostics_truncated = true;
            return;
        }
        // The reasons are already canonical and sorted on the obligation, and
        // their serialized spelling is the same one the report publishes.
        let reasons = obligation
            .reasons
            .iter()
            .map(|reason| match serde_json::to_value(reason) {
                Ok(serde_json::Value::String(label)) => label,
                _ => format!("{reason:?}"),
            })
            .collect::<Vec<_>>()
            .join(", ");
        let key = render_relational_key(&obligation.key);
        let scope = if key.is_empty() {
            format!("group `{}`", obligation.group)
        } else {
            format!("group `{}` key `{key}`", obligation.group)
        };
        let message = format!(
            "relational assertion `{}` published no verdict for {scope}: {} ({reasons})",
            obligation.assertion,
            obligation.kind.label(),
        );
        match PolicyDiagnostic::try_new_in_family(
            PolicyDiagnosticCode::EvaluationFailure,
            PolicyDiagnosticSeverity::Warning,
            PolicyDiagnosticImpact::RunIncomplete,
            format!("relational_obligation/{}", obligation.kind.label()),
            message,
            None,
            Vec::new(),
        ) {
            Ok(diagnostic) => diagnostics.push(diagnostic),
            Err(_) => *diagnostics_truncated = true,
        }
    }
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
    /// The binding a binding-scope assert reached, listed as the binding-of answer.
    binding: Option<&'rows CodeQueryBinding>,
    /// The scope the binding is declared in.
    declaring_scope: Option<&'rows CodeQueryLexicalScope>,
    /// Generation-site rows a generation assert fired on; the site and each
    /// generated declaration's naming argument become related locations.
    generation_sites: Vec<&'rows CodeQueryGenerationSite>,
    /// Prebuilt evidence locations for the families that read a derivation
    /// layer rather than wire rows: the unmatched edge's site and target
    /// files, or the considered establishments of a temporal assert. Built at
    /// evaluation time, in the order the evidence is stated, because these
    /// rows never travelled through a query.
    derivation_locations: Vec<PolicySourceLocation>,
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
            derivation_locations: Vec::new(),
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

/// A forward `Reference` row is the honest fallback when the occurrence role
/// and owner evidence do not prove a more specific usage kind. Only a
/// non-`Reference` forward row can make a field-level usage-kind claim that
/// parity should enforce; an inverse-only classification must not manufacture
/// a finding against that fallback.
fn forward_usage_kind_is_classified(row: &ReferenceEdgeRow) -> bool {
    row.provenance == EdgeProvenance::Forward && row.usage_kind != UsageHitKind::Reference
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
    // Compare usage kinds only when the forward producer made a structured
    // non-fallback classification. When it says `reference`, the inverse
    // producer may still have stronger self/import knowledge; that is an
    // honest abstention, not a parity mismatch. Surface membership remains an
    // explicit comparison through the assert's :surface option.
    if (forward_usage_kind_is_classified(left) || forward_usage_kind_is_classified(right))
        && left.usage_kind != right.usage_kind
    {
        mismatches.push(format!(
            "usage_kind {} != {}",
            left.usage_kind.wire_label(),
            right.usage_kind.wire_label()
        ));
    }
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
        brokk_bifrost_rql::schema::reference_kind_label(kind)
    })
}

/// One human-readable statement of an edge, used in observed text so a finding
/// names the unmatched edge exactly.
fn edge_description(row: &ReferenceEdgeRow) -> String {
    format!(
        "{}:{}..{} -> {} [{}; {}; {}; {}; {}]",
        workspace_relative_key(&row.site.file),
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

fn derivation_file_location(file: &ProjectFile) -> Option<PolicySourceLocation> {
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
                        locations.extend(derivation_file_location(&edge.site.file));
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
                            locations.extend(derivation_file_location(&edge.site.file));
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
                        locations.extend(derivation_file_location(edge.target.source()));
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
                            locations.extend(derivation_file_location(edge.target.source()));
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
    violation.derivation_locations = locations;
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
                    locations.extend(derivation_file_location(&edge.site.file));
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
    violation.derivation_locations = locations;
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
                brokk_bifrost_rql::schema::reference_kind_label(value).to_string()
            }),
        },
    }
}

/// What one terminal rewrite outcome means for a termination assert.
///
/// The three outcomes are deliberately not two: a cycle is a concrete
/// counterexample, convergence is a positive answer, and budget exhaustion is
/// *absence of evidence*, which may never become either verdict. Budget
/// exhaustion is structurally unreachable in the one domain declared today
/// (every rewrite consumes one distinct binder root, so the hop count cannot
/// pass the root count), so this mapping is pinned by a unit test rather than
/// by a fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TerminationVerdict {
    Satisfied,
    Counterexample,
    Inconclusive,
}

pub(super) const fn termination_verdict(outcome: &RewriteOutcome) -> TerminationVerdict {
    match outcome {
        RewriteOutcome::Converged { .. } => TerminationVerdict::Satisfied,
        RewriteOutcome::Cycle { .. } => TerminationVerdict::Counterexample,
        RewriteOutcome::ExceededBudget { .. } => TerminationVerdict::Inconclusive,
    }
}

/// Per-run memo of bounded rewrite-path derivations for the termination
/// family (#1480).
///
/// Unlike the flow-state family this needs no workspace snapshot: the domain's
/// chase reads the file's own import binder, so it runs in every execution
/// mode.
struct RewriteAssertContext<'context> {
    analyzer: &'context dyn IAnalyzer,
    cancellation: Option<&'context CancellationToken>,
    files: HashMap<ProjectFile, Arc<FileRewritePaths>>,
    /// The unscoped termination assert walks every analyzed file; the listing
    /// does not change within one run, so it is enumerated and sorted once.
    workspace_files: Option<Arc<[ProjectFile]>>,
}

impl<'context> RewriteAssertContext<'context> {
    fn new(
        analyzer: &'context dyn IAnalyzer,
        cancellation: Option<&'context CancellationToken>,
    ) -> Self {
        Self {
            analyzer,
            cancellation,
            files: HashMap::new(),
            workspace_files: None,
        }
    }

    fn workspace_files(&mut self) -> Arc<[ProjectFile]> {
        if let Some(cached) = &self.workspace_files {
            return Arc::clone(cached);
        }
        let mut files = self.analyzer.analyzed_files();
        files.sort_by_key(|file| file.rel_path().to_path_buf());
        let files: Arc<[ProjectFile]> = files.into();
        self.workspace_files = Some(Arc::clone(&files));
        files
    }

    fn for_file(&mut self, file: &ProjectFile) -> Arc<FileRewritePaths> {
        if let Some(cached) = self.files.get(file) {
            return Arc::clone(cached);
        }
        let token = self.cancellation.cloned().unwrap_or_default();
        let derived = Arc::new(rewrite_paths_for_file(
            self.analyzer,
            file,
            &mut RewritePathRequest::new(&token),
        ));
        self.files.insert(file.clone(), Arc::clone(&derived));
        derived
    }
}

/// Per-run memo of flow-state derivations for the temporal assert family
/// (#1480).
///
/// The derivation layer is consulted directly, exactly as the edge asserts
/// consult theirs: the assert needs the typed per-axis completeness and the
/// dense event identities both ends of a relation join on, and the wire rows
/// only re-render those.
struct FlowStateAssertContext<'context> {
    /// The production CFG is a workspace artifact. A host that supplied no
    /// workspace snapshot has not given this family its evidence source, and
    /// there is no second one.
    workspace: Option<&'context WorkspaceAnalyzer>,
    cancellation: Option<&'context CancellationToken>,
    /// Retained so every asserted file sees one activation snapshot even if a
    /// host publishes another set while this policy run is in progress.
    active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    active_model_set_hash: Option<Arc<str>>,
    files: HashMap<FlowStateAssertCacheKey, Arc<FileFlowState>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowStateAssertCacheKey {
    file: ProjectFile,
    active_model_set_hash: Option<Arc<str>>,
}

impl<'context> FlowStateAssertContext<'context> {
    fn new(
        workspace: Option<&'context WorkspaceAnalyzer>,
        cancellation: Option<&'context CancellationToken>,
        active_semantic_model_snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    ) -> Self {
        let active_model_set_hash = active_semantic_model_snapshot
            .as_ref()
            .map(|snapshot| Arc::<str>::from(snapshot.active_models().active_model_set_hash()));
        Self {
            workspace,
            cancellation,
            active_semantic_model_snapshot,
            active_model_set_hash,
            files: HashMap::new(),
        }
    }

    /// Derive (or replay) one workspace-relative file's flow state. `None`
    /// means the run has no workspace snapshot, which is a capability gap, not
    /// an empty answer.
    fn for_path(&mut self, path: &str) -> Option<Arc<FileFlowState>> {
        let workspace = self.workspace?;
        let file = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            path.to_string(),
        );
        let key = FlowStateAssertCacheKey {
            file: file.clone(),
            active_model_set_hash: self.active_model_set_hash.clone(),
        };
        if let Some(cached) = self.files.get(&key) {
            return Some(Arc::clone(cached));
        }
        let token = self.cancellation.cloned().unwrap_or_default();
        let mut request = FlowStateRequest::new(&token)
            .with_active_semantic_model_snapshot(self.active_semantic_model_snapshot.clone());
        let derived = Arc::new(flow_state_for_file(workspace, &file, &mut request));
        self.files.insert(key, Arc::clone(&derived));
        Some(derived)
    }
}

/// One human-readable statement of what a state event is about.
fn flow_subject_description(subject: &FlowSubject) -> String {
    match subject.member() {
        Some(member) => format!("property `.{member}`"),
        None => "binding".to_string(),
    }
}

/// One event, named by its subject and the line that spells it.
fn state_event_description(event: &StateEventRow) -> String {
    format!(
        "{} at {}:{}",
        flow_subject_description(&event.subject),
        workspace_relative_key(&event.site.file),
        event.site.range.start_line,
    )
}

/// Why one establishment does not serve one read, read off the derived
/// relations rather than guessed.
///
/// Only relations the derivation actually emitted are stated: "killed" is
/// claimed exactly when a kill of the same subject dominates the read, which
/// is a derived fact, and never inferred from the presence of a kill event
/// somewhere in the procedure.
fn establishment_rejection(
    derivation: &FlowStateDerivation,
    establishment: &StateEventRow,
    read: &StateEventRow,
    require: EstablishmentRequirement,
) -> &'static str {
    let relates = |relation: FlowRelation| {
        derivation.relations.iter().any(|row| {
            row.relation == relation
                && row.source_event == establishment.event
                && row.target_event == read.event
        })
    };
    if relates(FlowRelation::SameEvaluation) {
        return "serves its own evaluation of the read";
    }
    if require == EstablishmentRequirement::Dominated && relates(FlowRelation::Reaching) {
        return "reaches the read but does not dominate it";
    }
    "does not reach the read"
}

/// Whether a kill of the read's subject dominates the read, which is the one
/// provable form of "the establishment was killed before this read".
fn killed_before(derivation: &FlowStateDerivation, read: &StateEventRow) -> bool {
    derivation.relations.iter().any(|row| {
        row.relation == FlowRelation::Dominates && row.target_event == read.event && {
            let source = derivation.event(row.source_event);
            source.event_class == StateEventClass::Kill && source.subject == read.subject
        }
    })
}

/// The temporal assert: every read the capture joins must be reached by, or
/// dominated by, an establishment of its own subject, and -- under
/// `:forbid-same-evaluation` -- must never be served by a binder of its own
/// evaluation.
fn evaluate_flow_establishment_assert<'rows>(
    assertion: &FlowEstablishmentAssert,
    subject: &AssertionSubject,
    ast_ids: &[&str],
    flow: &mut FlowStateAssertContext<'_>,
    late_incomplete: &mut Vec<PolicyIncompleteReason>,
) -> Option<AssertionViolation<'rows>> {
    let Some(state) = flow.for_path(subject.path.as_str()) else {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    };
    let mut offending: Vec<String> = Vec::new();
    let mut locations: Vec<PolicySourceLocation> = Vec::new();
    let mut count = 0_u64;
    let mut joined_any_read = false;

    for derivation in &state.procedures {
        let reads: Vec<&StateEventRow> = derivation
            .events
            .iter()
            .filter(|event| {
                event.event_class == StateEventClass::Read
                    && event
                        .site
                        .ast_id
                        .as_deref()
                        .is_some_and(|id| ast_ids.contains(&id))
            })
            .collect();
        if reads.is_empty() {
            continue;
        }
        joined_any_read = true;
        for read in reads {
            if assertion.forbid_same_evaluation {
                let mut same_evaluation_found = false;
                for row in derivation.relations.iter().filter(|row| {
                    row.relation == FlowRelation::SameEvaluation && row.target_event == read.event
                }) {
                    let establishment = derivation.event(row.source_event);
                    count += 1;
                    offending.push(format!(
                        "establishment of {} serves the read of {} in the same evaluation",
                        state_event_description(establishment),
                        state_event_description(read),
                    ));
                    locations.extend(derivation_file_location(&establishment.site.file));
                    locations.extend(derivation_file_location(&read.site.file));
                    same_evaluation_found = true;
                }
                // Absence is only an answer over an enumerated axis. A
                // *present* relation, by contrast, is a proven counterexample
                // whatever else the derivation could not enumerate, so the
                // coverage question is asked here and not before the search.
                if !same_evaluation_found
                    && !derivation
                        .completeness
                        .covers(FlowStateAxis::SameEvaluationRelation)
                {
                    late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
                    return None;
                }
            }

            let required = assertion.require.relation();
            let qualifies = |event: usize| {
                let candidate = derivation.event(event);
                candidate.event_class == StateEventClass::Establish
                    && candidate.subject == read.subject
            };
            if derivation.relations.iter().any(|row| {
                row.relation == required
                    && row.target_event == read.event
                    && qualifies(row.source_event)
            }) {
                // Satisfied by a relation the derivation actually states; no
                // coverage question arises, because nothing is concluded from
                // an absence.
                continue;
            }
            // The finding below rests on two absences -- no qualifying
            // relation, and no further establishment of this subject -- so
            // both axes must be enumerable before it can be stated.
            if assertion
                .consulted_axes(Some(read.subject.axis()))
                .iter()
                .any(|axis| !derivation.completeness.covers(*axis))
            {
                late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
                return None;
            }

            // The ordered witness: every establishment of this subject the
            // derivation knows, in program-point order, each with the reason it
            // does not serve this read.
            let mut considered: Vec<&StateEventRow> = derivation
                .events
                .iter()
                .filter(|event| {
                    event.event_class == StateEventClass::Establish && event.subject == read.subject
                })
                .collect();
            considered.sort_by_key(|event| (event.point.index(), event.site.range.start_byte));
            let witness = if considered.is_empty() {
                "no establishment of this subject exists in the procedure".to_string()
            } else {
                considered
                    .iter()
                    .map(|event| {
                        format!(
                            "{} ({})",
                            state_event_description(event),
                            establishment_rejection(derivation, event, read, assertion.require),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            count += 1;
            offending.push(format!(
                "the read of {} is not {} by any establishment; considered: {witness}{}",
                state_event_description(read),
                assertion.require.label(),
                if killed_before(derivation, read) {
                    "; a kill of this subject dominates the read"
                } else {
                    ""
                },
            ));
            locations.extend(derivation_file_location(&read.site.file));
            for event in considered {
                locations.extend(derivation_file_location(&event.site.file));
            }
        }
    }

    if !joined_any_read {
        // "This capture reads nothing the CFG models" is a complete answer
        // only when both event axes were enumerable across the whole file --
        // the file-level account for a file that did not lower at all, and
        // every procedure's own account for a procedure whose events are
        // partial. Otherwise the absence is unknown, not proven.
        let axes = assertion.consulted_axes(None);
        let covered = axes.iter().all(|axis| state.completeness.covers(*axis))
            && state.procedures.iter().all(|derivation| {
                axes.iter()
                    .all(|axis| derivation.completeness.covers(*axis))
            });
        if !covered {
            late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        }
        return None;
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
    violation.derivation_locations = locations;
    Some(violation)
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

fn evaluate_binding_scope_assert<'rows>(
    assertion: &BindingScopeAssert,
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
        "a binding-of answer must belong to the file of the occurrence it was reached from"
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

/// The capture the assignment row family binds to an assignment's left
/// operand. It is internal to the evaluator: the value-origin family builds
/// the query, so no authored selector can collide with it.
const ASSIGNED_VALUE_CAPTURE: &str = "__bifrost_assigned_value";
const ORIGIN_LEFT_CAPTURE: &str = "__bifrost_origin_left";
const ORIGIN_LOOP_CAPTURE: &str = "__bifrost_origin_loop";
const ORIGIN_ITERABLE_CAPTURE: &str = "__bifrost_origin_iterable";
const ORIGIN_RIGHT_CAPTURE: &str = "__bifrost_origin_right";
const ORIGIN_LITERAL_CAPTURE_PREFIX: &str = "__bifrost_origin_literal_";

/// The refined loop-invariance predicate: where is the value read here
/// *established*?
///
/// Two origins count, and the requirement is over their union:
///
/// - the declaring scope of the binding in effect at the reference, which is
///   the question [`evaluate_binding_scope_assert`] asks on its own; and
/// - any assignment whose left operand reaches that same binding, which is how
///   a value declared once outside a loop but overwritten on every pass is
///   distinguished from one that is genuinely re-used unchanged.
///
/// The join to an assignment is binding identity, never the spelled name: an
/// assignment to a different `values` in a nested scope writes a different
/// value and must not exempt this one.
fn evaluate_value_origin_assert<'rows>(
    assertion: &ValueOriginAssert,
    subject: &AssertionSubject,
    ast_ids: &[&str],
    bindings_by_occurrence: &HashMap<(&str, &str), Vec<&'rows CodeQueryBinding>>,
    scopes_by_index: &HashMap<(&str, u32), &'rows CodeQueryLexicalScope>,
    assigned_positions: &[(&str, CodeQueryRange)],
    late_incomplete: &mut Vec<PolicyIncompleteReason>,
) -> Option<AssertionViolation<'rows>> {
    let mut reached: Vec<&CodeQueryBinding> = Vec::new();
    for ast_id in ast_ids {
        if let Some(rows) = bindings_by_occurrence.get(&(subject.path.as_str(), *ast_id)) {
            reached.extend(rows.iter().copied().filter(|row| !row.shadowed));
        }
    }
    // As for the binding-scope family: a name that resolves to something other
    // than a lexical binding has no origin for this assert to constrain, and
    // that is a complete answer rather than an incomplete one.
    let binding = reached.first().copied()?;
    let Some(scope) = scopes_by_index
        .get(&(binding.path.as_str(), binding.declaring_scope_index))
        .copied()
    else {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    };
    let Some(related) = subject
        .captures
        .get(&assertion.relative_to)
        .and_then(|captures| captures.iter().find_map(|capture| capture.range))
    else {
        late_incomplete.push(PolicyIncompleteReason::CapabilityIncomplete);
        return None;
    };
    assert_eq!(
        binding.path.as_str(),
        subject.path.as_str(),
        "a binding-of answer must belong to the file of the occurrence it was reached from"
    );
    assert_eq!(
        scope.path.as_str(),
        subject.path.as_str(),
        "a declaring scope must belong to the file of the binding that names it"
    );

    let declared_inside = region_contains(related, scope.range);
    let assigned_inside = assigned_positions.iter().any(|(ast_id, range)| {
        region_contains(related, *range)
            && bindings_by_occurrence
                .get(&(subject.path.as_str(), *ast_id))
                .is_some_and(|rows| {
                    rows.iter()
                        .filter(|row| !row.shadowed)
                        .any(|row| same_binding(row, binding))
                })
    });
    let established_inside = declared_inside || assigned_inside;
    if assertion.containment.satisfied_by(established_inside) {
        return None;
    }
    // State only what was checked. Under the `outside` polarity the violation
    // is an origin that *was* found inside, and naming which one is the
    // evidence; under `inside` it is the absence of both, and the message says
    // both absences rather than implying a search that did not happen.
    let observed = if established_inside {
        format!(
            "binding `{}` is established inside capture `{}`: {}",
            binding.name,
            assertion.relative_to,
            match (declared_inside, assigned_inside) {
                (true, true) => "declared there, and assigned there",
                (true, false) => "declared there",
                (false, true) => "assigned there",
                (false, false) => unreachable!("an established origin is one of the two"),
            }
        )
    } else {
        format!(
            "binding `{}` is declared outside capture `{}`, and no assignment inside it reaches that binding",
            binding.name, assertion.relative_to
        )
    };
    let mut violation =
        AssertionViolation::new("reference", assertion.expectation(), Some(observed));
    violation.actual_count = 1;
    violation.binding = Some(binding);
    violation.declaring_scope = Some(scope);
    Some(violation)
}

/// The regions every value-origin assert of this policy compares against, for
/// the subjects of one file.
///
/// An assignment outside all of them cannot exempt any subject in the file, so
/// this is what makes "does this file need the value-reference row family?" a
/// question the assignment rows alone can answer.
fn value_origin_regions(
    spec: &AssertionPolicySpec,
    file_subjects: &[&AssertionSubject],
) -> Vec<CodeQueryRange> {
    let mut regions = Vec::new();
    for assertion in &spec.asserts {
        let PolicyAssert::ValueOrigin(assertion) = assertion else {
            continue;
        };
        for subject in file_subjects {
            let Some(captures) = subject.captures.get(&assertion.relative_to) else {
                continue;
            };
            regions.extend(captures.iter().filter_map(|capture| capture.range));
        }
    }
    regions
}

fn region_contains_any(regions: &[CodeQueryRange], inner: CodeQueryRange) -> bool {
    regions.iter().any(|outer| region_contains(*outer, inner))
}

/// The captured left operands of one assignment-query outcome, as
/// (AST id, region). A capture without both is unjoinable and is skipped;
/// the row families that need identity report their own gaps.
fn assigned_left_operands(
    results: &[CodeQueryResultItem],
) -> impl Iterator<Item = (&str, CodeQueryRange)> {
    results.iter().flat_map(|item| {
        let captures = match &item.value {
            CodeQueryResultValue::StructuralMatch { value } => value.captures.as_slice(),
            _ => &[],
        };
        captures.iter().filter_map(|capture| {
            (capture.name == ASSIGNED_VALUE_CAPTURE)
                .then(|| capture.ast_id.as_deref().zip(capture.range))
                .flatten()
        })
    })
}

/// Whether two binding-of rows name the same binder. Rows reached from two
/// occurrences are two rows of one binding, so identity is the binder token's
/// file and byte interval rather than the row's own id.
fn same_binding(left: &CodeQueryBinding, right: &CodeQueryBinding) -> bool {
    left.path == right.path
        && left.start_byte == right.start_byte
        && left.end_byte == right.end_byte
}

/// The subject rows of one assertion run, as the rows every consumer joins on.
///
/// The rows arrive as the same serializable projection a match policy's
/// adapter consumes, on both the whole-run path and the unit path, so a subject
/// cannot differ by which execution produced it.
fn collect_assertion_subjects(
    results: &[UnitRowItem],
    evidence: &[UnitRowEvidence],
) -> Result<Vec<AssertionSubject>, &'static str> {
    if results.len() != evidence.len() {
        return Err("assertion subject rows and their detailed evidence disagree");
    }
    let mut subjects = Vec::with_capacity(results.len());
    for (item, evidence) in results.iter().zip(evidence) {
        let Some(UnitRowItemTerminal::StructuralMatch {
            node_range,
            captures: row_captures,
            ..
        }) = &item.terminal
        else {
            return Err(
                "an assertion subject selector must produce structural matches carrying captures",
            );
        };
        let Ok(path) = WorkspaceRelativePath::new(evidence.rel_path.as_ref()) else {
            return Err("an assertion subject row has no workspace-relative path");
        };
        let (Some(byte_span), Some(range)) = (evidence.byte_span.as_ref(), *node_range) else {
            return Err("an assertion subject row is missing its exact source span");
        };
        let Ok(location) = policy_span_location(path.clone(), byte_span, range) else {
            return Err("an assertion subject row span could not be projected");
        };
        let mut captures: HashMap<String, Vec<SubjectCapture>> = HashMap::new();
        let mut captures_without_ast_id = Vec::new();
        for capture in row_captures {
            if capture.ast_id.is_none() {
                captures_without_ast_id.push(capture.name.to_string());
            }
            captures
                .entry(capture.name.to_string())
                .or_default()
                .push(SubjectCapture {
                    ast_id: capture.ast_id.as_ref().map(ToString::to_string),
                    kind: capture.kind.clone(),
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

/// Every assignment of the subject file whose left operand is a named value,
/// with that operand captured so its binding-of answer can be joined.
///
/// A declaration's initializer is deliberately not special-cased here: its
/// left operand is a binder rather than a value reference, so it carries no
/// binding-of row and never joins. Declarations are already the other origin
/// this family reads, through the declaring scope.
fn assertion_assignment_query(
    paths: &[&str],
    budget: &PolicyBudget,
) -> Result<CodeQuery, &'static str> {
    assert!(
        !paths.is_empty(),
        "assertion assignment queries require subject paths"
    );
    let Ok(where_globs) = exact_path_globs(paths.iter().copied()) else {
        return Err("an assertion subject path is not a valid scan pattern");
    };
    let assigned = Pattern {
        kinds: vec![NormalizedKind::Identifier],
        capture: Some(ASSIGNED_VALUE_CAPTURE.to_owned()),
        ..Pattern::default()
    };
    let root = Pattern {
        kinds: vec![NormalizedKind::Assignment],
        left: Some(Box::new(assigned)),
        ..Pattern::default()
    };
    Ok(CodeQuery {
        schema_version: SCHEMA_VERSION,
        plan: CodeQueryPlan {
            source: CodeQueryPlanSource::Seed(Box::new(CodeQuerySeed {
                where_globs,
                languages: Vec::new(),
                root,
                inside: None,
                inside_decl: None,
                not_inside: None,
            })),
            steps: Vec::new(),
        },
        limit: budget.query_limits().max_pipeline_rows,
        // Full detail is what emits each capture's `ast_id`, which is the join.
        result_detail: CodeQueryResultDetail::Full,
        execution_mode: Default::default(),
    })
}

/// Every for-each loop of the subject file with its iterated expression
/// captured, for the origin-shape family (#2647). The `iterable` sub-pattern
/// is deliberately unconstrained: whatever expression the loop iterates, the
/// map must know it, and the assert decides what qualifies.
fn origin_shape_iterable_query(
    paths: &[&str],
    budget: &PolicyBudget,
) -> Result<CodeQuery, &'static str> {
    assert!(
        !paths.is_empty(),
        "assertion row queries require subject paths"
    );
    let Ok(where_globs) = exact_path_globs(paths.iter().copied()) else {
        return Err("an assertion subject path is not a valid scan pattern");
    };
    let iterable = Pattern {
        capture: Some(ORIGIN_ITERABLE_CAPTURE.to_owned()),
        ..Pattern::default()
    };
    let root = Pattern {
        kinds: vec![NormalizedKind::ForLoop],
        iterable: Some(Box::new(iterable)),
        capture: Some(ORIGIN_LOOP_CAPTURE.to_owned()),
        ..Pattern::default()
    };
    Ok(CodeQuery {
        schema_version: SCHEMA_VERSION,
        plan: CodeQueryPlan {
            source: CodeQueryPlanSource::Seed(Box::new(CodeQuerySeed {
                where_globs,
                languages: Vec::new(),
                root,
                inside: None,
                inside_decl: None,
                not_inside: None,
            })),
            steps: Vec::new(),
        },
        limit: budget.query_limits().max_pipeline_rows,
        result_detail: CodeQueryResultDetail::Full,
        execution_mode: Default::default(),
    })
}

/// Every assignment of the subject file with both operands captured, for the
/// origin-shape family (#2647). Unlike [`assertion_assignment_query`], the
/// left operand is joined two ways -- by binding-of row for a reassignment,
/// and by binder AST identity for a declaration initializer -- so the query
/// does not care which occurrence class the left operand carries, and the
/// right operand is captured because *it* is the establishing value whose
/// shape the assert checks.
fn origin_shape_assignment_query(
    paths: &[&str],
    budget: &PolicyBudget,
) -> Result<CodeQuery, &'static str> {
    assert!(
        !paths.is_empty(),
        "assertion row queries require subject paths"
    );
    let Ok(where_globs) = exact_path_globs(paths.iter().copied()) else {
        return Err("an assertion subject path is not a valid scan pattern");
    };
    let left = Pattern {
        kinds: vec![NormalizedKind::Identifier],
        capture: Some(ORIGIN_LEFT_CAPTURE.to_owned()),
        ..Pattern::default()
    };
    let right = Pattern {
        capture: Some(ORIGIN_RIGHT_CAPTURE.to_owned()),
        ..Pattern::default()
    };
    let root = Pattern {
        kinds: vec![NormalizedKind::Assignment],
        left: Some(Box::new(left)),
        right: Some(Box::new(right)),
        ..Pattern::default()
    };
    Ok(CodeQuery {
        schema_version: SCHEMA_VERSION,
        plan: CodeQueryPlan {
            source: CodeQueryPlanSource::Seed(Box::new(CodeQuerySeed {
                where_globs,
                languages: Vec::new(),
                root,
                inside: None,
                inside_decl: None,
                not_inside: None,
            })),
            steps: Vec::new(),
        },
        limit: budget.query_limits().max_pipeline_rows,
        result_detail: CodeQueryResultDetail::Full,
        execution_mode: Default::default(),
    })
}

/// Every collection literal of the subject file with at most `max_elements`
/// elements, for the origin-shape family (#2647). The element bound rides the
/// arity predicate, which counts a collection literal's `elements` role edges
/// the same way it counts a call's `args`.
fn origin_shape_literal_query(
    paths: &[&str],
    max_elements: u32,
    budget: &PolicyBudget,
) -> Result<CodeQuery, &'static str> {
    assert!(
        !paths.is_empty(),
        "assertion row queries require subject paths"
    );
    let Ok(where_globs) = exact_path_globs(paths.iter().copied()) else {
        return Err("an assertion subject path is not a valid scan pattern");
    };
    let root = Pattern {
        kinds: vec![NormalizedKind::CollectionLiteral],
        // At least one element: a Rust repeat array emits no element edges
        // precisely so it can never qualify, and an empty display literal has
        // nothing bounded to prove either.
        arity: Some(ArityConstraint {
            min: Some(1),
            max: Some(max_elements),
        }),
        capture: Some(format!("{ORIGIN_LITERAL_CAPTURE_PREFIX}{max_elements}")),
        ..Pattern::default()
    };
    Ok(CodeQuery {
        schema_version: SCHEMA_VERSION,
        plan: CodeQueryPlan {
            source: CodeQueryPlanSource::Seed(Box::new(CodeQuerySeed {
                where_globs,
                languages: Vec::new(),
                root,
                inside: None,
                inside_decl: None,
                not_inside: None,
            })),
            steps: Vec::new(),
        },
        limit: budget.query_limits().max_pipeline_rows,
        result_detail: CodeQueryResultDetail::Full,
        execution_mode: Default::default(),
    })
}

/// The exclusion half of a review-prompt policy (#2647): does the value read
/// at the `at` capture provably originate from a collection literal with at
/// most `max_elements` elements?
///
/// The polarity is inverted relative to every other family. The others
/// abstain when the subject is out of evidence, because their finding is a
/// positive claim; here the finding is the *review prompt the subject match
/// already earned*, and the assert only withdraws it on positive proof of the
/// bounded-literal shape. Everything short of proof -- the capture absent on
/// this subject row, a reference with no lexical binding, no establishing
/// initializer in evidence, an unjoinable initializer, or any establishing
/// initializer that is not a small collection literal -- keeps the finding.
fn evaluate_origin_shape_assert<'rows>(
    assertion: &OriginShapeAssert,
    subject: &AssertionSubject,
    bindings_by_occurrence: &HashMap<(&str, &str), Vec<&'rows CodeQueryBinding>>,
    origin_iterables: &HashMap<&str, Vec<&str>>,
    origin_assignments: &[(&str, Option<&str>)],
    origin_literals: &HashMap<u32, HashSet<&str>>,
) -> Option<AssertionViolation<'rows>> {
    let violation = |observed: String, binding: Option<&'rows CodeQueryBinding>| {
        let mut violation =
            AssertionViolation::new("reference", assertion.expectation(), Some(observed));
        violation.actual_count = 1;
        violation.binding = binding;
        Some(violation)
    };
    let empty = HashSet::new();
    let literals = origin_literals
        .get(&assertion.max_elements)
        .unwrap_or(&empty);

    let Some(captures) = subject.captures.get(&assertion.at) else {
        return violation(
            format!(
                "capture `{}` is not bound on this subject, so the iterated value is out of evidence",
                assertion.at
            ),
            None,
        );
    };
    let loop_ids: Vec<&str> = captures
        .iter()
        .filter_map(|capture| capture.ast_id.as_deref())
        .collect();
    if loop_ids.is_empty() {
        return violation(
            format!(
                "capture `{}` carries no AST identity, so the iterated value is out of evidence",
                assertion.at
            ),
            None,
        );
    }
    // The captured loop joins to its iterated expression by AST identity. A
    // loop with no iterable row -- a while loop, a counting for, an adapter
    // that could not attach the edge -- has an unknown iteration source.
    let ast_ids: Vec<&str> = loop_ids
        .iter()
        .filter_map(|loop_id| origin_iterables.get(loop_id))
        .flatten()
        .copied()
        .collect();
    if ast_ids.is_empty() {
        return violation(
            "the enclosing loop does not iterate an expression in evidence, so the iteration source is unknown".to_owned(),
            None,
        );
    }

    // Direct case: the captured expression is itself a qualifying literal.
    if ast_ids.iter().all(|ast_id| literals.contains(ast_id)) {
        return None;
    }

    let mut reached: Vec<&CodeQueryBinding> = Vec::new();
    for ast_id in &ast_ids {
        if let Some(rows) = bindings_by_occurrence.get(&(subject.path.as_str(), *ast_id)) {
            reached.extend(rows.iter().copied().filter(|row| !row.shadowed));
        }
    }
    let Some(binding) = reached.first().copied() else {
        return violation(
            "the iterated expression is not a qualifying literal and resolves to no lexical binding".to_owned(),
            None,
        );
    };

    // Establishing initializers: the declaration initializer joins by the
    // binder token's AST identity, a reassignment by its left operand's
    // binding-of row. Identity, never the spelled name.
    let mut establishing: Vec<Option<&str>> = Vec::new();
    for (left, right) in origin_assignments {
        let is_declaration_initializer = binding.ast_id.as_deref() == Some(*left);
        let reaches_binding = bindings_by_occurrence
            .get(&(subject.path.as_str(), *left))
            .is_some_and(|rows| {
                rows.iter()
                    .filter(|row| !row.shadowed)
                    .any(|row| same_binding(row, binding))
            });
        if is_declaration_initializer || reaches_binding {
            establishing.push(*right);
        }
    }
    if establishing.is_empty() {
        return violation(
            format!(
                "binding `{}` has no establishing initializer in evidence",
                binding.name
            ),
            Some(binding),
        );
    }
    let all_literal = establishing
        .iter()
        .all(|right| right.is_some_and(|ast_id| literals.contains(ast_id)));
    if all_literal {
        return None;
    }
    violation(
        format!(
            "binding `{}` is established by an initializer that is not a collection literal with at most {} elements",
            binding.name, assertion.max_elements
        ),
        Some(binding),
    )
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
    // An empty exact-path list is an unrestricted seed; a caller with no
    // subject files must skip the query instead of scanning the workspace.
    assert!(
        !paths.is_empty(),
        "assertion generation queries require subject paths"
    );
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
    for location in &violation.derivation_locations {
        push(
            PolicyLocationRelationship::Evidence,
            location.clone(),
            &mut related,
        )?;
    }
    if let Some(binding) = violation.binding {
        push(
            PolicyLocationRelationship::BindingOf,
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
        // The identity families derive their own rows with targets; a row
        // without them cannot answer this question, and saying "no
        // declarations" would be a claim the row does not support.
        InternalOccurrenceTarget::NotDerived => None,
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
