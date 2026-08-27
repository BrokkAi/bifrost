use std::collections::HashMap;
use std::fmt;
use std::ops::Range as ByteRange;
use std::sync::Arc;

use crate::definition::{RowBindingName, RowBindingSource, RowExpansionStep};
use crate::relational::{
    RelationCoverage, RelationalInput, evaluate_row_selector_ir, validate_row_selector_plan,
};
use crate::{PolicyWorkMetric, PolicyWorkReport, PolicyWorkUnit, ResolvedPolicySelector};
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::semantic::{
    EvidenceCompleteness, ProofStatus, SemanticArtifact, SemanticBudget, SemanticBudgetDimension,
    SemanticExecutionBudget, SemanticRequest, SemanticWork,
};
use brokk_bifrost_analysis::analyzer::{ProjectFile, Range, WorkspaceAnalyzer};
use brokk_bifrost_rql::structural::search::{
    DetailedCodeQueryDomain, execute_code_query_detailed_eager_index_workspace,
};
use brokk_bifrost_rql::structural::{
    CodeQueryCompletion, CodeQueryDiagnosticCode, CodeQueryExecutionLimits, CodeQueryExecutionWork,
    CodeQueryResultDetail, CodeQueryResultItem, CodeQueryResultValue,
    CodeQuerySemanticCompleteness, CodeQuerySemanticEvidence, CodeQuerySemanticLimits,
    CodeQuerySemanticProof, CodeQuerySemanticRowLimits, CodeQuerySemanticWork, QueryValueKind,
};
use brokk_bifrost_rql::{CallInputSelector, CodeQuery, QueryStep};

#[derive(Debug)]
pub(super) enum PolicySelectorSessionError {
    Incomplete {
        completion: CodeQueryCompletion,
        detail: String,
    },
    Unavailable(String),
    Provider(String),
}

impl fmt::Display for PolicySelectorSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { detail, .. }
            | Self::Unavailable(detail)
            | Self::Provider(detail) => formatter.write_str(detail),
        }
    }
}

#[derive(Clone)]
pub(super) struct PolicySelectedSite {
    pub(super) file: ProjectFile,
    pub(super) span: ByteRange<usize>,
    pub(super) proof: ProofStatus,
    pub(super) completeness: EvidenceCompleteness,
    pub(super) call_binding: Option<PolicySelectedCallBinding>,
}

/// Exact relational identity retained from one selected `call_binding` row.
///
/// `actual_index` is the caller-side operand ordinal. `formal_index` is kept
/// only as evidence and must never be passed to a `PolicyPort::ArgumentIndex`.
#[derive(Clone)]
pub(super) struct PolicySelectedCallBinding {
    pub(super) row_id: String,
    pub(super) site_id: String,
    pub(super) site_ast_id: String,
    pub(super) argument_id: String,
    pub(super) call_span: ByteRange<usize>,
    pub(super) actual_index: usize,
    pub(super) formal_index: usize,
    pub(super) formal_name: String,
    pub(super) semantic_target_id: String,
    pub(super) signature_id: String,
    pub(super) model_id: String,
    pub(super) pack_id: Option<String>,
}

impl PolicySelectedCallBinding {
    pub(super) fn assert_valid_identity(&self) {
        debug_assert!(!self.row_id.is_empty());
        debug_assert!(!self.site_id.is_empty());
        debug_assert!(!self.site_ast_id.is_empty());
        debug_assert!(!self.argument_id.is_empty());
        debug_assert!(!self.semantic_target_id.is_empty());
        debug_assert!(!self.signature_id.is_empty());
        debug_assert!(!self.model_id.is_empty());
        debug_assert!(self.pack_id.as_ref().is_none_or(|pack| !pack.is_empty()));
    }
}

pub(super) struct PolicySelectorSession<'a> {
    workspace: &'a WorkspaceAnalyzer,
    analysis: &'static str,
    query_limits: CodeQueryExecutionLimits,
    max_selector_results: usize,
    cancellation: &'a CancellationToken,
    semantic_budget: SemanticBudget,
    semantic_execution_budget: SemanticExecutionBudget,
    query_work: CodeQueryExecutionWork,
    artifacts: HashMap<ProjectFile, Arc<SemanticArtifact>>,
    materialized_files_limit: usize,
    // Semantic work retired by prior regions. `reset_region_semantic_budget`
    // replaces the live budgets, so their `used`/`work` counters only reflect
    // the current region; without this the reported work would collapse to the
    // last region's consumption. Accumulating the consumed counters here keeps
    // the compile-wide work report accurate. The materialization cache charges
    // each distinct file once, in whichever region first pulls it, so summing
    // per-region charges still totals distinct materializations, not duplicates.
    retired_program_points: usize,
    retired_source_bytes: usize,
    retired_materialized_files: usize,
    retired_traversal_steps: usize,
    // The largest single-region charge each per-region lane saw.  The lane
    // limits are per region -- `reset_region_semantic_budget` restores them --
    // so the quantity a lane must exceed for the compile to finish is the peak
    // one region reaches, not the sum the retired counters above accumulate.
    // These are the calibration inputs the derived-lane model never had (#1936).
    peak_row_dimension: usize,
    peak_retained_bytes: usize,
    peak_traversal_steps: usize,
    // How many procedure value-flow snapshots this compile actually built
    // through the semantic oracle, as opposed to reusing from the per-compile
    // materialization cache (#2284). The per-region budget resets above hide
    // this in the program-point total, and the program-point total also mixes
    // in dispatch, binding, and solve work, so a repeated materialization is
    // not visible there. This counter is: it must equal the number of distinct
    // procedures the compile reached, whatever their snapshots' completeness.
    semantic_snapshot_materializations: u64,
    // How many procedure visits this compile served on a handle that named a
    // second materialization of an artifact it had already seen (#2289). Keyed
    // on handles, each of those visits missed the discovery cache and re-ran
    // the oracle for the procedure's snapshot, each of its call sites'
    // dispatch, and each candidate's bindings; keyed durably they are hits. A
    // non-zero value here means the byte-bounded artifact cache is evicting
    // files this compile is still walking, which is worth knowing on its own.
    semantic_handle_identity_reuses: u64,
    // How many selector entries this compile scanned.  Each scan is granted the
    // whole-workspace scan allowance (see `remaining_query_limits`), so this is
    // the multiplier on that allowance the compile actually spent.
    selector_scans: u64,
}

impl<'a> PolicySelectorSession<'a> {
    pub(super) fn new(
        workspace: &'a WorkspaceAnalyzer,
        analysis: &'static str,
        query_limits: CodeQueryExecutionLimits,
        max_selector_results: usize,
        cancellation: &'a CancellationToken,
    ) -> Self {
        // Size the materialized-file budget to the workspace, not the fixed
        // per-query IDE cap. That cap bounds how much a single interactive query
        // loads; a policy compile is a whole-workspace analysis that must reach
        // every source and sink, so on a corpus larger than the cap the endpoint
        // enumeration exhausts it before discovery even begins and the whole
        // compile abstains (#1936). The content-keyed materialization cache makes
        // the real cost proportional to distinct files, which cannot exceed the
        // project file count, so this is a principled bound rather than an
        // uncapped one. `max` keeps the per-query default as the floor, so a
        // small workspace is unaffected. The per-region traversal budget, reset
        // in `reset_region_semantic_budget`, still bounds each region's work.
        let materialized_files_limit = query_limits
            .semantic
            .max_materialized_files
            .max(workspace.project_file_count());
        Self {
            workspace,
            analysis,
            query_limits,
            max_selector_results,
            cancellation,
            semantic_budget: SemanticBudget::new(semantic_work_limits(query_limits.semantic))
                .expect("validated CodeQuery semantic limits are positive"),
            semantic_execution_budget: SemanticExecutionBudget::new(
                materialized_files_limit,
                query_limits.semantic.max_traversal_steps,
            ),
            query_work: CodeQueryExecutionWork::default(),
            artifacts: HashMap::new(),
            materialized_files_limit,
            retired_program_points: 0,
            retired_source_bytes: 0,
            retired_materialized_files: 0,
            retired_traversal_steps: 0,
            peak_row_dimension: 0,
            peak_retained_bytes: 0,
            peak_traversal_steps: 0,
            semantic_snapshot_materializations: 0,
            semantic_handle_identity_reuses: 0,
            selector_scans: 0,
        }
    }

    /// Record that discovery built one procedure value-flow snapshot through
    /// the oracle rather than reusing a cached one (#2284).
    pub(super) fn record_semantic_snapshot_materialization(&mut self) {
        self.semantic_snapshot_materializations =
            self.semantic_snapshot_materializations.saturating_add(1);
    }

    /// Record how many procedure visits this compile served on a handle from a
    /// second materialization of one artifact (#2289).
    pub(super) fn record_semantic_handle_identity_reuses(&mut self, reuses: u64) {
        self.semantic_handle_identity_reuses =
            self.semantic_handle_identity_reuses.saturating_add(reuses);
    }

    /// Reset the semantic and execution budgets to their per-region starting
    /// limits.
    ///
    /// Require-model taint discovers and solves each source-to-sink region
    /// independently (#1935). Charging every region against one shared budget
    /// makes an N-file corpus abstain by accumulation, even though each region's
    /// own materialization is small: at corpus scale the shared `nested_entries`
    /// lane crosses its cap after ~76 files and the whole compile aborts.
    /// Resetting per region bounds each region on its own and lets independent
    /// flows all be analyzed. The shared materialization caches (the `#1936`
    /// discovery cache and the semantic artifact cache) are untouched, so
    /// cross-region work stays amortized and each region's budget only accounts
    /// for the material it newly pulls.
    pub(super) fn reset_region_semantic_budget(&mut self) {
        // Retire the finishing region's consumed work before the counters are
        // discarded, so the compile-wide work report stays a running total.
        let used = self.semantic_budget.used();
        self.retired_program_points = self
            .retired_program_points
            .saturating_add(used.program_points);
        self.retired_source_bytes = self.retired_source_bytes.saturating_add(used.source_bytes);
        let execution = self.semantic_execution_budget.work();
        self.retired_materialized_files = self
            .retired_materialized_files
            .saturating_add(execution.materialized_files);
        self.retired_traversal_steps = self
            .retired_traversal_steps
            .saturating_add(execution.traversal_steps);
        let (row_peak, retained_peak, traversal_peak) = self.live_region_peaks();
        self.peak_row_dimension = self.peak_row_dimension.max(row_peak);
        self.peak_retained_bytes = self.peak_retained_bytes.max(retained_peak);
        self.peak_traversal_steps = self.peak_traversal_steps.max(traversal_peak);

        self.semantic_budget =
            SemanticBudget::new(semantic_work_limits(self.query_limits.semantic))
                .expect("validated CodeQuery semantic limits are positive");
        self.semantic_execution_budget = SemanticExecutionBudget::new(
            self.materialized_files_limit,
            self.query_limits.semantic.max_traversal_steps,
        );
    }

    /// The source spans of the actuals one selector's call sites pass to the
    /// formal named `name`, through the analyzer's own actual-to-formal
    /// relation (`call-input :parameter-name`, issue #2438).
    ///
    /// This is the second of the two sources a formal-name port reads. The
    /// dispatch-aware oracle relation is the first and the authoritative one,
    /// but the semantic call row records only that an actual is a keyword
    /// argument, never which keyword, so the oracle retains no mapping for
    /// `put(value=x)`. The structural relation reads the label from the call's
    /// own syntax and is exactly what `(call-input :parameter-name "value")`
    /// publishes, so a port and a query row cannot disagree about which operand
    /// the formal names.
    ///
    /// The result is a flat span list per file, not a per-call map, because a
    /// row's evidence carries only its own byte span. The caller intersects it
    /// with one selected call's own operand spans, which is what distinguishes
    /// a nested call's actual from the enclosing call's.
    pub(super) fn select_named_actuals(
        &mut self,
        selector: &ResolvedPolicySelector,
        name: &str,
    ) -> Result<Vec<(ProjectFile, ByteRange<usize>)>, PolicySelectorSessionError> {
        let Some((_, query)) = selector.as_query() else {
            return Err(PolicySelectorSessionError::Unavailable(format!(
                "selector `{}` is relational; its exact call-binding row must supply the actual directly",
                selector.path
            )));
        };
        let mut query = query.clone();
        query.limit = self.max_selector_results;
        query
            .plan
            .steps
            .push(QueryStep::CallInput(CallInputSelector::ParameterName(
                name.to_owned(),
            )));
        // A selector that does not end at call sites cannot carry a call-input
        // step. That is a typed shortfall of this route, not a failure: the
        // caller falls back to refusing the row with a named reason.
        if query.validate_steps().is_err() {
            return Ok(Vec::new());
        }
        self.selector_scans = self.selector_scans.saturating_add(1);
        let detailed = execute_code_query_detailed_eager_index_workspace(
            self.workspace,
            &query,
            self.remaining_query_limits()?,
            Some(self.cancellation),
        );
        self.query_work = self.query_work.saturating_add(detailed.work);
        self.charge_query_semantic_work(detailed.work.semantic)?;
        if !matches!(detailed.result.completion(), CodeQueryCompletion::Complete) {
            return Ok(Vec::new());
        }
        Ok(detailed
            .evidence
            .into_iter()
            .filter(|evidence| matches!(evidence.domain, DetailedCodeQueryDomain::ExpressionSite))
            .filter_map(|evidence| Some((evidence.file, evidence.byte_span?)))
            .collect())
    }

    pub(super) fn select(
        &mut self,
        selector: &ResolvedPolicySelector,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        if let Some(plan) = selector.as_rows() {
            return self.select_rows(selector, plan);
        }
        // A policy batch runs many selectors against one immutable snapshot,
        // so index reuse is guaranteed: build it on the first selector rather
        // than letting Auto's first-request deferral turn the whole batch
        // into repeated full-workspace scans.
        //
        // Endpoint selection must bind every matching site, not the interactive
        // pagination sample the selector query carries: the catalog validates
        // the authored `limit` to the shared `DEFAULT_LIMIT` of 100, which
        // truncates a corpus-scale source or sink selector before binding and
        // fails the compile closed (#1935). Raise the selection result cap to
        // the host-controlled policy bound; the structural pipeline budget
        // still governs honest truncation above it.
        let (_, query) = selector.as_query().ok_or_else(|| {
            PolicySelectorSessionError::Unavailable(format!(
                "selector `{}` has no executable query kind",
                selector.path
            ))
        })?;
        let mut query = query.clone();
        query.limit = self.max_selector_results;
        self.selector_scans = self.selector_scans.saturating_add(1);
        let detailed = execute_code_query_detailed_eager_index_workspace(
            self.workspace,
            &query,
            self.remaining_query_limits()?,
            Some(self.cancellation),
        );
        self.query_work = self.query_work.saturating_add(detailed.work);
        self.charge_query_semantic_work(detailed.work.semantic)?;
        if !matches!(detailed.result.completion(), CodeQueryCompletion::Complete) {
            let diagnostics = detailed
                .result
                .diagnostics
                .iter()
                .map(|diagnostic| format!("{}: {}", diagnostic.code.as_str(), diagnostic.message))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(PolicySelectorSessionError::Incomplete {
                completion: detailed.result.completion(),
                detail: format!("`{}` ({diagnostics})", selector.path),
            });
        }
        detailed
            .evidence
            .into_iter()
            .filter(|evidence| !matches!(evidence.domain, DetailedCodeQueryDomain::File))
            .map(|evidence| {
                let item = detailed
                    .result
                    .results
                    .get(evidence.result_index)
                    .ok_or_else(|| {
                        PolicySelectorSessionError::Unavailable(format!(
                            "selector `{}` evidence refers to an absent result row",
                            selector.path
                        ))
                    })?;
                let span = evidence.byte_span.ok_or_else(|| {
                    PolicySelectorSessionError::Unavailable(format!(
                        "selector `{}` produced a row without a source span",
                        selector.path
                    ))
                })?;
                let (proof, completeness) = selected_site_quality(item);
                Ok(PolicySelectedSite {
                    file: evidence.file,
                    span,
                    proof,
                    completeness,
                    call_binding: None,
                })
            })
            .collect()
    }

    fn select_rows(
        &mut self,
        selector: &ResolvedPolicySelector,
        plan: &crate::definition::RowSelectorPlan,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        let lowered = validate_row_selector_plan(plan).map_err(|error| {
            PolicySelectorSessionError::Unavailable(format!(
                "selector `{}` has an invalid row plan: {error}",
                selector.path
            ))
        })?;
        let binding_queries = row_binding_queries(plan)?;
        let mut executed = Vec::with_capacity(binding_queries.len());
        let mut coverages = Vec::with_capacity(binding_queries.len());
        let mut incomplete_completion = None;
        let mut diagnostics = Vec::new();

        for (binding, mut query) in binding_queries {
            query.result_detail = CodeQueryResultDetail::Full;
            query.limit = self.max_selector_results;
            self.selector_scans = self.selector_scans.saturating_add(1);
            let detailed = execute_code_query_detailed_eager_index_workspace(
                self.workspace,
                &query,
                self.remaining_query_limits()?,
                Some(self.cancellation),
            );
            self.query_work = self.query_work.saturating_add(detailed.work);
            self.charge_query_semantic_work(detailed.work.semantic)?;
            let completion = detailed.result.completion();
            let coverage = match &completion {
                CodeQueryCompletion::Complete if !detailed.result.truncated => {
                    RelationCoverage::Exhaustive
                }
                CodeQueryCompletion::ProvenSubset { .. } => RelationCoverage::ProvenSubset,
                _ => RelationCoverage::incomplete(vec![
                    crate::PolicyIncompleteReason::PartialDiscovery,
                ]),
            };
            if !matches!(completion, CodeQueryCompletion::Complete) || detailed.result.truncated {
                incomplete_completion.get_or_insert(completion);
            }
            diagnostics.extend(detailed.result.diagnostics.iter().map(|diagnostic| {
                format!(
                    "{}: {}: {}",
                    binding.as_str(),
                    diagnostic.code.as_str(),
                    diagnostic.message
                )
            }));
            coverages.push(coverage);
            executed.push((binding, detailed));
        }

        let inputs = executed
            .iter()
            .zip(&coverages)
            .map(|((binding, detailed), coverage)| RelationalInput {
                binding,
                rows: &detailed.result.results,
                coverage: coverage.clone(),
            })
            .collect::<Vec<_>>();
        let selection = evaluate_row_selector_ir(
            &lowered.plan,
            lowered.relation,
            lowered.upstream,
            &lowered.upstream_binding,
            &inputs,
        )
        .map_err(|error| {
            PolicySelectorSessionError::Unavailable(format!(
                "selector `{}` row evaluation failed: {error}",
                selector.path
            ))
        })?;

        let upstream = executed
            .iter()
            .find(|(binding, _)| *binding == lowered.upstream_binding)
            .ok_or_else(|| {
                PolicySelectorSessionError::Unavailable(format!(
                    "selector `{}` did not execute output binding `{}`",
                    selector.path, lowered.upstream_binding
                ))
            })?;
        let uncertain_upstream = selection.upstream_rows.iter().any(|row| {
            upstream.1.result.results.get(row.row).is_none_or(|item| {
                if matches!(
                    &item.value,
                    CodeQueryResultValue::CallBinding { value }
                        if value.binding_kind == Some("receiver")
                ) {
                    return false;
                }
                let (proof, completeness) = selected_site_quality(item);
                !matches!(proof, ProofStatus::Proven)
                    || !matches!(completeness, EvidenceCompleteness::Complete)
            })
        });
        let incomplete = incomplete_completion.is_some()
            || !selection.upstream_coverage.is_exhaustive()
            || !selection.selected_coverage.is_exhaustive()
            || selection.limit_exceeded
            || uncertain_upstream;
        if selection.selected_rows.is_empty() && incomplete {
            return Err(PolicySelectorSessionError::Incomplete {
                completion: incomplete_completion
                    .unwrap_or(CodeQueryCompletion::Incomplete { codes: Vec::new() }),
                detail: format!(
                    "selector `{}` could not prove an empty row selection{}",
                    selector.path,
                    if diagnostics.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", diagnostics.join("; "))
                    }
                ),
            });
        }

        selection
            .selected_rows
            .into_iter()
            .map(|selected| {
                let item = upstream.1.result.results.get(selected.row).ok_or_else(|| {
                    PolicySelectorSessionError::Unavailable(format!(
                        "selector `{}` selected an absent row",
                        selector.path
                    ))
                })?;
                let evidence = upstream
                    .1
                    .evidence
                    .iter()
                    .find(|evidence| evidence.result_index == selected.row)
                    .ok_or_else(|| {
                        PolicySelectorSessionError::Unavailable(format!(
                            "selector `{}` selected a row without source evidence",
                            selector.path
                        ))
                    })?;
                let span = evidence.byte_span.clone().ok_or_else(|| {
                    PolicySelectorSessionError::Unavailable(format!(
                        "selector `{}` selected a row without a source span",
                        selector.path
                    ))
                })?;
                let CodeQueryResultValue::CallBinding { value } = &item.value else {
                    return Err(PolicySelectorSessionError::Unavailable(format!(
                        "selector `{}` output is not a call-binding row",
                        selector.path
                    )));
                };
                let call_span = self.call_span_for_ast_id(&evidence.file, &value.site_ast_id)?;
                let (proof, mut completeness) = selected_site_quality(item);
                if incomplete {
                    completeness = EvidenceCompleteness::Partial(
                        "row selector input or filtered output was not exhaustive".into(),
                    );
                }
                Ok(PolicySelectedSite {
                    file: evidence.file.clone(),
                    span,
                    proof,
                    completeness,
                    call_binding: Some(PolicySelectedCallBinding {
                        row_id: value.id.clone(),
                        site_id: value.site_id.clone(),
                        site_ast_id: value.site_ast_id.clone(),
                        argument_id: value.argument_id.clone().ok_or_else(|| {
                            PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` selected a binding without an argument identity",
                                selector.path
                            ))
                        })?,
                        call_span,
                        actual_index: value.actual_index.ok_or_else(|| {
                            PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` selected a binding without an actual index",
                                selector.path
                            ))
                        })?,
                        formal_index: value.formal_index.ok_or_else(|| {
                            PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` selected a binding without a formal index",
                                selector.path
                            ))
                        })?,
                        formal_name: value.formal_name.clone().ok_or_else(|| {
                            PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` selected a binding without a formal name",
                                selector.path
                            ))
                        })?,
                        semantic_target_id: value.semantic_target_id.clone().ok_or_else(|| {
                            PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` selected a binding without semantic target identity",
                                selector.path
                            ))
                        })?,
                        signature_id: value.signature_id.clone().ok_or_else(|| {
                            PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` selected a binding without signature identity",
                                selector.path
                            ))
                        })?,
                        model_id: value.model_id.clone().ok_or_else(|| {
                            PolicySelectorSessionError::Unavailable(format!(
                                "selector `{}` selected a binding without model identity",
                                selector.path
                            ))
                        })?,
                        pack_id: value.pack_id.clone(),
                    }),
                })
            })
            .collect()
    }

    fn call_span_for_ast_id(
        &self,
        file: &ProjectFile,
        expected_ast_id: &str,
    ) -> Result<ByteRange<usize>, PolicySelectorSessionError> {
        let facts = self
            .workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| provider.structural_facts(file))
            .ok_or_else(|| {
                PolicySelectorSessionError::Unavailable(format!(
                    "call-binding site identity cannot be resolved for `{}`",
                    file
                ))
            })?;
        let mut matches = facts.nodes().iter().enumerate().filter(|(index, _)| {
            brokk_bifrost_analysis::analyzer::structural::occurrence_rows::ast_id(
                facts.source_identity(),
                u32::try_from(*index).expect("facts arena node IDs fit u32"),
            ) == expected_ast_id
        });
        let (_, node) = matches.next().ok_or_else(|| {
            PolicySelectorSessionError::Unavailable(
                "selected call-binding AST identity is absent from structural facts".to_owned(),
            )
        })?;
        if matches.next().is_some() {
            return Err(PolicySelectorSessionError::Unavailable(
                "selected call-binding AST identity is ambiguous".to_owned(),
            ));
        }
        Ok(node.range.start_byte..node.range.end_byte)
    }

    pub(super) fn workspace(&self) -> &'a WorkspaceAnalyzer {
        self.workspace
    }

    pub(super) fn cancellation(&self) -> &'a CancellationToken {
        self.cancellation
    }

    pub(super) fn semantic_request(&mut self) -> SemanticRequest<'_> {
        SemanticRequest::with_execution_budget(
            &mut self.semantic_budget,
            self.cancellation,
            &self.semantic_execution_budget,
        )
    }

    pub(super) fn execution_budget(&self) -> &SemanticExecutionBudget {
        &self.semantic_execution_budget
    }

    pub(super) fn semantic_used(&self) -> SemanticWork {
        self.semantic_budget.used()
    }

    pub(super) fn semantic_remaining(&self) -> SemanticWork {
        self.semantic_budget.remaining()
    }

    pub(super) fn query_work(&self) -> CodeQueryExecutionWork {
        self.query_work
    }

    pub(super) fn materialized_artifacts(&self) -> impl Iterator<Item = &Arc<SemanticArtifact>> {
        self.artifacts.values()
    }

    pub(super) fn remember_artifact(&mut self, file: ProjectFile, artifact: Arc<SemanticArtifact>) {
        self.artifacts.entry(file).or_insert(artifact);
    }

    pub(super) fn materialize(
        &mut self,
        file: &ProjectFile,
    ) -> Result<Arc<SemanticArtifact>, PolicySelectorSessionError> {
        if let Some(artifact) = self.artifacts.get(file) {
            return Ok(Arc::clone(artifact));
        }
        let workspace = self.workspace;
        let outcome = {
            let mut request = self.semantic_request();
            workspace
                .materialize_program_semantics(file, &mut request)
                .map_err(|error| PolicySelectorSessionError::Provider(error.to_string()))?
        };
        self.require_uninterrupted(&outcome, "program semantics materialization")?;
        self.require_execution_budget("program semantics materialization")?;
        let artifact = outcome.available_value().cloned().ok_or_else(|| {
            PolicySelectorSessionError::Unavailable(format!(
                "program semantics are unavailable for {}",
                file.abs_path().display()
            ))
        })?;
        self.artifacts.insert(file.clone(), Arc::clone(&artifact));
        Ok(artifact)
    }

    pub(super) fn remaining_semantic_traversal_steps(
        &self,
    ) -> Result<usize, PolicySelectorSessionError> {
        let remaining = self.semantic_execution_budget.remaining_traversal_steps();
        if remaining == 0 {
            Err(semantic_budget_error(format!(
                "{} semantic lookup exhausted the shared traversal budget",
                self.analysis
            )))
        } else {
            Ok(remaining)
        }
    }

    pub(super) fn require_execution_budget(
        &self,
        operation: &str,
    ) -> Result<(), PolicySelectorSessionError> {
        if self.semantic_execution_budget.work().exhausted {
            Err(semantic_budget_error(format!(
                "{operation} exhausted the shared semantic file or traversal budget"
            )))
        } else {
            Ok(())
        }
    }

    pub(super) fn require_uninterrupted<T>(
        &self,
        outcome: &brokk_bifrost_analysis::analyzer::semantic::SemanticOutcome<T>,
        operation: &str,
    ) -> Result<(), PolicySelectorSessionError> {
        use brokk_bifrost_analysis::analyzer::semantic::SemanticOutcome;
        match outcome {
            SemanticOutcome::Cancelled { .. } => Err(PolicySelectorSessionError::Incomplete {
                completion: CodeQueryCompletion::Cancelled,
                detail: format!("{operation} was cancelled"),
            }),
            SemanticOutcome::ExceededBudget { exceeded, .. } => Err(semantic_budget_error(
                format!("{operation} exceeded the shared semantic budget: {exceeded}"),
            )),
            _ => Ok(()),
        }
    }

    pub(super) fn work_report(&self, analysis: &str) -> PolicyWorkReport {
        // Report retired regions' work plus the live region's, so per-region
        // budget resets do not hide the compile's cumulative semantic cost.
        let semantic = self.semantic_budget.used();
        let execution = self.semantic_execution_budget.work();
        let (live_row_peak, live_retained_peak, live_traversal_peak) = self.live_region_peaks();
        let metrics = [
            (
                "semantic_materialized_files",
                PolicyWorkUnit::Count,
                self.retired_materialized_files
                    .saturating_add(execution.materialized_files),
            ),
            (
                "semantic_traversal_steps",
                PolicyWorkUnit::Count,
                self.retired_traversal_steps
                    .saturating_add(execution.traversal_steps),
            ),
            (
                "semantic_source_bytes",
                PolicyWorkUnit::Bytes,
                self.retired_source_bytes
                    .saturating_add(semantic.source_bytes),
            ),
            (
                "semantic_program_points",
                PolicyWorkUnit::Rows,
                self.retired_program_points
                    .saturating_add(semantic.program_points),
            ),
            // Each selector entry's subject scan is granted the whole-workspace
            // scan allowance, so this count is the multiplier on that allowance
            // the compile spent.  Reporting it keeps the compile's total scan
            // cost auditable instead of implicit in the entry list.
            (
                "selector_scans",
                PolicyWorkUnit::Count,
                usize::try_from(self.selector_scans).unwrap_or(usize::MAX),
            ),
            // The three per-region lane peaks.  The retired counters above are
            // sums across regions, which is the compile's total cost but not
            // what any lane has to admit: the lanes reset per region, so a lane
            // has to exceed the largest single region's charge.  These are the
            // numbers the derived-lane model must be calibrated against (#1936).
            (
                "semantic_peak_row_dimension",
                PolicyWorkUnit::Rows,
                self.peak_row_dimension.max(live_row_peak),
            ),
            (
                "semantic_peak_retained_bytes",
                PolicyWorkUnit::Bytes,
                self.peak_retained_bytes.max(live_retained_peak),
            ),
            (
                "semantic_peak_traversal_steps",
                PolicyWorkUnit::Count,
                self.peak_traversal_steps.max(live_traversal_peak),
            ),
        ]
        .into_iter()
        .filter_map(|(name, unit, value)| {
            PolicyWorkMetric::try_new(
                format!("{analysis}.{name}"),
                unit,
                u64::try_from(value).unwrap_or(u64::MAX),
            )
            .ok()
        })
        // Reported only by an analysis that materializes value-flow snapshots,
        // so an analysis that never does is not given a permanent zero (#2284).
        .chain(
            (self.semantic_snapshot_materializations > 0)
                .then(|| {
                    PolicyWorkMetric::try_new(
                        format!("{analysis}.semantic_snapshot_materializations"),
                        PolicyWorkUnit::Count,
                        self.semantic_snapshot_materializations,
                    )
                    .ok()
                })
                .flatten(),
        )
        // Reported only when artifact-cache pressure actually presented one
        // procedure through two materializations, so an ordinary compile is
        // not given a permanent zero (#2289).
        .chain(
            (self.semantic_handle_identity_reuses > 0)
                .then(|| {
                    PolicyWorkMetric::try_new(
                        format!("{analysis}.semantic_handle_identity_reuses"),
                        PolicyWorkUnit::Count,
                        self.semantic_handle_identity_reuses,
                    )
                    .ok()
                })
                .flatten(),
        )
        .collect();
        PolicyWorkReport::try_new(
            self.query_work.scanned_files,
            self.query_work.scanned_source_bytes,
            self.query_work.fact_nodes,
            self.query_work.pipeline_rows,
            self.query_work.examined_references,
            0,
            0,
            0,
            metrics,
        )
        .unwrap_or_default()
    }

    /// The current region's charge against each per-region lane, as
    /// `(largest row dimension, retained bytes, traversal steps)`.
    ///
    /// This calibrates `PolicyBudget`'s row lane, and that lane is one
    /// uniform `max_rows_per_dimension` granted to every row dimension, so
    /// the charge it must exceed is the largest single dimension's, not any
    /// one dimension's on its own. Queries inside the region are now capped
    /// per dimension from this budget's own remainders (#2523), but what is
    /// being calibrated here is still the uniform grant those remainders
    /// start from.
    fn live_region_peaks(&self) -> (usize, usize, usize) {
        let used = self.semantic_budget.used();
        let row_peak = CodeQuerySemanticRowLimits::ROW_DIMENSIONS
            .into_iter()
            .map(|dimension| used.get(dimension))
            .max()
            .unwrap_or(0);
        (
            row_peak,
            used.owned_text_bytes,
            self.semantic_execution_budget.work().traversal_steps,
        )
    }

    /// What one more selector query may spend, taken from this session's own
    /// shared ledger.
    ///
    /// The row lanes are published per dimension rather than collapsed. They
    /// deplete at wildly different rates -- `nested_entries` is a census of
    /// every artifact's nested collections and also the dispatch walk's
    /// exploration lane, while `procedures` counts one row per procedure --
    /// so one whole-workspace bind can legitimately spend most of the first
    /// while barely touching the second. Reporting the minimum of the
    /// remainders as a uniform cap made every later query in the session run
    /// against the most depleted lane: on google/gson, reference policy B's
    /// second bind published verdicts for 6 of its 98 marked procedures
    /// before it stopped (#2523). Each dimension now carries its own
    /// remainder, so a drained lane bounds itself and nothing else.
    ///
    /// The uniform scalar stays populated with the minimum. It is not read
    /// while the table is present, and the minimum is the value that cannot
    /// overrun any lane if some later consumer reads it alone.
    fn remaining_query_limits(
        &self,
    ) -> Result<CodeQueryExecutionLimits, PolicySelectorSessionError> {
        let semantic_remaining = self.semantic_budget.remaining();
        let semantic = CodeQuerySemanticLimits {
            max_materialized_files: self
                .semantic_execution_budget
                .remaining_materialized_files(),
            max_source_bytes: semantic_remaining.source_bytes,
            max_rows_per_dimension: CodeQuerySemanticRowLimits::ROW_DIMENSIONS
                .into_iter()
                .map(|dimension| semantic_remaining.get(dimension))
                .min()
                .unwrap_or(0),
            max_retained_bytes: semantic_remaining.owned_text_bytes,
            max_traversal_steps: self.remaining_semantic_traversal_steps()?,
            rows_per_dimension: Some(CodeQuerySemanticRowLimits::from_rows(|dimension| {
                semantic_remaining.get(dimension)
            })),
        };
        if !semantic.all_positive() {
            return Err(semantic_budget_error(format!(
                "{} selectors exhausted the shared semantic query budget",
                self.analysis
            )));
        }
        // The structural scan lanes are granted per selector entry, not shared
        // across the compile.  `PolicyBudget::scaled_for_workspace` sizes them to
        // one whole-workspace subject scan because that is what one selector
        // costs: Theta(workspace facts) (#1771).  Deducting each entry's scan
        // from the next entry's allowance therefore divides one whole-workspace
        // allowance across every source and sink a policy declares, so the
        // first entries consume it and the rest cannot run at all.  On OWASP
        // BenchmarkJava (2766 files, 11.5MB; scaled lane 5532 files, 23.1MB)
        // the third of the taint policy's nine selector entries was left 639
        // files and 2.57MB, exhausted mid-scan, and every category abstained
        // (#1935).  Each entry now gets the whole-workspace allowance; the
        // compile total stays bounded because `select` runs exactly once per
        // declared entry and the policy schema bounds those sets (`:entries`
        // is `SET_256` for sources and for sinks, and the registry bounds
        // match-directory endpoints at `MAX_REGISTERED_ENDPOINTS`).  The
        // `selector_scans` metric reports the multiplier this compile actually
        // used, so the total cost stays auditable rather than implicit.
        //
        // `max_pipeline_rows` bounds one query's materialized rows rather than
        // workspace volume, so it was never a shared quantity either; it is
        // per-query by construction.
        Ok(CodeQueryExecutionLimits {
            max_scanned_files: self.query_limits.max_scanned_files,
            max_scanned_source_bytes: self.query_limits.max_scanned_source_bytes,
            max_fact_nodes: self.query_limits.max_fact_nodes,
            max_pipeline_rows: self.query_limits.max_pipeline_rows,
            semantic,
            typestate: self.query_limits.typestate,
            value_flow: self.query_limits.value_flow,
            taint: self.query_limits.taint,
        })
    }

    fn charge_query_semantic_work(
        &mut self,
        work: CodeQuerySemanticWork,
    ) -> Result<(), PolicySelectorSessionError> {
        let usize_work = |value| usize::try_from(value).unwrap_or(usize::MAX);
        if !self.semantic_execution_budget.charge_external_query_work(
            usize_work(work.unique_materialized_files),
            usize_work(work.traversal_steps),
        ) {
            return Err(semantic_budget_error(format!(
                "{} selectors exhausted the shared semantic execution budget",
                self.analysis
            )));
        }
        self.semantic_budget
            .charge(SemanticWork {
                source_bytes: usize_work(work.source_bytes),
                procedures: usize_work(work.procedures),
                blocks: usize_work(work.blocks),
                program_points: usize_work(work.program_points),
                values: usize_work(work.values),
                allocations: usize_work(work.allocations),
                call_sites: usize_work(work.call_sites),
                memory_locations: usize_work(work.memory_locations),
                captures: usize_work(work.captures),
                source_mappings: usize_work(work.source_mappings),
                evidence: usize_work(work.evidence),
                gaps: usize_work(work.gaps),
                events: usize_work(work.events),
                control_edges: usize_work(work.control_edges),
                nested_entries: usize_work(work.nested_entries),
                owned_text_bytes: usize_work(work.retained_bytes),
            })
            .map_err(|_| {
                semantic_budget_error(format!(
                    "{} selectors exhausted the shared semantic materialization budget",
                    self.analysis
                ))
            })
    }
}

fn semantic_budget_error(detail: impl Into<String>) -> PolicySelectorSessionError {
    PolicySelectorSessionError::Incomplete {
        completion: CodeQueryCompletion::Incomplete {
            codes: vec![CodeQueryDiagnosticCode::SemanticBudgetExhausted],
        },
        detail: detail.into(),
    }
}

pub(super) fn semantic_work_limits(limits: CodeQuerySemanticLimits) -> SemanticWork {
    use SemanticBudgetDimension as Dimension;
    SemanticWork {
        source_bytes: limits.max_source_bytes,
        procedures: limits.rows(Dimension::Procedures),
        blocks: limits.rows(Dimension::Blocks),
        program_points: limits.rows(Dimension::ProgramPoints),
        values: limits.rows(Dimension::Values),
        allocations: limits.rows(Dimension::Allocations),
        call_sites: limits.rows(Dimension::CallSites),
        memory_locations: limits.rows(Dimension::MemoryLocations),
        captures: limits.rows(Dimension::Captures),
        source_mappings: limits.rows(Dimension::SourceMappings),
        evidence: limits.rows(Dimension::Evidence),
        gaps: limits.rows(Dimension::Gaps),
        events: limits.rows(Dimension::Events),
        control_edges: limits.rows(Dimension::ControlEdges),
        nested_entries: limits.rows(Dimension::NestedEntries),
        owned_text_bytes: limits.max_retained_bytes,
    }
}

pub(super) fn source_range(span: &ByteRange<usize>) -> Range {
    Range {
        start_byte: span.start,
        end_byte: span.end,
        start_line: 0,
        end_line: 0,
    }
}

fn row_binding_queries(
    plan: &crate::definition::RowSelectorPlan,
) -> Result<Vec<(RowBindingName, CodeQuery)>, PolicySelectorSessionError> {
    let mut queries: Vec<(RowBindingName, CodeQuery)> = Vec::with_capacity(plan.bindings.len());
    let mut by_name = HashMap::<&str, usize>::new();
    for binding in &plan.bindings {
        let query = match &binding.source {
            RowBindingSource::Query(crate::PolicySelector::Inline { query, .. }) => query.clone(),
            RowBindingSource::Query(crate::PolicySelector::File { .. }) => {
                return Err(PolicySelectorSessionError::Unavailable(format!(
                    "row selector binding `{}` uses a deferred file selector",
                    binding.name
                )));
            }
            RowBindingSource::Query(crate::PolicySelector::Rows { .. }) => {
                return Err(PolicySelectorSessionError::Unavailable(format!(
                    "row selector binding `{}` nests another row selector",
                    binding.name
                )));
            }
            RowBindingSource::Expansion { from, step } => {
                let source = by_name
                    .get(from.as_str())
                    .and_then(|index| queries.get(*index));
                let Some((_, source)) = source else {
                    return Err(PolicySelectorSessionError::Unavailable(format!(
                        "row selector binding `{}` expands unavailable binding `{from}`",
                        binding.name
                    )));
                };
                let mut query = source.clone();
                match step {
                    RowExpansionStep::ReceiverOutcome | RowExpansionStep::ReceiverEvidence => {
                        let source_is_receiver = query
                            .validate_steps()
                            .is_ok_and(|kind| kind == QueryValueKind::ReceiverAnalysis);
                        if !source_is_receiver {
                            query
                                .plan
                                .steps
                                .push(QueryStep::ReceiverTargets(Default::default()));
                        }
                        query.plan.steps.push(match step {
                            RowExpansionStep::ReceiverOutcome => QueryStep::ReceiverOutcome,
                            _ => QueryStep::ReceiverEvidence,
                        });
                    }
                    RowExpansionStep::MemberSelection => {
                        query.plan.steps.push(QueryStep::MemberSelection)
                    }
                    RowExpansionStep::MemberCandidates => query
                        .plan
                        .steps
                        .push(QueryStep::CandidatesOf(Default::default())),
                    RowExpansionStep::CandidateHierarchy => {
                        query.plan.steps.push(QueryStep::CandidateHierarchy)
                    }
                    RowExpansionStep::MemberFamily => {
                        query.plan.steps.push(QueryStep::MemberFamily)
                    }
                    RowExpansionStep::FamilyEdges => query.plan.steps.push(QueryStep::FamilyEdges),
                    RowExpansionStep::DispatchOutcome => {
                        query.plan.steps.push(QueryStep::DispatchOutcome)
                    }
                    RowExpansionStep::DispatchTargets => {
                        query.plan.steps.push(QueryStep::DispatchTargets)
                    }
                }
                query
            }
        };
        by_name.insert(binding.name.as_str(), queries.len());
        queries.push((binding.name.clone(), query));
    }
    Ok(queries)
}

pub(super) fn selected_site_quality(
    item: &CodeQueryResultItem,
) -> (ProofStatus, EvidenceCompleteness) {
    let semantic = match &item.value {
        CodeQueryResultValue::Procedure { value } => Some(&value.evidence),
        CodeQueryResultValue::ProgramPoint { value } => Some(&value.evidence),
        CodeQueryResultValue::ControlEdge { value } => Some(&value.evidence),
        CodeQueryResultValue::TypestateWitness { value } => Some(&value.quality),
        CodeQueryResultValue::TaintFinding { value } => Some(&value.evidence),
        _ => None,
    };
    let (proof, mut completeness) = if let Some(semantic) = semantic {
        semantic_binding_quality(semantic)
    } else {
        match &item.value {
            CodeQueryResultValue::TypestateFinding { value } => (
                if value.path_proven {
                    ProofStatus::Proven
                } else {
                    ProofStatus::Unproven("selector path is unproven".into())
                },
                if value.path_complete && value.analysis_complete {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial("selector analysis is incomplete".into())
                },
            ),
            CodeQueryResultValue::ReferenceSite { value } => (
                proof_from_label(value.proof),
                EvidenceCompleteness::Complete,
            ),
            CodeQueryResultValue::CallSite { value } => (
                proof_from_label(value.proof),
                EvidenceCompleteness::Complete,
            ),
            CodeQueryResultValue::JsxAttributeValue { value } => (
                ProofStatus::Proven,
                if value.coverage == "complete" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        value
                            .reason
                            .unwrap_or("JSX attribute value projection is incomplete")
                            .to_string()
                            .into(),
                    )
                },
            ),
            // An edge row carries its own proof attribution, exactly as a
            // reference site does; set-level completeness is the query's
            // diagnostics' business (#1479).
            CodeQueryResultValue::ReferenceEdge { value } => (
                proof_from_label(value.proof),
                EvidenceCompleteness::Complete,
            ),
            // A flow-state row is exactly what the derivation computed; its
            // per-axis account is the row's own `completeness` field, so a
            // partial derivation makes the selector's evidence partial rather
            // than silently complete (#1480).
            CodeQueryResultValue::StateEvent { value } => (
                ProofStatus::Proven,
                flow_state_completeness(value.completeness, &value.uncovered_axes),
            ),
            CodeQueryResultValue::FlowRelation { value } => (
                ProofStatus::Proven,
                flow_state_completeness(value.completeness, &value.uncovered_axes),
            ),
            // A control-relation row states its own per-relation completeness
            // the same way, so a derivation whose budget ran out makes the
            // selector's evidence partial rather than silently complete
            // (#2443).
            CodeQueryResultValue::ControlRelation { value } => (
                ProofStatus::Proven,
                control_relation_completeness(value.completeness, &value.uncovered_relations),
            ),
            // A guard row carries the IR evidence of the decision it records,
            // so an unproven or partial lowering makes the selector's evidence
            // unproven or partial rather than silently clean (#2443).
            CodeQueryResultValue::Guard { value } => (
                proof_from_label(value.proof),
                if value.completeness == "complete" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        "guard lowering evidence is partial".into(),
                    )
                },
            ),
            // A topology row states its own completeness the same way: a build
            // model nobody could read in full makes the selector's evidence
            // partial rather than silently complete (#2448).
            CodeQueryResultValue::SourceSet { value } => (
                ProofStatus::Proven,
                topology_completeness(value.completeness),
            ),
            CodeQueryResultValue::BuildTarget { value } => (
                ProofStatus::Proven,
                topology_completeness(value.completeness),
            ),
            CodeQueryResultValue::TopologyEdge { value } => (
                ProofStatus::Proven,
                topology_completeness(value.completeness),
            ),
            // A rewrite-path row states its own per-domain completeness the
            // same way, so a derivation that could not run makes the
            // selector's evidence partial rather than silently complete
            // (#1480).
            CodeQueryResultValue::RewritePath { value } => (
                ProofStatus::Proven,
                rewrite_path_completeness(value.completeness, &value.uncovered_domains),
            ),
            CodeQueryResultValue::ReceiverAnalysis { .. }
            | CodeQueryResultValue::FlowEndpoint { .. }
            | CodeQueryResultValue::FlowWitness { .. } => (
                ProofStatus::Unproven("selector evidence is not exact".into()),
                EvidenceCompleteness::Partial("selector evidence is not exhaustive".into()),
            ),
            CodeQueryResultValue::CallShape { value } => (
                ProofStatus::Proven,
                if value.coverage == "exact" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("call shape coverage is {}", value.coverage).into(),
                    )
                },
            ),
            // A signature row is proven evidence of what the analyzer
            // persisted, but it is only complete when the language actually
            // recorded an arity. An `arity_unrecorded` or `unrecorded` row
            // must turn an exact-arity assertion unreliable rather than clean.
            CodeQueryResultValue::CallableSignature { value } => (
                ProofStatus::Proven,
                if value.coverage == "exact" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("callable signature coverage is {}", value.coverage).into(),
                    )
                },
            ),
            // A parameter row whose optionality the language never recorded
            // cannot support a required-versus-optional claim.
            CodeQueryResultValue::SignatureParameter { value } => (
                ProofStatus::Proven,
                if value.optional.is_some() {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        "declared parameter optionality is unrecorded".into(),
                    )
                },
            ),
            // A decorated parameter is an exact source anchor, but a policy
            // endpoint can bind its value only when the row retained a
            // complete parameter port and decorator-binding identity.
            CodeQueryResultValue::DecoratedParameter { value } => {
                let complete = value.terminal
                    && value.completion == "complete"
                    && value.coverage == "complete"
                    && value.parameter_ordinal.is_some()
                    && value.port_id.is_some();
                if complete {
                    (ProofStatus::Proven, EvidenceCompleteness::Complete)
                } else {
                    (
                        ProofStatus::Unproven(
                            "decorated parameter binding or value port is incomplete".into(),
                        ),
                        EvidenceCompleteness::Partial(
                            "decorated parameter binding or value port is incomplete".into(),
                        ),
                    )
                }
            }
            // An overload-selection summary is proven evidence of what the
            // resolver considered, but it is complete only when every verdict
            // was decidable. `unknown_shape` -- an unsupported language, an
            // untraced site, or any undecidable candidate -- must turn an
            // exact-cardinality assertion over the site unreliable rather than
            // clean.
            CodeQueryResultValue::OverloadSelection { value } => (
                ProofStatus::Proven,
                if value.resolution == "unknown_shape" {
                    EvidenceCompleteness::Partial(
                        if value.supported {
                            "overload selection is undecidable at this site"
                        } else {
                            "this language does not report callable applicability"
                        }
                        .into(),
                    )
                } else {
                    EvidenceCompleteness::Complete
                },
            ),
            // A candidate whose applicability nobody could decide cannot
            // support an applicable-or-not claim.
            CodeQueryResultValue::CallableApplicability { value } => (
                ProofStatus::Proven,
                if value.verdict == "unknown" {
                    EvidenceCompleteness::Partial(
                        "candidate applicability is undecided".into(),
                    )
                } else {
                    EvidenceCompleteness::Complete
                },
            ),
            CodeQueryResultValue::CallArgumentGroup { .. }
            | CodeQueryResultValue::CallArgument { .. } => (
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
            ),
            // An effect row's own quality is its derivation and its coverage:
            // a `declared` row with an exhaustive site or procedure is a
            // complete claim, and anything else admits a missing effect.
            CodeQueryResultValue::CallEffect { value } => (
                ProofStatus::Proven,
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("call effect coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::ProcedureEffect { value } => (
                ProofStatus::Proven,
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("procedure effect coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::CallBinding { value } => (
                value.dispatch_proof.map_or_else(
                    || ProofStatus::Unproven("call-binding dispatch proof is absent".into()),
                    proof_from_label,
                ),
                if value.mapping == "exact"
                    && value.coverage == "exhaustive"
                    && !value.terminal
                    && value.argument_id.is_some()
                    && value.dispatch_outcome == "resolved"
                    && value.dispatch_coverage == "exhaustive"
                    && value.dispatch_completeness == Some("complete")
                    && value.dispatch_target_count == 1
                    && !value.dispatch_targets_truncated
                {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!(
                            "call binding is mapping={}, coverage={}, terminal={}, dispatch={}/{}/{:?}, targets={}, truncated={}",
                            value.mapping,
                            value.coverage,
                            value.terminal,
                            value.dispatch_outcome,
                            value.dispatch_coverage,
                            value.dispatch_completeness,
                            value.dispatch_target_count,
                            value.dispatch_targets_truncated,
                        )
                        .into(),
                    )
                },
            ),
            CodeQueryResultValue::ReceiverOutcome { value } => (
                ProofStatus::Proven,
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("receiver outcome coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::ReceiverEvidence { value } => (
                proof_from_label(value.proof),
                if value.completeness == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("receiver evidence is {}", value.completeness).into(),
                    )
                },
            ),
            CodeQueryResultValue::MemberSelection { value } => (
                ProofStatus::Proven,
                if value.coverage == "exhaustive" {
                    EvidenceCompleteness::Complete
                } else {
                    EvidenceCompleteness::Partial(
                        format!("member selection coverage is {}", value.coverage).into(),
                    )
                },
            ),
            CodeQueryResultValue::StructuralMatch { .. }
            | CodeQueryResultValue::Declaration { .. }
            | CodeQueryResultValue::File { .. }
            | CodeQueryResultValue::CandidateHop { .. }
            | CodeQueryResultValue::DispatchOutcome { .. }
            | CodeQueryResultValue::DispatchTarget { .. }
            | CodeQueryResultValue::MemberFamily { .. }
            | CodeQueryResultValue::MemberFamilyEdge { .. }
            | CodeQueryResultValue::ExpressionSite { .. }
            // An occurrence row is an exact parser fact about one token. Its
            // completeness question is per role and is answered by the query's
            // diagnostics, not by this per-row evidence judgement.
            | CodeQueryResultValue::Occurrence { .. }
            // A scope, a binding and a candidate row are each an exact record
            // of what one producer derived at one position; whether the *set*
            // is complete is per axis and is answered by the query's
            // diagnostics, exactly as for an occurrence.
            | CodeQueryResultValue::LexicalScope { .. }
            | CodeQueryResultValue::Binding { .. }
            | CodeQueryResultValue::ResolutionCandidate { .. }
            // The materialization rows follow the same reasoning (#1476):
            // each is an exact record of recorded provenance, and per-axis
            // completeness arrives through the query's diagnostics.
            | CodeQueryResultValue::GenerationSite { .. }
            | CodeQueryResultValue::Export { .. }
            | CodeQueryResultValue::DeclarationState { .. }
            // The identity-route rows are parser facts with the same per-axis
            // completeness story (#1475).
            | CodeQueryResultValue::QualifiedPath { .. }
            | CodeQueryResultValue::PathSegment { .. } => {
                (ProofStatus::Proven, EvidenceCompleteness::Complete)
            }
            CodeQueryResultValue::Procedure { .. }
            | CodeQueryResultValue::ProgramPoint { .. }
            | CodeQueryResultValue::ControlEdge { .. }
            | CodeQueryResultValue::TypestateWitness { .. }
            | CodeQueryResultValue::TaintFinding { .. } => {
                unreachable!("semantic result evidence was handled above")
            }
        }
    };
    if item.provenance_truncated {
        completeness = EvidenceCompleteness::Partial("selector provenance was truncated".into());
    }
    (proof, completeness)
}

fn semantic_binding_quality(
    evidence: &CodeQuerySemanticEvidence,
) -> (ProofStatus, EvidenceCompleteness) {
    let proof = match evidence.proof {
        CodeQuerySemanticProof::Proven => ProofStatus::Proven,
        CodeQuerySemanticProof::Unproven => {
            ProofStatus::Unproven("selector semantic evidence is unproven".into())
        }
    };
    let completeness = match evidence.completeness {
        CodeQuerySemanticCompleteness::Complete => EvidenceCompleteness::Complete,
        CodeQuerySemanticCompleteness::Partial => {
            EvidenceCompleteness::Partial("selector semantic evidence is partial".into())
        }
    };
    (proof, completeness)
}

/// The evidence completeness one flow-state row carries (#1480).
///
/// `partial` is never silently upgraded: the uncovered axes travel into the
/// reason string so a policy reader sees which part of the derivation is
/// missing rather than a bare "incomplete".
fn flow_state_completeness(
    completeness: &str,
    uncovered_axes: &[&'static str],
) -> EvidenceCompleteness {
    if completeness == "complete" {
        EvidenceCompleteness::Complete
    } else {
        EvidenceCompleteness::Partial(
            format!(
                "flow-state derivation does not cover [{}]",
                uncovered_axes.join(", ")
            )
            .into(),
        )
    }
}

/// The evidence completeness one rewrite-path row carries (#1480).
fn rewrite_path_completeness(
    completeness: &str,
    uncovered_domains: &[&'static str],
) -> EvidenceCompleteness {
    if completeness == "complete" {
        EvidenceCompleteness::Complete
    } else {
        EvidenceCompleteness::Partial(
            format!(
                "rewrite-path derivation does not cover [{}]",
                uncovered_domains.join(", ")
            )
            .into(),
        )
    }
}

fn topology_completeness(completeness: &str) -> EvidenceCompleteness {
    if completeness == "complete" {
        EvidenceCompleteness::Complete
    } else {
        EvidenceCompleteness::Partial(
            "the workspace's declared build topology was not read in full".into(),
        )
    }
}

fn control_relation_completeness(
    completeness: &str,
    uncovered_relations: &[&'static str],
) -> EvidenceCompleteness {
    if completeness == "complete" {
        EvidenceCompleteness::Complete
    } else {
        EvidenceCompleteness::Partial(
            format!(
                "control-relation derivation does not cover [{}]",
                uncovered_relations.join(", ")
            )
            .into(),
        )
    }
}

fn proof_from_label(label: &str) -> ProofStatus {
    if label == "proven" {
        ProofStatus::Proven
    } else {
        ProofStatus::Unproven(format!("selector evidence is {label}").into())
    }
}

/// Whether one formal parameter slot names `expected`.
///
/// A slot carries every spelling the declaration gives one parameter, because
/// some languages name a formal twice (Swift's external and internal labels)
/// and some prefix it in source but not in a call (PHP's `$value`). Matching
/// any spelling is what lets one authored `(argument :name "value")` bind the
/// same formal in every language that declares it.
pub(super) fn parameter_names_match(names: &[String], expected: &str) -> bool {
    names
        .iter()
        .any(|name| parameter_name_matches(name, expected))
}

/// The single-spelling form of [`parameter_names_match`], for a name taken
/// from a call's keyword actual rather than from a declaration slot.
pub(super) fn parameter_name_matches(name: &str, expected: &str) -> bool {
    name == expected
        || name.strip_prefix('$') == Some(expected)
        || expected.strip_prefix('$') == Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PolicyBudget;
    use brokk_bifrost_analysis::analyzer::{
        AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer,
    };

    fn one_file_workspace() -> (tempfile::TempDir, WorkspaceAnalyzer) {
        let directory = tempfile::tempdir().expect("temporary workspace");
        std::fs::write(
            directory.path().join("subject.py"),
            "def subject():\n    pass\n",
        )
        .expect("fixture source");
        let project: Arc<dyn Project> =
            Arc::new(FilesystemProject::new(directory.path()).expect("fixture project"));
        let workspace = WorkspaceAnalyzer::build_ephemeral(
            project,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
        )
        .expect("an analyzer over the fixture");
        (directory, workspace)
    }

    /// Issue #2523. The lanes of the shared semantic ledger deplete at wildly
    /// different rates, so one bind that legitimately spends most of
    /// `nested_entries` must not cap every other dimension of every later
    /// query at what is left of that one lane.
    #[test]
    fn a_drained_lane_caps_itself_and_no_other_dimension() {
        let (_directory, workspace) = one_file_workspace();
        let cancellation = CancellationToken::default();
        let budget = PolicyBudget::default();
        let rows = budget.query_limits().semantic.max_rows_per_dimension;
        let mut session = PolicySelectorSession::new(
            &workspace,
            "test",
            budget.query_limits(),
            64,
            &cancellation,
        );

        session
            .charge_query_semantic_work(CodeQuerySemanticWork {
                nested_entries: rows as u64 - 1,
                procedures: 1,
                ..CodeQuerySemanticWork::default()
            })
            .expect("the charge fits the fresh ledger");

        let semantic = session
            .remaining_query_limits()
            .expect("one drained lane does not exhaust the session")
            .semantic;
        assert_eq!(semantic.rows(SemanticBudgetDimension::NestedEntries), 1);
        assert_eq!(semantic.rows(SemanticBudgetDimension::Procedures), rows - 1);
        for dimension in CodeQuerySemanticRowLimits::ROW_DIMENSIONS {
            if matches!(
                dimension,
                SemanticBudgetDimension::NestedEntries | SemanticBudgetDimension::Procedures
            ) {
                continue;
            }
            assert_eq!(
                semantic.rows(dimension),
                rows,
                "an untouched lane keeps its whole remainder: {dimension:?}"
            );
        }
    }

    /// The other half of the same contract: the guard still fires when the
    /// session really has nothing left, so an exhausted compile reports the
    /// budget rather than quietly returning fewer rows.
    #[test]
    fn a_fully_spent_ledger_still_reports_the_semantic_budget() {
        let (_directory, workspace) = one_file_workspace();
        let cancellation = CancellationToken::default();
        let budget = PolicyBudget::default();
        let rows = budget.query_limits().semantic.max_rows_per_dimension as u64;
        let mut session = PolicySelectorSession::new(
            &workspace,
            "test",
            budget.query_limits(),
            64,
            &cancellation,
        );

        session
            .charge_query_semantic_work(CodeQuerySemanticWork {
                procedures: rows,
                blocks: rows,
                program_points: rows,
                values: rows,
                allocations: rows,
                call_sites: rows,
                memory_locations: rows,
                captures: rows,
                source_mappings: rows,
                evidence: rows,
                gaps: rows,
                events: rows,
                control_edges: rows,
                nested_entries: rows,
                ..CodeQuerySemanticWork::default()
            })
            .expect("the charge exactly fills every row lane");

        let error = session
            .remaining_query_limits()
            .expect_err("a spent ledger cannot admit another query");
        assert!(
            matches!(
                error,
                PolicySelectorSessionError::Incomplete {
                    completion: CodeQueryCompletion::Incomplete { ref codes },
                    ..
                } if codes.contains(&CodeQueryDiagnosticCode::SemanticBudgetExhausted)
            ),
            "{error:?}"
        );
    }
}
