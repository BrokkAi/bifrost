use std::collections::HashMap;
use std::fmt;
use std::ops::Range as ByteRange;
use std::sync::Arc;

use crate::{PolicyWorkMetric, PolicyWorkReport, PolicyWorkUnit, ResolvedPolicySelector};
use brokk_bifrost_analysis::CancellationToken;
use brokk_bifrost_analysis::analyzer::semantic::{
    EvidenceCompleteness, ProofStatus, SemanticArtifact, SemanticBudget, SemanticBudgetDimension,
    SemanticExecutionBudget, SemanticRequest, SemanticWork,
};
use brokk_bifrost_analysis::analyzer::structural::search::{
    DetailedCodeQueryDomain, execute_code_query_detailed_eager_index,
};
use brokk_bifrost_analysis::analyzer::structural::{
    CodeQueryCompletion, CodeQueryDiagnosticCode, CodeQueryExecutionLimits, CodeQueryExecutionWork,
    CodeQueryResultItem, CodeQueryResultValue, CodeQuerySemanticCompleteness,
    CodeQuerySemanticEvidence, CodeQuerySemanticLimits, CodeQuerySemanticProof,
    CodeQuerySemanticWork,
};
use brokk_bifrost_analysis::analyzer::{ProjectFile, Range, WorkspaceAnalyzer};

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
        }
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

        self.semantic_budget =
            SemanticBudget::new(semantic_work_limits(self.query_limits.semantic))
                .expect("validated CodeQuery semantic limits are positive");
        self.semantic_execution_budget = SemanticExecutionBudget::new(
            self.materialized_files_limit,
            self.query_limits.semantic.max_traversal_steps,
        );
    }

    pub(super) fn select(
        &mut self,
        selector: &ResolvedPolicySelector,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
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
        let mut query = selector.query.clone();
        query.limit = self.max_selector_results;
        let detailed = execute_code_query_detailed_eager_index(
            self.workspace.analyzer(),
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
                })
            })
            .collect()
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

    fn remaining_query_limits(
        &self,
    ) -> Result<CodeQueryExecutionLimits, PolicySelectorSessionError> {
        let remaining = |limit: usize, used: u64| {
            limit.saturating_sub(usize::try_from(used).unwrap_or(usize::MAX))
        };
        let structural = [
            remaining(
                self.query_limits.max_scanned_files,
                self.query_work.scanned_files,
            ),
            remaining(
                self.query_limits.max_scanned_source_bytes,
                self.query_work.scanned_source_bytes,
            ),
            remaining(self.query_limits.max_fact_nodes, self.query_work.fact_nodes),
            remaining(
                self.query_limits.max_pipeline_rows,
                self.query_work.pipeline_rows,
            ),
        ];
        if structural.contains(&0) {
            return Err(PolicySelectorSessionError::Incomplete {
                completion: CodeQueryCompletion::Incomplete {
                    codes: vec![CodeQueryDiagnosticCode::ExecutionBudgetExhausted],
                },
                detail: format!(
                    "{} selectors exhausted the shared structural query budget",
                    self.analysis
                ),
            });
        }
        let semantic_remaining = self.semantic_budget.remaining();
        let semantic = CodeQuerySemanticLimits {
            max_materialized_files: self
                .semantic_execution_budget
                .remaining_materialized_files(),
            max_source_bytes: semantic_remaining.source_bytes,
            max_rows_per_dimension: SemanticBudgetDimension::ALL
                .into_iter()
                .filter(|dimension| {
                    !matches!(
                        dimension,
                        SemanticBudgetDimension::SourceBytes
                            | SemanticBudgetDimension::OwnedTextBytes
                    )
                })
                .map(|dimension| semantic_remaining.get(dimension))
                .min()
                .unwrap_or(0),
            max_retained_bytes: semantic_remaining.owned_text_bytes,
            max_traversal_steps: self.remaining_semantic_traversal_steps()?,
        };
        if !semantic.all_positive() {
            return Err(semantic_budget_error(format!(
                "{} selectors exhausted the shared semantic query budget",
                self.analysis
            )));
        }
        Ok(CodeQueryExecutionLimits {
            max_scanned_files: structural[0],
            max_scanned_source_bytes: structural[1],
            max_fact_nodes: structural[2],
            max_pipeline_rows: structural[3],
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
    SemanticWork {
        source_bytes: limits.max_source_bytes,
        procedures: limits.max_rows_per_dimension,
        blocks: limits.max_rows_per_dimension,
        program_points: limits.max_rows_per_dimension,
        values: limits.max_rows_per_dimension,
        allocations: limits.max_rows_per_dimension,
        call_sites: limits.max_rows_per_dimension,
        memory_locations: limits.max_rows_per_dimension,
        captures: limits.max_rows_per_dimension,
        source_mappings: limits.max_rows_per_dimension,
        evidence: limits.max_rows_per_dimension,
        gaps: limits.max_rows_per_dimension,
        events: limits.max_rows_per_dimension,
        control_edges: limits.max_rows_per_dimension,
        nested_entries: limits.max_rows_per_dimension,
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

fn proof_from_label(label: &str) -> ProofStatus {
    if label == "proven" {
        ProofStatus::Proven
    } else {
        ProofStatus::Unproven(format!("selector evidence is {label}").into())
    }
}
