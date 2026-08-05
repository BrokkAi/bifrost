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
    cancellation: &'a CancellationToken,
    semantic_budget: SemanticBudget,
    semantic_execution_budget: SemanticExecutionBudget,
    query_work: CodeQueryExecutionWork,
    artifacts: HashMap<ProjectFile, Arc<SemanticArtifact>>,
}

impl<'a> PolicySelectorSession<'a> {
    pub(super) fn new(
        workspace: &'a WorkspaceAnalyzer,
        analysis: &'static str,
        query_limits: CodeQueryExecutionLimits,
        cancellation: &'a CancellationToken,
    ) -> Self {
        Self {
            workspace,
            analysis,
            query_limits,
            cancellation,
            semantic_budget: SemanticBudget::new(semantic_work_limits(query_limits.semantic))
                .expect("validated CodeQuery semantic limits are positive"),
            semantic_execution_budget: SemanticExecutionBudget::new(
                query_limits.semantic.max_materialized_files,
                query_limits.semantic.max_traversal_steps,
            ),
            query_work: CodeQueryExecutionWork::default(),
            artifacts: HashMap::new(),
        }
    }

    pub(super) fn select(
        &mut self,
        selector: &ResolvedPolicySelector,
    ) -> Result<Vec<PolicySelectedSite>, PolicySelectorSessionError> {
        // A policy batch runs many selectors against one immutable snapshot,
        // so index reuse is guaranteed: build it on the first selector rather
        // than letting Auto's first-request deferral turn the whole batch
        // into repeated full-workspace scans.
        let detailed = execute_code_query_detailed_eager_index(
            self.workspace.analyzer(),
            &selector.query,
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
        let semantic = self.semantic_budget.used();
        let execution = self.semantic_execution_budget.work();
        let metrics = [
            (
                "semantic_materialized_files",
                PolicyWorkUnit::Count,
                execution.materialized_files,
            ),
            (
                "semantic_traversal_steps",
                PolicyWorkUnit::Count,
                execution.traversal_steps,
            ),
            (
                "semantic_source_bytes",
                PolicyWorkUnit::Bytes,
                semantic.source_bytes,
            ),
            (
                "semantic_program_points",
                PolicyWorkUnit::Rows,
                semantic.program_points,
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
            CodeQueryResultValue::ReceiverAnalysis { .. }
            | CodeQueryResultValue::FlowEndpoint { .. }
            | CodeQueryResultValue::FlowWitness { .. } => (
                ProofStatus::Unproven("selector evidence is not exact".into()),
                EvidenceCompleteness::Partial("selector evidence is not exhaustive".into()),
            ),
            CodeQueryResultValue::StructuralMatch { .. }
            | CodeQueryResultValue::Declaration { .. }
            | CodeQueryResultValue::File { .. }
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

fn proof_from_label(label: &str) -> ProofStatus {
    if label == "proven" {
        ProofStatus::Proven
    } else {
        ProofStatus::Unproven(format!("selector evidence is {label}").into())
    }
}
