use super::super::provider::StructuralSyntaxLimitedOutcome;
use super::*;

pub(super) fn receiver_operation(step: &QueryStep) -> ReceiverQueryOperation {
    match step {
        QueryStep::ReceiverTargets(_)
        | QueryStep::ReceiverOutcome
        | QueryStep::ReceiverEvidence => ReceiverQueryOperation::ReceiverTargets,
        QueryStep::PointsTo(_) => ReceiverQueryOperation::PointsTo,
        QueryStep::MemberTargets(_) => ReceiverQueryOperation::MemberTargets,
        _ => unreachable!("receiver operation requested for a non-receiver step"),
    }
}

/// Project receiver analyses produced as the prerequisite of a direct
/// `receiver_outcome` or `receiver_evidence` step. Inputs that were already a
/// receiver analysis are projected by the ordinary pipeline match arms and
/// pass through unchanged here.
pub(super) fn project_direct_receiver_terminal(
    step: &QueryStep,
    expansions: Vec<PipelineExpansion>,
) -> Vec<PipelineExpansion> {
    if !matches!(
        step,
        QueryStep::ReceiverOutcome | QueryStep::ReceiverEvidence
    ) {
        return expansions;
    }
    let mut projected = Vec::new();
    for expansion in expansions {
        let PipelineValue::ReceiverAnalysis(value) = expansion.value else {
            projected.push(expansion);
            continue;
        };
        match step {
            QueryStep::ReceiverOutcome => {
                let mut trace = expansion.trace;
                trace.push((PipelineTraceValue::ReceiverOutcome(value.clone()), None));
                projected.push(PipelineExpansion {
                    value: PipelineValue::ReceiverOutcome(value),
                    trace,
                    budgeted: false,
                });
            }
            QueryStep::ReceiverEvidence => {
                for evidence in receiver_evidence_expansions(&value) {
                    let mut trace = expansion.trace.clone();
                    trace.extend(evidence.trace);
                    projected.push(PipelineExpansion {
                        value: evidence.value,
                        trace,
                        budgeted: false,
                    });
                }
            }
            _ => unreachable!("direct receiver terminal checked above"),
        }
    }
    projected
}

pub(super) const RECEIVER_EVIDENCE_ID_DOMAIN: &[u8] = b"bifrost.code_query.receiver_evidence.v1";

pub(super) fn receiver_evidence_expansions(
    value: &ReceiverAnalysisValue,
) -> Vec<PipelineExpansion> {
    let ReceiverQueryAnalysis::Values(outcome) = &value.report.analysis else {
        return Vec::new();
    };
    let Some(values) = outcome.values() else {
        return Vec::new();
    };

    let mut expansions = Vec::new();
    for (ordinal, root) in values.iter().enumerate() {
        let mut current = root.clone();
        let mut parent_evidence_id = None;
        let mut chain_hop = 0usize;
        loop {
            let evidence_kind = receiver_evidence_kind(&current);
            let mut digest = LengthDelimitedDigest::new(RECEIVER_EVIDENCE_ID_DOMAIN);
            digest.push(value.site_id.as_bytes());
            digest.push(&ordinal.to_le_bytes());
            digest.push(&chain_hop.to_le_bytes());
            digest.push(evidence_kind.as_bytes());
            let id = digest.finish().to_string();
            let (factory, returned) = match &current {
                ReceiverValue::FactoryReturn { factory, value } => {
                    (Some(factory.clone()), Some(value.as_ref().clone()))
                }
                _ => (None, None),
            };
            let evidence = ReceiverEvidenceValue {
                receiver: value.clone(),
                id: id.clone(),
                parent_evidence_id,
                ordinal,
                chain_hop,
                value: current,
                factory,
            };
            expansions.push(PipelineExpansion {
                value: PipelineValue::ReceiverEvidence(evidence.clone()),
                trace: vec![(PipelineTraceValue::ReceiverEvidence(evidence), None)],
                budgeted: false,
            });
            let Some(returned) = returned else {
                break;
            };
            current = returned;
            parent_evidence_id = Some(id);
            chain_hop += 1;
        }
    }
    expansions
}

const POINTS_TO_CANDIDATE_ID_DOMAIN: &[u8] = b"bifrost.code_query.points_to_candidate.v1";

pub(super) fn points_to_candidate_expansions(
    value: &ReceiverAnalysisValue,
    semantic_identity: Option<(String, String)>,
) -> Vec<PipelineExpansion> {
    let Some(points_to) = &value.report.points_to else {
        return Vec::new();
    };
    let (site_id, program_point_id) = semantic_identity
        .map(|(site_id, program_point_id)| (site_id, Some(program_point_id)))
        .unwrap_or_else(|| (value.site_id.clone(), None));
    points_to
        .object_candidates()
        .enumerate()
        .map(|(candidate_index, candidate)| {
            let mut digest = LengthDelimitedDigest::new(POINTS_TO_CANDIDATE_ID_DOMAIN);
            digest.push(site_id.as_bytes());
            digest.push(&candidate_index.to_le_bytes());
            let object = candidate.value();
            let object_id = (candidate.is_proven_complete()
                && points_to.coverage().is_exhaustive()
                && object.cardinality() == crate::analyzer::semantic::ObjectCardinality::Singleton
                && !contains_type_summary(object.identity()))
            .then(|| {
                let canonical =
                    brokk_bifrost_flow::typestate::TypestateObjectKey::for_object(object)
                        .public_canonical_rendering();
                let mut identity =
                    LengthDelimitedDigest::new(b"bifrost.code_query.points_to_object_identity.v1");
                identity.push(canonical.as_bytes());
                identity.finish().to_string()
            });
            let row = PointsToCandidateValue {
                file: value.report.site.file.clone(),
                language: value.report.site.language,
                range: value.report.site.range,
                id: digest.finish().to_string(),
                site_id: site_id.clone(),
                program_point_id: program_point_id.clone(),
                candidate_index,
                object_id,
                object_cardinality: Some(match object.cardinality() {
                    crate::analyzer::semantic::ObjectCardinality::Singleton => "singleton",
                    crate::analyzer::semantic::ObjectCardinality::Summary => "summary",
                    crate::analyzer::semantic::ObjectCardinality::Unknown => "unknown",
                }),
                proof: candidate.proof().label(),
                completeness: candidate.completeness().label(),
                coverage: points_to.coverage().label(),
            };
            PipelineExpansion {
                value: PipelineValue::PointsToCandidate(Box::new(row.clone())),
                trace: vec![(PipelineTraceValue::PointsToCandidate(Box::new(row)), None)],
                budgeted: false,
            }
        })
        .collect()
}

fn contains_type_summary(identity: &crate::analyzer::semantic::AccessPathRoot) -> bool {
    match identity {
        crate::analyzer::semantic::AccessPathRoot::TypeSummary(_) => true,
        crate::analyzer::semantic::AccessPathRoot::FieldPath { base, .. } => {
            contains_type_summary(base)
        }
        _ => false,
    }
}

pub(super) fn correlate_receiver_expansions(expansions: &mut [PipelineExpansion], ast_id: String) {
    for expansion in expansions {
        let value = match &mut expansion.value {
            PipelineValue::ReceiverAnalysis(value) | PipelineValue::MemberTargetAnalysis(value) => {
                value
            }
            _ => unreachable!("receiver analysis expansion has its declared terminal domain"),
        };
        value.site_ast_id = Some(ast_id.clone());
        for (trace, _) in &mut expansion.trace {
            let value = match trace {
                PipelineTraceValue::ReceiverAnalysis(value)
                | PipelineTraceValue::MemberTargetAnalysis(value) => value,
                _ => unreachable!(
                    "receiver analysis expansion trace has its declared terminal domain"
                ),
            };
            value.site_ast_id = Some(ast_id.clone());
        }
    }
}

/// The value domain the `receiver_evidence.evidence_kind` row field
/// publishes, minted by [`receiver_evidence_kind`] (issue #2515).
pub(super) const RECEIVER_EVIDENCE_KIND_LABELS: &[&str] = &[
    "allocation_site",
    "instance_type",
    "class_or_static_object",
    "module_or_export_object",
    "current_receiver",
    "factory_return",
];

pub(super) fn receiver_evidence_kind(value: &ReceiverValue) -> &'static str {
    match value {
        ReceiverValue::AllocationSite { .. } => "allocation_site",
        ReceiverValue::InstanceType(_) => "instance_type",
        ReceiverValue::ClassOrStaticObject(_) => "class_or_static_object",
        ReceiverValue::ModuleOrExportObject(_) => "module_or_export_object",
        ReceiverValue::CurrentReceiver(_) => "current_receiver",
        ReceiverValue::FactoryReturn { .. } => "factory_return",
    }
}

pub(super) type ReceiverDiagnostics = Vec<(
    CodeQueryDiagnosticCode,
    Language,
    &'static str,
    String,
    Option<DerivationExecutionCause>,
)>;
pub(super) const RECEIVER_PIPELINE_OUTPUT_CAP_REASON: &str =
    "pipeline output cap omitted receiver inputs";

pub(super) fn structural_receiver_ranges(
    seed: &SeedMatch,
    operation: ReceiverQueryOperation,
    capture: Option<&str>,
) -> (Vec<Range>, ReceiverQueryInput) {
    let (spans, input) = if let Some(capture) = capture {
        let spans = seed
            .fact_match
            .captures
            .iter()
            .filter(|binding| binding.name == capture)
            .map(|binding| binding.span)
            .collect::<Vec<_>>();
        let input = ReceiverQueryInput::Expression;
        (spans, input)
    } else {
        let fact_id = seed.fact_match.node;
        let fact = seed.facts.node(fact_id);
        let normalized = match operation {
            ReceiverQueryOperation::PointsTo => seed
                .facts
                .role_targets(fact_id, Role::Right)
                .next()
                .map(|target| target.span),
            ReceiverQueryOperation::ReceiverTargets => {
                if fact.kind.satisfies(NormalizedKind::Call) {
                    seed.facts
                        .role_targets(fact_id, Role::Receiver)
                        .next()
                        .map(|target| target.span)
                } else if matches!(
                    fact.kind,
                    NormalizedKind::FieldAccess | NormalizedKind::Subscript
                ) {
                    seed.facts
                        .role_targets(fact_id, Role::Object)
                        .next()
                        .map(|target| target.span)
                } else {
                    None
                }
            }
            ReceiverQueryOperation::MemberTargets => seed
                .facts
                .role_targets(fact_id, Role::Left)
                .next()
                .map(|target| target.span),
        };
        let input = match operation {
            ReceiverQueryOperation::PointsTo => ReceiverQueryInput::Expression,
            ReceiverQueryOperation::ReceiverTargets if normalized.is_some() => {
                ReceiverQueryInput::Expression
            }
            ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::MemberTargets => {
                ReceiverQueryInput::ContainingSite
            }
        };
        (vec![normalized.unwrap_or_else(|| fact.span())], input)
    };
    let mut seen = HashSet::default();
    let ranges = spans
        .into_iter()
        .filter(|span| seen.insert((span.start_byte, span.end_byte)))
        .map(|span| Range {
            start_byte: span.start_byte,
            end_byte: span.end_byte,
            start_line: seed.facts.line_of_byte(span.start_byte),
            end_line: seed.facts.line_of_byte(span.end_byte),
        })
        .collect();
    (ranges, input)
}

pub(super) fn coherent_trace_facts_for_file<'a>(
    traces: &'a [PipelineTrace],
    file: &ProjectFile,
) -> Option<&'a Arc<FileFacts>> {
    let mut selected: Option<&Arc<FileFacts>> = None;
    for facts in traces
        .iter()
        .filter(|trace| &trace.seed.file == file)
        .map(|trace| &trace.seed.facts)
    {
        match selected {
            Some(existing) if existing.source() != facts.source() => return None,
            Some(_) => {}
            None => selected = Some(facts),
        }
    }
    selected
}

pub(super) enum PipelineReceiverFacts {
    Available(Arc<FileFacts>),
    Unavailable,
    Halted,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn receiver_facts_for_pipeline_row(
    analyzer: &dyn IAnalyzer,
    traces: &[PipelineTrace],
    file: &ProjectFile,
    receiver_facts: &mut HashMap<ProjectFile, Arc<FileFacts>>,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    cache_profile: &mut Option<QueryCacheProfile>,
) -> PipelineReceiverFacts {
    if let Some(facts) = coherent_trace_facts_for_file(traces, file) {
        return PipelineReceiverFacts::Available(Arc::clone(facts));
    }
    if let Some(facts) = receiver_facts.get(file) {
        return PipelineReceiverFacts::Available(Arc::clone(facts));
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return PipelineReceiverFacts::Halted;
    }

    let language = crate::analyzer::common::language_for_file(file);
    let Some(provider) = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
    else {
        return PipelineReceiverFacts::Unavailable;
    };
    let mut projected = *budget;
    projected.scanned_files = projected.scanned_files.saturating_add(1);
    if projected.scanned_files > limits.max_scanned_files {
        push_budget_diagnostic(diagnostics, &projected);
        return PipelineReceiverFacts::Halted;
    }
    budget.scanned_files = projected.scanned_files;

    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return PipelineReceiverFacts::Halted;
    }
    let remaining_source_bytes = limits
        .max_scanned_source_bytes
        .saturating_sub(budget.scanned_source_bytes);
    let source =
        match provider.structural_source_limited(file, remaining_source_bytes, cancellation) {
            StructuralSourceLimitedOutcome::Available(source) => source,
            StructuralSourceLimitedOutcome::Exceeded {
                minimum_source_bytes,
            } => {
                projected = *budget;
                projected.scanned_source_bytes = projected
                    .scanned_source_bytes
                    .saturating_add(minimum_source_bytes);
                push_budget_diagnostic(diagnostics, &projected);
                return PipelineReceiverFacts::Halted;
            }
            StructuralSourceLimitedOutcome::Cancelled => {
                return PipelineReceiverFacts::Halted;
            }
            StructuralSourceLimitedOutcome::Unavailable => {
                return PipelineReceiverFacts::Unavailable;
            }
        };
    projected = *budget;
    projected.scanned_source_bytes = projected.scanned_source_bytes.saturating_add(source.len());
    if projected.scanned_source_bytes > limits.max_scanned_source_bytes {
        push_budget_diagnostic(diagnostics, &projected);
        return PipelineReceiverFacts::Halted;
    }
    budget.scanned_source_bytes = projected.scanned_source_bytes;

    let remaining_fact_nodes = limits
        .max_fact_nodes
        .saturating_sub(budget.fact_nodes.saturating_add(budget.examined_references));
    let facts = match provider.structural_facts_limited(
        file,
        source.as_ref(),
        remaining_fact_nodes,
        cancellation,
    ) {
        StructuralFactsLimitedOutcome::Available {
            facts,
            cache_outcome,
        } => {
            if let Some(profile) = cache_profile.as_mut() {
                record_structural_facts_cache_outcome(profile, cache_outcome, true);
            }
            facts
        }
        StructuralFactsLimitedOutcome::Exceeded { minimum_fact_nodes } => {
            projected = *budget;
            projected.fact_nodes = projected.fact_nodes.saturating_add(minimum_fact_nodes);
            push_budget_diagnostic(diagnostics, &projected);
            return PipelineReceiverFacts::Halted;
        }
        StructuralFactsLimitedOutcome::Cancelled => {
            return PipelineReceiverFacts::Halted;
        }
        StructuralFactsLimitedOutcome::Unavailable => {
            if let Some(profile) = cache_profile.as_mut() {
                record_structural_facts_cache_outcome(
                    profile,
                    StructuralFactsCacheOutcome::Unavailable,
                    false,
                );
            }
            return PipelineReceiverFacts::Unavailable;
        }
    };
    if facts.source() != source.as_ref() {
        return PipelineReceiverFacts::Unavailable;
    }

    projected = *budget;
    projected.fact_nodes = projected.fact_nodes.saturating_add(facts.work_item_count());
    if projected
        .fact_nodes
        .saturating_add(projected.examined_references)
        > limits.max_fact_nodes
    {
        push_budget_diagnostic(diagnostics, &projected);
        return PipelineReceiverFacts::Halted;
    }
    budget.fact_nodes = projected.fact_nodes;
    receiver_facts.insert(file.clone(), Arc::clone(&facts));
    PipelineReceiverFacts::Available(facts)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn receiver_analysis_expansions_for_pipeline_row(
    analyzer: &dyn IAnalyzer,
    service: &ReceiverQueryService<'_>,
    operation: ReceiverQueryOperation,
    file: &ProjectFile,
    traces: &[PipelineTrace],
    ranges: Vec<Range>,
    input: ReceiverQueryInput,
    receiver_facts: &mut HashMap<ProjectFile, Arc<FileFacts>>,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    max_outputs: usize,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    cache_profile: &mut Option<QueryCacheProfile>,
    receiver_diagnostics: &mut ReceiverDiagnostics,
    member_step: &mut MemberFormStep<'_>,
    shared_budget_exhausted: &mut bool,
    receiver_truncated: &mut bool,
) -> Vec<PipelineExpansion> {
    if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
        budget.pipeline_rows,
        limits.max_pipeline_rows,
    )
    .allows(1)
    {
        *shared_budget_exhausted = true;
        *receiver_truncated = true;
        if !ranges.is_empty() {
            record_receiver_pipeline_output_omission(
                receiver_diagnostics,
                file,
                operation,
                ranges.len(),
            );
        }
        return Vec::new();
    }
    let structural_facts = match receiver_facts_for_pipeline_row(
        analyzer,
        traces,
        file,
        receiver_facts,
        budget,
        limits,
        cancellation,
        diagnostics,
        cache_profile,
    ) {
        PipelineReceiverFacts::Available(facts) => Some(facts),
        PipelineReceiverFacts::Unavailable => None,
        PipelineReceiverFacts::Halted => {
            *shared_budget_exhausted = true;
            *receiver_truncated = true;
            return Vec::new();
        }
    };
    receiver_analysis_expansions(
        service,
        analyzer,
        operation,
        file,
        structural_facts.as_ref(),
        ranges,
        input,
        None,
        budget,
        limits,
        receiver_budget_override,
        max_outputs,
        cancellation,
        receiver_diagnostics,
        member_step,
        shared_budget_exhausted,
        receiver_truncated,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn receiver_analysis_expansions(
    service: &ReceiverQueryService<'_>,
    analyzer: &dyn IAnalyzer,
    operation: ReceiverQueryOperation,
    file: &ProjectFile,
    structural_facts: Option<&Arc<FileFacts>>,
    mut ranges: Vec<Range>,
    input: ReceiverQueryInput,
    capture: Option<String>,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    receiver_budget_override: Option<ReceiverAnalysisBudget>,
    max_outputs: usize,
    cancellation: Option<&CancellationToken>,
    receiver_diagnostics: &mut ReceiverDiagnostics,
    member_step: &mut MemberFormStep<'_>,
    shared_budget_exhausted: &mut bool,
    receiver_truncated: &mut bool,
) -> Vec<PipelineExpansion> {
    ranges.sort_by_key(primary_range_key);
    ranges.dedup();
    if ranges.len() > max_outputs {
        *receiver_truncated = true;
        let omitted = ranges.len() - max_outputs;
        record_receiver_pipeline_output_omission(receiver_diagnostics, file, operation, omitted);
    }
    ranges.truncate(max_outputs);
    let mut expansions = Vec::with_capacity(ranges.len());
    let range_count = ranges.len();
    for (range_index, range) in ranges.into_iter().enumerate() {
        if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
            budget.pipeline_rows,
            limits.max_pipeline_rows,
        )
        .allows(1)
        {
            *shared_budget_exhausted = true;
            *receiver_truncated = true;
            record_receiver_pipeline_output_omission(
                receiver_diagnostics,
                file,
                operation,
                range_count - range_index,
            );
            break;
        }
        let remaining_facts = limits
            .max_fact_nodes
            .saturating_sub(budget.fact_nodes.saturating_add(budget.examined_references));
        let remaining_rows = limits
            .max_pipeline_rows
            .saturating_sub(budget.pipeline_rows);
        let base = receiver_budget_override.unwrap_or_default();
        let receiver_budget = receiver_budget_for_remaining_work(
            base,
            remaining_facts,
            remaining_rows.saturating_sub(1),
        );
        let report = match structural_facts.map_or_else(
            || service.analyze(operation, file, range, input, receiver_budget, cancellation),
            |facts| {
                service.analyze_with_structural_facts(
                    operation,
                    file,
                    range,
                    input,
                    facts,
                    receiver_budget,
                    cancellation,
                )
            },
        ) {
            Ok(report) => report,
            Err(ReceiverQueryError::Cancelled) => {
                *shared_budget_exhausted = true;
                break;
            }
            Err(ReceiverQueryError::SemanticProvider(error)) => {
                brokk_bifrost_core::profiling::note_with(|| {
                    format!(
                        "policy.units unbounded origin={}:{} cause=provider:receiver detail={error:?}",
                        file!(),
                        line!()
                    )
                });
                analyzer.mark_execution_dependent();
                receiver_diagnostics.push((
                    CodeQueryDiagnosticCode::ReceiverAnalysisFailed,
                    crate::analyzer::common::language_for_file(file),
                    operation.as_str(),
                    error.to_string(),
                    None,
                ));
                break;
            }
        };

        let candidate_count = receiver_candidate_count(&report);
        // Resolution rounds are iterations, not fact nodes.
        budget.fact_nodes = budget
            .fact_nodes
            .saturating_add(report.work.setup_nodes)
            .saturating_add(report.work.scope_nodes)
            .saturating_add(report.work.summary_expansions)
            .saturating_add(report.work.hierarchy_order_steps);
        budget.pipeline_rows = budget
            .pipeline_rows
            .saturating_add(1)
            .saturating_add(candidate_count);
        if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
            budget.fact_nodes.saturating_add(budget.examined_references),
            limits.max_fact_nodes,
        )
        .allows(0)
            || !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
                budget.pipeline_rows,
                limits.max_pipeline_rows,
            )
            .allows(0)
        {
            *shared_budget_exhausted = true;
        }

        let language = report.site.language;
        match &report.analysis {
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Unsupported { reason })
            | ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Unsupported {
                reason,
            }) => {
                let detail = if *reason == "cpp_c_receiver_unsupported" {
                    "plain C receiver sites are unsupported (cpp_c_receiver_unsupported)"
                        .to_string()
                } else {
                    format!("unsupported provider or shape: {reason}")
                };
                receiver_diagnostics.push((
                    CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
                    language,
                    operation.as_str(),
                    detail,
                    None,
                ));
            }
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::ExceededBudget { limit })
            | ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget {
                limit,
            }) => {
                brokk_bifrost_core::profiling::note_with(|| {
                    format!(
                        "policy.units unbounded origin={}:{} cause=budget:receiver",
                        file!(),
                        line!()
                    )
                });
                analyzer.mark_execution_dependent();
                *receiver_truncated = true;
                receiver_diagnostics.push((
                    CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
                    language,
                    operation.as_str(),
                    format!("exceeded receiver limit {limit}"),
                    Some(DerivationExecutionCause::Budget),
                ));
            }
            ReceiverQueryAnalysis::Values(
                ReceiverAnalysisOutcome::Precise(_)
                | ReceiverAnalysisOutcome::Ambiguous(_)
                | ReceiverAnalysisOutcome::Incomplete { .. }
                | ReceiverAnalysisOutcome::Unknown,
            )
            | ReceiverQueryAnalysis::MemberTargets(
                ReceiverAnalysisOutcome::Precise(_)
                | ReceiverAnalysisOutcome::Ambiguous(_)
                | ReceiverAnalysisOutcome::Incomplete { .. }
                | ReceiverAnalysisOutcome::Unknown,
            ) => {}
        }
        let has_possible = match &report.analysis {
            ReceiverQueryAnalysis::Values(outcome) => outcome.possible_candidates().is_some(),
            ReceiverQueryAnalysis::MemberTargets(outcome) => {
                outcome.possible_candidates().is_some()
            }
        };
        let incomplete = matches!(
            &report.analysis,
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Incomplete { .. })
                | ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Incomplete { .. })
        );
        // An Incomplete outcome reports itself: a mixed modeled and workspace
        // receiver is Incomplete even when its definition lookup resolved
        // with no diagnostic of its own.
        if incomplete && report.definition_diagnostics.is_empty() {
            receiver_diagnostics.push((
                CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
                language,
                operation.as_str(),
                "receiver candidates are possible, not proven".to_string(),
                None,
            ));
        }
        if has_possible || report.possible_candidates_suppressed {
            for diagnostic in &report.definition_diagnostics {
                receiver_diagnostics.push((
                    CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
                    language,
                    operation.as_str(),
                    format!("definition {}: {}", diagnostic.kind, diagnostic.message),
                    None,
                ));
            }
            if report.possible_candidates_suppressed {
                receiver_diagnostics.push((
                    CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
                    language,
                    operation.as_str(),
                    "possible candidates suppressed: neutral gate could not validate applicability"
                        .to_string(),
                    None,
                ));
            }
        }
        if let Some(capability) = report.semantic_unsupported {
            receiver_diagnostics.push((
                CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
                language,
                operation.as_str(),
                format!(
                    "semantic evidence is incomplete because {} is unsupported",
                    capability.label()
                ),
                None,
            ));
        }
        if report.candidates_truncated {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=budget:receiver_candidates",
                    file!(),
                    line!()
                )
            });
            analyzer.mark_execution_dependent();
            *receiver_truncated = true;
            receiver_diagnostics.push((
                CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
                language,
                operation.as_str(),
                "truncated candidates at max_targets".to_string(),
                Some(DerivationExecutionCause::Budget),
            ));
        }
        let Some((site_id, site_ast_id)) =
            receiver_site_identity(analyzer, &report, structural_facts)
        else {
            analyzer.mark_execution_dependent();
            receiver_diagnostics.push((
                CodeQueryDiagnosticCode::ReceiverAnalysisFailed,
                language,
                operation.as_str(),
                "selected parse variant unreadable".to_owned(),
                None,
            ));
            break;
        };
        let mut value = ReceiverAnalysisValue {
            report,
            capture: capture.clone(),
            site_id,
            site_ast_id,
            member_forms: Vec::new(),
        };
        // The verdict withholds a row whose target coverage is not exhaustive
        // before it reads any form, so only exhaustive rows spend scan budget
        // on classification; a withheld row cannot starve a later one.
        if member_step.filter.is_some() && member_target_coverage(&value) == "exhaustive" {
            let (member_forms, member_form_refused) = classify_member_targets(
                analyzer,
                &value.report,
                member_step,
                budget,
                limits,
                cancellation,
            );
            value.member_forms = member_forms;
            if member_form_refused {
                analyzer.mark_execution_dependent();
                receiver_diagnostics.push((
                    CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
                    value.report.site.language,
                    operation.as_str(),
                    "member form left unknown at max_scanned_files or max_scanned_source_bytes"
                        .to_string(),
                    Some(DerivationExecutionCause::Budget),
                ));
            }
        }
        if !member_step.admits(analyzer, &value) {
            continue;
        }
        let (value, trace) = if operation == ReceiverQueryOperation::MemberTargets {
            (
                PipelineValue::MemberTargetAnalysis(value.clone()),
                PipelineTraceValue::MemberTargetAnalysis(value),
            )
        } else {
            (
                PipelineValue::ReceiverAnalysis(value.clone()),
                PipelineTraceValue::ReceiverAnalysis(value),
            )
        };
        expansions.push(PipelineExpansion {
            value,
            trace: vec![(trace, None)],
            budgeted: true,
        });
    }
    expansions
}

/// The largest declaring file a member-form classification parses.
const MAX_MEMBER_FORM_SOURCE_BYTES: usize = 1024 * 1024;

type MemberDeclarationForms = Box<[(usize, usize, MemberForm)]>;

/// What the `member-targets` step keeps for all of its input rows (#10229).
///
/// The step creates one per execution, so a declaring file is parsed and
/// charged to the scan budget at most once however many rows reach it, and a
/// member is classified at most once.
pub(super) struct MemberFormStep<'f> {
    /// The step's `:member-form` and `:trivial-property` options; `None` when
    /// the step does not decide rows by the target's declaration.
    filter: Option<&'f crate::query::ReceiverTraversalFilter>,
    memo: HashMap<CodeUnit, MemberForm>,
    /// Every member declaration of each declaring file the step reached, as
    /// `(start_byte, end_byte, form)` sorted by start, classified in one walk
    /// when the file was first needed. `None` when the file could not be read.
    files: HashMap<ProjectFile, Option<MemberDeclarationForms>>,
    /// Rows the filter could neither keep nor drop, with the reason.
    withheld: Vec<(Language, String)>,
}

enum MemberFormVerdict {
    Match,
    Mismatch,
    Unknown(String),
}

impl<'f> MemberFormStep<'f> {
    pub(super) fn new(step: &'f QueryStep) -> Self {
        let filter = match step {
            QueryStep::MemberTargets(filter) if filter.filters_members() => Some(filter),
            _ => None,
        };
        Self {
            filter,
            memo: HashMap::default(),
            files: HashMap::default(),
            withheld: Vec::new(),
        }
    }

    /// Decide whether the row stays in the output. A row without a filter
    /// always stays. With one, a row is kept when its single exact target
    /// satisfies every option, dropped when it provably violates one, and
    /// otherwise withheld and recorded for `member_form_undecided`: unknown is
    /// not a mismatch, so a filter never turns an unexamined property into a
    /// complete empty answer.
    fn admits(&mut self, analyzer: &dyn IAnalyzer, value: &ReceiverAnalysisValue) -> bool {
        let Some(filter) = self.filter else {
            return true;
        };
        match member_form_verdict(filter, value) {
            MemberFormVerdict::Match => true,
            MemberFormVerdict::Mismatch => false,
            MemberFormVerdict::Unknown(reason) => {
                // The row is gone, so the answer no longer follows from the
                // source files alone.
                analyzer.mark_execution_dependent();
                let site = &value.report.site;
                self.withheld.push((
                    site.language,
                    format!(
                        "{}:{}: {reason}",
                        rel_path_string(&site.file),
                        site.range.start_line
                    ),
                ));
                false
            }
        }
    }

    /// One diagnostic for each language with withheld rows, naming every
    /// withheld site.
    pub(super) fn diagnostics(self) -> Vec<CodeQueryDiagnostic> {
        let mut by_language: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
        for (language, site) in self.withheld {
            by_language
                .entry(language.config_label())
                .or_default()
                .push(site);
        }
        by_language
            .into_iter()
            .map(|(language, mut sites)| {
                sites.sort();
                sites.dedup();
                CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                    incompleteness: brokk_bifrost_rql::Incompleteness::Content,
                    related: Vec::new(),
                    source: None,
                    code: CodeQueryDiagnosticCode::MemberFormUndecided,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language,
                    message: format!(
                        "member-targets withheld rows whose member form or property triviality was undecided: {sites:?}"
                    ),
                    exhausted_roots: Vec::new(),
                    withheld_rows_path: None,
                })
            })
            .collect()
    }
}

/// The target coverage of a member-target row, as the rendered row reports it.
fn member_target_coverage(value: &ReceiverAnalysisValue) -> &'static str {
    let ReceiverQueryAnalysis::MemberTargets(outcome) = &value.report.analysis else {
        unreachable!("member-target rows carry member-target analysis");
    };
    let (label, _, _) = receiver_outcome_metadata(outcome);
    receiver_coverage(value, label)
}

/// Apply the step options to one analysis. Only an `exhaustive` row (one
/// precise target, nothing truncated, no unsupported semantics) can decide;
/// every other row is unknown.
fn member_form_verdict(
    filter: &crate::query::ReceiverTraversalFilter,
    value: &ReceiverAnalysisValue,
) -> MemberFormVerdict {
    let coverage = member_target_coverage(value);
    if coverage != "exhaustive" {
        return MemberFormVerdict::Unknown(format!("target coverage is {coverage}"));
    }
    let ReceiverQueryAnalysis::MemberTargets(outcome) = &value.report.analysis else {
        unreachable!("member-target rows carry member-target analysis");
    };
    let targets = outcome.values().into_iter().flatten().collect::<Vec<_>>();
    if targets.is_empty() {
        return MemberFormVerdict::Unknown("no target".to_string());
    }
    let mut verdicts = targets.into_iter().map(|target| {
        let (member_form, trivial_property) = value.member_form(target);
        let ReceiverMemberTarget::Workspace { member, .. } = target else {
            return MemberFormVerdict::Unknown(
                "the target belongs to a semantic pack, which records no member form".to_string(),
            );
        };
        let mut unknown = Vec::new();
        if !filter.member_form.is_empty() {
            match member_form {
                Some(form) if filter.member_form.contains(&form) => {}
                Some(_) => return MemberFormVerdict::Mismatch,
                None => unknown.push(format!(
                    "the member form of {} is unknown",
                    member.fq_name()
                )),
            }
        }
        if let Some(wanted) = filter.trivial_property {
            match trivial_property {
                Some(actual) if actual == wanted => {}
                Some(_) => return MemberFormVerdict::Mismatch,
                None => unknown.push(format!(
                    "the property triviality of {} is unknown",
                    member.fq_name()
                )),
            }
        }
        if unknown.is_empty() {
            MemberFormVerdict::Match
        } else {
            MemberFormVerdict::Unknown(unknown.join("; "))
        }
    });
    // A precise outcome holds one target; if it ever held several, they must
    // agree for the row to be decided.
    let first = verdicts.next().expect("targets are not empty");
    for other in verdicts {
        match (&first, &other) {
            (MemberFormVerdict::Match, MemberFormVerdict::Match)
            | (MemberFormVerdict::Mismatch, MemberFormVerdict::Mismatch) => {}
            (MemberFormVerdict::Unknown(reason), _) | (_, MemberFormVerdict::Unknown(reason)) => {
                return MemberFormVerdict::Unknown(reason.clone());
            }
            _ => {
                return MemberFormVerdict::Unknown(
                    "the targets differ in member form or property triviality".to_string(),
                );
            }
        }
    }
    first
}

/// Classify each C# workspace member target of a member-target report (#10229).
///
/// The classification is made here, under the query's scanned-file and
/// source-byte budget and its cancellation, so that rendering and the step's
/// options only read it. `step` carries the memo and syntax cache for the
/// whole step. Returns the classifications and whether the budget refused a
/// declaring file.
fn classify_member_targets(
    analyzer: &dyn IAnalyzer,
    report: &ReceiverQueryReport,
    step: &mut MemberFormStep<'_>,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
) -> (Vec<(CodeUnit, MemberForm)>, bool) {
    let ReceiverQueryAnalysis::MemberTargets(outcome) = &report.analysis else {
        return (Vec::new(), false);
    };
    let mut refused = false;
    let mut forms = Vec::new();
    for target in outcome
        .values()
        .or_else(|| outcome.possible_candidates())
        .into_iter()
        .flatten()
    {
        let ReceiverMemberTarget::Workspace { member, .. } = target else {
            continue;
        };
        if crate::analyzer::common::language_for_file(member.source()) != Language::CSharp
            || forms.iter().any(|(unit, _)| unit == member)
        {
            continue;
        }
        let form = match step.memo.get(member) {
            Some(form) => *form,
            None => {
                let form = source_member_form(
                    analyzer,
                    member,
                    step,
                    budget,
                    limits,
                    cancellation,
                    &mut refused,
                );
                step.memo.insert(member.clone(), form);
                form
            }
        };
        forms.push((member.clone(), form));
    }
    (forms, refused)
}

/// Parse a declaring file through the provider's recorded, cancellable read,
/// charging it to the query's scanned-file and source-byte budget. The step
/// reads each file once. A file the budget cannot admit is not parsed, and
/// `refused` is set.
fn budgeted_member_syntax(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    refused: &mut bool,
) -> StructuralSyntaxLimitedOutcome {
    use brokk_bifrost_core::analyzer::work_budget::LimitedCounter;
    let scanned_files = budget.scanned_files.saturating_add(1);
    if !LimitedCounter::from_usage(scanned_files, limits.max_scanned_files).allows(0) {
        *refused = true;
        return StructuralSyntaxLimitedOutcome::Unavailable;
    }
    let remaining_bytes = limits
        .max_scanned_source_bytes
        .saturating_sub(budget.scanned_source_bytes);
    let Some(provider) = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::CSharp)
    else {
        return StructuralSyntaxLimitedOutcome::Unavailable;
    };
    let outcome = provider.structural_syntax_limited(
        file,
        remaining_bytes.min(MAX_MEMBER_FORM_SOURCE_BYTES),
        cancellation,
    );
    match &outcome {
        StructuralSyntaxLimitedOutcome::Available(syntax) => {
            budget.scanned_files = scanned_files;
            budget.scanned_source_bytes = budget
                .scanned_source_bytes
                .saturating_add(syntax.prepared().source().len());
        }
        StructuralSyntaxLimitedOutcome::Exceeded { .. }
            if remaining_bytes < MAX_MEMBER_FORM_SOURCE_BYTES =>
        {
            *refused = true;
        }
        StructuralSyntaxLimitedOutcome::Exceeded { .. }
        | StructuralSyntaxLimitedOutcome::Cancelled
        | StructuralSyntaxLimitedOutcome::Unavailable => {}
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
fn source_member_form(
    analyzer: &dyn IAnalyzer,
    member: &CodeUnit,
    step: &mut MemberFormStep<'_>,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    refused: &mut bool,
) -> MemberForm {
    let Some(support) = crate::analyzer::languages::language_support_for_hook(
        Language::CSharp,
        "member_declaration_form",
    ) else {
        return (None, None);
    };
    let Some(ranges) = support.declaration_ranges_limited(analyzer, member, 2) else {
        return (None, None);
    };
    if !ranges.complete || ranges.rows.len() != 1 {
        return (None, None);
    }
    let file = member.source();
    let forms = step.files.entry(file.clone()).or_insert_with(|| {
        let outcome = budgeted_member_syntax(analyzer, file, budget, limits, cancellation, refused);
        let StructuralSyntaxLimitedOutcome::Available(syntax) = outcome else {
            return None;
        };
        Some(classify_member_declarations(support, syntax.prepared()))
    });
    let Some(forms) = forms else {
        return (None, None);
    };
    // Member declarations do not nest, so at most one contains the range.
    let range = ranges.rows[0];
    forms[..forms.partition_point(|(start, _, _)| *start <= range.start_byte)]
        .last()
        .filter(|(_, end, _)| range.end_byte <= *end)
        .map_or((None, None), |(_, _, form)| *form)
}

/// Classify every C# member declaration of one file in a single walk, sorted
/// by start byte. Looking members up one at a time from the root re-reads the
/// whole member list of their type for each of them, which is quadratic in
/// the width of a large generated class; the file's full source is already
/// charged to the scan budget, so classifying all of it costs nothing extra
/// against the budget. A field or event declarator is classified through its
/// whole declaration: an undecided `#if` in the prefix (`System.Action` in one
/// branch, `event System.Action` in the other, then a shared `E;`) changes
/// what the name declares.
fn classify_member_declarations(
    support: &dyn crate::analyzer::languages::LanguageSupport,
    syntax: &brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree,
) -> MemberDeclarationForms {
    let regions = syntax.conditional_regions();
    let mut memo = brokk_bifrost_analysis::analyzer::languages::MemberDeclarationMemo::default();
    let mut forms = Vec::new();
    let mut stack = vec![syntax.tree().root_node()];
    let mut cursor = syntax.tree().walk();
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "field_declaration"
                | "enum_member_declaration"
                | "property_declaration"
                | "method_declaration"
                | "operator_declaration"
                | "conversion_operator_declaration"
                | "constructor_declaration"
                | "destructor_declaration"
                | "event_declaration"
                | "event_field_declaration"
        ) {
            forms.push((
                node.start_byte(),
                node.end_byte(),
                support.member_declaration_form(&mut memo, node, syntax.source(), &regions),
            ));
            continue;
        }
        stack.extend(node.named_children(&mut cursor));
    }
    forms.sort_unstable_by_key(|(start, _, _)| *start);
    forms.into_boxed_slice()
}

pub(super) const RECEIVER_SITE_ID_DOMAIN: &[u8] = b"bifrost.code_query.receiver_site.v1";

pub(super) fn receiver_site_identity(
    analyzer: &dyn IAnalyzer,
    report: &ReceiverQueryReport,
    facts: Option<&Arc<FileFacts>>,
) -> Option<(String, Option<String>)> {
    let variant = analyzer.selected_parse_variant(&report.site.file)?;
    let content_identity = facts.map_or_else(
        || {
            analyzer.indexed_source(&report.site.file).map_or_else(
                || {
                    ContentIdentity::from_source_bytes(
                        report.site.text.as_bytes(),
                        report.site.file.language(),
                        variant,
                    )
                },
                |source| {
                    ContentIdentity::from_source_bytes(
                        source.as_bytes(),
                        report.site.file.language(),
                        variant,
                    )
                },
            )
        },
        |facts| facts.source_identity(),
    );
    let mut digest = LengthDelimitedDigest::new(RECEIVER_SITE_ID_DOMAIN);
    digest.push(content_identity.as_bytes());
    digest.push(report.operation.as_str().as_bytes());
    digest.push(&report.site.range.start_byte.to_le_bytes());
    digest.push(&report.site.range.end_byte.to_le_bytes());
    let site_id = digest.finish().to_string();

    let site_ast_id =
        facts.and_then(|facts| site_ast_id_for_range(facts, content_identity, report.site.range));
    Some((site_id, site_ast_id))
}

/// The AST identity of the one facts-arena node whose span is exactly `range`.
///
/// `None` when no node has that exact span or when more than one does: an
/// ambiguous position must not claim an exact AST identity. Every site family
/// mints `site_ast_id` here, so a receiver row, a dispatch row, and an
/// occurrence row over the same token carry byte-identical identities.
pub(super) fn site_ast_id_for_range(
    facts: &FileFacts,
    content_identity: ContentIdentity,
    range: Range,
) -> Option<String> {
    let mut exact = facts.nodes().iter().enumerate().filter(|(_, node)| {
        node.range.start_byte == range.start_byte && node.range.end_byte == range.end_byte
    });
    let (node, _) = exact.next()?;
    if exact.next().is_some() {
        return None;
    }
    Some(super::super::occurrence_rows::ast_id(
        content_identity,
        u32::try_from(node).expect("facts arena node IDs fit u32"),
    ))
}

pub(super) fn record_receiver_pipeline_output_omission(
    diagnostics: &mut ReceiverDiagnostics,
    file: &ProjectFile,
    operation: ReceiverQueryOperation,
    omitted: usize,
) {
    diagnostics.extend((0..omitted).map(|_| {
        (
            CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
            crate::analyzer::common::language_for_file(file),
            operation.as_str(),
            RECEIVER_PIPELINE_OUTPUT_CAP_REASON.to_string(),
            Some(DerivationExecutionCause::Budget),
        )
    }));
}

/// Project CodeQuery's single remaining fact budget onto the receiver axes.
///
/// Scope, summary and hierarchy-order work all count as facts; resolution
/// rounds are iterations, not facts, and keep their own limit. Scope and
/// summary are allocated first. Hierarchy-order work gets only what they
/// leave, so the three never exceed the fact budget together. It can be zero
/// while facts remain (a small custom budget, or a nearly spent one); order
/// work then stops with the ordinary hierarchy budget stop and fails closed.
/// This scope-and-summary-first priority makes RQL the exception to the rule
/// that a preset's hierarchy allowance equals its scope allowance
/// (`DEFAULT_RECEIVER_MAX_HIERARCHY_ORDER_WORK`).
pub(super) fn receiver_budget_for_remaining_work(
    base: ReceiverAnalysisBudget,
    remaining_facts: usize,
    remaining_targets: usize,
) -> ReceiverAnalysisBudget {
    let desired_scope = base.max_scope_nodes.min(remaining_facts);
    let desired_summaries = base.max_summary_expansions.min(remaining_facts);
    let with_hierarchy_remainder = |max_scope_nodes: usize, max_summary_expansions: usize| {
        let allocated = max_scope_nodes
            .checked_add(max_summary_expansions)
            .filter(|allocated| *allocated <= remaining_facts)
            .expect("scope and summary projections fit the remaining fact budget");
        let unallocated = remaining_facts - allocated;
        ReceiverAnalysisBudget {
            context_depth: base.context_depth,
            max_targets: base.max_targets.min(remaining_targets),
            max_summary_expansions,
            max_resolution_rounds: base.max_resolution_rounds,
            max_hierarchy_order_steps: base.max_hierarchy_order_steps,
            max_scope_nodes,
            max_hierarchy_order_work: base.max_hierarchy_order_work.min(unallocated),
        }
    };
    if desired_scope
        .checked_add(desired_summaries)
        .is_some_and(|desired| desired <= remaining_facts)
    {
        return with_hierarchy_remainder(desired_scope, desired_summaries);
    }

    // CodeQuery has one fact-node budget, while receiver analysis exposes
    // separate scope and summary caps. Reserve up to one quarter for summary
    // expansion, then give scope traversal the remainder; this prevents the
    // two dimensions from each spending the same scalar remainder in full.
    let summary_reserve = desired_summaries.min(remaining_facts / 4);
    let max_scope_nodes = desired_scope.min(remaining_facts - summary_reserve);
    let unallocated = remaining_facts - summary_reserve - max_scope_nodes;
    let max_summary_expansions =
        summary_reserve.saturating_add((desired_summaries - summary_reserve).min(unallocated));
    with_hierarchy_remainder(max_scope_nodes, max_summary_expansions)
}

pub(super) fn receiver_candidate_count(report: &ReceiverQueryReport) -> usize {
    match &report.analysis {
        ReceiverQueryAnalysis::Values(outcome) => outcome
            .values()
            .or_else(|| outcome.possible_candidates())
            .map_or(0, <[_]>::len),
        ReceiverQueryAnalysis::MemberTargets(outcome) => outcome
            .values()
            .or_else(|| outcome.possible_candidates())
            .map_or(0, <[_]>::len),
    }
}
