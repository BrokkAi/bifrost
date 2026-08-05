use super::*;

pub(super) fn receiver_operation(step: &QueryStep) -> ReceiverQueryOperation {
    match step {
        QueryStep::ReceiverTargets(_) => ReceiverQueryOperation::ReceiverTargets,
        QueryStep::PointsTo(_) => ReceiverQueryOperation::PointsTo,
        QueryStep::MemberTargets(_) => ReceiverQueryOperation::MemberTargets,
        _ => unreachable!("receiver operation requested for a non-receiver step"),
    }
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

pub(super) fn correlate_receiver_expansions(expansions: &mut [PipelineExpansion], ast_id: String) {
    for expansion in expansions {
        let PipelineValue::ReceiverAnalysis(value) = &mut expansion.value else {
            unreachable!("receiver analysis expansion has its declared terminal domain")
        };
        value.site_ast_id = Some(ast_id.clone());
        for (trace, _) in &mut expansion.trace {
            let PipelineTraceValue::ReceiverAnalysis(value) = trace else {
                unreachable!("receiver analysis expansion trace has its declared terminal domain")
            };
            value.site_ast_id = Some(ast_id.clone());
        }
    }
}

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

pub(super) type ReceiverDiagnostics =
    BTreeMap<(CodeQueryDiagnosticCode, Language, &'static str, String), usize>;
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
        (spans, ReceiverQueryInput::Expression)
    } else {
        let fact_id = seed.fact_match.node;
        let fact = seed.facts.node(fact_id);
        let normalized = match operation {
            ReceiverQueryOperation::PointsTo => seed
                .facts
                .role_targets(fact_id, Role::Right)
                .next()
                .map(|target| target.span),
            ReceiverQueryOperation::ReceiverTargets => match fact.kind {
                NormalizedKind::Call => seed
                    .facts
                    .role_targets(fact_id, Role::Receiver)
                    .next()
                    .map(|target| target.span),
                NormalizedKind::FieldAccess => seed
                    .facts
                    .role_targets(fact_id, Role::Object)
                    .next()
                    .map(|target| target.span),
                _ => None,
            },
            ReceiverQueryOperation::MemberTargets => None,
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
        .structural_search_providers()
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
    shared_budget_exhausted: &mut bool,
    receiver_truncated: &mut bool,
) -> Vec<PipelineExpansion> {
    if budget.pipeline_rows >= limits.max_pipeline_rows {
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
        if budget.pipeline_rows >= limits.max_pipeline_rows {
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
                *receiver_diagnostics
                    .entry((
                        CodeQueryDiagnosticCode::ReceiverAnalysisFailed,
                        crate::analyzer::common::language_for_file(file),
                        operation.as_str(),
                        error.to_string(),
                    ))
                    .or_default() += 1;
                break;
            }
        };

        let candidate_count = receiver_candidate_count(&report);
        budget.fact_nodes = budget
            .fact_nodes
            .saturating_add(report.work.setup_nodes)
            .saturating_add(report.work.scope_nodes)
            .saturating_add(report.work.summary_expansions);
        budget.pipeline_rows = budget
            .pipeline_rows
            .saturating_add(1)
            .saturating_add(candidate_count);
        if budget.fact_nodes.saturating_add(budget.examined_references) > limits.max_fact_nodes
            || budget.pipeline_rows > limits.max_pipeline_rows
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
                *receiver_diagnostics
                    .entry((
                        CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
                        language,
                        operation.as_str(),
                        detail,
                    ))
                    .or_default() += 1;
            }
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::ExceededBudget { limit })
            | ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget {
                limit,
            }) => {
                *receiver_truncated = true;
                *receiver_diagnostics
                    .entry((
                        CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
                        language,
                        operation.as_str(),
                        format!("exceeded receiver limit {limit}"),
                    ))
                    .or_default() += 1;
            }
            ReceiverQueryAnalysis::Values(
                ReceiverAnalysisOutcome::Precise(_)
                | ReceiverAnalysisOutcome::Ambiguous(_)
                | ReceiverAnalysisOutcome::Unknown,
            )
            | ReceiverQueryAnalysis::MemberTargets(
                ReceiverAnalysisOutcome::Precise(_)
                | ReceiverAnalysisOutcome::Ambiguous(_)
                | ReceiverAnalysisOutcome::Unknown,
            ) => {}
        }
        if let Some(capability) = report.semantic_unsupported {
            *receiver_diagnostics
                .entry((
                    CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
                    language,
                    operation.as_str(),
                    format!(
                        "semantic evidence is incomplete because {} is unsupported",
                        capability.label()
                    ),
                ))
                .or_default() += 1;
        }
        if report.candidates_truncated {
            *receiver_truncated = true;
            *receiver_diagnostics
                .entry((
                    CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
                    language,
                    operation.as_str(),
                    "truncated candidates at max_targets".to_string(),
                ))
                .or_default() += 1;
        }
        let (site_id, site_ast_id) = receiver_site_identity(analyzer, &report, structural_facts);
        let value = ReceiverAnalysisValue {
            report,
            capture: capture.clone(),
            site_id,
            site_ast_id,
        };
        expansions.push(PipelineExpansion {
            value: PipelineValue::ReceiverAnalysis(value.clone()),
            trace: vec![(PipelineTraceValue::ReceiverAnalysis(value), None)],
            budgeted: true,
        });
    }
    expansions
}

pub(super) const RECEIVER_SITE_ID_DOMAIN: &[u8] = b"bifrost.code_query.receiver_site.v1";

pub(super) fn receiver_site_identity(
    analyzer: &dyn IAnalyzer,
    report: &ReceiverQueryReport,
    facts: Option<&Arc<FileFacts>>,
) -> (String, Option<String>) {
    let content_identity = facts.map_or_else(
        || {
            analyzer.indexed_source(&report.site.file).map_or_else(
                || ContentIdentity::hash_bytes(report.site.text.as_bytes()),
                |source| ContentIdentity::hash_bytes(source.as_bytes()),
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

    let site_ast_id = facts.and_then(|facts| {
        let mut exact = facts.nodes().iter().enumerate().filter(|(_, node)| {
            node.range.start_byte == report.site.range.start_byte
                && node.range.end_byte == report.site.range.end_byte
        });
        let (node, _) = exact.next()?;
        if exact.next().is_some() {
            return None;
        }
        Some(super::super::occurrence_rows::ast_id(
            content_identity,
            u32::try_from(node).expect("facts arena node IDs fit u32"),
        ))
    });
    (site_id, site_ast_id)
}

pub(super) fn record_receiver_pipeline_output_omission(
    diagnostics: &mut ReceiverDiagnostics,
    file: &ProjectFile,
    operation: ReceiverQueryOperation,
    omitted: usize,
) {
    *diagnostics
        .entry((
            CodeQueryDiagnosticCode::ReceiverAnalysisPartial,
            crate::analyzer::common::language_for_file(file),
            operation.as_str(),
            RECEIVER_PIPELINE_OUTPUT_CAP_REASON.to_string(),
        ))
        .or_default() += omitted;
}

pub(super) fn receiver_budget_for_remaining_work(
    base: ReceiverAnalysisBudget,
    remaining_facts: usize,
    remaining_targets: usize,
) -> ReceiverAnalysisBudget {
    let desired_scope = base.max_scope_nodes.min(remaining_facts);
    let desired_summaries = base.max_summary_expansions.min(remaining_facts);
    if desired_scope.saturating_add(desired_summaries) <= remaining_facts {
        return ReceiverAnalysisBudget {
            context_depth: base.context_depth,
            max_targets: base.max_targets.min(remaining_targets),
            max_summary_expansions: desired_summaries,
            max_scope_nodes: desired_scope,
        };
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
    debug_assert!(max_scope_nodes.saturating_add(max_summary_expansions) <= remaining_facts);
    ReceiverAnalysisBudget {
        context_depth: base.context_depth,
        max_targets: base.max_targets.min(remaining_targets),
        max_summary_expansions,
        max_scope_nodes,
    }
}

pub(super) fn receiver_candidate_count(report: &ReceiverQueryReport) -> usize {
    match &report.analysis {
        ReceiverQueryAnalysis::Values(outcome) => outcome.values().map_or(0, <[_]>::len),
        ReceiverQueryAnalysis::MemberTargets(outcome) => outcome.values().map_or(0, <[_]>::len),
    }
}
