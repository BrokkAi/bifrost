use std::collections::{BTreeMap, BTreeSet};

use super::value_flow::{
    call_symbol_site, point_symbol_site, public_carrier_symbol, public_symbol_site,
};
use super::{
    CodeQueryAbsentMemberWitness, CodeQueryAbsentMemberWitnessStatus, CodeQueryFlowCarrierSymbol,
    CodeQueryFlowEvent, CodeQueryFlowFactSymbol, CodeQueryRange, CodeQuerySemanticCompleteness,
    CodeQuerySemanticEvidence, CodeQuerySemanticProof, CodeQuerySourceSite, CodeQueryTaintFinding,
    CodeQueryTaintOrigin, CodeQueryTaintProjectionLimits, CodeQueryTaintWitness,
    public_witness_step,
};
use crate::analyzer::semantic::{
    CallSiteHandle, EvidenceCompleteness, LengthDelimitedDigest, ProgramPointHandle, ProofStatus,
    ReturnTransferKind, SemanticLocator,
};
use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::text_utils::{compute_line_starts, line_column_for_offset};
use brokk_bifrost_analysis::analyzer::common::serialized_json_len;
use brokk_bifrost_flow::dataflow::{
    PathQuality, SummaryWitness, SummaryWitnessStep, SummaryWitnessStepKind,
};
use brokk_bifrost_flow::taint::{
    SourceEventKey, TaintAnalysisPlan, TaintFindingReport, TaintModelError,
};

pub(super) fn retain_prefix_by_bytes<T>(
    items: impl IntoIterator<Item = T>,
    max_items: usize,
    max_bytes: usize,
    measure: impl Fn(&T) -> usize,
) -> (Vec<T>, usize, usize) {
    let mut items = items.into_iter();
    let mut retained = Vec::new();
    let mut retained_bytes = 0usize;
    while let Some(item) = items.next() {
        let item_bytes = measure(&item);
        if retained.len() >= max_items || item_bytes > max_bytes.saturating_sub(retained_bytes) {
            let omitted = 1usize.saturating_add(items.count());
            return (retained, retained_bytes, omitted);
        }
        retained_bytes = retained_bytes.saturating_add(item_bytes);
        retained.push(item);
    }
    (retained, retained_bytes, 0)
}

/// Source/identity snapshots of a reconstructed path. Projecting while the
/// solve is live lets later witnesses apply narrower limits without pinning IR.
#[derive(Debug, Clone)]
pub(super) struct ProjectedSummaryWitness {
    steps: Vec<super::CodeQueryFlowWitnessStep>,
    quality: PathQuality,
    truncated: bool,
    omitted_steps_lower_bound: usize,
    alternatives_truncated: bool,
    retention_truncated: bool,
}

impl ProjectedSummaryWitness {
    pub(super) fn new(
        workspace: &WorkspaceAnalyzer,
        witness: &SummaryWitness,
        max_steps: usize,
        max_bytes: usize,
    ) -> Self {
        let (steps, _, omitted) = retain_prefix_by_bytes(
            witness
                .steps()
                .iter()
                .map(|step| public_witness_step(workspace, step)),
            max_steps,
            max_bytes,
            serialized_json_len,
        );
        Self {
            steps,
            quality: witness.quality(),
            truncated: witness.truncated() || omitted > 0,
            omitted_steps_lower_bound: witness.omitted_steps_lower_bound().saturating_add(omitted),
            alternatives_truncated: witness.alternatives_truncated(),
            retention_truncated: witness.retention_truncated(),
        }
    }
    pub(super) fn steps(&self) -> &[super::CodeQueryFlowWitnessStep] {
        &self.steps
    }
    fn quality(&self) -> PathQuality {
        self.quality
    }
    fn truncated(&self) -> bool {
        self.truncated
    }
    fn omitted_steps_lower_bound(&self) -> usize {
        self.omitted_steps_lower_bound
    }
    fn alternatives_truncated(&self) -> bool {
        self.alternatives_truncated
    }
    fn retention_truncated(&self) -> bool {
        self.retention_truncated
    }
}

/// Project the evidence already retained by the class-set solve. Zero payload
/// budgets still retain a bounded metadata row; they cannot manufacture a
/// complete empty path or turn a reconstruction error into retention exhaustion.
pub(super) fn public_absent_member_witness(
    workspace: &WorkspaceAnalyzer,
    finding: &super::type_flow::AbsentMemberFindingValue,
    root: &super::type_flow::AbsentMemberRootEvidence,
    witness_index: usize,
    max_steps: usize,
    max_bytes: usize,
    cache: &mut super::PipelineRenderCache,
) -> CodeQueryAbsentMemberWitness {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.absent_member_witness.v1");
    digest.push(finding.id.as_bytes());
    digest.push(root.root_procedure_id.as_bytes());
    // The engine retains one representative witness for this root/site/class.
    // Its identity is independent of how much of that evidence is projected.
    let mut row = CodeQueryAbsentMemberWitness {
        id: digest.finish().to_string(),
        finding_id: finding.id.clone(),
        witness_index,
        path: crate::path_utils::rel_path_string(&finding.file),
        language: crate::analyzer::common::language_for_file(&finding.file).config_label(),
        range: super::render::render_source_range(
            workspace.analyzer(),
            &finding.file,
            &finding.range,
            cache,
        ),
        evidence: CodeQuerySemanticEvidence::new(
            CodeQuerySemanticProof::Unproven,
            CodeQuerySemanticCompleteness::Partial,
            None,
        ),
        steps: Vec::new(),
        retained_bytes: 0,
        truncated: false,
        omitted_steps_lower_bound: 0,
        alternatives_truncated: false,
        retention_truncated: false,
        witness_status: CodeQueryAbsentMemberWitnessStatus::Unavailable,
        unavailable_reason: None,
    };
    match &root.witness {
        Err(error) => {
            let reason = bounded_reason(&error.to_string());
            row.evidence.reason = Some(format!(
                "proof: {reason}; completeness: retained witness evidence is unavailable"
            ));
            row.unavailable_reason = Some(reason);
        }
        Ok(witness) => {
            let (steps, retained_bytes, omitted) = retain_prefix_by_bytes(
                witness.steps.iter().cloned(),
                max_steps,
                max_bytes,
                serialized_json_len,
            );
            row.steps = steps;
            row.retained_bytes = retained_bytes;
            row.truncated = witness.truncated() || omitted > 0;
            row.omitted_steps_lower_bound =
                witness.omitted_steps_lower_bound().saturating_add(omitted);
            row.alternatives_truncated = witness.alternatives_truncated();
            row.retention_truncated = witness.retention_truncated();
            row.evidence.proof = if witness.quality().is_proven() {
                CodeQuerySemanticProof::Proven
            } else {
                CodeQuerySemanticProof::Unproven
            };
            row.evidence.completeness = if witness.quality().is_complete() && !row.truncated {
                CodeQuerySemanticCompleteness::Complete
            } else {
                CodeQuerySemanticCompleteness::Partial
            };
            if row.truncated {
                row.evidence.reason = Some(format!(
                    "retained witness is truncated; at least {} step(s) omitted",
                    row.omitted_steps_lower_bound,
                ));
            }
            row.witness_status = if row.truncated {
                CodeQueryAbsentMemberWitnessStatus::Truncated
            } else {
                CodeQueryAbsentMemberWitnessStatus::Available
            };
        }
    }
    row
}

pub(super) fn locator_file(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> ProjectFile {
    ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        locator.path().as_path(),
    )
}

pub(super) fn locator_range(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> CodeQueryRange {
    let span = locator.anchor().span();
    let file = locator_file(workspace, locator);
    let Some(source) = workspace.analyzer().indexed_source(&file) else {
        return CodeQueryRange {
            start_line: span.start().line() as usize + 1,
            start_column: span.start().byte_column() as usize + 1,
            end_line: span.end().line() as usize + 1,
            end_column: span.end().byte_column() as usize + 1,
        };
    };
    let line_starts = compute_line_starts(&source);
    let (start_line, start_column) =
        line_column_for_offset(&source, &line_starts, span.start_byte() as usize);
    let (end_line, end_column) =
        line_column_for_offset(&source, &line_starts, span.end_byte() as usize);
    CodeQueryRange {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

pub(super) fn public_evidence(
    proof: &ProofStatus,
    completeness: &EvidenceCompleteness,
) -> CodeQuerySemanticEvidence {
    super::results::public_semantic_evidence(
        matches!(proof, ProofStatus::Proven),
        matches!(completeness, EvidenceCompleteness::Complete),
        match proof {
            ProofStatus::Proven => None,
            ProofStatus::Unproven(reason) => Some(bounded_reason(reason)),
        },
        match completeness {
            EvidenceCompleteness::Complete => None,
            EvidenceCompleteness::Partial(reason) => Some(bounded_reason(reason)),
        },
    )
}

pub(super) fn bounded_reason(reason: &str) -> String {
    const MAX_REASON_CHARS: usize = 256;
    let mut chars = reason.chars();
    let mut bounded = chars.by_ref().take(MAX_REASON_CHARS).collect::<String>();
    if chars.next().is_some() {
        bounded.push('…');
    }
    bounded
}

pub(super) fn hash_public_locator(digest: &mut LengthDelimitedDigest, locator: &SemanticLocator) {
    digest.push(locator.path().as_str().as_bytes());
    digest.push(locator.language().config_label().as_bytes());
    for segment in locator.declaration().segments() {
        digest.push(segment.kind().stable_label().as_bytes());
        digest.push(segment.name().unwrap_or("").as_bytes());
        digest.push_anchor(segment.anchor());
        digest.push(&segment.sibling_ordinal().to_le_bytes());
    }
    digest.push(locator.role().stable_label().as_bytes());
    digest.push_anchor(locator.anchor());
}

pub(super) fn saturating_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

pub(super) fn record_omitted_witnesses(
    witness_truncated: &mut bool,
    omitted_witnesses: &mut u64,
    omitted_lower_bound: usize,
) {
    *witness_truncated = true;
    *omitted_witnesses = omitted_witnesses.saturating_add(saturating_u64(omitted_lower_bound));
}

pub(super) fn map_witness_step_kind<T>(
    kind: SummaryWitnessStepKind,
    seed: T,
    edge: impl FnOnce(&'static str) -> T,
    end_summary_gap: impl FnOnce(&'static str) -> T,
) -> T {
    match kind {
        SummaryWitnessStepKind::Seed => seed,
        SummaryWitnessStepKind::Edge(kind) => edge(kind.label()),
        SummaryWitnessStepKind::EndSummaryGap(kind) => end_summary_gap(match kind {
            ReturnTransferKind::Normal => "normal",
            ReturnTransferKind::Exceptional => "exceptional",
        }),
    }
}

pub(super) fn public_flow_fact_symbol(
    source: Option<CodeQueryFlowEvent>,
    carrier: Option<CodeQueryFlowCarrierSymbol>,
    sink: Option<CodeQueryFlowEvent>,
    uncertain: bool,
) -> CodeQueryFlowFactSymbol {
    match (source, carrier, sink) {
        (None, None, None) => CodeQueryFlowFactSymbol::Zero,
        (Some(source), Some(carrier), None) => CodeQueryFlowFactSymbol::Carrier {
            source: Box::new(source),
            carrier: Box::new(carrier),
            uncertain,
        },
        (Some(source), None, Some(sink)) => CodeQueryFlowFactSymbol::Meeting {
            source: Box::new(source),
            sink: Box::new(sink),
            uncertain,
        },
        shape => panic!("invalid projected flow witness fact shape: {shape:?}"),
    }
}

pub(super) fn public_flow_witness_step(
    workspace: &WorkspaceAnalyzer,
    step: &SummaryWitnessStep,
    mut project_fact: impl FnMut(brokk_bifrost_flow::dataflow::FactId) -> CodeQueryFlowFactSymbol,
) -> super::CodeQueryFlowWitnessStep {
    let mut public = public_witness_step(workspace, step);
    public.source_symbol = Some(point_symbol_site(workspace, step.source()));
    public.target_symbol = step
        .target()
        .map(|point| point_symbol_site(workspace, point));
    public.origin_symbol = step.origin().map(|call| call_symbol_site(workspace, call));
    public.input = Some(project_fact(step.input_fact()));
    public.output = Some(project_fact(step.output_fact()));
    public
}

/// Project one retained diagnostic-neutral report into the public taint query
/// envelope without invoking propagation or witness reconstruction.
pub fn project_taint_finding_report(
    workspace: &WorkspaceAnalyzer,
    plan: &TaintAnalysisPlan,
    report: &TaintFindingReport,
    projection_scope: &str,
    limits: CodeQueryTaintProjectionLimits,
) -> Result<Vec<CodeQueryTaintFinding>, TaintModelError> {
    let outcome = project_taint_finding_report_bounded(
        workspace,
        plan,
        report,
        projection_scope,
        limits,
        usize::MAX,
        usize::MAX,
        None,
    )?;
    debug_assert!(!outcome.truncated && !outcome.cancelled);
    Ok(outcome
        .findings
        .into_iter()
        .map(|finding| finding.public)
        .collect())
}

/// Project one retained production result through the public CodeQuery
/// envelope without rerunning flow analysis.
pub fn project_production_taint_findings(
    workspace: &WorkspaceAnalyzer,
    result: &brokk_bifrost_flow::taint::ProductionTaintAnalysisResult,
    limits: brokk_bifrost_flow::taint::TaintProjectionLimits,
) -> Result<Vec<CodeQueryTaintFinding>, TaintModelError> {
    project_taint_finding_report(
        workspace,
        result.plan(),
        result.report(),
        result.projection_scope(),
        CodeQueryTaintProjectionLimits::new(
            limits.max_origins_per_finding,
            limits.max_witnesses_per_finding,
            limits.max_steps_per_witness,
            limits.max_witness_bytes,
        ),
    )
}

pub(crate) struct ProjectedTaintFinding {
    pub(crate) public: CodeQueryTaintFinding,
    pub(crate) file: ProjectFile,
    pub(crate) byte_span: std::ops::Range<usize>,
}

pub(crate) struct BoundedTaintProjection {
    pub(crate) findings: Vec<ProjectedTaintFinding>,
    pub(crate) retained_bytes: usize,
    pub(crate) truncated: bool,
    pub(crate) cancelled: bool,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn project_taint_finding_report_bounded(
    workspace: &WorkspaceAnalyzer,
    plan: &TaintAnalysisPlan,
    report: &TaintFindingReport,
    projection_scope: &str,
    limits: CodeQueryTaintProjectionLimits,
    max_findings: usize,
    max_projected_bytes: usize,
    cancellation: Option<&CancellationToken>,
) -> Result<BoundedTaintProjection, TaintModelError> {
    let mut groups = report
        .findings()
        .chunk_by(|left, right| left.key().sink() == right.key().sink())
        .peekable();
    let mut projected = Vec::with_capacity(max_findings.min(report.findings().len()));
    let mut retained_bytes = 0usize;
    let mut truncated = false;
    let mut cancelled = false;

    for findings in groups.by_ref() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            cancelled = true;
            break;
        }
        if projected.len() == max_findings {
            truncated = true;
            break;
        }
        let sink = findings[0].key().sink();
        let mut reached_labels = BTreeSet::new();
        let mut origin_evidence = BTreeMap::<
            SourceEventKey,
            (
                BTreeSet<String>,
                Vec<&SummaryWitness>,
                Option<FrontierSourceObservation<'_>>,
            ),
        >::new();
        let mut proven = true;
        let mut complete = report.is_complete();
        let mut origins_truncated = false;
        let mut witnesses_truncated = false;

        for finding in findings {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                cancelled = true;
                break;
            }
            reached_labels.extend(
                plan.universe()
                    .stable_classes(finding.classes())?
                    .into_iter()
                    .map(|class| class.as_str().to_owned()),
            );
            proven &= finding.is_proven();
            complete &= finding.is_complete() && finding.origins().is_complete();
            origins_truncated |= finding.origins().origin_truncated();
            witnesses_truncated |=
                finding.origins().witness_truncated() || finding.origins().witness_unavailable();
            for origin in finding.origins().evidence() {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    cancelled = true;
                    break;
                }
                let (labels, witnesses, frontier_source) =
                    origin_evidence.entry(origin.origin().clone()).or_default();
                if frontier_source.is_none() {
                    *frontier_source = origin.frontier_source();
                }
                labels.extend(
                    plan.universe()
                        .stable_classes(origin.classes())?
                        .into_iter()
                        .map(|class| class.as_str().to_owned()),
                );
                for witness in origin.witnesses() {
                    let witness = witness.as_ref();
                    if !witnesses.contains(&witness) {
                        witnesses.push(witness);
                    }
                }
            }
            if cancelled {
                break;
            }
        }
        if cancelled {
            break;
        }

        let reached_labels = reached_labels.into_iter().collect::<Vec<_>>();
        let sink_event_id = public_taint_event_id(projection_scope, "sink", sink);
        let origin_event_ids = origin_evidence
            .keys()
            .map(|origin| {
                public_taint_event_id(projection_scope, "source", origin.value_flow_key())
            })
            .collect::<Vec<_>>();
        let finding_id = public_taint_finding_id(
            projection_scope,
            &sink_event_id,
            &reached_labels,
            &origin_event_ids,
        );
        let omitted_origins = origin_evidence
            .len()
            .saturating_sub(limits.max_origins_per_finding);
        origins_truncated |= omitted_origins > 0;

        let mut origins = Vec::new();
        let mut retained_witnesses = Vec::new();
        for (origin, (labels, witnesses, _)) in
            origin_evidence.iter().take(limits.max_origins_per_finding)
        {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                cancelled = true;
                break;
            }
            let event = origin.value_flow_key();
            let event_id = public_taint_event_id(projection_scope, "source", event);
            let labels = labels.iter().cloned().collect::<Vec<_>>();
            origins.push(CodeQueryTaintOrigin {
                id: public_taint_origin_id(&finding_id, &event_id, &labels),
                event_id,
                labels,
                site: public_source_site(workspace, event.site()),
            });
            for witness in witnesses {
                if !retained_witnesses.contains(&(origin, *witness)) {
                    retained_witnesses.push((origin, *witness));
                }
            }
        }
        if cancelled {
            break;
        }
        origins.sort_by(|left, right| left.id.cmp(&right.id));

        let omitted_witnesses = retained_witnesses
            .len()
            .saturating_sub(limits.max_witnesses_per_finding);
        witnesses_truncated |= omitted_witnesses > 0;
        let mut witnesses = Vec::new();
        for (index, (origin, witness)) in retained_witnesses
            .into_iter()
            .take(limits.max_witnesses_per_finding)
            .enumerate()
        {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                cancelled = true;
                break;
            }
            let source_event = public_taint_source_event(
                workspace,
                plan,
                projection_scope,
                origin,
                origin_evidence[origin].2,
            );
            let mut public_steps = witness.steps().iter().map(|step| {
                public_flow_witness_step(workspace, step, |fact_id| {
                    public_taint_fact_symbol(
                        workspace,
                        plan,
                        report,
                        projection_scope,
                        &source_event,
                        fact_id,
                    )
                })
            });
            let mut steps = Vec::new();
            let mut witness_bytes = 0usize;
            let mut omitted_steps = 0usize;
            let mut projection_cause = None::<&'static str>;
            while let Some(step) = public_steps.next() {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    cancelled = true;
                    break;
                }
                let step_bytes = serialized_json_len(&step);
                if steps.len() == limits.max_steps_per_witness {
                    projection_cause = Some("projection_step_limit");
                    omitted_steps = 1usize.saturating_add(public_steps.count());
                    break;
                }
                if step_bytes > limits.max_witness_bytes.saturating_sub(witness_bytes) {
                    projection_cause = Some("projection_byte_limit");
                    omitted_steps = 1usize.saturating_add(public_steps.count());
                    break;
                }
                witness_bytes = witness_bytes.saturating_add(step_bytes);
                steps.push(step);
            }
            if cancelled {
                break;
            }
            // Unretained sibling alternatives do not truncate this witness:
            // its own steps are complete without them. They stay reported
            // through the dedicated `alternatives_truncated` field.
            let truncated = witness.truncated() || omitted_steps > 0;
            let truncation_cause = witness
                .truncation_cause()
                .map(|cause| cause.stable_label().to_owned())
                .or_else(|| projection_cause.map(str::to_owned));
            witnesses_truncated |= truncated;
            witnesses.push(CodeQueryTaintWitness {
                id: public_taint_witness_id(&finding_id, index, witness.quality()),
                finding_id: finding_id.clone(),
                witness_index: index,
                path: sink.site().path().as_str().to_owned(),
                language: sink.site().language().config_label(),
                range: locator_range(workspace, sink.site()),
                evidence: public_taint_quality(
                    witness.quality(),
                    truncated,
                    truncation_cause.as_deref(),
                ),
                steps,
                retained_bytes: witness_bytes,
                truncated,
                omitted_steps_lower_bound: witness
                    .omitted_steps_lower_bound()
                    .saturating_add(omitted_steps),
                alternatives_truncated: witness.alternatives_truncated(),
                retention_truncated: witness.retention_truncated(),
                truncation_cause,
            });
        }
        if cancelled {
            break;
        }

        complete &= !origins_truncated && !witnesses_truncated;
        let public = CodeQueryTaintFinding {
            id: finding_id,
            path: sink.site().path().as_str().to_owned(),
            language: sink.site().language().config_label(),
            range: locator_range(workspace, sink.site()),
            sink_event_id,
            sink: public_source_site(workspace, sink.site()),
            reached_labels,
            origins,
            origins_truncated,
            witnesses,
            witnesses_truncated,
            evidence: CodeQuerySemanticEvidence::new(
                if proven {
                    CodeQuerySemanticProof::Proven
                } else {
                    CodeQuerySemanticProof::Unproven
                },
                if complete {
                    CodeQuerySemanticCompleteness::Complete
                } else {
                    CodeQuerySemanticCompleteness::Partial
                },
                (!complete)
                    .then(|| "taint finding or retained origin evidence is incomplete".to_owned()),
            ),
            ambiguous: !proven,
        };
        let projected_bytes = if max_projected_bytes == usize::MAX {
            0
        } else {
            serialized_json_len(&public)
        };
        if projected_bytes > max_projected_bytes.saturating_sub(retained_bytes) {
            truncated = true;
            break;
        }
        retained_bytes = retained_bytes.saturating_add(projected_bytes);
        let locator = sink.site();
        let span = locator.anchor().span();
        projected.push(ProjectedTaintFinding {
            public,
            file: locator_file(workspace, locator),
            byte_span: span.start_byte() as usize..span.end_byte() as usize,
        });
    }
    truncated |= groups.peek().is_some();
    Ok(BoundedTaintProjection {
        findings: projected,
        retained_bytes,
        truncated,
        cancelled,
    })
}

fn public_taint_fact_symbol(
    workspace: &WorkspaceAnalyzer,
    plan: &TaintAnalysisPlan,
    report: &TaintFindingReport,
    projection_scope: &str,
    source_event: &CodeQueryFlowEvent,
    fact_id: brokk_bifrost_flow::dataflow::FactId,
) -> CodeQueryFlowFactSymbol {
    let fact = *report
        .result()
        .fact_result()
        .fact(fact_id)
        .expect("validated taint witness fact resolves");
    let carrier_id = fact.carrier();
    let sink_id = fact.sink();
    let source = (carrier_id.is_some() || sink_id.is_some()).then(|| source_event.clone());
    let carrier = carrier_id.map(|carrier| {
        public_carrier_symbol(
            workspace,
            plan.value_flow()
                .carrier_key(carrier)
                .expect("validated taint witness carrier resolves"),
        )
    });
    let sink = sink_id
        .map(|sink| public_taint_flow_event_for_sink(workspace, plan, projection_scope, sink));
    public_flow_fact_symbol(source, carrier, sink, fact.is_uncertain())
}

/// The phase and carrier of a source a composition matched on its frontier.
type FrontierSourceObservation<'a> = (
    brokk_bifrost_flow::value_flow::ValueFlowObservationPhase,
    &'a brokk_bifrost_flow::value_flow::ValueFlowCarrier,
);

/// The public event of one origin: the plan's source specification, or for a
/// source a composition matched on its frontier, the phase and carrier its
/// evidence carries.
fn public_taint_source_event(
    workspace: &WorkspaceAnalyzer,
    plan: &TaintAnalysisPlan,
    projection_scope: &str,
    origin: &SourceEventKey,
    frontier_source: Option<FrontierSourceObservation<'_>>,
) -> CodeQueryFlowEvent {
    let key = origin.value_flow_key();
    let (phase, carrier) = match frontier_source {
        Some(observation) => observation,
        None => plan
            .value_flow()
            .sources()
            .find_map(|(_, spec)| (spec.key() == key).then(|| (spec.phase(), spec.carrier())))
            .expect("validated taint origin source resolves"),
    };
    public_taint_event(workspace, projection_scope, "source", key, phase, carrier)
}

fn public_taint_flow_event_for_sink(
    workspace: &WorkspaceAnalyzer,
    plan: &TaintAnalysisPlan,
    projection_scope: &str,
    sink: brokk_bifrost_flow::value_flow::ValueFlowSinkId,
) -> CodeQueryFlowEvent {
    let spec = plan
        .value_flow()
        .sink(sink)
        .expect("validated taint witness sink resolves");
    public_taint_event(
        workspace,
        projection_scope,
        "sink",
        spec.key(),
        spec.phase(),
        spec.carrier(),
    )
}

fn public_taint_event(
    workspace: &WorkspaceAnalyzer,
    projection_scope: &str,
    role: &str,
    key: &brokk_bifrost_flow::value_flow::ValueFlowEventKey,
    phase: brokk_bifrost_flow::value_flow::ValueFlowObservationPhase,
    carrier: &brokk_bifrost_flow::value_flow::ValueFlowCarrier,
) -> CodeQueryFlowEvent {
    let locator = key.site();
    CodeQueryFlowEvent {
        id: public_taint_event_id(projection_scope, role, key),
        site: public_symbol_site(workspace, locator),
        path: locator.path().as_str().to_owned(),
        range: locator_range(workspace, locator),
        phase: match phase {
            brokk_bifrost_flow::value_flow::ValueFlowObservationPhase::BeforeEffects => {
                "before_effects"
            }
            brokk_bifrost_flow::value_flow::ValueFlowObservationPhase::AfterEffects => {
                "after_effects"
            }
        },
        ordinal: key.ordinal(),
        carrier: public_carrier_symbol(
            workspace,
            &carrier
                .stable_key()
                .expect("validated taint event carrier has stable identity"),
        ),
    }
}

pub(super) fn public_source_site(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> CodeQuerySourceSite {
    CodeQuerySourceSite {
        path: locator.path().as_str().to_owned(),
        range: locator_range(workspace, locator),
    }
}

pub(super) fn program_point_locator(handle: &ProgramPointHandle) -> &SemanticLocator {
    let _point = handle
        .procedure()
        .semantics()
        .point(handle.id())
        .expect("validated witness point resolves");
    handle
        .locator()
        .expect("validated witness point has source mapping")
}

pub(super) fn call_site_locator(handle: &CallSiteHandle) -> &SemanticLocator {
    let _call = handle
        .procedure()
        .semantics()
        .call_site(handle.id())
        .expect("validated witness call resolves");
    handle
        .locator()
        .expect("validated witness call has source mapping")
}

pub(super) fn public_program_point_site(
    workspace: &WorkspaceAnalyzer,
    handle: &ProgramPointHandle,
) -> CodeQuerySourceSite {
    public_source_site(workspace, program_point_locator(handle))
}

pub(super) fn public_call_site(
    workspace: &WorkspaceAnalyzer,
    handle: &CallSiteHandle,
) -> CodeQuerySourceSite {
    public_source_site(workspace, call_site_locator(handle))
}

pub(super) fn public_taint_event_id(
    plan_ref: &str,
    role: &str,
    event: &brokk_bifrost_flow::value_flow::ValueFlowEventKey,
) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.taint_event.v1");
    digest.push(plan_ref.as_bytes());
    digest.push(role.as_bytes());
    hash_public_locator(&mut digest, event.site());
    digest.push(&event.ordinal().to_le_bytes());
    digest.finish().to_string()
}

fn public_taint_finding_id(
    plan_ref: &str,
    sink_event_id: &str,
    reached_labels: &[String],
    origin_event_ids: &[String],
) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.taint_finding.v1");
    digest.push(plan_ref.as_bytes());
    digest.push(sink_event_id.as_bytes());
    for label in reached_labels {
        digest.push(label.as_bytes());
    }
    for origin_event_id in origin_event_ids {
        digest.push(origin_event_id.as_bytes());
    }
    digest.finish().to_string()
}

fn public_taint_origin_id(finding_id: &str, event_id: &str, labels: &[String]) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.taint_origin.v1");
    digest.push(finding_id.as_bytes());
    digest.push(event_id.as_bytes());
    for label in labels {
        digest.push(label.as_bytes());
    }
    digest.finish().to_string()
}

fn public_taint_witness_id(finding_id: &str, index: usize, quality: PathQuality) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.taint_witness.v1");
    digest.push(finding_id.as_bytes());
    digest.push(&(index as u64).to_le_bytes());
    digest.push(&(quality.ordinal() as u64).to_le_bytes());
    digest.finish().to_string()
}

fn public_taint_quality(
    quality: PathQuality,
    truncated: bool,
    truncation_cause: Option<&str>,
) -> CodeQuerySemanticEvidence {
    super::results::public_semantic_evidence(
        quality.is_proven(),
        quality.is_complete() && !truncated,
        None,
        truncated.then(|| match truncation_cause {
            Some(cause) => format!("taint witness evidence is truncated: {cause}"),
            None => "taint witness evidence is truncated".to_owned(),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::{bounded_reason, retain_prefix_by_bytes};

    #[test]
    fn byte_trimming_keeps_a_contiguous_prefix() {
        let (retained, retained_bytes, omitted) =
            retain_prefix_by_bytes(["aaaa", "bbbbbb", "c"], 3, 5, |value| value.len());

        assert_eq!(retained, ["aaaa"]);
        assert_eq!(retained_bytes, 4);
        assert_eq!(omitted, 2);
    }

    #[test]
    fn bounded_reasons_mark_omitted_text() {
        let reason = "x".repeat(257);
        let bounded = bounded_reason(&reason);
        assert_eq!(bounded.chars().count(), 257);
        assert!(bounded.ends_with('…'));
    }
}
