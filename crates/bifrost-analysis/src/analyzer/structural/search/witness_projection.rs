use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use super::value_flow::{
    call_symbol_site, point_symbol_site, public_carrier_symbol, public_symbol_site,
};
use super::{
    CodeQueryFlowEvent, CodeQueryFlowFactSymbol, CodeQueryRange, CodeQuerySemanticCompleteness,
    CodeQuerySemanticEvidence, CodeQuerySemanticProof, CodeQuerySourceSite, CodeQueryTaintFinding,
    CodeQueryTaintOrigin, CodeQueryTaintProjectionLimits, CodeQueryTaintWitness,
    public_witness_step,
};
use crate::analyzer::dataflow::{PathQuality, SummaryWitness};
use crate::analyzer::semantic::{
    EvidenceCompleteness, LengthDelimitedDigest, ProofStatus, SemanticLocator,
};
use crate::analyzer::taint::{
    SourceEventKey, TaintAnalysisPlan, TaintFindingReport, TaintModelError,
};
use crate::analyzer::{ProjectFile, WorkspaceAnalyzer};
use crate::cancellation::CancellationToken;
use crate::text_utils::{compute_line_starts, line_column_for_offset};

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

fn serialized_json_bytes(value: &impl serde::Serialize) -> usize {
    struct ByteCounter(usize);

    impl Write for ByteCounter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| io::Error::other("serialized byte count overflow"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, value).map_or(usize::MAX, |()| counter.0)
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
    CodeQuerySemanticEvidence {
        proof: match proof {
            ProofStatus::Proven => CodeQuerySemanticProof::Proven,
            ProofStatus::Unproven(_) => CodeQuerySemanticProof::Unproven,
        },
        proof_reason: match proof {
            ProofStatus::Proven => None,
            ProofStatus::Unproven(reason) => Some(bounded_reason(reason)),
        },
        completeness: match completeness {
            EvidenceCompleteness::Complete => CodeQuerySemanticCompleteness::Complete,
            EvidenceCompleteness::Partial(_) => CodeQuerySemanticCompleteness::Partial,
        },
        completeness_reason: match completeness {
            EvidenceCompleteness::Complete => None,
            EvidenceCompleteness::Partial(reason) => Some(bounded_reason(reason)),
        },
    }
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
        let mut origin_evidence =
            BTreeMap::<SourceEventKey, (BTreeSet<String>, Vec<&SummaryWitness>)>::new();
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
                let (labels, witnesses) =
                    origin_evidence.entry(origin.origin().clone()).or_default();
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
        for (origin, (labels, witnesses)) in
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
            let source_event = public_taint_source_event(workspace, plan, projection_scope, origin);
            let mut public_steps = witness.steps().iter().map(|step| {
                public_taint_witness_step(
                    workspace,
                    plan,
                    report,
                    projection_scope,
                    &source_event,
                    step,
                )
            });
            let mut steps = Vec::new();
            let mut witness_bytes = 0usize;
            let mut omitted_steps = 0usize;
            while let Some(step) = public_steps.next() {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    cancelled = true;
                    break;
                }
                let step_bytes = serialized_json_bytes(&step);
                if steps.len() == limits.max_steps_per_witness
                    || step_bytes > limits.max_witness_bytes.saturating_sub(witness_bytes)
                {
                    omitted_steps = 1usize.saturating_add(public_steps.count());
                    break;
                }
                witness_bytes = witness_bytes.saturating_add(step_bytes);
                steps.push(step);
            }
            if cancelled {
                break;
            }
            let truncated = witness.truncated()
                || witness.alternatives_truncated()
                || witness.retention_truncated()
                || omitted_steps > 0;
            witnesses_truncated |= truncated;
            witnesses.push(CodeQueryTaintWitness {
                id: public_taint_witness_id(&finding_id, index, witness.quality()),
                finding_id: finding_id.clone(),
                witness_index: index,
                path: sink.site().path().as_str().to_owned(),
                language: sink.site().language().config_label(),
                range: locator_range(workspace, sink.site()),
                quality: public_taint_quality(witness.quality(), truncated),
                steps,
                retained_bytes: witness_bytes,
                truncated,
                omitted_steps_lower_bound: witness
                    .omitted_steps_lower_bound()
                    .saturating_add(omitted_steps),
                alternatives_truncated: witness.alternatives_truncated(),
                retention_truncated: witness.retention_truncated(),
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
            evidence: CodeQuerySemanticEvidence {
                proof: if proven {
                    CodeQuerySemanticProof::Proven
                } else {
                    CodeQuerySemanticProof::Unproven
                },
                proof_reason: None,
                completeness: if complete {
                    CodeQuerySemanticCompleteness::Complete
                } else {
                    CodeQuerySemanticCompleteness::Partial
                },
                completeness_reason: (!complete)
                    .then(|| "taint finding or retained origin evidence is incomplete".to_owned()),
            },
            ambiguous: !proven,
        };
        let projected_bytes = if max_projected_bytes == usize::MAX {
            0
        } else {
            serialized_json_bytes(&public)
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

fn public_taint_witness_step(
    workspace: &WorkspaceAnalyzer,
    plan: &TaintAnalysisPlan,
    report: &TaintFindingReport,
    projection_scope: &str,
    source_event: &CodeQueryFlowEvent,
    step: &crate::analyzer::dataflow::SummaryWitnessStep,
) -> super::CodeQueryFlowWitnessStep {
    let mut public = public_witness_step(workspace, step);
    public.source_symbol = Some(point_symbol_site(workspace, step.source()));
    public.target_symbol = step
        .target()
        .map(|point| point_symbol_site(workspace, point));
    public.origin_symbol = step.origin().map(|call| call_symbol_site(workspace, call));
    public.input = Some(public_taint_fact_symbol(
        workspace,
        plan,
        report,
        projection_scope,
        source_event,
        step.input_fact(),
    ));
    public.output = Some(public_taint_fact_symbol(
        workspace,
        plan,
        report,
        projection_scope,
        source_event,
        step.output_fact(),
    ));
    public
}

fn public_taint_fact_symbol(
    workspace: &WorkspaceAnalyzer,
    plan: &TaintAnalysisPlan,
    report: &TaintFindingReport,
    projection_scope: &str,
    source_event: &CodeQueryFlowEvent,
    fact_id: crate::analyzer::dataflow::FactId,
) -> CodeQueryFlowFactSymbol {
    let fact = *report
        .result()
        .fact_result()
        .fact(fact_id)
        .expect("validated taint witness fact resolves");
    if let Some(carrier) = fact.carrier() {
        return CodeQueryFlowFactSymbol::Carrier {
            source: Box::new(source_event.clone()),
            carrier: Box::new(public_carrier_symbol(
                workspace,
                plan.value_flow()
                    .carrier_key(carrier)
                    .expect("validated taint witness carrier resolves"),
            )),
            uncertain: fact.is_uncertain(),
        };
    }
    if let Some(sink) = fact.sink() {
        return CodeQueryFlowFactSymbol::Meeting {
            source: Box::new(source_event.clone()),
            sink: Box::new(public_taint_flow_event_for_sink(
                workspace,
                plan,
                projection_scope,
                sink,
            )),
            uncertain: fact.is_uncertain(),
        };
    }
    CodeQueryFlowFactSymbol::Zero
}

fn public_taint_source_event(
    workspace: &WorkspaceAnalyzer,
    plan: &TaintAnalysisPlan,
    projection_scope: &str,
    origin: &SourceEventKey,
) -> CodeQueryFlowEvent {
    let key = origin.value_flow_key();
    let spec = plan
        .value_flow()
        .sources()
        .find_map(|(_, spec)| (spec.key() == key).then_some(spec))
        .expect("validated taint origin source resolves");
    public_taint_event(
        workspace,
        projection_scope,
        "source",
        spec.key(),
        spec.phase(),
        spec.carrier(),
    )
}

fn public_taint_flow_event_for_sink(
    workspace: &WorkspaceAnalyzer,
    plan: &TaintAnalysisPlan,
    projection_scope: &str,
    sink: crate::analyzer::value_flow::ValueFlowSinkId,
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
    key: &crate::analyzer::value_flow::ValueFlowEventKey,
    phase: crate::analyzer::value_flow::ValueFlowObservationPhase,
    carrier: &crate::analyzer::value_flow::ValueFlowCarrier,
) -> CodeQueryFlowEvent {
    let locator = key.site();
    CodeQueryFlowEvent {
        id: public_taint_event_id(projection_scope, role, key),
        site: public_symbol_site(workspace, locator),
        path: locator.path().as_str().to_owned(),
        range: locator_range(workspace, locator),
        phase: match phase {
            crate::analyzer::value_flow::ValueFlowObservationPhase::BeforeEffects => {
                "before_effects"
            }
            crate::analyzer::value_flow::ValueFlowObservationPhase::AfterEffects => "after_effects",
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

fn public_source_site(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> CodeQuerySourceSite {
    CodeQuerySourceSite {
        path: locator.path().as_str().to_owned(),
        range: locator_range(workspace, locator),
    }
}

pub(super) fn public_taint_event_id(
    plan_ref: &str,
    role: &str,
    event: &crate::analyzer::value_flow::ValueFlowEventKey,
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

fn public_taint_quality(quality: PathQuality, truncated: bool) -> CodeQuerySemanticEvidence {
    CodeQuerySemanticEvidence {
        proof: if quality.is_proven() {
            CodeQuerySemanticProof::Proven
        } else {
            CodeQuerySemanticProof::Unproven
        },
        proof_reason: None,
        completeness: if quality.is_complete() && !truncated {
            CodeQuerySemanticCompleteness::Complete
        } else {
            CodeQuerySemanticCompleteness::Partial
        },
        completeness_reason: truncated.then(|| "taint witness evidence is truncated".to_owned()),
    }
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
    fn zero_step_projection_omits_the_whole_witness() {
        let (retained, retained_bytes, omitted) =
            retain_prefix_by_bytes(["first", "second"], 0, usize::MAX, |value| value.len());

        assert!(retained.is_empty());
        assert_eq!(retained_bytes, 0);
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
