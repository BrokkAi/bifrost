use super::*;

pub(super) fn insert_pipeline_row(
    rows: &mut Vec<PipelineRow>,
    indexes: &mut HashMap<PipelineKey, usize>,
    value: PipelineValue,
    mut traces: Vec<PipelineTrace>,
    provenance_truncated: bool,
) {
    let key = value.key();
    if let Some(&index) = indexes.get(&key) {
        let row = &mut rows[index];
        let remaining = MAX_PROVENANCE_TRACES.saturating_sub(row.traces.len());
        if traces.len() > remaining {
            row.provenance_truncated = true;
        }
        row.traces.extend(traces.into_iter().take(remaining));
        row.provenance_truncated |= provenance_truncated;
        return;
    }

    let truncated = provenance_truncated || traces.len() > MAX_PROVENANCE_TRACES;
    traces.truncate(MAX_PROVENANCE_TRACES);
    indexes.insert(key, rows.len());
    rows.push(PipelineRow {
        value,
        traces,
        provenance_truncated: truncated,
    });
}

pub(super) fn render_pipeline_item(
    analyzer: &dyn IAnalyzer,
    row: PipelineRow,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultItem {
    let provenance = row
        .traces
        .iter()
        .map(|trace| render_provenance(analyzer, trace, detail, cache))
        .collect();
    let value = match row.value {
        PipelineValue::StructuralMatch(seed) => CodeQueryResultValue::StructuralMatch {
            value: render_match(
                analyzer,
                seed.language,
                &seed.file,
                &seed.facts,
                &seed.fact_match,
                detail,
                cache,
            ),
        },
        PipelineValue::Declaration(declaration) => CodeQueryResultValue::Declaration {
            value: render_declaration(analyzer, &declaration, detail, cache),
        },
        PipelineValue::Semantic(value) => value.public_result(),
        PipelineValue::File(file) => CodeQueryResultValue::File {
            value: render_file(analyzer, &file),
        },
        PipelineValue::ReferenceSite(site) => CodeQueryResultValue::ReferenceSite {
            value: Box::new(render_reference_site(analyzer, &site, detail, cache)),
        },
        PipelineValue::CallSite(site) => CodeQueryResultValue::CallSite {
            value: Box::new(render_call_site(analyzer, &site, detail, cache)),
        },
        PipelineValue::ExpressionSite(site) => CodeQueryResultValue::ExpressionSite {
            value: Box::new(render_expression_site(analyzer, &site, cache)),
        },
        PipelineValue::ReceiverAnalysis(value) => CodeQueryResultValue::ReceiverAnalysis {
            value: Box::new(render_receiver_analysis(analyzer, &value, detail, cache)),
        },
        PipelineValue::ReceiverOutcome(value) => CodeQueryResultValue::ReceiverOutcome {
            value: Box::new(render_receiver_outcome(analyzer, &value, cache)),
        },
        PipelineValue::ReceiverEvidence(value) => CodeQueryResultValue::ReceiverEvidence {
            value: Box::new(render_receiver_evidence(analyzer, &value, cache)),
        },
        PipelineValue::CallShape(value) => CodeQueryResultValue::CallShape {
            value: Box::new(render_call_shape(analyzer, &value, cache)),
        },
        PipelineValue::CallArgumentGroup(value) => CodeQueryResultValue::CallArgumentGroup {
            value: Box::new(render_call_argument_group(analyzer, &value, cache)),
        },
        PipelineValue::CallArgument(value) => CodeQueryResultValue::CallArgument {
            value: Box::new(render_call_shape_argument(analyzer, &value, cache)),
        },
        PipelineValue::MemberSelection(value) => CodeQueryResultValue::MemberSelection {
            value: Box::new(render_member_selection(analyzer, &value, cache)),
        },
        PipelineValue::Occurrence(value) => CodeQueryResultValue::Occurrence {
            value: Box::new(render_occurrence(analyzer, &value, detail, cache)),
        },
        PipelineValue::LexicalScope(value) => CodeQueryResultValue::LexicalScope {
            value: Box::new(render_scope(analyzer, &value, cache)),
        },
        PipelineValue::Binding(value) => CodeQueryResultValue::Binding {
            value: Box::new(render_binding(analyzer, &value, cache)),
        },
        PipelineValue::ResolutionCandidate(value) => CodeQueryResultValue::ResolutionCandidate {
            value: Box::new(render_resolution_candidate(analyzer, &value, detail, cache)),
        },
        PipelineValue::GenerationSite(value) => CodeQueryResultValue::GenerationSite {
            value: Box::new(render_generation_site(analyzer, &value, cache)),
        },
        PipelineValue::Export(value) => CodeQueryResultValue::Export {
            value: Box::new(render_export(analyzer, &value, cache)),
        },
        PipelineValue::DeclarationState(value) => CodeQueryResultValue::DeclarationState {
            value: Box::new(render_declaration_state(analyzer, &value, cache)),
        },
        PipelineValue::ReferenceEdge(value) => CodeQueryResultValue::ReferenceEdge {
            value: Box::new(render_reference_edge(analyzer, &value, detail, cache)),
        },
        PipelineValue::QualifiedPath(value) => CodeQueryResultValue::QualifiedPath {
            value: Box::new(render_qualified_path(analyzer, &value, cache)),
        },
        PipelineValue::PathSegment(value) => CodeQueryResultValue::PathSegment {
            value: Box::new(render_path_segment(analyzer, &value, cache)),
        },
    };
    CodeQueryResultItem {
        value,
        provenance,
        provenance_truncated: row.provenance_truncated,
    }
}

pub(super) fn render_provenance(
    analyzer: &dyn IAnalyzer,
    trace: &PipelineTrace,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryProvenance {
    CodeQueryProvenance {
        branch: trace.branch.clone(),
        seed: render_seed_ref(&trace.seed, detail),
        steps: trace
            .steps
            .iter()
            .map(|step| CodeQueryProvenanceStep {
                op: step.op.label(),
                result: match &step.value {
                    PipelineTraceValue::Declaration(declaration) => {
                        render_declaration_ref(analyzer, declaration, detail, cache)
                    }
                    PipelineTraceValue::Semantic(value) => value.public_ref(),
                    PipelineTraceValue::File(file) => render_file_ref(file),
                    PipelineTraceValue::ReferenceSite(site) => {
                        render_reference_site_ref(analyzer, site, detail, cache)
                    }
                    PipelineTraceValue::CallSite(site) => {
                        render_call_site_ref(analyzer, site, cache)
                    }
                    PipelineTraceValue::ExpressionSite(site) => {
                        render_expression_site_ref(analyzer, site, cache)
                    }
                    PipelineTraceValue::ReceiverAnalysis(value) => {
                        render_receiver_analysis_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::ReceiverOutcome(value) => {
                        render_receiver_outcome_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::ReceiverEvidence(value) => {
                        render_receiver_evidence_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::CallShape(value) => {
                        let rendered = render_call_shape(analyzer, value, cache);
                        CodeQueryResultRef::CallShape {
                            id: rendered.id,
                            site_id: rendered.site_id,
                            path: rendered.path,
                            range: rendered.range,
                            call_kind: rendered.call_kind,
                            coverage: rendered.coverage,
                        }
                    }
                    PipelineTraceValue::CallArgumentGroup(value) => {
                        let rendered = render_call_argument_group(analyzer, value, cache);
                        CodeQueryResultRef::CallArgumentGroup {
                            id: rendered.id,
                            site_id: rendered.site_id,
                            path: rendered.path,
                            range: rendered.range,
                            kind: rendered.kind,
                        }
                    }
                    PipelineTraceValue::CallArgument(value) => {
                        let rendered = render_call_shape_argument(analyzer, value, cache);
                        CodeQueryResultRef::CallArgument {
                            id: rendered.id,
                            group_id: rendered.group_id,
                            path: rendered.path,
                            range: rendered.range,
                            argument_index: rendered.argument_index,
                        }
                    }
                    PipelineTraceValue::MemberSelection(value) => {
                        render_member_selection_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::Occurrence(value) => {
                        render_occurrence_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::GenerationSite(value) => {
                        render_generation_site_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::Export(value) => render_export_ref(analyzer, value, cache),
                    PipelineTraceValue::DeclarationState(value) => {
                        render_declaration_state_ref(value)
                    }
                    PipelineTraceValue::LexicalScope(value) => {
                        render_scope_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::Binding(value) => {
                        render_binding_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::ResolutionCandidate(value) => {
                        render_candidate_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::ReferenceEdge(value) => {
                        render_edge_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::QualifiedPath(value) => {
                        render_qualified_path_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::PathSegment(value) => {
                        render_path_segment_ref(analyzer, value, cache)
                    }
                },
                via: step.via.as_ref().map(|via| match via {
                    PipelineVia::ReferenceSite(site) => {
                        render_reference_site_ref(analyzer, site, detail, cache)
                    }
                    PipelineVia::CallSite(site) => render_call_site_ref(analyzer, site, cache),
                }),
            })
            .collect(),
    }
}

pub(super) fn render_seed_ref(
    seed: &SeedMatch,
    detail: CodeQueryResultDetail,
) -> CodeQueryResultRef {
    let fact = seed.facts.node(seed.fact_match.node);
    let full = !detail.is_compact();
    let path = rel_path_string(&seed.file);
    CodeQueryResultRef::StructuralMatch {
        id: full.then(|| match_id(&path, fact.kind.label(), fact.span())),
        path,
        kind: fact.kind.label(),
        start_line: fact.range.start_line,
        end_line: fact.range.end_line,
        node_range: full.then(|| range_for_span(&seed.facts, fact.span())),
    }
}

pub(super) fn render_declaration_ref(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let path = rel_path_string(declaration.unit.source());
    let fq_name = declaration.unit.fq_name();
    let kind = declaration.unit.kind().display_lowercase();
    let full = !detail.is_compact();
    CodeQueryResultRef::Declaration {
        id: full.then(|| declaration_id(&path, kind, &fq_name, declaration.range)),
        path,
        kind,
        fq_name,
        start_line: declaration.range.start_line,
        end_line: declaration.range.end_line,
        node_range: full
            .then(|| cache.range_for_declaration(analyzer, declaration))
            .flatten(),
    }
}

pub(super) fn render_file_ref(file: &ProjectFile) -> CodeQueryResultRef {
    CodeQueryResultRef::File {
        path: rel_path_string(file),
    }
}

pub(super) fn render_reference_site_ref(
    analyzer: &dyn IAnalyzer,
    site: &ReferenceSiteValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let target_path = rel_path_string(site.target.unit.source());
    let target_fq_name = site.target.unit.fq_name();
    let target_kind = site.target.unit.kind().display_lowercase();
    CodeQueryResultRef::ReferenceSite {
        path: rel_path_string(&site.file),
        range: render_reference_range(analyzer, site, cache),
        target_id: (!detail.is_compact()).then(|| {
            declaration_id(
                &target_path,
                target_kind,
                &target_fq_name,
                site.target.range,
            )
        }),
        target_fq_name,
        usage_kind: (site.usage_kind != UsageHitKind::Reference)
            .then(|| site.usage_kind.wire_label()),
        proof: usage_proof_label(site.proof),
        reference_kind: site.reference_kind.map(reference_kind_label),
    }
}

pub(super) fn render_call_site_ref(
    analyzer: &dyn IAnalyzer,
    site: &CallSiteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    CodeQueryResultRef::CallSite {
        path: rel_path_string(&site.0.file),
        range: render_source_range(analyzer, &site.0.file, &site.0.range, cache),
        caller_fq_name: site.0.caller.fq_name(),
        callee_fq_name: site.0.callee.fq_name(),
        proof: usage_proof_label(site.0.proof),
    }
}

pub(super) fn render_expression_site_ref(
    analyzer: &dyn IAnalyzer,
    site: &ExpressionSiteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let (input_kind, parameter_index, parameter_name) = expression_input_parts(&site.input);
    CodeQueryResultRef::ExpressionSite {
        path: rel_path_string(&site.call_site.0.file),
        range: render_source_range(analyzer, &site.call_site.0.file, &site.range, cache),
        input_kind,
        parameter_index,
        parameter_name,
    }
}

pub(super) fn render_receiver_analysis_ref(
    analyzer: &dyn IAnalyzer,
    value: &ReceiverAnalysisValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    CodeQueryResultRef::ReceiverAnalysis {
        path: rel_path_string(&value.report.site.file),
        range: render_source_range(
            analyzer,
            &value.report.site.file,
            &value.report.site.range,
            cache,
        ),
        analysis_kind: value.report.operation.as_str(),
        outcome: receiver_query_outcome_label(&value.report.analysis),
        capture: value.capture.clone(),
    }
}

pub(super) fn render_receiver_outcome_ref(
    analyzer: &dyn IAnalyzer,
    value: &ReceiverAnalysisValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let rendered = render_receiver_outcome(analyzer, value, cache);
    CodeQueryResultRef::ReceiverOutcome {
        id: rendered.id,
        site_id: rendered.site_id,
        path: rendered.path,
        range: rendered.range,
        outcome: rendered.outcome,
        coverage: rendered.coverage,
    }
}

pub(super) fn render_receiver_evidence_ref(
    analyzer: &dyn IAnalyzer,
    value: &ReceiverEvidenceValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    CodeQueryResultRef::ReceiverEvidence {
        id: value.id.clone(),
        site_id: value.receiver.site_id.clone(),
        path: rel_path_string(&value.receiver.report.site.file),
        range: render_source_range(
            analyzer,
            &value.receiver.report.site.file,
            &value.receiver.report.site.range,
            cache,
        ),
        evidence_kind: receiver_evidence_kind(&value.value),
    }
}

pub(super) fn render_reference_edge(
    analyzer: &dyn IAnalyzer,
    value: &EdgeValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryReferenceEdge {
    let row = &value.row;
    let range = render_source_range(analyzer, &row.site.file, &row.site.range, cache);
    let target = render_declaration(analyzer, &value.target, detail, cache);
    let enclosing = value
        .enclosing
        .as_ref()
        .map(|declaration| render_declaration(analyzer, declaration, detail, cache));
    edges::public_edge(value, range, target, enclosing)
}

pub(super) fn render_edge_ref(
    analyzer: &dyn IAnalyzer,
    value: &EdgeValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let row = &value.row;
    CodeQueryResultRef::ReferenceEdge {
        id: value.id(),
        ast_id: row.site.ast_id.clone(),
        path: rel_path_string(&row.site.file),
        range: render_source_range(analyzer, &row.site.file, &row.site.range, cache),
        target_fq_name: value.target.unit.fq_name(),
        provenance: row.provenance.label(),
    }
}

/// The mandatory member-selection summary for one occurrence, computed from
/// the production resolver's candidate trace. `untraced` states the language
/// recorded no trace; it is never rendered as a proven-empty selection.
pub(super) fn render_member_selection(
    analyzer: &dyn IAnalyzer,
    value: &MemberSelectionValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryMemberSelection {
    use crate::analyzer::usages::get_definition::trace::TraceCompleteness;
    let row = &value.occurrence;
    let resolved = if value.selected > 0 {
        "selected"
    } else {
        "unresolved"
    };
    let (outcome, trace_completeness, coverage) = match value.completeness {
        Some(TraceCompleteness::Full) => (resolved, "full", "exhaustive"),
        Some(TraceCompleteness::SelectionOnly) => (resolved, "selection_only", "open"),
        None => ("untraced", "absent", "unsupported"),
    };
    CodeQueryMemberSelection {
        id: value.stable_id(),
        site_ast_id: row.ast_id(),
        path: rel_path_string(&row.file),
        language: crate::analyzer::common::language_for_file(&row.file).config_label(),
        range: render_source_range(analyzer, &row.file, &row.range, cache),
        member: row.effective_spelling().to_string(),
        role: row.role.label(),
        outcome,
        selected_count: value.selected,
        candidate_count: value.candidates,
        trace_completeness,
        coverage,
    }
}

pub(super) fn render_member_selection_ref(
    analyzer: &dyn IAnalyzer,
    value: &MemberSelectionValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let rendered = render_member_selection(analyzer, value, cache);
    CodeQueryResultRef::MemberSelection {
        id: rendered.id,
        site_ast_id: rendered.site_ast_id,
        path: rendered.path,
        range: rendered.range,
        outcome: rendered.outcome,
        coverage: rendered.coverage,
    }
}

pub(super) fn render_occurrence(
    analyzer: &dyn IAnalyzer,
    value: &OccurrenceValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryOccurrence {
    let row = &value.row;
    let range = render_source_range(analyzer, &row.file, &row.range, cache);
    let target = match &row.target {
        OccurrenceTarget::None => CodeQueryOccurrenceTarget::None,
        OccurrenceTarget::Resolved(units) => CodeQueryOccurrenceTarget::Resolved {
            units: units
                .iter()
                .filter_map(|unit| {
                    let declaration = analyzer
                        .ranges_of(unit)
                        .into_iter()
                        .min_by_key(primary_range_key)
                        .map(|range| DeclarationValue {
                            unit: unit.clone(),
                            range,
                        })?;
                    Some(render_declaration(analyzer, &declaration, detail, cache))
                })
                .collect(),
        },
        OccurrenceTarget::Lexical(lexical) => CodeQueryOccurrenceTarget::Lexical {
            name: lexical.identifier.clone(),
            kind: lexical.kind.label(),
            range: render_source_range(analyzer, &row.file, &lexical.name_range, cache),
        },
        OccurrenceTarget::Unresolved(_) => CodeQueryOccurrenceTarget::Unresolved {
            status: occurrences::target_status_label(&row.target),
        },
    };
    occurrences::public_occurrence(row, range, target)
}

pub(super) fn render_scope(
    analyzer: &dyn IAnalyzer,
    value: &ScopeValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryLexicalScope {
    let row = value.row();
    let range = render_source_range(analyzer, &row.file, &row.range, cache);
    environment::public_scope(value, range)
}

pub(super) fn render_binding(
    analyzer: &dyn IAnalyzer,
    value: &BindingValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryBinding {
    let row = value.row();
    let range = render_source_range(analyzer, &row.file, &row.range, cache);
    environment::public_binding(value, range)
}

pub(super) fn render_generation_site(
    analyzer: &dyn IAnalyzer,
    value: &materialization::GenerationSiteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryGenerationSite {
    let row = value.row();
    let range = render_source_range(analyzer, &row.file, &row.site, cache);
    let file = row.file.clone();
    materialization::public_generation_site(value, range, |argument| {
        render_source_range(analyzer, &file, argument, cache)
    })
}

pub(super) fn render_export(
    analyzer: &dyn IAnalyzer,
    value: &materialization::ExportValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryExport {
    let row = value.row();
    let range = render_source_range(analyzer, &row.file, &row.range, cache);
    materialization::public_export(value, range)
}

pub(super) fn render_declaration_state(
    analyzer: &dyn IAnalyzer,
    value: &materialization::DeclarationStateValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryDeclarationState {
    let row = value.row();
    let range = row
        .declaration
        .map(|declaration| render_source_range(analyzer, &row.file, &declaration, cache));
    materialization::public_declaration_state(value, range)
}

pub(super) fn render_resolution_candidate(
    analyzer: &dyn IAnalyzer,
    value: &CandidateValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResolutionCandidate {
    let occurrence = &value.occurrence;
    let range = render_source_range(analyzer, &occurrence.file, &occurrence.range, cache);
    let candidate = match &value.candidate.candidate {
        TraceCandidateRef::Unit(unit) => {
            let declaration = analyzer
                .ranges_of(unit)
                .into_iter()
                .min_by_key(primary_range_key)
                .map(|range| DeclarationValue {
                    unit: unit.clone(),
                    range,
                });
            match declaration {
                Some(declaration) => CodeQueryCandidateRef::Unit {
                    unit: Box::new(render_declaration(analyzer, &declaration, detail, cache)),
                },
                // A candidate whose unit the workspace can no longer locate is
                // reported as an external route rather than dropped: the
                // resolver did consider something, and saying nothing would be
                // the silent gap this domain exists to remove.
                None => CodeQueryCandidateRef::ExternalRoute {
                    name: unit.fq_name(),
                },
            }
        }
        TraceCandidateRef::Lexical(lexical) => CodeQueryCandidateRef::Lexical {
            name: lexical.identifier.clone(),
            kind: lexical.kind.label(),
            range: render_source_range(analyzer, &occurrence.file, &lexical.name_range, cache),
        },
        TraceCandidateRef::Binding { file, node, name } => CodeQueryCandidateRef::Binding {
            name: name.clone(),
            path: rel_path_string(file),
            ast_id: node.map(|node| {
                super::super::occurrence_rows::ast_id(occurrence.content_identity, node)
            }),
        },
        TraceCandidateRef::ImportBinder {
            file,
            node,
            name,
            target_segments,
        } => CodeQueryCandidateRef::ImportBinder {
            name: name.clone(),
            path: rel_path_string(file),
            ast_id: node.map(|node| {
                super::super::occurrence_rows::ast_id(occurrence.content_identity, node)
            }),
            target_segments: target_segments.clone(),
        },
        TraceCandidateRef::ExternalRoute { name } => {
            CodeQueryCandidateRef::ExternalRoute { name: name.clone() }
        }
    };
    let canonical_member_id = environment::candidate_unit(&value.candidate.candidate)
        .map(|unit| canonical_member_digest(analyzer, unit));
    environment::public_candidate(value, range, candidate, canonical_member_id)
}

/// A stable, domain-separated digest of one declaration's #1475 canonical
/// identity. The digest input is the structured identity (kind-tagged
/// segments, namespace, language, recorded generic arity), never a rendered
/// FQN or signature string, so same-spelling decoys with different segment
/// kinds hash apart and aliases/partial types canonicalized by the analyzer
/// hash together.
fn canonical_member_digest(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> String {
    let identity = crate::analyzer::structural::canonical_identity_of(analyzer, unit);
    let mut hasher = Sha256::new();
    hasher.update(b"bifrost.canonical_member_id.v1");
    hasher.update(serde_json::to_vec(&identity).expect("canonical identity serializes"));
    format!("{:x}", hasher.finalize())
}

pub(super) fn render_generation_site_ref(
    analyzer: &dyn IAnalyzer,
    value: &materialization::GenerationSiteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let row = value.row();
    CodeQueryResultRef::GenerationSite {
        id: value.id(),
        ast_id: row.ast_id(),
        path: rel_path_string(&row.file),
        range: render_source_range(analyzer, &row.file, &row.site, cache),
        kind: row.kind.label(),
    }
}

pub(super) fn render_export_ref(
    analyzer: &dyn IAnalyzer,
    value: &materialization::ExportValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let row = value.row();
    CodeQueryResultRef::Export {
        id: value.id(),
        path: rel_path_string(&row.file),
        range: render_source_range(analyzer, &row.file, &row.range, cache),
        form: row.form.label(),
        exported_name: row.exported_name.clone(),
    }
}

pub(super) fn render_declaration_state_ref(
    value: &materialization::DeclarationStateValue,
) -> CodeQueryResultRef {
    let row = value.row();
    CodeQueryResultRef::DeclarationState {
        id: value.id(),
        path: rel_path_string(&row.file),
        fq_name: row.unit.fq_name().to_string(),
        origin: row.origin.label(),
    }
}

pub(super) fn render_scope_ref(
    analyzer: &dyn IAnalyzer,
    value: &ScopeValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let row = value.row();
    CodeQueryResultRef::LexicalScope {
        id: value.id(),
        ast_id: row.ast_id(),
        path: rel_path_string(&row.file),
        range: render_source_range(analyzer, &row.file, &row.range, cache),
        index: row.index,
    }
}

pub(super) fn render_qualified_path(
    analyzer: &dyn IAnalyzer,
    value: &PathValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryQualifiedPath {
    let row = value.row();
    let range = render_source_range(analyzer, &row.file, &row.range, cache);
    public_path(value, range)
}

pub(super) fn render_path_segment(
    analyzer: &dyn IAnalyzer,
    value: &SegmentValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryPathSegment {
    let row = value.row();
    let range = render_source_range(analyzer, &row.file, &row.range, cache);
    public_segment(value, range)
}

pub(super) fn render_qualified_path_ref(
    analyzer: &dyn IAnalyzer,
    value: &PathValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let row = value.row();
    CodeQueryResultRef::QualifiedPath {
        id: value.id(),
        ast_id: row.ast_id(),
        path: rel_path_string(&row.file),
        range: render_source_range(analyzer, &row.file, &row.range, cache),
        segment_count: row.segment_count,
    }
}

pub(super) fn render_path_segment_ref(
    analyzer: &dyn IAnalyzer,
    value: &SegmentValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let row = value.row();
    CodeQueryResultRef::PathSegment {
        id: value.id(),
        ast_id: row.ast_id(),
        path: rel_path_string(&row.file),
        range: render_source_range(analyzer, &row.file, &row.range, cache),
        ordinal: row.ordinal,
        text: row.text.clone(),
    }
}

pub(super) fn render_binding_ref(
    analyzer: &dyn IAnalyzer,
    value: &BindingValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let row = value.row();
    CodeQueryResultRef::Binding {
        id: value.id(),
        ast_id: row.ast_id(),
        path: rel_path_string(&row.file),
        range: render_source_range(analyzer, &row.file, &row.range, cache),
        name: row.name.clone(),
        kind: row.kind.label(),
    }
}

pub(super) fn render_candidate_ref(
    analyzer: &dyn IAnalyzer,
    value: &CandidateValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let occurrence = &value.occurrence;
    CodeQueryResultRef::ResolutionCandidate {
        id: value.id(),
        ast_id: occurrence.ast_id(),
        path: rel_path_string(&occurrence.file),
        range: render_source_range(analyzer, &occurrence.file, &occurrence.range, cache),
        tier: value.candidate.tier.map(|tier| tier.label()),
        outcome: value.candidate.outcome.label(),
    }
}

pub(super) fn render_occurrence_ref(
    analyzer: &dyn IAnalyzer,
    value: &OccurrenceValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let row = &value.row;
    CodeQueryResultRef::Occurrence {
        id: row.id(),
        ast_id: row.ast_id(),
        path: rel_path_string(&row.file),
        range: render_source_range(analyzer, &row.file, &row.range, cache),
        class: row.class.label(),
        role: row.role.label(),
        namespace: row.namespace.label(),
    }
}

pub(super) fn render_declaration(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryDeclaration {
    let path = rel_path_string(declaration.unit.source());
    let fq_name = declaration.unit.fq_name();
    let kind = declaration.unit.kind().display_lowercase();
    let full = !detail.is_compact();
    let signature = declaration
        .unit
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.signatures_of(&declaration.unit).into_iter().next());
    let semantic_model = analyzer.semantic_model_overlay().and_then(|overlay| {
        let matched = overlay.symbols_named(&fq_name);
        (matched.disposition
            == crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique)
            .then(|| Box::new(matched.records[0].provenance.clone()))
    });
    CodeQueryDeclaration {
        id: full.then(|| declaration_id(&path, kind, &fq_name, declaration.range)),
        path,
        language: crate::analyzer::common::language_for_file(declaration.unit.source())
            .config_label(),
        kind,
        fq_name,
        start_line: declaration.range.start_line,
        end_line: declaration.range.end_line,
        signature,
        node_range: full
            .then(|| cache.range_for_declaration(analyzer, declaration))
            .flatten(),
        semantic_model,
    }
}

pub(super) fn augment_public_result_with_semantic_overlay(
    analyzer: &dyn IAnalyzer,
    query: &CodeQuery,
    result: &mut CodeQueryResult,
) {
    let Some(seed) = query.seed() else {
        return;
    };
    if !seed.where_globs.is_empty()
        || seed.inside.is_some()
        || seed.inside_decl.is_some()
        || seed.not_inside.is_some()
        || !model_pattern_is_supported(&seed.root)
    {
        return;
    }
    let traversal = match query.plan.steps.as_slice() {
        [QueryStep::EnclosingDecl] => None,
        [QueryStep::EnclosingDecl, step @ QueryStep::Members]
        | [QueryStep::EnclosingDecl, step @ QueryStep::Owner]
        | [QueryStep::EnclosingDecl, step @ QueryStep::Supertypes(_)]
        | [QueryStep::EnclosingDecl, step @ QueryStep::Subtypes(_)] => Some(step),
        _ => return,
    };
    let Some(overlay) = analyzer.semantic_model_overlay() else {
        return;
    };

    let roots = overlay
        .symbols()
        .iter()
        .filter(|symbol| {
            symbol.externally_visible()
                && !symbol.provenance.ambiguous
                && (seed.languages.is_empty()
                    || seed
                        .languages
                        .iter()
                        .any(|language| language.config_label() == symbol.language))
                && model_pattern_matches(&seed.root, symbol)
        })
        .collect::<Vec<_>>();
    let mut ambiguous_match = overlay.symbols().iter().any(|symbol| {
        symbol.externally_visible()
            && symbol.provenance.ambiguous
            && (seed.languages.is_empty()
                || seed
                    .languages
                    .iter()
                    .any(|language| language.config_label() == symbol.language))
            && model_pattern_matches(&seed.root, symbol)
    });

    let mut modeled = Vec::new();
    for root in roots {
        match traversal {
            None => modeled.push(root),
            Some(QueryStep::Members) => modeled.extend(
                overlay
                    .members_of(&root.id)
                    .records
                    .into_iter()
                    .filter(|symbol| !symbol.provenance.ambiguous),
            ),
            Some(QueryStep::Owner) => {
                if let Some(owner) = root.owner_id.as_deref() {
                    let matched = overlay.symbols_with_id(owner);
                    if matched.disposition
                        == crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
                    {
                        modeled.push(matched.records[0]);
                    }
                }
            }
            Some(QueryStep::Supertypes(hierarchy)) => {
                let (symbols, conflict) = model_hierarchy_symbols(&overlay, root, *hierarchy, true);
                modeled.extend(symbols);
                ambiguous_match |= conflict;
            }
            Some(QueryStep::Subtypes(hierarchy)) => {
                let (symbols, conflict) =
                    model_hierarchy_symbols(&overlay, root, *hierarchy, false);
                modeled.extend(symbols);
                ambiguous_match |= conflict;
            }
            Some(_) => unreachable!("model overlay traversal was validated above"),
        }
    }
    modeled.sort_by(|left, right| {
        left.qualified_name
            .cmp(&right.qualified_name)
            .then_with(|| left.id.cmp(&right.id))
    });
    modeled.dedup_by(|left, right| left.id == right.id);

    let mut existing = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::Declaration { value } => Some(value.fq_name.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let available = query.limit.saturating_sub(result.results.len());
    let mut retained = 0usize;
    for symbol in modeled {
        if existing.contains(&symbol.qualified_name) {
            continue;
        }
        if retained == available {
            result.truncated = true;
            break;
        }
        let Some(language) = model_language_label(&symbol.language) else {
            continue;
        };
        let Some(kind) = model_declaration_kind(symbol.kind) else {
            continue;
        };
        existing.insert(symbol.qualified_name.clone());
        let range = symbol.location.range();
        result.results.push(CodeQueryResultItem {
            value: CodeQueryResultValue::Declaration {
                value: CodeQueryDeclaration {
                    path: symbol.location.identity().to_string(),
                    language,
                    kind,
                    fq_name: symbol.qualified_name.clone(),
                    start_line: range.start_line,
                    end_line: range.end_line,
                    signature: symbol.signature.clone(),
                    id: (!query.result_detail.is_compact()).then(|| symbol.id.clone()),
                    node_range: None,
                    semantic_model: Some(Box::new(symbol.provenance.clone())),
                },
            },
            provenance: Vec::new(),
            provenance_truncated: false,
        });
        retained = retained.saturating_add(1);
    }
    if ambiguous_match
        && !result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::SemanticResultsOmitted
                && diagnostic
                    .message
                    .contains("semantic-model declaration conflict")
        })
    {
        result.diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: "workspace",
            message:
                "semantic-model declaration conflict prevented an authoritative CodeQuery result"
                    .to_string(),
        });
    }
}

pub(super) fn model_hierarchy_symbols<'a>(
    overlay: &'a crate::analyzer::semantic_model::SemanticModelOverlay,
    root: &crate::analyzer::semantic_model::SemanticModelSymbol,
    traversal: HierarchyTraversal,
    supertypes: bool,
) -> (
    Vec<&'a crate::analyzer::semantic_model::SemanticModelSymbol>,
    bool,
) {
    let max_depth = match traversal {
        HierarchyTraversal::Direct => 1,
        HierarchyTraversal::Depth(depth) => depth.get(),
        HierarchyTraversal::Transitive => usize::MAX,
    };
    let mut queue = VecDeque::from([(root.id.clone(), 0usize)]);
    let mut visited = HashSet::default();
    visited.insert(root.id.clone());
    let mut symbols = Vec::new();
    let mut conflict = false;
    while let Some((id, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        let relations = if supertypes {
            overlay.relations_from(&id)
        } else {
            overlay.relations_to(&id)
        };
        for relation in relations.records {
            if relation.provenance.ambiguous {
                conflict = true;
                continue;
            }
            if !matches!(
                relation.kind.as_str(),
                "extends" | "implements" | "uses_trait"
            ) {
                continue;
            }
            let endpoint = if supertypes {
                &relation.to
            } else {
                &relation.from
            };
            let mut matched = overlay.symbols_with_id(endpoint);
            if matched.records.is_empty() {
                matched = overlay.symbols_named(endpoint);
            }
            if matched.disposition
                != crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
            {
                conflict |= !matched.records.is_empty();
                continue;
            }
            let symbol = matched.records[0];
            if visited.insert(symbol.id.clone()) {
                symbols.push(symbol);
                queue.push_back((symbol.id.clone(), depth.saturating_add(1)));
            }
        }
    }
    (symbols, conflict)
}

pub(super) fn model_pattern_is_supported(pattern: &Pattern) -> bool {
    pattern.text.is_none()
        && pattern.capture.is_none()
        && pattern.has.is_none()
        && pattern.not_has.is_none()
        && pattern.callee.is_none()
        && pattern.receiver.is_none()
        && pattern.args.is_empty()
        && pattern.kwargs.is_empty()
        && pattern.left.is_none()
        && pattern.right.is_none()
        && pattern.module.is_none()
        && pattern.decorators.is_empty()
        && pattern.object.is_none()
        && pattern.field.is_none()
}

pub(super) fn model_pattern_matches(
    pattern: &Pattern,
    symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
) -> bool {
    let Some(kind) = model_normalized_kind(symbol.kind) else {
        return false;
    };
    (pattern.kinds.is_empty()
        || pattern
            .kinds
            .iter()
            .copied()
            .any(|query_kind| kind.satisfies(query_kind)))
        && !pattern
            .not_kinds
            .iter()
            .copied()
            .any(|query_kind| kind.satisfies(query_kind))
        && pattern
            .name
            .as_ref()
            .is_none_or(|name| name.matches(&symbol.name) || name.matches(&symbol.qualified_name))
}

pub(super) fn model_normalized_kind(
    kind: crate::analyzer::semantic_model::SemanticModelSymbolKind,
) -> Option<NormalizedKind> {
    use crate::analyzer::semantic_model::SemanticModelSymbolKind as ModelKind;
    match kind {
        ModelKind::Class
        | ModelKind::Annotation
        | ModelKind::Interface
        | ModelKind::Trait
        | ModelKind::Struct
        | ModelKind::Union
        | ModelKind::Enum
        | ModelKind::Record => Some(NormalizedKind::Class),
        ModelKind::Constructor => Some(NormalizedKind::Constructor),
        ModelKind::Method => Some(NormalizedKind::Method),
        ModelKind::Function | ModelKind::Delegate => Some(NormalizedKind::Function),
        ModelKind::Module
        | ModelKind::TypeAlias
        | ModelKind::Field
        | ModelKind::Property
        | ModelKind::Constant
        | ModelKind::Static
        | ModelKind::Macro
        | ModelKind::Event => None,
    }
}

pub(super) fn model_declaration_kind(
    kind: crate::analyzer::semantic_model::SemanticModelSymbolKind,
) -> Option<&'static str> {
    model_normalized_kind(kind).map(NormalizedKind::label)
}

pub(super) fn model_language_label(language: &str) -> Option<&'static str> {
    Language::from_config_label(language).map(Language::config_label)
}

pub(super) fn render_file(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> CodeQueryFile {
    let package = super::super::lexical_environment::package_clause_for_file(analyzer, file);
    CodeQueryFile {
        path: rel_path_string(file),
        language: crate::analyzer::common::language_for_file(file).config_label(),
        // `syntactic` only means something once a package was named, so the two
        // fields appear and disappear together rather than leaving a stray
        // "derived from the path" claim about a file with no package at all.
        package_syntactic: package.package_fq.is_some().then_some(package.syntactic),
        package_fq: package
            .package_fq
            .map(|fq| fq.display(crate::analyzer::fq_name::segment_interner())),
    }
}

pub(super) fn render_reference_site(
    analyzer: &dyn IAnalyzer,
    site: &ReferenceSiteValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryReferenceSite {
    CodeQueryReferenceSite {
        path: rel_path_string(&site.file),
        language: crate::analyzer::common::language_for_file(&site.file).config_label(),
        range: render_reference_range(analyzer, site, cache),
        target: render_declaration(analyzer, &site.target, detail, cache),
        enclosing_declaration: site
            .enclosing
            .as_ref()
            .map(|declaration| render_declaration(analyzer, declaration, detail, cache)),
        usage_kind: site.usage_kind.wire_label(),
        proof: usage_proof_label(site.proof),
        reference_kind: site.reference_kind.map(reference_kind_label),
    }
}

pub(super) fn render_call_site(
    analyzer: &dyn IAnalyzer,
    site: &CallSiteValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryCallSite {
    let caller = declaration_value_for_unit(analyzer, &site.0.caller, site.0.range);
    let callee = declaration_value_for_unit(analyzer, &site.0.callee, site.0.callee_range);
    CodeQueryCallSite {
        path: rel_path_string(&site.0.file),
        language: crate::analyzer::common::language_for_file(&site.0.file).config_label(),
        range: render_source_range(analyzer, &site.0.file, &site.0.range, cache),
        callee_range: render_source_range(analyzer, &site.0.file, &site.0.callee_range, cache),
        caller: render_declaration(analyzer, &caller, detail, cache),
        callee: render_declaration(analyzer, &callee, detail, cache),
        call_kind: call_syntax_kind_label(site.0.kind),
        proof: usage_proof_label(site.0.proof),
        receiver: site
            .0
            .receiver
            .as_ref()
            .map(|range| render_source_range(analyzer, &site.0.file, range, cache)),
        arguments: site
            .0
            .arguments
            .iter()
            .map(|argument| CodeQueryCallArgument {
                range: render_source_range(analyzer, &site.0.file, &argument.range, cache),
                name: argument.name.clone(),
                position: argument.position,
                formal_index: argument.formal_index,
                formal_name: argument.formal_name.clone(),
                variadic: argument.variadic,
                spread: argument.spread,
            })
            .collect(),
    }
}

pub(super) fn render_expression_site(
    analyzer: &dyn IAnalyzer,
    site: &ExpressionSiteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryExpressionSite {
    let file = &site.call_site.0.file;
    let text = cache
        .coordinates_for(file, || analyzer.indexed_source(file))
        .and_then(|coordinates| {
            coordinates
                .source
                .get(site.range.start_byte..site.range.end_byte)
        })
        .map(snippet)
        .unwrap_or_default();
    let (input_kind, parameter_index, parameter_name) = expression_input_parts(&site.input);
    CodeQueryExpressionSite {
        path: rel_path_string(file),
        language: crate::analyzer::common::language_for_file(file).config_label(),
        range: render_source_range(analyzer, file, &site.range, cache),
        text,
        input_kind,
        parameter_index,
        parameter_name,
        caller_fq_name: site.call_site.0.caller.fq_name(),
        callee_fq_name: site.call_site.0.callee.fq_name(),
        call_range: render_source_range(analyzer, file, &site.call_site.0.range, cache),
    }
}

pub(super) fn render_receiver_analysis(
    analyzer: &dyn IAnalyzer,
    value: &ReceiverAnalysisValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryReceiverAnalysis {
    let fallback = value.report.site.range;
    let (outcome, values, member_targets, reason, limit) = match &value.report.analysis {
        ReceiverQueryAnalysis::Values(outcome) => {
            let rendered = outcome
                .values()
                .into_iter()
                .flatten()
                .map(|value| render_receiver_value(analyzer, value, fallback, detail, cache))
                .collect();
            let (label, reason, limit) = receiver_outcome_metadata(outcome);
            (label, rendered, Vec::new(), reason, limit)
        }
        ReceiverQueryAnalysis::MemberTargets(outcome) => {
            let rendered = outcome
                .values()
                .into_iter()
                .flatten()
                .map(|unit| {
                    let declaration = declaration_value_for_unit(analyzer, unit, fallback);
                    render_declaration(analyzer, &declaration, detail, cache)
                })
                .collect();
            let (label, reason, limit) = receiver_outcome_metadata(outcome);
            (label, Vec::new(), rendered, reason, limit)
        }
    };
    CodeQueryReceiverAnalysis {
        site_id: value.site_id.clone(),
        site_ast_id: value.site_ast_id.clone(),
        analysis_kind: value.report.operation.as_str(),
        path: rel_path_string(&value.report.site.file),
        language: value.report.site.language.config_label(),
        range: render_source_range(
            analyzer,
            &value.report.site.file,
            &value.report.site.range,
            cache,
        ),
        text: snippet(&value.report.site.text),
        input_kind: value.report.site.syntax_kind.clone(),
        capture: value.capture.clone(),
        outcome,
        values,
        member_targets,
        reason,
        limit,
    }
}

pub(super) fn render_receiver_outcome(
    analyzer: &dyn IAnalyzer,
    value: &ReceiverAnalysisValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryReceiverOutcome {
    let (outcome, reason, limit) = match &value.report.analysis {
        ReceiverQueryAnalysis::Values(outcome) => receiver_outcome_metadata(outcome),
        ReceiverQueryAnalysis::MemberTargets(outcome) => receiver_outcome_metadata(outcome),
    };
    let coverage = if outcome == "unsupported" {
        "unsupported"
    } else if outcome == "exceeded_budget" || value.report.candidates_truncated {
        "truncated"
    } else if value.report.semantic_unsupported.is_some() || outcome == "ambiguous" {
        "open"
    } else if outcome == "unknown" {
        "unknown"
    } else {
        "exhaustive"
    };
    CodeQueryReceiverOutcome {
        id: value.site_id.clone(),
        site_id: value.site_id.clone(),
        site_ast_id: value.site_ast_id.clone(),
        path: rel_path_string(&value.report.site.file),
        language: value.report.site.language.config_label(),
        range: render_source_range(
            analyzer,
            &value.report.site.file,
            &value.report.site.range,
            cache,
        ),
        analysis_kind: value.report.operation.as_str(),
        outcome,
        coverage,
        candidate_count: receiver_candidate_count(&value.report),
        candidates_truncated: value.report.candidates_truncated,
        reason,
        limit,
        semantic_unsupported: value.report.semantic_unsupported.map(|value| value.label()),
        setup_nodes: value.report.work.setup_nodes,
        summary_expansions: value.report.work.summary_expansions,
        scope_nodes: value.report.work.scope_nodes,
    }
}

pub(super) fn render_call_shape(
    analyzer: &dyn IAnalyzer,
    value: &CallShapeValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryCallShape {
    let outcome = &value.report.outcome;
    CodeQueryCallShape {
        id: outcome.id.clone(),
        site_id: outcome.site_id.clone(),
        site_ast_id: outcome.site_ast_id.clone(),
        path: rel_path_string(&outcome.file),
        language: crate::analyzer::common::language_for_file(&outcome.file).config_label(),
        range: render_source_range(analyzer, &outcome.file, &outcome.range, cache),
        callee_range: outcome
            .callee_range
            .map(|range| render_source_range(analyzer, &outcome.file, &range, cache)),
        call_kind: outcome.call_kind.label(),
        coverage: outcome.coverage.label(),
        group_count: value.report.groups.len(),
    }
}

pub(super) fn render_call_argument_group(
    analyzer: &dyn IAnalyzer,
    value: &CallArgumentGroupValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryCallArgumentGroup {
    let outcome = &value.shape.report.outcome;
    let group = &value.shape.report.groups[value.group_index];
    CodeQueryCallArgumentGroup {
        id: group.id.clone(),
        site_id: group.site_id.clone(),
        path: rel_path_string(&outcome.file),
        range: render_source_range(analyzer, &outcome.file, &outcome.range, cache),
        group_index: group.group_index,
        kind: group.kind.label(),
        argument_count: group.argument_count,
    }
}

pub(super) fn render_call_shape_argument(
    analyzer: &dyn IAnalyzer,
    value: &CallArgumentValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryCallShapeArgument {
    let outcome = &value.shape.report.outcome;
    let argument = &value.shape.report.arguments[value.argument_index];
    CodeQueryCallShapeArgument {
        id: argument.id.clone(),
        group_id: argument.group_id.clone(),
        site_id: outcome.site_id.clone(),
        path: rel_path_string(&outcome.file),
        range: render_source_range(analyzer, &outcome.file, &argument.range, cache),
        argument_index: argument.argument_index,
        name: argument.name.clone(),
        spread: argument.spread,
    }
}

pub(super) fn render_receiver_evidence(
    analyzer: &dyn IAnalyzer,
    value: &ReceiverEvidenceValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryReceiverEvidence {
    let fallback = value.receiver.report.site.range;
    let declaration_unit = match &value.value {
        ReceiverValue::AllocationSite { ty, .. } => Some(ty),
        ReceiverValue::InstanceType(unit)
        | ReceiverValue::ClassOrStaticObject(unit)
        | ReceiverValue::ModuleOrExportObject(unit)
        | ReceiverValue::CurrentReceiver(unit) => Some(unit),
        ReceiverValue::FactoryReturn { .. } => None,
    };
    let declaration =
        declaration_unit.map(|unit| declaration_value_for_unit(analyzer, unit, fallback));
    let rendered_declaration_id = declaration.as_ref().map(|declaration| {
        declaration_id(
            &rel_path_string(declaration.unit.source()),
            declaration.unit.kind().display_lowercase(),
            &declaration.unit.fq_name(),
            declaration.range,
        )
    });
    let factory_id = value.factory.as_ref().map(|factory| {
        let declaration = declaration_value_for_unit(analyzer, factory, fallback);
        declaration_id(
            &rel_path_string(declaration.unit.source()),
            declaration.unit.kind().display_lowercase(),
            &declaration.unit.fq_name(),
            declaration.range,
        )
    });
    let proof = match &value.receiver.report.analysis {
        ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Precise(_)) => "precise",
        _ => "ambiguous",
    };
    let completeness = render_receiver_outcome(analyzer, &value.receiver, cache).coverage;
    CodeQueryReceiverEvidence {
        id: value.id.clone(),
        site_id: value.receiver.site_id.clone(),
        site_ast_id: value.receiver.site_ast_id.clone(),
        path: rel_path_string(&value.receiver.report.site.file),
        parent_evidence_id: value.parent_evidence_id.clone(),
        ordinal: value.ordinal,
        chain_hop: value.chain_hop,
        evidence_kind: receiver_evidence_kind(&value.value),
        declaration_id: rendered_declaration_id,
        declaration_fq_name: declaration.as_ref().map(|value| value.unit.fq_name()),
        declaration_kind: declaration
            .as_ref()
            .map(|value| value.unit.kind().display_lowercase()),
        factory_id,
        proof,
        completeness,
    }
}

pub(super) fn render_receiver_value(
    analyzer: &dyn IAnalyzer,
    value: &ReceiverValue,
    fallback: Range,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryReceiverValue {
    let declaration = |unit: &CodeUnit, cache: &mut PipelineRenderCache| {
        let value = declaration_value_for_unit(analyzer, unit, fallback);
        render_declaration(analyzer, &value, detail, cache)
    };
    match value {
        ReceiverValue::AllocationSite { ty, file, range } => {
            CodeQueryReceiverValue::AllocationSite {
                type_declaration: declaration(ty, cache),
                allocation_site: CodeQuerySourceSite {
                    path: rel_path_string(file),
                    range: render_source_range(analyzer, file, range, cache),
                },
            }
        }
        ReceiverValue::InstanceType(unit) => CodeQueryReceiverValue::InstanceType {
            declaration: declaration(unit, cache),
        },
        ReceiverValue::ClassOrStaticObject(unit) => CodeQueryReceiverValue::ClassOrStaticObject {
            declaration: declaration(unit, cache),
        },
        ReceiverValue::ModuleOrExportObject(unit) => CodeQueryReceiverValue::ModuleOrExportObject {
            declaration: declaration(unit, cache),
        },
        ReceiverValue::CurrentReceiver(unit) => CodeQueryReceiverValue::CurrentReceiver {
            declaration: declaration(unit, cache),
        },
        ReceiverValue::FactoryReturn { factory, value } => CodeQueryReceiverValue::FactoryReturn {
            factory: declaration(factory, cache),
            returned_value: Box::new(render_receiver_value(
                analyzer, value, fallback, detail, cache,
            )),
        },
    }
}

pub(super) fn receiver_query_outcome_label(analysis: &ReceiverQueryAnalysis) -> &'static str {
    match analysis {
        ReceiverQueryAnalysis::Values(outcome) => receiver_outcome_metadata(outcome).0,
        ReceiverQueryAnalysis::MemberTargets(outcome) => receiver_outcome_metadata(outcome).0,
    }
}

pub(super) fn receiver_outcome_metadata<T>(
    outcome: &ReceiverAnalysisOutcome<T>,
) -> (&'static str, Option<&'static str>, Option<&'static str>) {
    match outcome {
        ReceiverAnalysisOutcome::Precise(_) => ("precise", None, None),
        ReceiverAnalysisOutcome::Ambiguous(_) => ("ambiguous", None, None),
        ReceiverAnalysisOutcome::Unknown => ("unknown", None, None),
        ReceiverAnalysisOutcome::Unsupported { reason } => ("unsupported", Some(*reason), None),
        ReceiverAnalysisOutcome::ExceededBudget { limit } => {
            ("exceeded_budget", None, Some(*limit))
        }
    }
}

pub(super) fn expression_input_parts(
    input: &ExpressionInput,
) -> (&'static str, Option<usize>, Option<String>) {
    match input {
        ExpressionInput::Receiver => ("receiver", None, None),
        ExpressionInput::Parameter { index, name } => ("parameter", Some(*index), name.clone()),
    }
}

pub(super) fn declaration_value_for_unit(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    fallback: Range,
) -> DeclarationValue {
    DeclarationValue {
        unit: unit.clone(),
        range: analyzer
            .ranges_of(unit)
            .into_iter()
            .min_by_key(primary_range_key)
            .unwrap_or(fallback),
    }
}

pub(super) fn call_syntax_kind_label(kind: CallSyntaxKind) -> &'static str {
    match kind {
        CallSyntaxKind::Function => "function",
        CallSyntaxKind::Method => "method",
        CallSyntaxKind::Constructor => "constructor",
        CallSyntaxKind::Super => "super",
    }
}

pub(super) fn render_reference_range(
    analyzer: &dyn IAnalyzer,
    site: &ReferenceSiteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryRange {
    render_source_range(analyzer, &site.file, &site.range, cache)
}

pub(super) fn render_source_range(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    range: &Range,
    cache: &mut PipelineRenderCache,
) -> CodeQueryRange {
    cache
        .coordinates_for(file, || analyzer.indexed_source(file))
        .map(|coordinates| {
            range_for_offsets(
                &coordinates.source,
                &coordinates.line_starts,
                range.start_byte,
                range.end_byte,
            )
        })
        .unwrap_or(CodeQueryRange {
            start_line: range.start_line,
            start_column: 1,
            end_line: range.end_line,
            end_column: 1,
        })
}

pub(super) fn declaration_id(path: &str, kind: &str, fq_name: &str, range: Range) -> String {
    format!(
        "{path}:{kind}:{fq_name}:{}-{}",
        range.start_byte, range.end_byte
    )
}

pub(super) fn range_for_offsets(
    source: &str,
    line_starts: &[usize],
    start_byte: usize,
    end_byte: usize,
) -> CodeQueryRange {
    let (start_line, start_column) = line_column_for_offset(source, line_starts, start_byte);
    let (end_line, end_column) = line_column_for_offset(source, line_starts, end_byte);
    CodeQueryRange {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

pub(super) fn provider_supports_feature(
    provider: &dyn super::StructuralSearchProvider,
    feature: QueryFeature,
) -> bool {
    match feature {
        QueryFeature::Kind(kind) => provider.structural_supports_kind(kind),
        QueryFeature::Role(role) => provider.structural_supports_role(role),
        QueryFeature::OccurrenceRole(role) => provider.structural_supports_occurrence_role(role),
        QueryFeature::EnvironmentAxis(axis) => provider.structural_supports_environment_axis(axis),
        QueryFeature::MaterializationAxis(axis) => {
            provider.structural_supports_materialization_axis(axis)
        }
        QueryFeature::EdgeAxis(axis) => provider.structural_supports_edge_axis(axis),
        QueryFeature::IdentityAxis(axis) => provider.structural_supports_identity_axis(axis),
        QueryFeature::RouteRelation(relation) => {
            provider.structural_supports_route_relation(relation)
        }
    }
}

pub(super) fn push_budget_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
) {
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::ExecutionBudgetExhausted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: format!(
            "query_code execution budget exhausted after scanning {} files, {} bytes, {} facts, and examining {} references; refine the query with where, languages, kind/name anchors, or a narrower pattern",
            budget.scanned_files,
            budget.scanned_source_bytes,
            budget.fact_nodes,
            budget.examined_references
        ),
    });
}

pub(super) fn push_pipeline_budget_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
) {
    if diagnostics.iter().any(|diagnostic| {
        diagnostic.branch.is_empty()
            && diagnostic.code == CodeQueryDiagnosticCode::PipelineBudgetExhausted
    }) {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::PipelineBudgetExhausted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: format!(
            "query_code pipeline budget exhausted after producing {} seed and edge rows; refine the match, where, or languages filters",
            budget.pipeline_rows
        ),
    });
}

pub(super) fn push_import_graph_budget_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    graph: &RequestLocalDirectImportGraph,
) {
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::ImportGraphBudgetExhausted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: format!(
            "query_code import graph budget exhausted after resolving {} files and {} direct edges; import traversal results are partial",
            graph.resolved_files(), graph.resolved_edges()
        ),
    });
}

pub(super) fn push_truncation_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
    limit: usize,
) {
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::ResultLimitReached,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: format!(
            "query_code returned the first {limit} results after scanning {} files, {} bytes, {} facts, and examining {} references; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern",
            budget.scanned_files,
            budget.scanned_source_bytes,
            budget.fact_nodes,
            budget.examined_references
        ),
    });
}

pub(super) fn should_report_broad_query(
    plan: &QueryPlan,
    query: &CodeQuerySeed,
    budget: &CodeQueryExecutionBudget,
    truncated: bool,
) -> bool {
    !plan.has_source_anchors()
        && query.where_globs.is_empty()
        && query.languages.is_empty()
        && (truncated || budget.scanned_files >= BROAD_QUERY_SCANNED_FILE_HINT_THRESHOLD)
}

pub(super) fn push_broad_query_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
) {
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::BroadQuery,
        impact: CodeQueryDiagnosticImpact::Advisory,
        branch: Vec::new(),
        language: "workspace",
        message: format!(
            "broad unanchored query_code query scanned {} files, {} bytes, {} facts, and examined {} references; add where, languages, exact name predicates, or a more specific pattern to reduce work and output",
            budget.scanned_files,
            budget.scanned_source_bytes,
            budget.fact_nodes,
            budget.examined_references
        ),
    });
}

pub(super) fn file_matches_globs(file: &ProjectFile, query: &CodeQuerySeed) -> bool {
    if query.where_globs.is_empty() {
        return true;
    }
    let rel_path = rel_path_string(file);
    query.where_globs.iter().any(|glob| glob.matches(&rel_path))
}

pub(super) fn render_match(
    analyzer: &dyn IAnalyzer,
    language: Language,
    file: &ProjectFile,
    facts: &FileFacts,
    fact_match: &FactMatch,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryMatch {
    let fact = facts.node(fact_match.node);
    let full_detail = matches!(detail, CodeQueryResultDetail::Full);
    let path = rel_path_string(file);
    let captures = fact_match
        .captures
        .iter()
        .map(|capture| CodeQueryCapture {
            name: capture.name.clone(),
            text: snippet(capture.span.text(facts.source())),
            start_line: facts.line_of_byte(capture.span.start_byte),
            range: full_detail.then(|| range_for_span(facts, capture.span)),
            kind: if full_detail {
                capture.kind.map(|kind| kind.label())
            } else {
                None
            },
            ast_id: full_detail
                .then_some(capture.node)
                .flatten()
                .map(|node| super::super::occurrence_rows::ast_id(facts.source_identity(), node)),
        })
        .collect();
    let node_range = full_detail.then(|| range_for_span(facts, fact.span()));
    let decorator_spans: Vec<_> = if full_detail {
        facts
            .role_targets(fact_match.node, Role::Decorator)
            .map(|target| target.span)
            .collect()
    } else {
        Vec::new()
    };
    let decorator_ranges = decorator_spans
        .iter()
        .map(|&span| range_for_span(facts, span))
        .collect::<Vec<_>>();
    let decorated_range = if full_detail && !decorator_spans.is_empty() {
        let mut decorated = fact.span();
        for span in decorator_spans {
            decorated.start_byte = decorated.start_byte.min(span.start_byte);
            decorated.end_byte = decorated.end_byte.max(span.end_byte);
        }
        Some(range_for_span(facts, decorated))
    } else {
        None
    };
    CodeQueryMatch {
        id: full_detail.then(|| match_id(&path, fact.kind.label(), fact.span())),
        ast_id: full_detail.then(|| {
            super::super::occurrence_rows::ast_id(facts.source_identity(), fact_match.node)
        }),
        path,
        language: language.config_label(),
        kind: fact.kind.label(),
        start_line: fact.range.start_line,
        end_line: fact.range.end_line,
        text: snippet(fact.span().text(facts.source())),
        node_range,
        decorated_range,
        decorator_ranges,
        captures,
        enclosing_symbol: cache
            .enclosing_unit_for_lines(analyzer, file, fact.range.start_line, fact.range.end_line)
            .map(|code_unit| code_unit.fq_name()),
    }
}

pub(super) fn match_id(path: &str, kind: &str, span: Span) -> String {
    format!("{path}:{kind}:{}-{}", span.start_byte, span.end_byte)
}

pub(super) fn range_for_span(facts: &FileFacts, span: Span) -> CodeQueryRange {
    let (start_line, start_column) = facts.line_column_of_byte(span.start_byte);
    let (end_line, end_column) = facts.line_column_of_byte(span.end_byte);
    CodeQueryRange {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

/// First line of `text`, truncated to [`SNIPPET_MAX_CHARS`] on a char
/// boundary, with an ellipsis when anything was dropped.
pub(super) fn snippet(text: &str) -> String {
    let first_line = text.lines().next().unwrap_or("");
    let mut end = first_line.len().min(SNIPPET_MAX_CHARS);
    while !first_line.is_char_boundary(end) {
        end -= 1;
    }
    let mut result = first_line[..end].to_string();
    if end < text.len() {
        result.push('…');
    }
    result
}
