use super::*;

use brokk_bifrost_core::analyzer::model::CallableArity;
use brokk_bifrost_core::analyzer::structural::resolution::MethodFamilyRelation;

use super::call_binding::{
    semantic_model_completeness_label, semantic_model_origin_label, semantic_model_proof_label,
};

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
        PipelineValue::JsxAttributeValue(value) => CodeQueryResultValue::JsxAttributeValue {
            value: Box::new(render_jsx_attribute_value(analyzer, &value, detail, cache)),
        },
        PipelineValue::ReceiverAnalysis(value) => CodeQueryResultValue::ReceiverAnalysis {
            value: Box::new(render_receiver_analysis(analyzer, &value, detail, cache)),
        },
        PipelineValue::MemberTargetAnalysis(value) => CodeQueryResultValue::MemberTargetAnalysis {
            value: Box::new(render_member_target_analysis(
                analyzer, &value, detail, cache,
            )),
        },
        PipelineValue::ReceiverOutcome(value) => CodeQueryResultValue::ReceiverOutcome {
            value: Box::new(render_receiver_outcome(analyzer, &value, cache)),
        },
        PipelineValue::ReceiverEvidence(value) => CodeQueryResultValue::ReceiverEvidence {
            value: Box::new(render_receiver_evidence(analyzer, &value, cache)),
        },
        PipelineValue::FieldWriteValue(value) => CodeQueryResultValue::FieldWriteValue {
            value: Box::new(render_field_write_value(analyzer, &value, detail, cache)),
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
        PipelineValue::CallBinding(value) => CodeQueryResultValue::CallBinding {
            value: Box::new(render_call_binding(analyzer, &value, detail, cache)),
        },
        PipelineValue::CallEffect(value) => CodeQueryResultValue::CallEffect {
            value: Box::new(render_call_effect(analyzer, &value, detail, cache)),
        },
        PipelineValue::CallResultContract(value) => CodeQueryResultValue::CallResultContract {
            value: Box::new(render_call_result_contract(analyzer, &value, detail, cache)),
        },
        PipelineValue::ResultContractUse(value) => CodeQueryResultValue::ResultContractUse {
            value: Box::new(render_result_contract_use(analyzer, &value, cache)),
        },
        PipelineValue::ResultContractFailureUse(value) => {
            CodeQueryResultValue::ResultContractFailureUse {
                value: Box::new(render_result_contract_failure_use(analyzer, &value, cache)),
            }
        }
        PipelineValue::NilnessOperation(value) => CodeQueryResultValue::NilnessOperation {
            value: Box::new(render_nilness_operation(analyzer, &value, cache)),
        },
        PipelineValue::SwitchCoverage(value) => CodeQueryResultValue::SwitchCoverage {
            value: Box::new(render_switch_coverage(analyzer, &value, cache)),
        },
        PipelineValue::ConcurrentAccessConflict(value) => {
            CodeQueryResultValue::ConcurrentAccessConflict {
                value: Box::new(render_concurrent_access_conflict(analyzer, &value, cache)),
            }
        }
        PipelineValue::ClassSetRow(value) => CodeQueryResultValue::ClassSetRow {
            value: Box::new(render_class_set_row(analyzer, &value, cache)),
        },
        PipelineValue::AbsentMemberFinding(value) => CodeQueryResultValue::AbsentMemberFinding {
            value: Box::new(render_absent_member_finding(analyzer, &value, cache)),
        },
        PipelineValue::DetachedTaskTransfer(value) => CodeQueryResultValue::DetachedTaskTransfer {
            value: Box::new(render_detached_task_transfer(analyzer, &value, cache)),
        },
        PipelineValue::ProcedureEffect(value) => CodeQueryResultValue::ProcedureEffect {
            value: Box::new(render_procedure_effect(analyzer, &value, cache)),
        },
        PipelineValue::CallableSignature(value) => CodeQueryResultValue::CallableSignature {
            value: Box::new(render_callable_signature(analyzer, &value, detail, cache)),
        },
        PipelineValue::SignatureParameter(value) => CodeQueryResultValue::SignatureParameter {
            value: Box::new(render_signature_parameter(analyzer, &value, cache)),
        },
        PipelineValue::DecoratedParameter(value) => CodeQueryResultValue::DecoratedParameter {
            value: Box::new(render_decorated_parameter(&value)),
        },
        PipelineValue::CallableApplicability(value) => {
            CodeQueryResultValue::CallableApplicability {
                value: Box::new(render_callable_applicability(
                    analyzer, &value, detail, cache,
                )),
            }
        }
        PipelineValue::OverloadSelection(value) => CodeQueryResultValue::OverloadSelection {
            value: Box::new(render_overload_selection(analyzer, &value, cache)),
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
        PipelineValue::CandidateHop(value) => CodeQueryResultValue::CandidateHop {
            value: Box::new(render_candidate_hop(analyzer, &value, detail, cache)),
        },
        PipelineValue::DispatchOutcome(value) => CodeQueryResultValue::DispatchOutcome {
            value: Box::new(render_dispatch_outcome(analyzer, &value, cache)),
        },
        PipelineValue::DispatchTarget(value) => CodeQueryResultValue::DispatchTarget {
            value: Box::new(render_dispatch_target(analyzer, &value, detail, cache)),
        },
        PipelineValue::MemberFamily(value) => CodeQueryResultValue::MemberFamily {
            value: Box::new(render_member_family(analyzer, &value, detail, cache)),
        },
        PipelineValue::MemberFamilyEdge(value) => CodeQueryResultValue::MemberFamilyEdge {
            value: Box::new(render_member_family_edge(analyzer, &value, detail, cache)),
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
        PipelineValue::StateEvent(value) => CodeQueryResultValue::StateEvent {
            value: Box::new(render_state_event(analyzer, &value, cache)),
        },
        PipelineValue::FlowRelation(value) => CodeQueryResultValue::FlowRelation {
            value: Box::new(render_flow_relation(analyzer, &value, cache)),
        },
        PipelineValue::ControlRelation(value) => CodeQueryResultValue::ControlRelation {
            value: Box::new(control_relations::public_control_relation(&value)),
        },
        PipelineValue::Guard(value) => CodeQueryResultValue::Guard {
            value: Box::new(guards::public_guard(&value)),
        },
        PipelineValue::SourceSet(value) => CodeQueryResultValue::SourceSet {
            value: Box::new(topology_rows::public_source_set(&value)),
        },
        PipelineValue::BuildTarget(value) => CodeQueryResultValue::BuildTarget {
            value: Box::new(topology_rows::public_build_target(&value)),
        },
        PipelineValue::TopologyEdge(value) => CodeQueryResultValue::TopologyEdge {
            value: Box::new(topology_rows::public_topology_edge(&value)),
        },
        PipelineValue::RewritePath(value) => CodeQueryResultValue::RewritePath {
            value: Box::new(render_rewrite_path(analyzer, &value, cache)),
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
                    PipelineTraceValue::JsxAttributeValue(value) => {
                        render_jsx_attribute_value_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::ReceiverAnalysis(value) => {
                        render_receiver_analysis_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::MemberTargetAnalysis(value) => {
                        render_member_target_analysis_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::ReceiverOutcome(value) => {
                        render_receiver_outcome_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::ReceiverEvidence(value) => {
                        render_receiver_evidence_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::FieldWriteValue(value) => {
                        render_field_write_value_ref(analyzer, value, cache)
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
                    PipelineTraceValue::CallBinding(value) => {
                        let rendered = render_call_binding(analyzer, value, detail, cache);
                        CodeQueryResultRef::CallBinding {
                            id: rendered.id,
                            site_id: rendered.site_id,
                            path: rendered.path,
                            range: rendered.range,
                            semantic_target_id: rendered.semantic_target_id,
                            target_origin: rendered.target_origin,
                            model_id: rendered.model_id,
                            receiver_type_id: rendered.receiver_type_id,
                            pack_id: rendered.pack_id,
                            model_record_id: rendered.model_record_id,
                            model_activation_status: rendered.model_activation_status,
                            model_activation_source_kind: rendered.model_activation_source_kind,
                            model_activation_source_id: rendered.model_activation_source_id,
                            model_origin: rendered.model_origin,
                            model_proof: rendered.model_proof,
                            model_completeness: rendered.model_completeness,
                            binding_kind: rendered.binding_kind,
                            mapping: rendered.mapping,
                            coverage: rendered.coverage,
                        }
                    }
                    PipelineTraceValue::CallEffect(value) => {
                        let rendered = render_call_effect(analyzer, value, detail, cache);
                        CodeQueryResultRef::CallEffect {
                            id: rendered.id,
                            site_id: rendered.site_id,
                            path: rendered.path,
                            range: rendered.range,
                            effect_id: rendered.effect_id,
                            derivation: rendered.derivation,
                            coverage: rendered.coverage,
                        }
                    }
                    PipelineTraceValue::CallResultContract(value) => {
                        let rendered = render_call_result_contract(analyzer, value, detail, cache);
                        CodeQueryResultRef::CallResultContract {
                            id: rendered.id,
                            site_id: rendered.site_id,
                            path: rendered.path,
                            range: rendered.range,
                            result_ordinal: rendered.result_ordinal,
                            condition_result_ordinal: rendered.condition_result_ordinal,
                            predicate: rendered.predicate,
                            result_success_predicate: rendered.result_success_predicate,
                            coverage: rendered.coverage,
                        }
                    }
                    PipelineTraceValue::ResultContractUse(value) => {
                        let rendered = render_result_contract_use(analyzer, value, cache);
                        CodeQueryResultRef::ResultContractUse {
                            id: rendered.id,
                            acquisition_id: rendered.acquisition_id,
                            path: rendered.path,
                            range: rendered.range,
                            use_kind: rendered.use_kind,
                            parameter_ordinal: rendered.parameter_ordinal,
                            applicability: rendered.applicability,
                            guard: rendered.guard,
                            coverage: rendered.coverage,
                        }
                    }
                    PipelineTraceValue::ResultContractFailureUse(value) => {
                        let rendered = render_result_contract_failure_use(analyzer, value, cache);
                        CodeQueryResultRef::ResultContractFailureUse {
                            id: rendered.id,
                            acquisition_id: rendered.acquisition_id,
                            path: rendered.path,
                            range: rendered.range,
                            provenance: rendered.failure_provenance,
                            consumer: rendered.consumer,
                            coverage: rendered.coverage,
                        }
                    }
                    PipelineTraceValue::NilnessOperation(value) => {
                        let rendered = render_nilness_operation(analyzer, value, cache);
                        CodeQueryResultRef::NilnessOperation {
                            id: rendered.id,
                            path: rendered.path,
                            range: rendered.range,
                            use_kind: rendered.use_kind,
                            fact: rendered.fact,
                            coverage: rendered.coverage,
                        }
                    }
                    PipelineTraceValue::SwitchCoverage(value) => {
                        let rendered = render_switch_coverage(analyzer, value, cache);
                        CodeQueryResultRef::SwitchCoverage {
                            id: rendered.id,
                            path: rendered.path,
                            range: rendered.range,
                            verdict: rendered.verdict,
                            proof: rendered.proof,
                        }
                    }
                    PipelineTraceValue::ConcurrentAccessConflict(value) => {
                        let rendered = render_concurrent_access_conflict(analyzer, value, cache);
                        CodeQueryResultRef::ConcurrentAccessConflict {
                            id: rendered.id,
                            path: rendered.path,
                            range: rendered.range,
                            ordering: rendered.ordering,
                            protection: rendered.protection,
                            proof: rendered.proof,
                        }
                    }
                    PipelineTraceValue::ClassSetRow(value) => {
                        let rendered = render_class_set_row(analyzer, value, cache);
                        CodeQueryResultRef::ClassSetRow {
                            id: rendered.id,
                            path: rendered.file,
                            range: rendered.range,
                            member: rendered.member,
                            status: rendered.status,
                        }
                    }
                    PipelineTraceValue::AbsentMemberFinding(value) => {
                        let rendered = render_absent_member_finding(analyzer, value, cache);
                        CodeQueryResultRef::AbsentMemberFinding {
                            id: rendered.id,
                            path: rendered.file,
                            range: rendered.range,
                            member: rendered.member,
                            class: rendered.class,
                        }
                    }
                    PipelineTraceValue::DetachedTaskTransfer(value) => {
                        let rendered = render_detached_task_transfer(analyzer, value, cache);
                        CodeQueryResultRef::DetachedTaskTransfer {
                            id: rendered.id,
                            path: rendered.path,
                            range: rendered.range,
                            role: rendered.role,
                            timing: rendered.timing,
                            coverage: rendered.coverage,
                        }
                    }
                    PipelineTraceValue::ProcedureEffect(value) => {
                        let rendered = render_procedure_effect(analyzer, value, cache);
                        CodeQueryResultRef::ProcedureEffect {
                            id: rendered.id,
                            procedure_id: rendered.procedure_id,
                            path: rendered.path,
                            range: rendered.range,
                            effect_id: rendered.effect_id,
                            derivation: rendered.derivation,
                            coverage: rendered.coverage,
                        }
                    }
                    PipelineTraceValue::CallableSignature(value) => {
                        let rendered = render_callable_signature(analyzer, value, detail, cache);
                        CodeQueryResultRef::CallableSignature {
                            id: rendered.id,
                            declaration_id: rendered.declaration.id,
                            path: rendered.path,
                            range: rendered.range,
                            role: rendered.role,
                            coverage: rendered.coverage,
                        }
                    }
                    PipelineTraceValue::SignatureParameter(value) => {
                        let rendered = render_signature_parameter(analyzer, value, cache);
                        CodeQueryResultRef::SignatureParameter {
                            id: rendered.id,
                            signature_id: rendered.signature_id,
                            path: rendered.path,
                            range: rendered.range,
                            parameter_index: rendered.parameter_index,
                        }
                    }
                    PipelineTraceValue::DecoratedParameter(value) => {
                        let rendered = render_decorated_parameter(value);
                        CodeQueryResultRef::DecoratedParameter {
                            id: rendered.id,
                            parameter_id: rendered.parameter_id,
                            decorator_id: rendered.decorator_id,
                            path: rendered.path,
                            range: rendered.range,
                            decorator_range: rendered.decorator_range,
                            parameter_ordinal: rendered.parameter_ordinal,
                            binding_status: rendered.binding_status,
                            coverage: rendered.coverage,
                        }
                    }
                    PipelineTraceValue::CallableApplicability(value) => {
                        let rendered =
                            render_callable_applicability(analyzer, value, detail, cache);
                        CodeQueryResultRef::CallableApplicability {
                            id: rendered.id,
                            site_ast_id: rendered.site_ast_id,
                            path: rendered.path,
                            range: rendered.range,
                            ordinal: rendered.ordinal,
                            verdict: rendered.verdict,
                            selected: rendered.selected,
                        }
                    }
                    PipelineTraceValue::OverloadSelection(value) => {
                        let rendered = render_overload_selection(analyzer, value, cache);
                        CodeQueryResultRef::OverloadSelection {
                            id: rendered.id,
                            site_ast_id: rendered.site_ast_id,
                            path: rendered.path,
                            range: rendered.range,
                            resolution: rendered.resolution,
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
                    PipelineTraceValue::CandidateHop(value) => {
                        render_candidate_hop_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::DispatchOutcome(value) => {
                        render_dispatch_outcome_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::DispatchTarget(value) => {
                        render_dispatch_target_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::MemberFamily(value) => {
                        render_member_family_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::MemberFamilyEdge(value) => {
                        render_member_family_edge_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::ReferenceEdge(value) => {
                        render_edge_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::StateEvent(value) => {
                        render_state_event_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::FlowRelation(value) => {
                        render_flow_relation_ref(analyzer, value, cache)
                    }
                    PipelineTraceValue::ControlRelation(value) => {
                        control_relations::control_relation_ref(value)
                    }
                    PipelineTraceValue::Guard(value) => guards::guard_ref(value),
                    PipelineTraceValue::SourceSet(value) => topology_rows::source_set_ref(value),
                    PipelineTraceValue::BuildTarget(value) => {
                        topology_rows::build_target_ref(value)
                    }
                    PipelineTraceValue::TopologyEdge(value) => {
                        topology_rows::topology_edge_ref(value)
                    }
                    PipelineTraceValue::RewritePath(value) => {
                        render_rewrite_path_ref(analyzer, value, cache)
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
    let kind = declaration.kind_label();
    let full = !detail.is_compact();
    CodeQueryResultRef::Declaration {
        id: full.then(|| {
            declaration_id(
                &path,
                declaration.identity_kind_label(),
                &fq_name,
                declaration.range,
            )
        }),
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
    CodeQueryResultRef::ReferenceSite {
        path: rel_path_string(&site.file),
        range: render_reference_range(analyzer, site, cache),
        target_id: (!detail.is_compact()).then(|| {
            declaration_id(
                &target_path,
                site.target.identity_kind_label(),
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

pub(super) fn render_member_target_analysis_ref(
    analyzer: &dyn IAnalyzer,
    value: &ReceiverAnalysisValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let rendered =
        render_member_target_analysis(analyzer, value, CodeQueryResultDetail::Compact, cache);
    CodeQueryResultRef::MemberTargetAnalysis {
        site_id: rendered.site_id,
        path: rendered.path,
        receiver_range: rendered.receiver_range,
        outcome: rendered.outcome,
        coverage: rendered.coverage,
        capture: rendered.capture,
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

pub(super) fn render_field_write_value_ref(
    analyzer: &dyn IAnalyzer,
    value: &FieldWriteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let rendered = render_field_write_value(analyzer, value, CodeQueryResultDetail::Compact, cache);
    CodeQueryResultRef::FieldWriteValue {
        id: rendered.id,
        assignment_ast_id: rendered.assignment_ast_id,
        rhs_ast_id: rendered.rhs_ast_id,
        receiver_identity_id: rendered.receiver_identity_id,
        member_target_id: rendered.member_target_id,
        path: rendered.path,
        range: rendered.range,
        proof: rendered.proof,
        completeness: rendered.completeness,
        coverage: rendered.coverage,
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

/// One state event, with its own source range resolved against the analyzed
/// content the derivation ran over.
pub(super) fn render_state_event(
    analyzer: &dyn IAnalyzer,
    value: &StateEventValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryStateEvent {
    let row = value.row();
    let range = render_source_range(analyzer, &row.site.file, &row.site.range, cache);
    flow_state::public_state_event(value, range)
}

/// One flow relation, with both endpoints rendered inline: a relation without
/// its write and its read is not readable evidence.
pub(super) fn render_flow_relation(
    analyzer: &dyn IAnalyzer,
    value: &FlowRelationValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryFlowRelation {
    let source = value.source();
    let target = value.target();
    let source_range = render_source_range(analyzer, &source.site.file, &source.site.range, cache);
    let target_range = render_source_range(analyzer, &target.site.file, &target.site.range, cache);
    flow_state::public_flow_relation(value, source_range, target_range)
}

pub(super) fn render_state_event_ref(
    analyzer: &dyn IAnalyzer,
    value: &StateEventValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let row = value.row();
    CodeQueryResultRef::StateEvent {
        id: value.id(),
        ast_id: row.site.ast_id.clone(),
        path: rel_path_string(&row.site.file),
        range: render_source_range(analyzer, &row.site.file, &row.site.range, cache),
        procedure_id: value.procedure_id.to_string(),
        event_class: row.event_class.label(),
    }
}

pub(super) fn render_flow_relation_ref(
    analyzer: &dyn IAnalyzer,
    value: &FlowRelationValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let target = value.target();
    CodeQueryResultRef::FlowRelation {
        id: value.id(),
        path: rel_path_string(&target.site.file),
        range: render_source_range(analyzer, &target.site.file, &target.site.range, cache),
        procedure_id: value.procedure_id.to_string(),
        relation: value.row().relation.label(),
        certainty: value.row().certainty.label(),
    }
}

/// One bounded rewrite path, with its origin range resolved against the
/// analyzed content the chase ran over.
pub(super) fn render_rewrite_path(
    analyzer: &dyn IAnalyzer,
    value: &RewritePathValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryRewritePath {
    let row = value.row();
    let range = render_source_range(analyzer, &row.origin.file, &row.origin.range, cache);
    rewrite_paths::public_rewrite_path(value, range)
}

pub(super) fn render_rewrite_path_ref(
    analyzer: &dyn IAnalyzer,
    value: &RewritePathValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let row = value.row();
    CodeQueryResultRef::RewritePath {
        id: value.id(),
        path: rel_path_string(&row.origin.file),
        range: render_source_range(analyzer, &row.origin.file, &row.origin.range, cache),
        domain: row.domain.label(),
        outcome: row.outcome.kind().label(),
    }
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
/// The value domains the three `member_selection` summary fields publish.
/// Minted by [`render_member_selection`] below rather than by a typed
/// vocabulary (issue #2515).
pub(super) const MEMBER_SELECTION_OUTCOME_LABELS: &[&str] = &["selected", "unresolved", "untraced"];
pub(super) const MEMBER_SELECTION_TRACE_COMPLETENESS_LABELS: &[&str] =
    &["full", "selection_only", "absent"];
pub(super) const MEMBER_SELECTION_COVERAGE_LABELS: &[&str] = &["exhaustive", "open", "unsupported"];

/// The value domain the `member_family_edge.completeness` row field publishes.
/// A family edge the resolver recorded is complete by construction, so the
/// domain is the single label [`render_member_family_edge`] writes.
pub(super) const MEMBER_FAMILY_EDGE_COMPLETENESS_LABELS: &[&str] = &["complete"];

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

/// The mandatory overload-selection summary of one occurrence (#1478 M3).
pub(super) fn render_overload_selection(
    analyzer: &dyn IAnalyzer,
    value: &OverloadSelectionValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryOverloadSelection {
    let occurrence = &value.occurrence;
    let row = value.row();
    CodeQueryOverloadSelection {
        id: row.id.clone(),
        site_ast_id: row.site_ast_id.clone(),
        path: rel_path_string(&occurrence.file),
        language: crate::analyzer::common::language_for_file(&occurrence.file).config_label(),
        range: render_source_range(analyzer, &occurrence.file, &occurrence.range, cache),
        resolution: row.resolution.label(),
        supported: row.supported,
        considered_count: row.considered,
        applicable_count: row.applicable,
        inapplicable_count: row.inapplicable,
        unknown_count: row.unknown,
    }
}

/// One considered candidate's applicability row (#1478 M3).
pub(super) fn render_callable_applicability(
    analyzer: &dyn IAnalyzer,
    value: &CallableApplicabilityValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryCallableApplicability {
    let occurrence = &value.occurrence;
    let row = value.row();
    CodeQueryCallableApplicability {
        id: row.id.clone(),
        site_ast_id: row.site_ast_id.clone(),
        path: rel_path_string(&occurrence.file),
        language: crate::analyzer::common::language_for_file(&occurrence.file).config_label(),
        range: render_source_range(analyzer, &occurrence.file, &occurrence.range, cache),
        ordinal: row.ordinal,
        verdict: row.verdict.label(),
        reason: row.reason.map(|reason| reason.label()),
        tier: row.tier.map(|tier| tier.label()),
        selected: row.selected,
        candidate: render_trace_candidate_ref(
            analyzer,
            occurrence,
            &value.candidate.candidate,
            detail,
            cache,
        ),
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
                        .map(|range| DeclarationValue::new(unit.clone(), range))?;
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
        OccurrenceTarget::NotDerived => CodeQueryOccurrenceTarget::NotDerived,
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

/// What one trace candidate points at, rendered for a result row.
///
/// Shared by the `candidates` and `callable_applicability` domains so the two
/// never describe the same candidate differently.
pub(super) fn render_trace_candidate_ref(
    analyzer: &dyn IAnalyzer,
    occurrence: &OccurrenceRow,
    candidate: &TraceCandidateRef,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryCandidateRef {
    match candidate {
        TraceCandidateRef::Unit(unit) => {
            match render_unit_declaration(analyzer, unit, detail, cache) {
                Some(declaration) => CodeQueryCandidateRef::Unit {
                    unit: Box::new(declaration),
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
    }
}

pub(super) fn render_resolution_candidate(
    analyzer: &dyn IAnalyzer,
    value: &CandidateValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResolutionCandidate {
    let occurrence = &value.occurrence;
    let range = render_source_range(analyzer, &occurrence.file, &occurrence.range, cache);
    let candidate = render_trace_candidate_ref(
        analyzer,
        occurrence,
        &value.candidate.candidate,
        detail,
        cache,
    );
    let canonical_member_id = environment::candidate_unit(&value.candidate.candidate)
        .map(|unit| canonical_member_digest(analyzer, unit));
    let owner = value
        .candidate
        .member
        .as_ref()
        .and_then(|member| render_unit_declaration(analyzer, &member.owner, detail, cache));
    environment::public_candidate(value, range, candidate, canonical_member_id, owner)
}

/// The mandatory dispatch outcome row of one site.
pub(super) fn render_dispatch_outcome(
    analyzer: &dyn IAnalyzer,
    value: &DispatchSiteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryDispatchOutcome {
    let answer = &value.answer;
    CodeQueryDispatchOutcome {
        id: value.site_id.clone(),
        site_id: value.site_id.clone(),
        site_ast_id: value.site_ast_id.clone(),
        path: rel_path_string(&value.file),
        language: crate::analyzer::common::language_for_file(&value.file).config_label(),
        range: render_source_range(analyzer, &value.file, &value.range, cache),
        outcome: answer.outcome,
        coverage: answer.coverage.label(),
        call_site_count: answer.call_site_count,
        target_count: answer.arms.len(),
        targets_truncated: answer.coverage.is_truncated(),
        semantic_unsupported: answer.semantic_unsupported,
        exceeded_limit: answer.exceeded_limit,
    }
}

/// One bounded dispatch arm of one site.
///
/// The target declaration is rendered through the same `render_unit_declaration`
/// the candidate and hop rows use, so a dispatch target and a member candidate
/// naming the same declaration render identically.
pub(super) fn render_dispatch_target(
    analyzer: &dyn IAnalyzer,
    value: &DispatchTargetValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryDispatchTarget {
    let site = &value.site;
    let arm = value.arm();
    CodeQueryDispatchTarget {
        id: value.id(),
        site_id: site.site_id.clone(),
        site_ast_id: site.site_ast_id.clone(),
        path: rel_path_string(&site.file),
        ordinal: value.ordinal,
        target_id: arm.target_id.clone(),
        target_path: arm.target_path.clone(),
        target_declaration: arm
            .target_unit
            .as_ref()
            .and_then(|unit| render_unit_declaration(analyzer, unit, detail, cache)),
        proof: arm.proof,
        completeness: arm.completeness,
        coverage: site.answer.coverage.label(),
        dispatch: site.answer.dispatch_label(arm),
        boundary_kind: arm.boundary_kind,
    }
}

pub(super) fn render_dispatch_outcome_ref(
    analyzer: &dyn IAnalyzer,
    value: &DispatchSiteValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    CodeQueryResultRef::DispatchOutcome {
        id: value.site_id.clone(),
        site_id: value.site_id.clone(),
        path: rel_path_string(&value.file),
        range: render_source_range(analyzer, &value.file, &value.range, cache),
        outcome: value.answer.outcome,
        coverage: value.answer.coverage.label(),
    }
}

pub(super) fn render_dispatch_target_ref(
    analyzer: &dyn IAnalyzer,
    value: &DispatchTargetValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let site = &value.site;
    CodeQueryResultRef::DispatchTarget {
        id: value.id(),
        site_id: site.site_id.clone(),
        path: rel_path_string(&site.file),
        range: render_source_range(analyzer, &site.file, &site.range, cache),
        ordinal: value.ordinal,
        dispatch: site.answer.dispatch_label(value.arm()),
    }
}

/// The mandatory method-family outcome row of one member.
pub(super) fn render_member_family(
    analyzer: &dyn IAnalyzer,
    value: &MemberFamilyValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryMemberFamily {
    let answer = &value.answer;
    let count = |relation: MethodFamilyRelation| {
        value
            .edges
            .iter()
            .filter(|edge| edge.relation == relation)
            .count()
    };
    let file = value.file();
    CodeQueryMemberFamily {
        id: value.id(),
        member_id: value.member_id.clone(),
        path: rel_path_string(file),
        language: crate::analyzer::common::language_for_file(file).config_label(),
        range: render_source_range(analyzer, file, &value.member.range, cache),
        member: render_unit_declaration(analyzer, &value.member.unit, detail, cache),
        outcome: answer.outcome.label(),
        reason: answer.reason.map(|reason| reason.label()),
        capability: answer.capability.label(),
        coverage: member_family::family_coverage(answer.outcome),
        family_id: value.family_id.clone(),
        overrides_count: count(MethodFamilyRelation::Overrides),
        implements_count: count(MethodFamilyRelation::Implements),
        overridden_by_count: count(MethodFamilyRelation::OverriddenBy),
        implemented_by_count: count(MethodFamilyRelation::ImplementedBy),
        edge_count: value.edges.len(),
        root_count: answer.roots.len(),
    }
}

/// One typed method-family edge.
///
/// Source and target are rendered through the same `render_unit_declaration`
/// the candidate, hop, and dispatch-target rows use, so the same declaration
/// renders identically wherever it appears.
pub(super) fn render_member_family_edge(
    analyzer: &dyn IAnalyzer,
    value: &MemberFamilyEdgeValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryMemberFamilyEdge {
    let family = &value.family;
    let edge = value.edge();
    let file = family.file();
    CodeQueryMemberFamilyEdge {
        id: value.id(),
        member_id: family.member_id.clone(),
        path: rel_path_string(file),
        range: render_source_range(analyzer, file, &family.member.range, cache),
        ordinal: value.ordinal,
        source: render_unit_declaration(analyzer, &family.member.unit, detail, cache),
        target_id: edge.target_id.clone(),
        target: render_unit_declaration(analyzer, &edge.target, detail, cache),
        relation: edge.relation.label(),
        family_id: family.family_id.clone(),
        hierarchy_depth: edge.depth,
        proof: edge.proof,
        completeness: "complete",
        coverage: member_family::family_coverage(family.answer.outcome),
    }
}

pub(super) fn render_member_family_ref(
    analyzer: &dyn IAnalyzer,
    value: &MemberFamilyValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let file = value.file();
    CodeQueryResultRef::MemberFamily {
        id: value.id(),
        member_id: value.member_id.clone(),
        path: rel_path_string(file),
        range: render_source_range(analyzer, file, &value.member.range, cache),
        outcome: value.answer.outcome.label(),
        coverage: member_family::family_coverage(value.answer.outcome),
    }
}

pub(super) fn render_member_family_edge_ref(
    analyzer: &dyn IAnalyzer,
    value: &MemberFamilyEdgeValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let family = &value.family;
    let file = family.file();
    CodeQueryResultRef::MemberFamilyEdge {
        id: value.id(),
        member_id: family.member_id.clone(),
        path: rel_path_string(file),
        range: render_source_range(analyzer, file, &family.member.range, cache),
        ordinal: value.ordinal,
        relation: value.edge().relation.label(),
    }
}

/// One exact hierarchy hop of one traced member candidate.
///
/// The endpoints are rendered through the same `render_unit_declaration` the
/// candidate row's `owner` uses, so a hop's `to` at the last hop and the
/// candidate's `owner` are the same rendered declaration.
pub(super) fn render_candidate_hop(
    analyzer: &dyn IAnalyzer,
    value: &CandidateHopValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryCandidateHop {
    let occurrence = &value.occurrence;
    let range = render_source_range(analyzer, &occurrence.file, &occurrence.range, cache);
    let from = render_unit_declaration(analyzer, &value.hop.from, detail, cache);
    let to = render_unit_declaration(analyzer, &value.hop.to, detail, cache);
    environment::public_candidate_hop(value, range, from, to)
}

pub(super) fn render_candidate_hop_ref(
    analyzer: &dyn IAnalyzer,
    value: &CandidateHopValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let occurrence = &value.occurrence;
    CodeQueryResultRef::CandidateHop {
        id: value.id(),
        candidate_id: value.candidate_id(),
        path: rel_path_string(&occurrence.file),
        range: render_source_range(analyzer, &occurrence.file, &occurrence.range, cache),
        hop: value.hop.hop,
        relation: value.hop.relation.label(),
    }
}

/// Render one workspace declaration for a row field, or `None` when the
/// workspace can no longer locate the unit.
fn render_unit_declaration(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> Option<CodeQueryDeclaration> {
    analyzer
        .ranges_of(unit)
        .into_iter()
        .min_by_key(primary_range_key)
        .map(|range| DeclarationValue::new(unit.clone(), range))
        .map(|declaration| render_declaration(analyzer, &declaration, detail, cache))
}

/// A stable, domain-separated digest of one declaration's #1475 canonical
/// identity. The digest input is the structured identity (kind-tagged
/// segments, namespace, language, recorded generic arity), never a rendered
/// FQN or signature string, so same-spelling decoys with different segment
/// kinds hash apart and aliases/partial types canonicalized by the analyzer
/// hash together.
pub(super) fn canonical_member_digest(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> String {
    let identity = crate::structural::canonical_identity_of(analyzer, unit);
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
    let kind = declaration.kind_label();
    let full = !detail.is_compact();
    let signature = declaration
        .unit
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.signatures_of(&declaration.unit).into_iter().next());
    let semantic_model = analyzer.semantic_model_overlay().and_then(|overlay| {
        let matched = overlay.symbols_named(&fq_name);
        if matched.disposition
            != crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        {
            return None;
        }
        let symbol = matched.records[0];
        let exact_origin = declaration.unit.is_synthetic()
            || matches!(
                &symbol.location,
                crate::analyzer::semantic_model::SemanticModelLocation::Authored(anchor)
                    if anchor.path == path && anchor.symbol == fq_name
            );
        exact_origin.then(|| (symbol.id.clone(), Box::new(symbol.provenance.clone())))
    });
    CodeQueryDeclaration {
        id: full.then(|| {
            semantic_model
                .as_ref()
                .map(|(id, _)| id.clone())
                .unwrap_or_else(|| {
                    declaration_id(
                        &path,
                        declaration.identity_kind_label(),
                        &fq_name,
                        declaration.range,
                    )
                })
        }),
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
        semantic_model: semantic_model.map(|(_, provenance)| provenance),
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
            .map(|fq| fq.display(brokk_bifrost_core::analyzer::fq_name::segment_interner())),
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

pub(super) fn render_jsx_attribute_value(
    analyzer: &dyn IAnalyzer,
    value: &JsxAttributeValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryJsxAttributeValue {
    let node = value.seed.facts.node(value.value_node);
    let range = Range {
        start_byte: node.range.start_byte,
        end_byte: node.range.end_byte,
        start_line: node.range.start_line,
        end_line: node.range.end_line,
    };
    let text = value
        .seed
        .facts
        .source()
        .get(range.start_byte..range.end_byte)
        .map(snippet)
        .unwrap_or_default();
    let component = value.component.as_ref().map(|unit| {
        let declaration = declaration_value_for_unit(analyzer, unit, range);
        render_declaration(analyzer, &declaration, detail, cache)
    });
    let attribute_target = value.attribute_target.as_ref().map(|unit| {
        let declaration = declaration_value_for_unit(analyzer, unit, range);
        render_declaration(analyzer, &declaration, detail, cache)
    });
    CodeQueryJsxAttributeValue {
        id: value.id(),
        ast_id: value.ast_id(),
        path: rel_path_string(&value.seed.file),
        language: value.seed.language.config_label(),
        range: render_source_range(analyzer, &value.seed.file, &range, cache),
        text,
        element_identity: value.element_identity.label(),
        element_name: value.element_name.clone(),
        attribute_kind: value.seed.facts.node(value.attribute_node).kind.label(),
        attribute_name: value.attribute_name.clone(),
        property_name: value.property_name.clone(),
        coverage: value.coverage.label(),
        reason: value.reason,
        component,
        attribute_target,
    }
}

fn render_jsx_attribute_value_ref(
    analyzer: &dyn IAnalyzer,
    value: &JsxAttributeValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultRef {
    let rendered =
        render_jsx_attribute_value(analyzer, value, CodeQueryResultDetail::Compact, cache);
    CodeQueryResultRef::JsxAttributeValue {
        id: rendered.id,
        ast_id: rendered.ast_id,
        path: rendered.path,
        range: rendered.range,
        element_identity: rendered.element_identity,
        coverage: rendered.coverage,
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
            let (label, reason, limit) = receiver_outcome_metadata(outcome);
            (label, Vec::new(), Vec::new(), reason, limit)
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

pub(super) fn render_member_target_analysis(
    analyzer: &dyn IAnalyzer,
    value: &ReceiverAnalysisValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryMemberTargetAnalysis {
    let ReceiverQueryAnalysis::MemberTargets(outcome) = &value.report.analysis else {
        unreachable!("member-target rows carry member-target analysis");
    };
    let member_targets = outcome
        .values()
        .into_iter()
        .flatten()
        .map(|target| {
            render_member_target(analyzer, target, value.report.site.range, detail, cache)
        })
        .collect();
    let (outcome, reason, limit) = receiver_outcome_metadata(outcome);
    let coverage = render_receiver_outcome(analyzer, value, cache).coverage;
    CodeQueryMemberTargetAnalysis {
        site_id: value.site_id.clone(),
        site_ast_id: value.site_ast_id.clone(),
        path: rel_path_string(&value.report.site.file),
        language: value.report.site.language.config_label(),
        receiver_range: render_source_range(
            analyzer,
            &value.report.site.file,
            &value.report.site.range,
            cache,
        ),
        member_range: value
            .report
            .member_range
            .map(|range| render_source_range(analyzer, &value.report.site.file, &range, cache)),
        receiver_text: snippet(&value.report.site.text),
        input_kind: value.report.site.syntax_kind.clone(),
        capture: value.capture.clone(),
        outcome,
        member_targets,
        reason,
        limit,
        coverage,
    }
}

pub(super) fn render_member_target(
    analyzer: &dyn IAnalyzer,
    target: &ReceiverMemberTarget,
    fallback: Range,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryMemberTarget {
    match target {
        ReceiverMemberTarget::Workspace { receiver, member } => {
            let receiver_declaration = receiver.as_ref().map(|receiver| {
                let declaration = declaration_value_for_unit(analyzer, receiver, fallback);
                render_declaration(analyzer, &declaration, detail, cache)
            });
            let declaration = declaration_value_for_unit(analyzer, member, fallback);
            let rendered = render_declaration(analyzer, &declaration, detail, cache);
            CodeQueryMemberTarget {
                id: target.member_identity_id(),
                path: Some(rendered.path.clone()),
                language: Some(rendered.language),
                start_line: Some(rendered.start_line),
                end_line: Some(rendered.end_line),
                signature: rendered.signature.clone(),
                node_range: rendered.node_range,
                receiver_id: target.receiver_identity_id(),
                receiver_fq_name: receiver.as_ref().map(CodeUnit::fq_name),
                receiver_kind: receiver_declaration.as_ref().map(|value| value.kind),
                receiver_declaration,
                receiver_semantic_model: None,
                receiver_proof: None,
                receiver_binding_path: None,
                receiver_binding_range: None,
                name: member.identifier().to_string(),
                fq_name: member.fq_name(),
                kind: rendered.kind,
                declaration: Some(rendered),
                semantic_model: None,
            }
        }
        ReceiverMemberTarget::SemanticModel {
            receiver,
            member,
            receiver_proof,
        } => {
            let (receiver_proof, receiver_binding_path, receiver_binding_range) =
                match receiver_proof {
                    ReceiverIdentityProof::ExactValueAnalysis => {
                        ("exact_value_analysis", None, None)
                    }
                    ReceiverIdentityProof::ExactStaticTypeReference => {
                        ("exact_static_type_reference", None, None)
                    }
                    ReceiverIdentityProof::ImmutableBinding {
                        file,
                        declaration_range,
                    } => (
                        "immutable_binding",
                        Some(rel_path_string(file)),
                        Some(render_source_range(
                            analyzer,
                            file,
                            declaration_range,
                            cache,
                        )),
                    ),
                };
            CodeQueryMemberTarget {
                id: member.id.clone(),
                path: None,
                language: model_language_label(&member.language),
                start_line: None,
                end_line: None,
                signature: None,
                node_range: None,
                receiver_id: Some(receiver.id.clone()),
                receiver_fq_name: Some(receiver.qualified_name.clone()),
                receiver_kind: Some(model_symbol_kind_label(receiver.kind)),
                receiver_declaration: None,
                receiver_semantic_model: Some(Box::new(receiver.provenance.clone())),
                receiver_proof: Some(receiver_proof),
                receiver_binding_path,
                receiver_binding_range,
                name: member.name.clone(),
                fq_name: member.qualified_name.clone(),
                kind: model_symbol_kind_label(member.kind),
                declaration: None,
                semantic_model: Some(Box::new(member.provenance.clone())),
            }
        }
    }
}

pub(super) fn render_field_write_value(
    analyzer: &dyn IAnalyzer,
    value: &FieldWriteValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryFieldWriteValue {
    let facts = &value.seed.facts;
    let assignment = facts.node(value.assignment_node).range;
    let receiver = facts.node(value.receiver_node).range;
    let member = facts.node(value.member_node).range;
    let rhs = facts.node(value.rhs_node).range;
    CodeQueryFieldWriteValue {
        id: value.id(),
        write_site_id: value.assignment_ast_id(),
        assignment_ast_id: value.assignment_ast_id(),
        left_ast_id: value.ast_id(value.left_node),
        receiver_ast_id: value.ast_id(value.receiver_node),
        member_ast_id: value.ast_id(value.member_node),
        rhs_ast_id: value.rhs_ast_id(),
        path: rel_path_string(&value.seed.file),
        language: value.seed.language.config_label(),
        range: render_source_range(analyzer, &value.seed.file, &rhs, cache),
        text: snippet(
            facts
                .source()
                .get(rhs.start_byte..rhs.end_byte)
                .unwrap_or_default(),
        ),
        assignment_range: render_source_range(analyzer, &value.seed.file, &assignment, cache),
        receiver_range: render_source_range(analyzer, &value.seed.file, &receiver, cache),
        member_range: render_source_range(analyzer, &value.seed.file, &member, cache),
        receiver_identity_id: value
            .target
            .receiver_identity_id()
            .expect("field-write values retain exact receiver identity"),
        member_target_id: value.target.member_identity_id(),
        member_target: render_member_target(
            analyzer,
            &value.target,
            value.analysis.report.site.range,
            detail,
            cache,
        ),
        proof: "precise",
        completeness: "complete",
        coverage: "exhaustive",
    }
}

fn model_symbol_kind_label(
    kind: crate::analyzer::semantic_model::SemanticModelSymbolKind,
) -> &'static str {
    use crate::analyzer::semantic_model::SemanticModelSymbolKind as Kind;
    match kind {
        Kind::Class => "class",
        Kind::Annotation => "annotation",
        Kind::Delegate => "delegate",
        Kind::Interface => "interface",
        Kind::Trait => "trait",
        Kind::Struct => "struct",
        Kind::Union => "union",
        Kind::Enum => "enum",
        Kind::Record => "record",
        Kind::Module => "module",
        Kind::TypeAlias => "type_alias",
        Kind::Constructor => "constructor",
        Kind::Method => "method",
        Kind::Function => "function",
        Kind::Field => "field",
        Kind::Property => "property",
        Kind::Constant => "constant",
        Kind::Static => "static",
        Kind::Macro => "macro",
        Kind::Event => "event",
    }
}

/// The value domain the `receiver_outcome.coverage` row field publishes, and
/// with it the `receiver_evidence.completeness` field that copies it. Minted
/// by [`render_receiver_outcome`] below rather than by a typed vocabulary
/// (issue #2515).
pub(super) const RECEIVER_COVERAGE_LABELS: &[&str] =
    &["unsupported", "truncated", "open", "unknown", "exhaustive"];

/// The value domain the `receiver_evidence.proof` row field publishes: an
/// evidence row is `precise` exactly when its site's analysis was precise.
pub(super) const RECEIVER_EVIDENCE_PROOF_LABELS: &[&str] = &["precise", "ambiguous"];

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
        callee_name: outcome.callee_name.clone(),
        call_kind: outcome.call_kind.label(),
        coverage: outcome.coverage.label(),
        group_count: value.report.groups.len(),
        argument_count: value.report.arguments.len(),
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

pub(super) fn render_call_binding(
    analyzer: &dyn IAnalyzer,
    value: &CallBindingValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryCallBinding {
    let report = &value.site.report;
    let row = value.row();
    let provenance = value.site.semantic_model_provenance.as_deref();
    let summary = value.site.selector.summary_provenance.as_deref();
    CodeQueryCallBinding {
        id: row.id.clone(),
        site_id: row.site_id.clone(),
        site_ast_id: report.site_ast_id.clone(),
        path: rel_path_string(&report.file),
        language: crate::analyzer::common::language_for_file(&report.file).config_label(),
        range: render_source_range(analyzer, &report.file, &row.range, cache),
        group_id: row.group_id.clone(),
        argument_id: row.argument_id.clone(),
        target: value
            .site
            .target
            .as_ref()
            .map(|target| render_declaration(analyzer, target, detail, cache)),
        semantic_target_id: value.site.semantic_target_id.clone(),
        target_origin: value.site.target_origin,
        dispatch_outcome: value.site.dispatch.outcome,
        dispatch_coverage: value.site.dispatch.coverage,
        dispatch_proof: value.site.dispatch.proof,
        dispatch_completeness: value.site.dispatch.completeness,
        dispatch_target_count: value.site.dispatch.target_count,
        dispatch_targets_truncated: value.site.dispatch.targets_truncated,
        selector_exact: value.site.selector.exact,
        selector_proof: value.site.selector.tier,
        selector_summary_id: value.site.selector.summary_id.clone(),
        selector_summary_model_id: value.site.selector.summary_model_id.clone(),
        selector_summary_pack_id: summary.map(|value| value.pack_id.clone()),
        selector_summary_active_set_hash: summary.map(|value| value.active_model_set_hash.clone()),
        selector_summary_pack_digest: summary.map(|value| value.pack_digest.clone()),
        selector_summary_pack_version: summary.map(|value| value.pack_version.clone()),
        selector_summary_record_id: summary.map(|value| value.record_id.clone()),
        selector_summary_origin: summary.map(|value| semantic_model_origin_label(value.origin)),
        selector_summary_model_proof: summary.map(|value| semantic_model_proof_label(value.proof)),
        selector_summary_completeness: summary
            .map(|value| semantic_model_completeness_label(value.completeness)),
        selector_summary_producer: summary.map(|value| value.producer.clone()),
        selector_summary_producer_version: summary.map(|value| value.producer_version.clone()),
        signature_id: value.site.signature_id.clone(),
        model_callable_id: value.site.model_callable_id.clone(),
        formal_layout_id: value.site.formal_layout_id.clone(),
        model_id: value.site.model_id.clone(),
        receiver_type_id: value.site.receiver_type_id.clone(),
        pack_id: value.site.pack_id.clone(),
        model_active_set_hash: provenance.map(|value| value.active_model_set_hash.clone()),
        model_pack_digest: provenance.map(|value| value.pack_digest.clone()),
        model_pack_version: provenance.map(|value| value.pack_version.clone()),
        model_record_id: provenance.map(|value| value.record_id.clone()),
        model_activation_status: provenance.map(|value| value.activation.status.clone()),
        model_activation_reason: provenance.map(|value| value.activation.reason.clone()),
        model_activation_source_kind: provenance.map(|value| value.activation.source_kind.clone()),
        model_activation_source_id: provenance.map(|value| value.activation.source_id.clone()),
        model_origin: provenance.map(|value| semantic_model_origin_label(value.origin)),
        model_proof: provenance.map(|value| semantic_model_proof_label(value.proof)),
        model_completeness: provenance
            .map(|value| semantic_model_completeness_label(value.completeness)),
        model_ambiguous: provenance.map(|value| value.ambiguous),
        model_producer: provenance.map(|value| value.producer.clone()),
        model_producer_version: provenance.map(|value| value.producer_version.clone()),
        actual_index: row.actual_index,
        actual_name: row.actual_name.clone(),
        formal_index: row.formal_index,
        formal_name: row.formal_name.clone(),
        binding_kind: row.binding_kind.map(|kind| kind.label()),
        conversion: row.conversion.clone(),
        mapping: row.mapping.label(),
        reason: row.reason.map(|reason| reason.label()),
        coverage: report.coverage.label(),
        actual_count: report.actual_count,
        bound_count: report.bound_count,
        terminal: row.terminal,
    }
}

pub(super) fn render_call_effect(
    analyzer: &dyn IAnalyzer,
    value: &effects::CallEffectValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryCallEffect {
    let report = &value.report;
    let row = value.row();
    let callee = value
        .callee_declaration()
        .cloned()
        .map(|declaration| render_declaration(analyzer, &declaration, detail, cache));
    CodeQueryCallEffect {
        id: row.id.clone(),
        site_id: row.site_id.clone(),
        site_ast_id: row.site_ast_id.clone(),
        path: rel_path_string(&report.file),
        language: crate::analyzer::common::language_for_file(&report.file).config_label(),
        range: render_source_range(analyzer, &report.file, &row.range, cache),
        target_id: row.target_id.clone(),
        callee,
        callee_symbol: row.callee_symbol.clone(),
        effect_id: row.effect_id.clone(),
        classification: row.classification.label(),
        timing: row.timing.map(|timing| timing.label()),
        execution_timing: row.execution_timing.map(|timing| timing.label()),
        certainty: row.certainty.map(|certainty| certainty.label()),
        proof: row.proof.map(|proof| proof.label()),
        derivation: row.derivation.label(),
        reason: row.reason.map(|reason| reason.label()),
        coverage: report.coverage.label(),
        pack_id: row.pack_id.clone(),
        model_id: row.model_id.clone(),
        summary_id: row.summary_id.clone(),
        arm_count: report.arm_count,
        modeled_arm_count: report.modeled_arm_count,
        terminal: row.terminal,
    }
}

pub(super) fn render_call_result_contract(
    analyzer: &dyn IAnalyzer,
    value: &effects::CallResultContractValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryCallResultContract {
    CodeQueryCallResultContract {
        id: value.id.clone(),
        site_id: value.site_id.clone(),
        site_ast_id: value.site_ast_id.clone(),
        path: rel_path_string(&value.file),
        language: crate::analyzer::common::language_for_file(&value.file).config_label(),
        range: render_source_range(analyzer, &value.file, &value.range, cache),
        target_id: value.target_id.clone(),
        callee: value
            .callee
            .as_ref()
            .map(|callee| render_declaration(analyzer, callee, detail, cache)),
        callee_symbol: value.callee_symbol.clone(),
        result_ordinal: value.result_ordinal,
        condition_result_ordinal: value.condition_result_ordinal,
        predicate: value.predicate.map(effects::result_predicate_label),
        result_success_predicate: value
            .result_success_predicate
            .map(effects::result_predicate_label),
        proof: value.proof.map(|proof| proof.label()),
        coverage: value.coverage.label(),
        reason: value.reason.map(|reason| reason.label()),
        pack_id: value.pack_id.clone(),
        model_id: value.model_id.clone(),
        summary_id: value.summary_id.clone(),
        arm_count: value.arm_count,
        modeled_arm_count: value.modeled_arm_count,
        terminal: value.terminal,
        result_use_count: value.result_use_count,
        unguarded_result_use_count: value.unguarded_result_use_count,
        use_validation: value.use_validation,
        use_validation_coverage: value
            .use_validation_coverage
            .map(|coverage| coverage.label()),
        success_guard_count: value.success_guard_edges.len(),
        fresh_allocation: value.fresh_allocation,
        member_contract_count: value.member_contracts.len(),
        member_contracts: value.member_contracts.clone(),
        success_guard_coverage: value.success_guard_coverage,
        success_guard_edges: value.success_guard_edges.clone(),
        possible_success_guard_edges: value.possible_success_guard_edges.clone(),
    }
}

pub(super) fn render_result_contract_use(
    analyzer: &dyn IAnalyzer,
    value: &effects::ResultContractUseValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultContractUse {
    CodeQueryResultContractUse {
        id: value.id.clone(),
        acquisition_id: value.acquisition_id.clone(),
        acquisition_site_id: value.acquisition_site_id.clone(),
        acquisition_site_ast_id: value.acquisition_site_ast_id.clone(),
        operation_point_id: value.operation_point_id.clone(),
        operation_site_id: value.operation_site_id.clone(),
        operation_site_ast_id: value.operation_site_ast_id.clone(),
        ast_id: value.ast_id.clone(),
        path: rel_path_string(&value.file),
        language: crate::analyzer::common::language_for_file(&value.file).config_label(),
        range: render_source_range(analyzer, &value.file, &value.range, cache),
        result_ordinal: value.result_ordinal,
        condition_result_ordinal: value.condition_result_ordinal,
        acquisition_predicate: value
            .acquisition_predicate
            .map(effects::result_predicate_label),
        result_success_predicate: value
            .result_success_predicate
            .map(effects::result_predicate_label),
        required_predicate: value
            .required_predicate
            .map(effects::result_predicate_label),
        use_kind: value.use_kind.label(),
        timing: value.timing.label(),
        applicability: value.applicability.label(),
        guard: value.guard.label(),
        coverage: value.coverage.label(),
        member: value.member.clone(),
        parameter_count: value.parameter_count,
        parameter_ordinal: value.parameter_ordinal,
        pack_id: value.pack_id.clone(),
        model_id: value.model_id.clone(),
        summary_id: value.summary_id.clone(),
    }
}

pub(super) fn render_nilness_operation(
    analyzer: &dyn IAnalyzer,
    value: &effects::NilnessOperationValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryNilnessOperation {
    CodeQueryNilnessOperation {
        id: value.id.clone(),
        procedure_id: value.procedure_id.clone(),
        operation_point_id: value.operation_point_id.clone(),
        subject_value_id: value.subject_value_id,
        ast_id: value.ast_id.clone(),
        path: rel_path_string(&value.file),
        language: crate::analyzer::common::language_for_file(&value.file).config_label(),
        range: render_source_range(analyzer, &value.file, &value.range, cache),
        use_kind: value.use_kind.label(),
        fact: value.fact.label(),
        origin: value.origin,
        proof: value.proof,
        coverage: value.coverage.label(),
        reason: value.reason,
    }
}

pub(super) fn render_switch_coverage(
    analyzer: &dyn IAnalyzer,
    value: &effects::SwitchCoverageValue,
    cache: &mut PipelineRenderCache,
) -> CodeQuerySwitchCoverage {
    CodeQuerySwitchCoverage {
        id: value.id.clone(),
        procedure_id: value.procedure_id.clone(),
        switch_fact_id: value.switch_fact_id,
        ast_id: value.ast_id.clone(),
        path: rel_path_string(&value.file),
        language: crate::analyzer::common::language_for_file(&value.file).config_label(),
        range: render_source_range(analyzer, &value.file, &value.range, cache),
        kind: value.kind,
        selector_value_id: value.selector_value_id,
        selector_domain: value.selector_domain,
        case_count: value.case_count,
        has_true_case: value.has_true_case,
        has_false_case: value.has_false_case,
        default_present: value.default_present,
        verdict: value.verdict,
        proof: value.proof,
        reason: value.reason,
    }
}

pub(super) fn render_concurrent_access_conflict(
    analyzer: &dyn IAnalyzer,
    value: &concurrency::ConcurrentAccessConflictValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryConcurrentAccessConflict {
    use brokk_bifrost_flow::concurrency::{
        ConcurrencyOpenReason, ConcurrentAccessMode, ConcurrentOrdering, ConcurrentProtection,
        ConcurrentTaskRelation,
    };
    let access = |mode| match mode {
        ConcurrentAccessMode::Read => "read",
        ConcurrentAccessMode::Write => "write",
    };
    let relation = match value.conflict.task_relation {
        ConcurrentTaskRelation::ParentChild => "parent_child",
        ConcurrentTaskRelation::Siblings => "siblings",
        ConcurrentTaskRelation::Nested => "nested",
        ConcurrentTaskRelation::Repeated => "repeated",
    };
    let ordering = match value.conflict.ordering {
        ConcurrentOrdering::Unordered => "unordered",
        ConcurrentOrdering::HappensBefore => "happens_before",
        ConcurrentOrdering::Open => "open",
    };
    let protection = match value.conflict.protection {
        ConcurrentProtection::Unprotected => "unprotected",
        ConcurrentProtection::CompatibleLock => "compatible_lock",
        ConcurrentProtection::AtomicOnly => "atomic_only",
        ConcurrentProtection::Open => "open",
    };
    let reason = |reason: &ConcurrencyOpenReason| match reason {
        ConcurrencyOpenReason::UnresolvedTarget => "unresolved_target".to_owned(),
        ConcurrencyOpenReason::AmbiguousTarget => "ambiguous_target".to_owned(),
        ConcurrencyOpenReason::UnknownLocation => "unknown_location".to_owned(),
        ConcurrencyOpenReason::AliasSetTruncated => "alias_set_truncated".to_owned(),
        ConcurrencyOpenReason::UnknownOwnership => "unknown_ownership".to_owned(),
        ConcurrencyOpenReason::AmbiguousSynchronization => "ambiguous_synchronization".to_owned(),
        ConcurrencyOpenReason::UnsupportedSynchronization(protocol) => {
            format!("unsupported_synchronization:{protocol}")
        }
        ConcurrencyOpenReason::RecursiveExpansion => "recursive_expansion".to_owned(),
        ConcurrencyOpenReason::BudgetExhausted => "budget_exhausted".to_owned(),
    };
    CodeQueryConcurrentAccessConflict {
        id: value.id.clone(),
        root_procedure_id: value.root_procedure_id.clone(),
        ast_id: value.ast_id.clone(),
        path: rel_path_string(&value.file),
        language: crate::analyzer::common::language_for_file(&value.file).config_label(),
        range: render_source_range(analyzer, &value.file, &value.range, cache),
        location_id: value.conflict.location.identity.to_string(),
        location_kind: value.conflict.location.kind.to_string(),
        first_procedure_id: super::semantic::procedure_wire_id(&value.conflict.first.procedure),
        first_point_id: value.conflict.first.point.get(),
        first_access: access(value.conflict.first.mode),
        first_path: rel_path_string(&value.first_file),
        first_range: render_source_range(analyzer, &value.first_file, &value.first_range, cache),
        first_start_byte: value.first_range.start_byte,
        first_end_byte: value.first_range.end_byte,
        second_procedure_id: super::semantic::procedure_wire_id(&value.conflict.second.procedure),
        second_point_id: value.conflict.second.point.get(),
        second_access: access(value.conflict.second.mode),
        second_path: rel_path_string(&value.second_file),
        second_range: render_source_range(analyzer, &value.second_file, &value.second_range, cache),
        second_start_byte: value.second_range.start_byte,
        second_end_byte: value.second_range.end_byte,
        task_relation: relation,
        ordering,
        protection,
        verdict: if value.conflict.ordering == ConcurrentOrdering::HappensBefore {
            "ordered"
        } else if matches!(
            value.conflict.protection,
            ConcurrentProtection::CompatibleLock | ConcurrentProtection::AtomicOnly
        ) {
            "protected"
        } else {
            "conflict"
        },
        proof: if value.conflict.proven {
            "proven"
        } else {
            "open"
        },
        coverage: if value.conflict.exhaustive {
            "exhaustive"
        } else {
            "open"
        },
        reasons: value.conflict.reasons.iter().map(reason).collect(),
    }
}

pub(super) fn render_class_set_row(
    analyzer: &dyn IAnalyzer,
    value: &type_flow::ClassSetRowValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryClassSetRow {
    CodeQueryClassSetRow {
        id: value.id.clone(),
        file: rel_path_string(&value.file),
        range: render_source_range(analyzer, &value.file, &value.range, cache),
        member: value.member.clone(),
        class: value.class.clone(),
        origin: value.origin.clone(),
        status: value.status,
    }
}

pub(super) fn render_absent_member_finding(
    analyzer: &dyn IAnalyzer,
    value: &type_flow::AbsentMemberFindingValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryAbsentMemberFinding {
    CodeQueryAbsentMemberFinding {
        id: value.id.clone(),
        file: rel_path_string(&value.file),
        range: render_source_range(analyzer, &value.file, &value.range, cache),
        member: value.member.clone(),
        class: value.class.clone(),
        origin_file: rel_path_string(&value.origin_file),
        origin_range: render_source_range(analyzer, &value.origin_file, &value.origin_range, cache),
        caller: value.caller.clone(),
        witness_steps: value.witness_steps,
    }
}

pub(super) fn render_detached_task_transfer(
    analyzer: &dyn IAnalyzer,
    value: &effects::DetachedTaskTransferValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryDetachedTaskTransfer {
    CodeQueryDetachedTaskTransfer {
        id: value.id.clone(),
        procedure_id: value.procedure_id.clone(),
        call_id: value.call_id.clone(),
        call_point_id: value.call_point_id.clone(),
        ast_id: value.ast_id.clone(),
        path: rel_path_string(&value.file),
        language: crate::analyzer::common::language_for_file(&value.file).config_label(),
        range: render_source_range(analyzer, &value.file, &value.range, cache),
        role: value.role,
        ordinal: value.ordinal,
        value_id: value.value_id.clone(),
        object_id: value.object_id.clone(),
        object_cardinality: value.object_cardinality,
        timing: value.timing,
        proof: value.proof,
        coverage: value.coverage,
        reason: value.reason,
    }
}

pub(super) fn render_result_contract_failure_use(
    analyzer: &dyn IAnalyzer,
    value: &effects::ResultContractFailureUseValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryResultContractFailureUse {
    CodeQueryResultContractFailureUse {
        id: value.id.clone(),
        acquisition_id: value.acquisition_id.clone(),
        acquisition_site_id: value.acquisition_site_id.clone(),
        acquisition_site_ast_id: value.acquisition_site_ast_id.clone(),
        procedure_id: value.procedure_id.clone(),
        condition_result_ordinal: value.condition_result_ordinal,
        condition_value_id: value.condition_value_id,
        failure_edge_id: value.failure_edge_id.clone(),
        consumer_point_id: value.consumer_point_id.clone(),
        consumer_call_id: value.consumer_call_id.clone(),
        consumer_site_id: value.consumer_site_id.clone(),
        consumer_site_ast_id: value.consumer_site_ast_id.clone(),
        ast_id: value.ast_id.clone(),
        path: rel_path_string(&value.file),
        language: crate::analyzer::common::language_for_file(&value.file).config_label(),
        range: render_source_range(analyzer, &value.file, &value.range, cache),
        operand_value_id: value.operand_value_id,
        binding_value_id: value.binding_value_id,
        establishment_point_id: value.establishment_point_id.clone(),
        establishment_value_id: value.establishment_value_id,
        failure_provenance: value.provenance.label(),
        consumer: value.consumer.label(),
        argument_ordinal: value.argument_ordinal,
        proof: value.proof.label(),
        coverage: value.coverage.label(),
        pack_id: value.pack_id.clone(),
        model_id: value.model_id.clone(),
        summary_id: value.summary_id.clone(),
    }
}

pub(super) fn render_procedure_effect(
    analyzer: &dyn IAnalyzer,
    value: &effects::ProcedureEffectValue,
    cache: &mut PipelineRenderCache,
) -> CodeQueryProcedureEffect {
    let declaration = &value.subject.declaration;
    let row = value.row();
    CodeQueryProcedureEffect {
        id: row.id.clone(),
        procedure_id: row.procedure_declaration_id.clone(),
        procedure_name: row.procedure_name.clone(),
        path: rel_path_string(declaration.unit.source()),
        language: crate::analyzer::common::language_for_file(declaration.unit.source())
            .config_label(),
        range: render_source_range(
            analyzer,
            declaration.unit.source(),
            &declaration.range,
            cache,
        ),
        effect_id: row.effect_id.clone(),
        classification: row
            .classification
            .map(|classification| classification.label()),
        certainty: row.certainty.map(|certainty| certainty.label()),
        timing: row.timing.map(|timing| timing.label()),
        execution_timing: row.execution_timing.map(|timing| timing.label()),
        depth: row.depth,
        derivation: row.derivation.label(),
        reason: row.reason.map(|reason| reason.label()),
        coverage: row.coverage.label(),
        witness_available: !row.witness.is_empty(),
        witness_steps: row.witness.len(),
        witness_site_id: row.witness_site_id().map(str::to_owned),
        witness_effect_site_id: row.witness_effect_site_id().map(str::to_owned),
        witness_chain: row.witness_chain(),
        witness_truncated: row.witness_truncated,
        pack_id: row.pack_id.clone(),
        model_id: row.model_id.clone(),
        summary_id: row.summary_id.clone(),
        terminal: row.terminal,
    }
}

pub(super) fn render_callable_signature(
    analyzer: &dyn IAnalyzer,
    value: &CallableSignatureValue,
    detail: CodeQueryResultDetail,
    cache: &mut PipelineRenderCache,
) -> CodeQueryCallableSignature {
    let signature = &value.report.signature;
    let file = value.file();
    CodeQueryCallableSignature {
        id: signature.id.clone(),
        path: rel_path_string(file),
        language: crate::analyzer::common::language_for_file(file).config_label(),
        range: render_source_range(analyzer, file, &value.declaration.range, cache),
        declaration: render_declaration(analyzer, &value.declaration, detail, cache),
        ordinal: signature.ordinal,
        coverage: signature.coverage.label(),
        role: signature.role.label(),
        label: signature.label.clone(),
        required_arity: signature.arity.map(CallableArity::required),
        total_arity: signature.arity.map(CallableArity::total),
        repeated: signature.arity.is_some_and(CallableArity::is_repeated),
        generic_arity: signature.generic_arity,
        receiver_contract: signature.receiver_contract.map(|contract| contract.label()),
        return_type: signature.return_type.clone(),
        declaration_only: signature.declaration_only,
        parameter_count: signature.parameter_count,
    }
}

pub(super) fn render_signature_parameter(
    analyzer: &dyn IAnalyzer,
    value: &SignatureParameterValue,
    cache: &mut PipelineRenderCache,
) -> CodeQuerySignatureParameter {
    let parameter = value.row();
    let file = value.file();
    CodeQuerySignatureParameter {
        id: parameter.id.clone(),
        signature_id: parameter.signature_id.clone(),
        path: rel_path_string(file),
        range: render_source_range(analyzer, file, &value.signature.declaration.range, cache),
        parameter_index: parameter.parameter_index,
        label: parameter.label.clone(),
        declared_type: parameter.declared_type.clone(),
        optional: parameter.optional,
        repeated: parameter.repeated,
        label_start_byte: parameter.label_start_byte,
        label_end_byte: parameter.label_end_byte,
    }
}

pub(super) fn render_decorated_parameter(
    value: &decorator_binding::DecoratedParameterValue,
) -> CodeQueryDecoratedParameter {
    value.row.clone()
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
    let rendered_declaration = declaration.as_ref().map(|declaration| {
        render_declaration(analyzer, declaration, CodeQueryResultDetail::Full, cache)
    });
    let rendered_declaration_id = rendered_declaration
        .as_ref()
        .and_then(|declaration| declaration.id.clone());
    let model_id = rendered_declaration.as_ref().and_then(|declaration| {
        declaration
            .semantic_model
            .as_ref()
            .and_then(|_| declaration.id.clone())
    });
    let pack_id = rendered_declaration.as_ref().and_then(|declaration| {
        declaration
            .semantic_model
            .as_ref()
            .map(|provenance| provenance.pack_id.clone())
    });
    let factory_id = value.factory.as_ref().map(|factory| {
        let declaration = declaration_value_for_unit(analyzer, factory, fallback);
        declaration_id(
            &rel_path_string(declaration.unit.source()),
            declaration.identity_kind_label(),
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
        range: render_source_range(
            analyzer,
            &value.receiver.report.site.file,
            &value.receiver.report.site.range,
            cache,
        ),
        parent_evidence_id: value.parent_evidence_id.clone(),
        ordinal: value.ordinal,
        chain_hop: value.chain_hop,
        evidence_kind: receiver_evidence_kind(&value.value),
        declaration_id: rendered_declaration_id,
        declaration_fq_name: declaration.as_ref().map(|value| value.unit.fq_name()),
        declaration_kind: declaration.as_ref().map(DeclarationValue::kind_label),
        model_id,
        pack_id,
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

/// The value domain the `receiver_analysis.outcome` and
/// `receiver_outcome.outcome` row fields publish. Declared here because these
/// labels are minted by [`receiver_outcome_metadata`] rather than by a typed
/// vocabulary (issue #2515).
pub(super) const RECEIVER_OUTCOME_LABELS: &[&str] = &[
    "precise",
    "ambiguous",
    "unknown",
    "unsupported",
    "exceeded_budget",
];

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

/// The value domain the `expression_site.input_kind` row field publishes,
/// minted by [`expression_input_parts`] (issue #2515).
pub(super) const EXPRESSION_INPUT_KIND_LABELS: &[&str] = &["receiver", "parameter"];

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
    DeclarationValue::new(
        unit.clone(),
        analyzer
            .ranges_of(unit)
            .into_iter()
            .min_by_key(primary_range_key)
            .unwrap_or(fallback),
    )
}

/// The value domain the `call_site.call_kind` row field publishes. This is the
/// usage-seam call syntax vocabulary, which is deliberately not the
/// `call_shape.call_kind` one (issue #2515).
pub(super) const CALL_SYNTAX_KIND_LABELS: &[&str] = &["function", "method", "constructor", "super"];

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
    provider: &dyn super::StructuralFactProvider,
    feature: QueryFeature,
) -> bool {
    match feature {
        QueryFeature::Kind(kind) => provider.structural_supports_kind(kind),
        QueryFeature::Role(role) => provider.structural_supports_role(role),
        QueryFeature::BooleanLiteralValue => provider.structural_supports_boolean_literal_value(),
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

/// Report the live work counters for a limit diagnostic that cannot restate
/// them.
///
/// The counters depend on worker scheduling and cache state at the moment the
/// limit tripped, so two executions of one query over an unchanged workspace
/// disagree (#2897: 5178 facts on one run, 4927 on the next). A diagnostic
/// message is snapshot, diffed, and documented, so it must carry only stable
/// facts. `CodeQueryExecutionWork` on `DetailedCodeQueryResult` remains the
/// machine-readable form of the same numbers; this note is the run-dependent
/// view a profiling session asks for.
fn note_budget_work(code: CodeQueryDiagnosticCode, budget: &CodeQueryExecutionBudget) {
    crate::profiling::note_with(|| {
        format!(
            "query_code.{} scanned_files={} scanned_source_bytes={} fact_nodes={} pipeline_rows={} examined_references={} provenance_steps={}",
            code.as_str(),
            budget.scanned_files,
            budget.scanned_source_bytes,
            budget.fact_nodes,
            budget.pipeline_rows,
            budget.examined_references,
            budget.provenance_steps
        )
    });
}

/// Whether this execution already named `code` for the branch being collected.
///
/// Budget walls are detected per file, per row, or per relation scan, so one
/// execution can reach the same wall many times. The counters used to make
/// each report look different; without them the repeats are the same sentence,
/// and how many arrive depends on scheduling, so one report per code per
/// branch is both the readable and the reproducible answer.
fn already_reported(diagnostics: &[CodeQueryDiagnostic], code: CodeQueryDiagnosticCode) -> bool {
    diagnostics
        .iter()
        .any(|diagnostic| diagnostic.branch.is_empty() && diagnostic.code == code)
}

pub(super) fn push_budget_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
) {
    note_budget_work(CodeQueryDiagnosticCode::ExecutionBudgetExhausted, budget);
    if already_reported(
        diagnostics,
        CodeQueryDiagnosticCode::ExecutionBudgetExhausted,
    ) {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::ExecutionBudgetExhausted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: "query_code execution budget exhausted before the query finished; refine the query with where, languages, kind/name anchors, or a narrower pattern".to_string(),
    });
}

pub(super) fn push_pipeline_budget_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
) {
    note_budget_work(CodeQueryDiagnosticCode::PipelineBudgetExhausted, budget);
    if already_reported(
        diagnostics,
        CodeQueryDiagnosticCode::PipelineBudgetExhausted,
    ) {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::PipelineBudgetExhausted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: "query_code pipeline budget exhausted while producing seed and edge rows; refine the match, where, or languages filters".to_string(),
    });
}

pub(super) fn push_import_graph_budget_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    graph: &RequestLocalDirectImportGraph,
) {
    crate::profiling::note_with(|| {
        format!(
            "query_code.{} resolved_files={} resolved_edges={}",
            CodeQueryDiagnosticCode::ImportGraphBudgetExhausted.as_str(),
            graph.resolved_files(),
            graph.resolved_edges()
        )
    });
    if already_reported(
        diagnostics,
        CodeQueryDiagnosticCode::ImportGraphBudgetExhausted,
    ) {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::ImportGraphBudgetExhausted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: "query_code import graph budget exhausted while resolving files and direct edges; import traversal results are partial".to_string(),
    });
}

pub(super) fn push_truncation_diagnostic(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    budget: &CodeQueryExecutionBudget,
    limit: usize,
) {
    note_budget_work(CodeQueryDiagnosticCode::ResultLimitReached, budget);
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::ResultLimitReached,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: "workspace",
        message: format!(
            "query_code reached the query limit of {limit} and returned the first {limit} results; results are ordered by project-relative path; refine the query with where, languages, exact names, or a narrower pattern"
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
    note_budget_work(CodeQueryDiagnosticCode::BroadQuery, budget);
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::BroadQuery,
        impact: CodeQueryDiagnosticImpact::Advisory,
        branch: Vec::new(),
        language: "workspace",
        message: "broad unanchored query_code query scanned the workspace without a source anchor; add where, languages, exact name predicates, or a more specific pattern to reduce work and output".to_string(),
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
