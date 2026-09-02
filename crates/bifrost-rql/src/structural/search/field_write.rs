use super::*;

pub(super) fn field_write_value_expansions(
    analysis: &ReceiverAnalysisValue,
    filter: &FieldWriteValueTraversal,
    traces: &[PipelineTrace],
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let ReceiverQueryAnalysis::MemberTargets(outcome) = &analysis.report.analysis else {
        unreachable!("field_write_value accepts only member-target analyses");
    };
    let [target] = outcome.values().unwrap_or_default() else {
        push_incomplete(
            diagnostics,
            analysis.report.site.language,
            "field_write_value requires one precise static member target",
        );
        return Vec::new();
    };
    if !outcome.is_precise()
        || analysis.report.candidates_truncated
        || analysis.report.semantic_unsupported.is_some()
    {
        push_incomplete(
            diagnostics,
            analysis.report.site.language,
            "field_write_value member-target coverage is incomplete",
        );
        return Vec::new();
    }
    if target.receiver_identity_id().is_none() {
        push_incomplete(
            diagnostics,
            analysis.report.site.language,
            "field_write_value member target has no exact receiver identity",
        );
        return Vec::new();
    }
    if filter
        .receiver_identity_id
        .as_deref()
        .is_some_and(|wanted| target.receiver_identity_id().as_deref() != Some(wanted))
        || filter
            .member_target_id
            .as_deref()
            .is_some_and(|wanted| target.member_identity_id() != wanted)
    {
        return Vec::new();
    }
    let Some(member_range) = analysis.report.member_range else {
        push_incomplete(
            diagnostics,
            analysis.report.site.language,
            "field_write_value member target has no exact member range",
        );
        return Vec::new();
    };

    traces
        .iter()
        .filter_map(|trace| project_trace(&trace.seed, analysis, target, member_range, diagnostics))
        .map(|value| pipeline_expansion(PipelineValue::FieldWriteValue(Box::new(value))))
        .collect()
}

fn project_trace(
    seed: &Arc<SeedMatch>,
    analysis: &ReceiverAnalysisValue,
    target: &ReceiverMemberTarget,
    member_range: Range,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Option<FieldWriteValue> {
    let facts = &seed.facts;
    let assignment_node = seed.fact_match.node;
    if facts.node(assignment_node).kind != NormalizedKind::Assignment {
        push_incomplete(
            diagnostics,
            seed.language,
            "field_write_value requires an assignment structural match",
        );
        return None;
    }

    let operators = facts
        .role_targets(assignment_node, Role::Operator)
        .collect::<Vec<_>>();
    if !matches!(operators.as_slice(), [operator] if operator.span.text(facts.source()) == "=") {
        push_incomplete(
            diagnostics,
            seed.language,
            "field_write_value supports only a simple assignment operator",
        );
        return None;
    }

    let Some(left_node) = exactly_one_node(facts, assignment_node, Role::Left) else {
        push_incomplete(
            diagnostics,
            seed.language,
            "field_write_value assignment has no unique normalized left operand",
        );
        return None;
    };
    if facts.node(left_node).kind != NormalizedKind::FieldAccess {
        push_incomplete(
            diagnostics,
            seed.language,
            "field_write_value left operand is not a static field access",
        );
        return None;
    }
    let Some(receiver_node) = exactly_one_node(facts, left_node, Role::Object) else {
        push_incomplete(
            diagnostics,
            seed.language,
            "field_write_value field access has no unique normalized receiver",
        );
        return None;
    };
    let Some(member_node) = exactly_one_node(facts, left_node, Role::Field) else {
        push_incomplete(
            diagnostics,
            seed.language,
            "field_write_value field access has no unique static member node",
        );
        return None;
    };
    let Some(rhs_node) = exactly_one_node(facts, assignment_node, Role::Right) else {
        push_incomplete(
            diagnostics,
            seed.language,
            "field_write_value assignment has no unique normalized right operand",
        );
        return None;
    };

    if !same_byte_range(
        &facts.node(receiver_node).range,
        &analysis.report.site.range,
    ) {
        push_incomplete(
            diagnostics,
            seed.language,
            "field_write_value receiver node differs from the analyzed receiver site",
        );
        return None;
    }
    if !same_byte_range(&facts.node(member_node).range, &member_range) {
        push_incomplete(
            diagnostics,
            seed.language,
            "field_write_value member node differs from the resolved member site",
        );
        return None;
    }
    let member_name = facts
        .role_targets(left_node, Role::Field)
        .next()
        .and_then(|field| field.name)
        .or(facts.node(member_node).name)
        .map(|span| span.text(facts.source()));
    if member_name != Some(target.member_name()) {
        push_incomplete(
            diagnostics,
            seed.language,
            "field_write_value member spelling differs from the resolved member identity",
        );
        return None;
    }

    Some(FieldWriteValue {
        seed: seed.clone(),
        analysis: analysis.clone(),
        target: target.clone(),
        assignment_node,
        left_node,
        receiver_node,
        member_node,
        rhs_node,
    })
}

fn same_byte_range(left: &Range, right: &Range) -> bool {
    left.start_byte == right.start_byte && left.end_byte == right.end_byte
}

fn exactly_one_node(facts: &FileFacts, source: u32, role: Role) -> Option<u32> {
    let mut nodes = facts
        .role_targets(source, role)
        .filter_map(|target| target.node);
    let node = nodes.next()?;
    nodes.next().is_none().then_some(node)
}

fn push_incomplete(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    language: Language,
    message: &'static str,
) {
    if diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::SemanticResultsOmitted
            && diagnostic.message == message
    }) {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: language.config_label(),
        message: message.to_string(),
    });
}
