use super::*;

impl CodeQueryResult {
    pub fn structural_matches(&self) -> Vec<&CodeQueryMatch> {
        self.results
            .iter()
            .filter_map(|result| match &result.value {
                CodeQueryResultValue::StructuralMatch { value } => Some(value),
                CodeQueryResultValue::Declaration { .. }
                | CodeQueryResultValue::Procedure { .. }
                | CodeQueryResultValue::ProgramPoint { .. }
                | CodeQueryResultValue::ControlEdge { .. }
                | CodeQueryResultValue::TypestateFinding { .. }
                | CodeQueryResultValue::TypestateWitness { .. }
                | CodeQueryResultValue::FlowEndpoint { .. }
                | CodeQueryResultValue::FlowWitness { .. }
                | CodeQueryResultValue::TaintFinding { .. }
                | CodeQueryResultValue::File { .. }
                | CodeQueryResultValue::ReferenceSite { .. }
                | CodeQueryResultValue::CallSite { .. }
                | CodeQueryResultValue::ExpressionSite { .. }
                | CodeQueryResultValue::JsxAttributeValue { .. }
                | CodeQueryResultValue::ReceiverAnalysis { .. }
                | CodeQueryResultValue::ReceiverOutcome { .. }
                | CodeQueryResultValue::ReceiverEvidence { .. }
                | CodeQueryResultValue::CallShape { .. }
                | CodeQueryResultValue::CallArgumentGroup { .. }
                | CodeQueryResultValue::CallArgument { .. }
                | CodeQueryResultValue::CallBinding { .. }
                | CodeQueryResultValue::CallEffect { .. }
                | CodeQueryResultValue::ProcedureEffect { .. }
                | CodeQueryResultValue::CallableSignature { .. }
                | CodeQueryResultValue::SignatureParameter { .. }
                | CodeQueryResultValue::DecoratedParameter { .. }
                | CodeQueryResultValue::CallableApplicability { .. }
                | CodeQueryResultValue::OverloadSelection { .. }
                | CodeQueryResultValue::MemberSelection { .. }
                | CodeQueryResultValue::DispatchOutcome { .. }
                | CodeQueryResultValue::DispatchTarget { .. }
                | CodeQueryResultValue::MemberFamily { .. }
                | CodeQueryResultValue::MemberFamilyEdge { .. }
                | CodeQueryResultValue::Occurrence { .. }
                | CodeQueryResultValue::LexicalScope { .. }
                | CodeQueryResultValue::Binding { .. }
                | CodeQueryResultValue::ResolutionCandidate { .. }
                | CodeQueryResultValue::CandidateHop { .. }
                | CodeQueryResultValue::GenerationSite { .. }
                | CodeQueryResultValue::Export { .. }
                | CodeQueryResultValue::DeclarationState { .. }
                | CodeQueryResultValue::ReferenceEdge { .. } => None,
                CodeQueryResultValue::QualifiedPath { .. }
                | CodeQueryResultValue::PathSegment { .. }
                | CodeQueryResultValue::StateEvent { .. }
                | CodeQueryResultValue::FlowRelation { .. }
                | CodeQueryResultValue::ControlRelation { .. }
                | CodeQueryResultValue::Guard { .. }
                | CodeQueryResultValue::SourceSet { .. }
                | CodeQueryResultValue::BuildTarget { .. }
                | CodeQueryResultValue::TopologyEdge { .. }
                | CodeQueryResultValue::RewritePath { .. } => None,
            })
            .collect()
    }

    pub fn result_count_line(&self) -> String {
        format!(
            "{} result{}{}",
            self.results.len(),
            if self.results.len() == 1 { "" } else { "s" },
            if self.truncated {
                " (truncated; refine the query or raise limit)"
            } else {
                ""
            },
        )
    }

    /// Human/agent-readable rendering following SearchTools conventions:
    /// structured JSON stays canonical, this is the display form.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        if self.results.is_empty() {
            out.push_str("No query results.\n");
        } else {
            out.push_str(&format!("{}\n", self.result_count_line()));
            for result in &self.results {
                out.push('\n');
                match &result.value {
                    CodeQueryResultValue::StructuralMatch { value: m } => {
                        let lines = m.line_span_label();
                        out.push_str(&format!("{}:{} [{}] `{}`", m.path, lines, m.kind, m.text));
                        if let Some(enclosing) = &m.enclosing_symbol {
                            out.push_str(&format!(" in {enclosing}"));
                        }
                        out.push('\n');
                        for capture in &m.captures {
                            out.push_str(&format!(
                                "  ${} = `{}` (line {})\n",
                                capture.name, capture.text, capture.start_line
                            ));
                        }
                    }
                    CodeQueryResultValue::Declaration { value } => {
                        let lines = line_span_label(value.start_line, value.end_line);
                        out.push_str(&format!(
                            "{}:{} [{}] {}",
                            value.path, lines, value.kind, value.fq_name
                        ));
                        if let Some(signature) = &value.signature {
                            out.push_str(&format!(" `{signature}`"));
                        }
                        out.push('\n');
                    }
                    CodeQueryResultValue::Procedure { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [procedure; {}; {}] {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.procedure_kind,
                            value.evidence.status_label(),
                            value.id,
                        ));
                    }
                    CodeQueryResultValue::ProgramPoint { value } => {
                        let boundary = CodeQueryProgramPointBoundary::row_label(value.boundary);
                        out.push_str(&format!(
                            "{}:{}:{} [program point; {}; {}; {} event{}] {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            boundary,
                            value.evidence.status_label(),
                            value.event_count,
                            if value.event_count == 1 { "" } else { "s" },
                            value.id,
                        ));
                    }
                    CodeQueryResultValue::ControlEdge { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [control edge; {}; {}] {} -> {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.edge_kind,
                            value.evidence.status_label(),
                            value.source.id,
                            value.target.id,
                        ));
                    }
                    CodeQueryResultValue::TypestateFinding { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [typestate finding; {}; {}] {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.certainty.label(),
                            value.finding_kind.presentation_label(),
                            value.id,
                        ));
                    }
                    CodeQueryResultValue::TypestateWitness { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [typestate witness; {} step{}{}] {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.steps.len(),
                            if value.steps.len() == 1 { "" } else { "s" },
                            if value.truncated { "; truncated" } else { "" },
                            value.id,
                        ));
                    }
                    CodeQueryResultValue::FlowEndpoint { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [flow endpoint; {:?}; {:?}; {:?}{}] {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.reachability,
                            value.certainty,
                            value.completion,
                            if value.ambiguous { "; ambiguous" } else { "" },
                            value.id,
                        ));
                    }
                    CodeQueryResultValue::FlowWitness { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [flow witness; {} step{}{}] {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.steps.len(),
                            if value.steps.len() == 1 { "" } else { "s" },
                            if value.truncated { "; truncated" } else { "" },
                            value.id,
                        ));
                    }
                    CodeQueryResultValue::TaintFinding { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [taint finding; {} label{}; {} origin{}; {} witness{}{}] {}\n",
                            value.sink.path,
                            value.sink.range.start_line,
                            value.sink.range.start_column,
                            value.reached_labels.len(),
                            if value.reached_labels.len() == 1 { "" } else { "s" },
                            value.origins.len(),
                            if value.origins.len() == 1 { "" } else { "s" },
                            value.witnesses.len(),
                            if value.witnesses.len() == 1 { "" } else { "es" },
                            if value.ambiguous { "; ambiguous" } else { "" },
                            value.id,
                        ));
                    }
                    CodeQueryResultValue::File { value } => {
                        out.push_str(&format!("{} [file; {}]\n", value.path, value.language));
                    }
                    CodeQueryResultValue::ReferenceSite { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [reference; {}; {}] -> {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.usage_kind,
                            value.proof,
                            value.target.fq_name
                        ));
                    }
                    CodeQueryResultValue::CallSite { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [call; {}; {}] {} -> {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.call_kind,
                            value.proof,
                            value.caller.fq_name,
                            value.callee.fq_name
                        ));
                    }
                    CodeQueryResultValue::ExpressionSite { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [call input; {}] `{}` -> {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.input_kind,
                            value.text,
                            value.callee_fq_name
                        ));
                    }
                    CodeQueryResultValue::JsxAttributeValue { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [jsx attribute value; {}; {}] `{}`\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.element_identity,
                            value.coverage,
                            value.text
                        ));
                    }
                    CodeQueryResultValue::ReceiverAnalysis { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [receiver analysis; {}; {}] `{}`\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.analysis_kind,
                            value.outcome,
                            value.text
                        ));
                        for detail in value.render_detail_lines() {
                            out.push_str(&format!("  {detail}\n"));
                        }
                    }
                    CodeQueryResultValue::ReceiverOutcome { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [receiver outcome; {}; {}; {}] candidates={}; site={}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.analysis_kind,
                            value.outcome,
                            value.coverage,
                            value.candidate_count,
                            value.site_id
                        ));
                    }
                    CodeQueryResultValue::ReceiverEvidence { value } => {
                        out.push_str(&format!(
                            "[receiver evidence; {}; {}; {}] site={} id={}\n",
                            value.evidence_kind,
                            value.proof,
                            value.completeness,
                            value.site_id,
                            value.id
                        ));
                    }
                    CodeQueryResultValue::DispatchOutcome { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [dispatch outcome; {}; {}] calls={}; targets={}{}; site={}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.outcome,
                            value.coverage,
                            value.call_site_count,
                            value.target_count,
                            if value.targets_truncated {
                                " (truncated)"
                            } else {
                                ""
                            },
                            value.site_id
                        ));
                    }
                    CodeQueryResultValue::DispatchTarget { value } => {
                        out.push_str(&format!(
                            "[dispatch target {}; {}; {}; {}; {}] {} -> {}; site={}\n",
                            value.ordinal,
                            value.dispatch,
                            value.proof,
                            value.completeness,
                            value.coverage,
                            value.boundary_kind.unwrap_or("candidate"),
                            value
                                .target_declaration
                                .as_ref()
                                .map_or(value.target_path.as_str(), |unit| unit.fq_name.as_str()),
                            value.site_id
                        ));
                    }
                    CodeQueryResultValue::MemberFamily { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [member family; {}; {}] {}overrides={}; implements={}; overridden_by={}; implemented_by={}{}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.outcome,
                            value.coverage,
                            value
                                .reason
                                .map(|reason| format!("{reason}; "))
                                .unwrap_or_default(),
                            value.overrides_count,
                            value.implements_count,
                            value.overridden_by_count,
                            value.implemented_by_count,
                            value
                                .family_id
                                .as_deref()
                                .map(|id| format!("; family={id}"))
                                .unwrap_or_default(),
                        ));
                    }
                    CodeQueryResultValue::MemberFamilyEdge { value } => {
                        out.push_str(&format!(
                            "[family edge {}; {}; {}; {}] {} -> {}; depth={}\n",
                            value.ordinal,
                            value.relation,
                            value.proof,
                            value.coverage,
                            value
                                .source
                                .as_ref()
                                .map_or(value.path.as_str(), |unit| unit.fq_name.as_str()),
                            value
                                .target
                                .as_ref()
                                .map_or(value.target_id.as_str(), |unit| unit.fq_name.as_str()),
                            value.hierarchy_depth,
                        ));
                    }
                    CodeQueryResultValue::CallShape { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [call shape; {}; {}] groups={}; site={}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.call_kind,
                            value.coverage,
                            value.group_count,
                            value.site_id
                        ));
                    }
                    CodeQueryResultValue::CallArgumentGroup { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [argument group {}; {}] arguments={}; site={}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.group_index,
                            value.kind,
                            value.argument_count,
                            value.site_id
                        ));
                    }
                    CodeQueryResultValue::CallArgument { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [argument {}{}{}] group={}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.argument_index,
                            value
                                .name
                                .as_deref()
                                .map(|name| format!("; name={name}"))
                                .unwrap_or_default(),
                            if value.spread { "; spread" } else { "" },
                            value.group_id
                        ));
                    }
                    CodeQueryResultValue::CallBinding { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [call binding; {}; {}] {} -> {}; site={}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.binding_kind.unwrap_or("terminal"),
                            value.mapping,
                            value
                                .actual_name
                                .as_deref()
                                .map(|name| format!("actual `{name}`"))
                                .unwrap_or_else(|| value.actual_index.map_or_else(
                                    || "no actual".to_string(),
                                    |index| format!("actual {index}")
                                )),
                            value
                                .formal_name
                                .as_deref()
                                .map(|name| format!("formal `{name}`"))
                                .unwrap_or_else(|| value.formal_index.map_or_else(
                                    || format!(
                                        "no formal ({})",
                                        value.reason.unwrap_or(value.coverage)
                                    ),
                                    |index| format!("formal {index}")
                                )),
                            value.site_id,
                        ));
                    }
                    CodeQueryResultValue::CallEffect { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [call effect; {}; {}] {}{}; site={}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.derivation,
                            value.coverage,
                            value.effect_id.as_deref().unwrap_or("no declared effect"),
                            value
                                .certainty
                                .map(|certainty| format!(
                                    " ({certainty}, {})",
                                    value.timing.unwrap_or("unknown")
                                ))
                                .unwrap_or_else(|| value
                                    .reason
                                    .map(|reason| format!(" ({reason})"))
                                    .unwrap_or_default()),
                            value.site_id,
                        ));
                    }
                    CodeQueryResultValue::ProcedureEffect { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [procedure effect; {}; {}] {} {}{}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.derivation,
                            value.coverage,
                            value.procedure_name,
                            value.effect_id.as_deref().unwrap_or("no declared effect"),
                            value
                                .witness_chain
                                .as_deref()
                                .map(|chain| format!("; witness={chain}"))
                                .unwrap_or_default(),
                        ));
                    }
                    CodeQueryResultValue::CallableSignature { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [callable signature {}; {}; {}] {} arity={} generics={}{}{}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.ordinal,
                            value.role,
                            value.coverage,
                            value.declaration.fq_name,
                            arity_label(value),
                            value.generic_arity,
                            value
                                .receiver_contract
                                .map(|contract| format!("; receiver={contract}"))
                                .unwrap_or_default(),
                            value
                                .return_type
                                .as_deref()
                                .map(|return_type| format!("; returns={return_type}"))
                                .unwrap_or_default(),
                        ));
                    }
                    CodeQueryResultValue::SignatureParameter { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [parameter {}] `{}`{}{}{}; signature={}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.parameter_index,
                            value.label,
                            value
                                .declared_type
                                .as_deref()
                                .map(|declared| format!("; type={declared}"))
                                .unwrap_or_default(),
                            match value.optional {
                                Some(true) => "; optional",
                                Some(false) => "",
                                None => "; optionality unrecorded",
                            },
                            if value.repeated == Some(true) {
                                "; repeated"
                            } else {
                                ""
                            },
                            value.signature_id
                        ));
                    }
                    CodeQueryResultValue::DecoratedParameter { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [decorated parameter; {}; {}; {}] `{}` ordinal={}{}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.binding_status,
                            value.boundary,
                            value.completion,
                            value.decorator_name,
                            value.parameter_ordinal.map_or_else(
                                || "unknown".to_string(),
                                |ordinal| ordinal.to_string()
                            ),
                            value
                                .module
                                .as_deref()
                                .map(|module| format!("; module={module}"))
                                .unwrap_or_default(),
                        ));
                    }
                    CodeQueryResultValue::OverloadSelection { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [overload selection; {}] considered={} applicable={} inapplicable={} unknown={} site_ast={}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.resolution,
                            value.considered_count,
                            value.applicable_count,
                            value.inapplicable_count,
                            value.unknown_count,
                            value.site_ast_id
                        ));
                    }
                    CodeQueryResultValue::CallableApplicability { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [callable applicability {}; {}]{}{}{} site_ast={}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.ordinal,
                            value.verdict,
                            value
                                .reason
                                .map(|reason| format!("; {reason}"))
                                .unwrap_or_default(),
                            value
                                .tier
                                .map(|tier| format!("; tier {tier}"))
                                .unwrap_or_default(),
                            if value.selected { "; selected" } else { "" },
                            value.site_ast_id
                        ));
                    }
                    CodeQueryResultValue::MemberSelection { value } => {
                        out.push_str(&format!(
                            "[member selection; {}; {}; {}] `{}` selected={} candidates={} site_ast={}\n",
                            value.outcome,
                            value.trace_completeness,
                            value.coverage,
                            value.member,
                            value.selected_count,
                            value.candidate_count,
                            value.site_ast_id
                        ));
                    }
                    CodeQueryResultValue::Occurrence { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [occurrence; {}; {}; {}] `{}`",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.class,
                            value.role,
                            value.namespace,
                            value.raw_spelling
                        ));
                        if let Some(decoded) = &value.decoded_spelling {
                            out.push_str(&format!(" (decodes to `{decoded}`)"));
                        }
                        if let Some(enclosing) = &value.enclosing_symbol {
                            out.push_str(&format!(" in {enclosing}"));
                        }
                        out.push('\n');
                        for line in value.target.render_detail_lines() {
                            out.push_str(&format!("  {line}\n"));
                        }
                    }
                    CodeQueryResultValue::LexicalScope { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [lexical_scope #{}; {}]\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.index,
                            value.kind.unwrap_or("file"),
                        ));
                        if let Some(parent) = value.parent_index {
                            out.push_str(&format!("  inside scope #{parent}\n"));
                        }
                    }
                    CodeQueryResultValue::Binding { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [binding; {}; {}] `{}`{}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.kind,
                            value.hoisting,
                            value.name,
                            if value.shadowed { " (shadowed)" } else { "" },
                        ));
                        out.push_str(&format!(
                            "  declared in scope #{}, active over bytes {}..{}\n",
                            value.declaring_scope_index,
                            value.activation_start_byte,
                            value.activation_end_byte
                        ));
                        if let Some(import) = &value.import {
                            out.push_str(&format!(
                                "  import {} -> {}{}\n",
                                import.local_name,
                                if import.target_segments.is_empty() {
                                    "<target not recorded by this adapter>".to_string()
                                } else {
                                    import.target_segments.join(".")
                                },
                                if import.wildcard { " (wildcard)" } else { "" }
                            ));
                        }
                    }
                    CodeQueryResultValue::GenerationSite { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [generation_site {}; {}] generates {} declaration(s)\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.kind,
                            value.input,
                            value.generated_count,
                        ));
                        for generated in &value.generated {
                            out.push_str(&format!(
                                "  -> {} (named at line {})\n",
                                generated.fq_name, generated.argument_range.start_line
                            ));
                        }
                    }
                    CodeQueryResultValue::Export { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [export {}] {}",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.form,
                            value.exported_name,
                        ));
                        if let Some(target) = &value.target_fq_name {
                            out.push_str(&format!(" -> {target}"));
                        }
                        out.push('\n');
                    }
                    CodeQueryResultValue::DeclarationState { value } => {
                        out.push_str(&format!(
                            "{} [declaration_state {}] {} ({})",
                            value.path, value.origin, value.fq_name, value.unit_kind,
                        ));
                        if value.declaration_only {
                            out.push_str(" declaration-only");
                        }
                        if value.config_gated {
                            out.push_str(" config-gated");
                        }
                        out.push('\n');
                    }
                    CodeQueryResultValue::ResolutionCandidate { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [resolution_candidate; {}; {}] {} `{}`\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.tier.unwrap_or("unattributed"),
                            value.outcome,
                            value.candidate.label(),
                            value.candidate.name(),
                        ));
                        if let Some(reason) = value.rejection_reason {
                            out.push_str(&format!("  rejected: {reason}\n"));
                        }
                        out.push_str(&format!(
                            "  boundary {}, trace {}\n",
                            value.boundary, value.trace_completeness
                        ));
                        if let (Some(owner), Some(depth), Some(tier), Some(applicability)) = (
                            value.owner.as_ref(),
                            value.hierarchy_depth,
                            value.dispatch_tier,
                            value.applicability,
                        ) {
                            out.push_str(&format!(
                                "  owner {} at depth {depth}, tier {tier}, {applicability}\n",
                                owner.fq_name,
                            ));
                        }
                    }
                    CodeQueryResultValue::CandidateHop { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [candidate_hop] hop {}: {} -> {} ({})\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.hop,
                            value
                                .from
                                .as_ref()
                                .map(|unit| unit.fq_name.as_str())
                                .unwrap_or("<unlocatable>"),
                            value
                                .to
                                .as_ref()
                                .map(|unit| unit.fq_name.as_str())
                                .unwrap_or("<unlocatable>"),
                            value.relation,
                        ));
                        out.push_str(&format!("  candidate {}\n", value.candidate_id));
                    }
                    CodeQueryResultValue::ReferenceEdge { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [reference_edge; {}; {}; {}] -> {} [{}]\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.provenance,
                            value.proof,
                            value.usage_kind,
                            value.target.fq_name,
                            value.target.kind,
                        ));
                        out.push_str(&format!(
                            "  kind {}, site {}, relation {}, generation {}\n",
                            value.reference_kind.unwrap_or("unclassified"),
                            value.site_class,
                            value.owner_relation,
                            value.generation,
                        ));
                    }
                    CodeQueryResultValue::StateEvent { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [state_event; {}; {}{}]\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.event_class,
                            value.subject,
                            match &value.member {
                                Some(member) => format!(".{member}"),
                                None => String::new(),
                            },
                        ));
                        out.push_str(&format!(
                            "  point {}, value {}, {}, generation {}\n",
                            value.program_point, value.value, value.completeness, value.generation,
                        ));
                        if !value.uncovered_axes.is_empty() {
                            out.push_str(&format!(
                                "  uncovered axes: {}\n",
                                value.uncovered_axes.join(", ")
                            ));
                        }
                    }
                    CodeQueryResultValue::FlowRelation { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [flow_relation; {}; {}] {} -> {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.relation,
                            value.certainty,
                            value.source.event_class,
                            value.target.event_class,
                        ));
                        out.push_str(&format!(
                            "  source {}:{} point {}, target {}:{} point {}\n",
                            value.source.path,
                            value.source.range.start_line,
                            value.source.program_point,
                            value.target.path,
                            value.target.range.start_line,
                            value.target.program_point,
                        ));
                        out.push_str(&format!(
                            "  {}, generation {}\n",
                            value.completeness, value.generation
                        ));
                        if !value.uncovered_axes.is_empty() {
                            out.push_str(&format!(
                                "  uncovered axes: {}\n",
                                value.uncovered_axes.join(", ")
                            ));
                        }
                    }
                    CodeQueryResultValue::ControlRelation { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [control_relation; {}; {}; {}] {} -> {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.relation,
                            value.certainty,
                            value.exit_partition,
                            value.source.range.start_line,
                            value.target.range.start_line,
                        ));
                        if let Some(edge) = &value.controlling_edge_id {
                            out.push_str(&format!("  controlling edge {edge}\n"));
                        }
                        out.push_str(&format!(
                            "  {}, generation {}\n",
                            value.completeness, value.generation
                        ));
                        if !value.uncovered_relations.is_empty() {
                            out.push_str(&format!(
                                "  uncovered relations: {}\n",
                                value.uncovered_relations.join(", ")
                            ));
                        }
                    }
                    CodeQueryResultValue::Guard { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [guard; {}] point {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.predicate,
                            value.point.range.start_line,
                        ));
                        if let Some(constant) = value.constant {
                            out.push_str(&format!("  constant {constant}\n"));
                        }
                        // Naming the absent arm is the point of the row: after
                        // a constant fold, this is the only place the branch
                        // that cannot execute is still visible.
                        for (label, edge) in [
                            ("true", &value.true_edge_id),
                            ("false", &value.false_edge_id),
                        ] {
                            match edge {
                                Some(edge) => {
                                    out.push_str(&format!("  {label} edge {edge}\n"));
                                }
                                None => out.push_str(&format!("  no {label} edge\n")),
                            }
                        }
                        out.push_str(&format!("  {}, {}\n", value.proof, value.completeness));
                    }
                    CodeQueryResultValue::SourceSet { value } => {
                        out.push_str(&format!(
                            "{} [source_set; {}] {}\n",
                            value.build_file, value.completeness, value.name,
                        ));
                        if let Some(target) = &value.target_id {
                            out.push_str(&format!("  target {target}\n"));
                        }
                    }
                    CodeQueryResultValue::BuildTarget { value } => {
                        out.push_str(&format!(
                            "{} [build_target; {}] {}\n",
                            value.build_file, value.completeness, value.name,
                        ));
                        if let Some(project) = &value.build_project_id {
                            out.push_str(&format!("  build project {project}\n"));
                        }
                    }
                    CodeQueryResultValue::TopologyEdge { value } => {
                        out.push_str(&format!(
                            "{} [topology_edge; {}; {}] {} -> {}\n",
                            value.build_file,
                            value.scope,
                            value.completeness,
                            value.from_name,
                            value.to_name,
                        ));
                    }
                    CodeQueryResultValue::RewritePath { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [rewrite_path; {}; {}] {}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.domain,
                            value.outcome,
                            value.origin_specifier,
                        ));
                        out.push_str(&format!(
                            "  {} of {} steps, generation {}\n",
                            value.step_count, value.declared_bound, value.generation,
                        ));
                        for step in &value.steps {
                            out.push_str(&format!(
                                "  [{}] {} -> {} ({})\n",
                                step.state_key, step.input, step.output, step.rule,
                            ));
                        }
                        if let Some(fixed_point) = &value.fixed_point {
                            out.push_str(&format!("  fixed point: {fixed_point}\n"));
                        }
                        if !value.witness.is_empty() {
                            out.push_str(&format!(
                                "  cycle witness: {}\n",
                                value.witness.join(" -> ")
                            ));
                        }
                        if let Some(explored) = value.explored {
                            out.push_str(&format!(
                                "  explored {explored} steps before the bound\n"
                            ));
                        }
                        if !value.uncovered_domains.is_empty() {
                            out.push_str(&format!(
                                "  uncovered domains: {}\n",
                                value.uncovered_domains.join(", ")
                            ));
                        }
                    }
                    CodeQueryResultValue::QualifiedPath { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [qualified_path; {} segments]\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.segment_count,
                        ));
                    }
                    CodeQueryResultValue::PathSegment { value } => {
                        out.push_str(&format!(
                            "{}:{}:{} [path_segment #{}] `{}`{}\n",
                            value.path,
                            value.range.start_line,
                            value.range.start_column,
                            value.ordinal,
                            value.text,
                            match value.generic_arity {
                                Some(arity) => format!(" <{arity} generic args>"),
                                None => String::new(),
                            },
                        ));
                        if let Some(namespace) = value.namespace {
                            out.push_str(&format!("  namespace {namespace}\n"));
                        }
                        if let Some(status) = value.resolution_status {
                            out.push_str(&format!(
                                "  resolves: {status}{}\n",
                                match value.target_count {
                                    Some(count) if count > 0 => format!(" ({count} target(s))"),
                                    _ => String::new(),
                                }
                            ));
                        }
                    }
                }
                if let Some(summary) = result.provenance_summary() {
                    out.push_str(&format!("  {summary}\n"));
                }
            }
        }
        for diagnostic in &self.diagnostics {
            out.push_str(&format!(
                "{}: {}\n",
                diagnostic.presentation_label(),
                diagnostic.message
            ));
        }
        out
    }
}

impl CodeQueryOccurrenceTarget {
    /// Human-readable detail lines; an empty vector for `none` so a
    /// non-reference row renders as one line.
    pub fn render_detail_lines(&self) -> Vec<String> {
        match self {
            Self::None => Vec::new(),
            Self::Resolved { units } => units
                .iter()
                .map(|unit| format!("-> {} [{}] {}", unit.fq_name, unit.kind, unit.path))
                .collect(),
            Self::Lexical { name, kind, range } => vec![format!(
                "-> lexical binder `{name}` [{kind}] at line {}",
                range.start_line
            )],
            Self::Unresolved { status } => vec![format!("-> unresolved ({status})")],
            Self::NotDerived => vec!["-> target not derived (not requested)".to_string()],
        }
    }
}

impl CodeQueryMatch {
    pub fn line_span_label(&self) -> String {
        if self.start_line == self.end_line {
            self.start_line.to_string()
        } else {
            format!("{}-{}", self.start_line, self.end_line)
        }
    }
}

fn line_span_label(start_line: usize, end_line: usize) -> String {
    if start_line == end_line {
        start_line.to_string()
    } else {
        format!("{start_line}-{end_line}")
    }
}

/// The arity a signature row states, rendered as a range when defaults make
/// one, with a trailing `+` for a repeating trailing parameter. An arity the
/// language never recorded renders as `unrecorded` rather than as `0`.
fn arity_label(value: &CodeQueryCallableSignature) -> String {
    let (Some(required), Some(total)) = (value.required_arity, value.total_arity) else {
        return "unrecorded".to_owned();
    };
    let range = if required == total {
        total.to_string()
    } else {
        format!("{required}..{total}")
    };
    if value.repeated {
        format!("{range}+")
    } else {
        range
    }
}
