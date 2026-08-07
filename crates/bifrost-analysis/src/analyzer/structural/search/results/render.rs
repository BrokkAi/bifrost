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
                | CodeQueryResultValue::ReceiverAnalysis { .. }
                | CodeQueryResultValue::ReceiverOutcome { .. }
                | CodeQueryResultValue::ReceiverEvidence { .. }
                | CodeQueryResultValue::CallShape { .. }
                | CodeQueryResultValue::CallArgumentGroup { .. }
                | CodeQueryResultValue::CallArgument { .. }
                | CodeQueryResultValue::MemberSelection { .. }
                | CodeQueryResultValue::DispatchOutcome { .. }
                | CodeQueryResultValue::DispatchTarget { .. }
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
                | CodeQueryResultValue::PathSegment { .. } => None,
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
                        let boundary = value
                            .boundary
                            .map_or("interior", CodeQueryProgramPointBoundary::label);
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
