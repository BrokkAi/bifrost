use super::*;

pub(super) fn direct_member_expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    mut children: Vec<CodeUnit>,
    indexed: &mut IndexedDeclarations,
    budget: &mut CodeQueryExecutionBudget,
    max_pipeline_rows: usize,
    omissions: &mut BTreeMap<(Language, &'static str), usize>,
) -> (Vec<PipelineExpansion>, bool) {
    children.sort();
    children.dedup();
    let mut expansions = Vec::new();
    let mut exhausted = false;
    for unit in children {
        if budget.pipeline_rows >= max_pipeline_rows {
            exhausted = true;
            break;
        }
        budget.pipeline_rows += 1;
        let Some(child) = indexed.get(analyzer, &unit) else {
            record_semantic_omission(
                omissions,
                &unit,
                "a direct member declaration had no exact indexed range",
            );
            exhausted = true;
            continue;
        };
        indexed.record_owner(&unit, &declaration.unit);
        expansions.push(budgeted_declaration_expansion(child));
    }
    (expansions, exhausted)
}

pub(super) fn reference_expansion(
    value: PipelineValue,
    site: ReferenceSiteValue,
) -> PipelineExpansion {
    let trace_value =
        pipeline_trace_value(&value).expect("reference steps produce a semantic value");
    PipelineExpansion {
        value,
        trace: vec![(trace_value, Some(PipelineVia::ReferenceSite(site)))],
        budgeted: false,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn call_site_expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    step: &QueryStep,
    filter: &CallSiteTraversalFilter,
    cache: &mut CallTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    max_outputs: usize,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    cache_profile: &mut Option<QueryCacheProfile>,
) -> (Vec<PipelineExpansion>, bool) {
    let incoming = matches!(step, QueryStep::CallSitesTo(_));
    let result = cached_call_relation(
        analyzer,
        &declaration.unit,
        incoming,
        cache,
        budget,
        limits,
        cancellation,
        diagnostics,
        cache_profile,
    );
    let mut sites = result
        .sites
        .into_iter()
        .filter(|site| filter.proof.is_none_or(|proof| proof == site.proof))
        .collect::<Vec<_>>();
    let truncated = result.truncated || result.cancelled || sites.len() > max_outputs;
    sites.truncate(max_outputs);
    let expansions = sites
        .into_iter()
        .map(|mut site| {
            let binding = bind_call_site_arguments(analyzer, &mut site, &mut cache.bindings);
            pipeline_expansion(PipelineValue::CallSite(CallSiteValue(site, binding)))
        })
        .collect();
    (expansions, truncated)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cached_call_relation(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    incoming: bool,
    cache: &mut CallTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    cache_profile: &mut Option<QueryCacheProfile>,
) -> CallRelationResult {
    let results = if incoming {
        &mut cache.incoming
    } else {
        &mut cache.outgoing
    };
    let layer = cache_profile.as_mut().map(|profile| {
        if incoming {
            &mut profile.incoming_call
        } else {
            &mut profile.outgoing_call
        }
    });
    let result = if let Some(result) = results.get(unit) {
        if let Some(layer) = layer {
            layer.record_hit(
                Some(call_relation_result_complete(result)),
                result.sites.len(),
            );
        }
        result.clone()
    } else {
        if let Some(layer) = layer {
            layer.record_miss();
        }
        let relation_limits = CallRelationLimits {
            max_files: limits
                .max_scanned_files
                .saturating_sub(budget.scanned_files)
                .min(DEFAULT_MAX_FILES),
            max_source_bytes: limits
                .max_scanned_source_bytes
                .saturating_sub(budget.scanned_source_bytes),
            max_candidates: limits
                .max_fact_nodes
                .saturating_sub(budget.fact_nodes.saturating_add(budget.examined_references)),
        };
        let result = if relation_limits.max_files == 0
            || relation_limits.max_source_bytes == 0
            || relation_limits.max_candidates == 0
        {
            push_budget_diagnostic(diagnostics, budget);
            CallRelationResult {
                truncated: true,
                ..CallRelationResult::default()
            }
        } else if incoming {
            CallRelationService::incoming_bounded(analyzer, unit, relation_limits, cancellation)
        } else {
            CallRelationService::outgoing_bounded(analyzer, unit, relation_limits, cancellation)
        };
        let budget_exhausted = charge_reference_scan(
            budget,
            limits,
            result.work.scanned_files,
            result.work.scanned_source_bytes,
            result.work.examined_candidates,
        );
        let mut result = result;
        result.truncated |= budget_exhausted;
        if budget_exhausted {
            push_budget_diagnostic(diagnostics, budget);
        }
        if let Some(profile) = cache_profile {
            let layer = if incoming {
                &mut profile.incoming_call
            } else {
                &mut profile.outgoing_call
            };
            layer.record_build(Some(call_relation_result_complete(&result)));
        }
        results.insert(unit.clone(), result.clone());
        result
    };
    let reported = if incoming {
        &mut cache.reported_incoming
    } else {
        &mut cache.reported_outgoing
    };
    if reported.insert(unit.clone()) {
        let language = crate::analyzer::common::language_for_file(unit.source()).config_label();
        diagnostics.extend(
            result
                .diagnostics
                .iter()
                .cloned()
                .map(|diagnostic| map_call_relation_diagnostic(language, diagnostic)),
        );
    }
    result
}

pub(super) fn call_relation_result_complete(result: &CallRelationResult) -> bool {
    !result.truncated
        && !result.cancelled
        && result.diagnostics.iter().all(|diagnostic| {
            map_call_relation_diagnostic_code(diagnostic.code).1
                != CodeQueryDiagnosticImpact::Incomplete
        })
}

pub(super) fn map_call_relation_diagnostic_code(
    code: CallRelationDiagnosticCode,
) -> (CodeQueryDiagnosticCode, CodeQueryDiagnosticImpact) {
    match code {
        CallRelationDiagnosticCode::BudgetExhausted => (
            CodeQueryDiagnosticCode::CallRelationBudgetExhausted,
            CodeQueryDiagnosticImpact::Incomplete,
        ),
        CallRelationDiagnosticCode::ParseFailed => (
            CodeQueryDiagnosticCode::CallRelationParseFailed,
            CodeQueryDiagnosticImpact::Incomplete,
        ),
        CallRelationDiagnosticCode::CandidatesOmitted => (
            CodeQueryDiagnosticCode::CallRelationCandidatesOmitted,
            CodeQueryDiagnosticImpact::Incomplete,
        ),
        CallRelationDiagnosticCode::TargetsAmbiguous => (
            CodeQueryDiagnosticCode::CallRelationTargetsAmbiguous,
            CodeQueryDiagnosticImpact::Advisory,
        ),
        CallRelationDiagnosticCode::CandidateLimit => (
            CodeQueryDiagnosticCode::CallRelationCandidateLimit,
            CodeQueryDiagnosticImpact::Incomplete,
        ),
        CallRelationDiagnosticCode::AnalysisFailed => (
            CodeQueryDiagnosticCode::CallRelationAnalysisFailed,
            CodeQueryDiagnosticImpact::Incomplete,
        ),
    }
}

pub(super) fn map_call_relation_diagnostic(
    language: &'static str,
    diagnostic: CallRelationDiagnostic,
) -> CodeQueryDiagnostic {
    debug_assert!(!diagnostic.context.is_empty());
    debug_assert_eq!(
        diagnostic.reason_kind.is_some(),
        diagnostic.code == CallRelationDiagnosticCode::AnalysisFailed
    );
    let (code, impact) = map_call_relation_diagnostic_code(diagnostic.code);
    CodeQueryDiagnostic {
        code,
        impact,
        branch: Vec::new(),
        language,
        message: diagnostic.message,
    }
}

pub(super) fn call_input_expansions(
    site: &CallSiteValue,
    selector: &CallInputSelector,
) -> (Vec<PipelineExpansion>, bool) {
    let formal_binding_required =
        !matches!(selector, CallInputSelector::Receiver) && !site.0.arguments.is_empty();
    if formal_binding_required && site.1 == CallBindingStatus::Unavailable {
        return (Vec::new(), true);
    }
    let expressions = match selector {
        CallInputSelector::Receiver => site
            .0
            .receiver
            .map(|range| ExpressionSiteValue {
                call_site: site.clone(),
                range,
                input: ExpressionInput::Receiver,
            })
            .into_iter()
            .collect::<Vec<_>>(),
        CallInputSelector::ParameterIndex(index) => site
            .0
            .arguments
            .iter()
            .filter(|argument| argument.formal_index == Some(*index))
            .map(|argument| ExpressionSiteValue {
                call_site: site.clone(),
                range: argument.range,
                input: ExpressionInput::Parameter {
                    index: *index,
                    name: argument.formal_name.clone(),
                },
            })
            .collect(),
        CallInputSelector::ParameterName(name) => site
            .0
            .arguments
            .iter()
            .filter(|argument| argument.formal_name.as_deref() == Some(name))
            .filter_map(|argument| {
                Some(ExpressionSiteValue {
                    call_site: site.clone(),
                    range: argument.range,
                    input: ExpressionInput::Parameter {
                        index: argument.formal_index?,
                        name: argument.formal_name.clone(),
                    },
                })
            })
            .collect(),
    };
    let expansions = expressions
        .into_iter()
        .map(|expression| pipeline_expansion(PipelineValue::ExpressionSite(expression)))
        .collect();
    let spread_binding_incomplete =
        formal_binding_required && site.0.arguments.iter().any(|argument| argument.spread);
    (expansions, spread_binding_incomplete)
}

pub(super) fn charge_reference_scan(
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    scanned_files: usize,
    scanned_source_bytes: usize,
    examined_references: usize,
) -> bool {
    budget.scanned_files = budget.scanned_files.saturating_add(scanned_files);
    budget.scanned_source_bytes = budget
        .scanned_source_bytes
        .saturating_add(scanned_source_bytes);
    budget.examined_references = budget
        .examined_references
        .saturating_add(examined_references);
    budget.scanned_files > limits.max_scanned_files
        || budget.scanned_source_bytes > limits.max_scanned_source_bytes
        || budget.fact_nodes.saturating_add(budget.examined_references) > limits.max_fact_nodes
}

pub(super) fn reference_hit_matches(hit: &ReferenceHit, filter: &ReferenceTraversalFilter) -> bool {
    hit.usage_kind.included_in(filter.surface)
        && filter.proof.is_none_or(|proof| proof == hit.proof)
        && (filter.reference_kinds.is_empty()
            || hit
                .kind
                .is_some_and(|kind| filter.reference_kinds.contains(&kind)))
}

pub(super) fn reference_site_value(
    analyzer: &dyn IAnalyzer,
    hit: &ReferenceHit,
    target: DeclarationValue,
    indexed: &mut IndexedDeclarations,
    known_enclosing: Option<&DeclarationValue>,
) -> (ReferenceSiteValue, bool) {
    let (enclosing, enclosing_projection_omitted) =
        if let Some(known) = known_enclosing.filter(|known| known.unit == hit.enclosing_unit) {
            (Some(known.clone()), false)
        } else if hit.enclosing_unit.is_synthetic() || hit.enclosing_unit.is_file_scope() {
            (None, false)
        } else {
            let enclosing = indexed.get(analyzer, &hit.enclosing_unit);
            let omitted = enclosing.is_none();
            (enclosing, omitted)
        };
    (
        ReferenceSiteValue {
            file: hit.file.clone(),
            range: hit.range,
            target,
            enclosing,
            usage_kind: hit.usage_kind,
            proof: hit.proof,
            reference_kind: hit.kind,
        },
        enclosing_projection_omitted,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn outbound_reference_expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    filter: &ReferenceTraversalFilter,
    indexed: &mut IndexedDeclarations,
    cache: &mut ReferenceTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    max_step_outputs: usize,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    cache_profile: &mut Option<QueryCacheProfile>,
) -> (Vec<PipelineExpansion>, bool) {
    let source_file = declaration.unit.source();
    let cache_hit = cache.outbound.contains_key(source_file);
    let mut exhausted = cache_hit && cache.outbound_exhausted.contains(source_file);
    if let Some(profile) = cache_profile {
        if cache_hit {
            profile.outbound_reference.record_hit(
                Some(!cache.outbound_incomplete.contains(source_file)),
                cache.outbound.get(source_file).map_or(0, Vec::len),
            );
        } else {
            profile.outbound_reference.record_miss();
        }
    }
    if !cache_hit {
        let diagnostic_start = diagnostics.len();
        let (hits, scan_exhausted) = scan_outbound_reference_hits(
            analyzer,
            declaration.unit.source(),
            budget,
            limits,
            max_step_outputs,
            cancellation,
            diagnostics,
        );
        exhausted = scan_exhausted;
        let cache_complete = cache_profile.as_ref().map(|_| {
            !scan_exhausted
                && !diagnostics[diagnostic_start..]
                    .iter()
                    .any(|diagnostic| diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete)
        });
        if cache_complete == Some(false) {
            cache.outbound_incomplete.insert(source_file.clone());
        }
        if scan_exhausted {
            cache.outbound_exhausted.insert(source_file.clone());
        }
        if let Some(profile) = cache_profile {
            profile.outbound_reference.record_build(cache_complete);
        }
        cache.outbound.insert(source_file.clone(), hits);
    }
    let mut sites = Vec::new();
    let mut omitted = 0usize;
    for hit in cache
        .outbound
        .get(declaration.unit.source())
        .into_iter()
        .flatten()
        .filter(|hit| hit.enclosing_unit == declaration.unit)
        .filter(|hit| reference_hit_matches(hit, filter))
    {
        let Some(target) = indexed.get(analyzer, &hit.resolved) else {
            omitted = omitted.saturating_add(1);
            continue;
        };
        let (site, enclosing_projection_omitted) =
            reference_site_value(analyzer, hit, target, indexed, Some(declaration));
        debug_assert!(
            !enclosing_projection_omitted,
            "outbound hits are filtered to the already projected input declaration"
        );
        sites.push(site);
    }
    if omitted > 0 {
        exhausted = true;
        diagnostics
            .retain(|diagnostic| diagnostic.code != CodeQueryDiagnosticCode::UsesTargetsAmbiguous);
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UsesCandidatesOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: crate::analyzer::common::language_for_file(declaration.unit.source())
                .config_label(),
            message: format!(
                "uses omitted {omitted} retained reference candidate{} from {} because the resolved target had no exact indexed range",
                if omitted == 1 { "" } else { "s" },
                declaration.unit.fq_name()
            ),
        });
    }
    sort_reference_sites(&mut sites);
    sites.dedup();
    let expansions = sites
        .into_iter()
        .map(|site| reference_expansion(PipelineValue::Declaration(site.target.clone()), site))
        .collect();
    (expansions, exhausted)
}

pub(super) fn sort_reference_sites(sites: &mut [ReferenceSiteValue]) {
    sites.sort_by(|left, right| {
        rel_path_string(&left.file)
            .cmp(&rel_path_string(&right.file))
            .then_with(|| primary_range_key(&left.range).cmp(&primary_range_key(&right.range)))
            .then_with(|| left.target.unit.cmp(&right.target.unit))
            .then_with(|| {
                left.enclosing
                    .as_ref()
                    .map(|value| &value.unit)
                    .cmp(&right.enclosing.as_ref().map(|value| &value.unit))
            })
            .then_with(|| {
                left.usage_kind
                    .wire_label()
                    .cmp(right.usage_kind.wire_label())
            })
            .then_with(|| usage_proof_label(left.proof).cmp(usage_proof_label(right.proof)))
            .then_with(|| {
                left.reference_kind
                    .map(reference_kind_label)
                    .cmp(&right.reference_kind.map(reference_kind_label))
            })
    });
}

#[allow(clippy::too_many_arguments)]
pub(super) fn expand_hierarchy(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    step: &QueryStep,
    traversal: HierarchyTraversal,
    indexed: &mut IndexedDeclarations,
    budget: &mut CodeQueryExecutionBudget,
    max_pipeline_rows: usize,
    omissions: &mut BTreeMap<(Language, &'static str), usize>,
) -> (Vec<PipelineExpansion>, bool) {
    let Some(provider) = analyzer.type_hierarchy_provider() else {
        record_semantic_omission(
            omissions,
            &declaration.unit,
            "its language does not provide type hierarchy analysis",
        );
        return (Vec::new(), false);
    };
    if !provider.supports_type_hierarchy(&declaration.unit) {
        record_semantic_omission(
            omissions,
            &declaration.unit,
            "input is not a supported type declaration",
        );
        return (Vec::new(), false);
    }

    let max_depth = match traversal {
        HierarchyTraversal::Direct => 1,
        HierarchyTraversal::Depth(depth) => depth.get(),
        HierarchyTraversal::Transitive => usize::MAX,
    };
    let mut queue = VecDeque::from([HierarchyWork {
        unit: declaration.unit.clone(),
        depth: 0,
        path_tail: None,
    }]);
    let mut paths = Vec::new();
    let mut expansions = Vec::new();
    let mut exhausted = false;

    while let Some(work) = queue.pop_front() {
        let mut related = match step {
            QueryStep::Supertypes(_) => provider.get_direct_ancestors(&work.unit),
            QueryStep::Subtypes(_) => provider
                .get_direct_descendants(&work.unit)
                .into_iter()
                .collect(),
            _ => unreachable!("hierarchy expansion requires a hierarchy step"),
        };
        related.sort();
        related.dedup();
        for unit in related {
            if budget.pipeline_rows >= max_pipeline_rows {
                return (expansions, true);
            }
            budget.pipeline_rows += 1;
            match hierarchy_path_contains(
                &paths,
                work.path_tail,
                &declaration.unit,
                &unit,
                &mut budget.provenance_steps,
                max_pipeline_rows,
            ) {
                Some(true) => continue,
                Some(false) => {}
                None => return (expansions, true),
            }
            let Some(value) =
                project_hierarchy_declaration(analyzer, &unit, indexed, omissions, &mut exhausted)
            else {
                continue;
            };
            let next_depth = work.depth + 1;
            if budget.provenance_steps.saturating_add(next_depth) > max_pipeline_rows {
                return (expansions, true);
            }
            budget.provenance_steps += next_depth;
            let path_tail = paths.len();
            paths.push(HierarchyPathNode {
                value: value.clone(),
                parent: work.path_tail,
            });
            expansions.push(PipelineExpansion {
                value: PipelineValue::Declaration(value),
                trace: hierarchy_trace_values(&paths, path_tail, next_depth)
                    .into_iter()
                    .map(|value| (value, None))
                    .collect(),
                budgeted: true,
            });

            if next_depth < max_depth {
                queue.push_back(HierarchyWork {
                    unit,
                    depth: next_depth,
                    path_tail: Some(path_tail),
                });
            }
        }
    }
    (expansions, exhausted)
}

pub(super) fn project_hierarchy_declaration(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    indexed: &mut IndexedDeclarations,
    omissions: &mut BTreeMap<(Language, &'static str), usize>,
    exhausted: &mut bool,
) -> Option<DeclarationValue> {
    let value = indexed.get(analyzer, unit);
    if value.is_none() {
        record_semantic_omission(
            omissions,
            unit,
            "a related hierarchy declaration had no exact indexed range",
        );
        *exhausted = true;
    }
    value
}

pub(super) struct HierarchyWork {
    unit: CodeUnit,
    depth: usize,
    path_tail: Option<usize>,
}

pub(super) struct HierarchyPathNode {
    value: DeclarationValue,
    parent: Option<usize>,
}

pub(super) fn hierarchy_path_contains(
    paths: &[HierarchyPathNode],
    mut tail: Option<usize>,
    root: &CodeUnit,
    candidate: &CodeUnit,
    work: &mut usize,
    max_work: usize,
) -> Option<bool> {
    if *work >= max_work {
        return None;
    }
    *work += 1;
    if candidate == root {
        return Some(true);
    }
    while let Some(index) = tail {
        if *work >= max_work {
            return None;
        }
        *work += 1;
        let node = &paths[index];
        if &node.value.unit == candidate {
            return Some(true);
        }
        tail = node.parent;
    }
    Some(false)
}

pub(super) fn hierarchy_trace_values(
    paths: &[HierarchyPathNode],
    mut tail: usize,
    depth: usize,
) -> Vec<PipelineTraceValue> {
    let mut values = Vec::with_capacity(depth);
    loop {
        let node = &paths[tail];
        values.push(PipelineTraceValue::Declaration(node.value.clone()));
        let Some(parent) = node.parent else {
            break;
        };
        tail = parent;
    }
    values.reverse();
    values
}

pub(super) fn semantic_row_seed_generations_current(
    semantic: &mut SemanticQueryContext<'_>,
    row: &PipelineRow,
) -> bool {
    row.traces
        .iter()
        .all(|trace| semantic.seed_generation_is_current(&trace.seed))
}

pub(super) fn is_type_declaration(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    unit.is_class()
        || analyzer
            .type_hierarchy_provider()
            .is_some_and(|provider| provider.supports_type_hierarchy(unit))
}

pub(super) fn record_semantic_omission(
    omissions: &mut BTreeMap<(Language, &'static str), usize>,
    unit: &CodeUnit,
    reason: &'static str,
) {
    let language = crate::analyzer::common::language_for_file(unit.source());
    *omissions.entry((language, reason)).or_default() += 1;
}

pub(super) fn append_semantic_omission_diagnostics(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    step: &QueryStep,
    omissions: BTreeMap<(Language, &'static str), usize>,
) {
    for ((language, reason), count) in omissions {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "{} omitted {count} input{} because {reason}",
                step.label(),
                if count == 1 { "" } else { "s" }
            ),
        });
    }
}

#[derive(Default)]
pub(super) struct EnclosingDeclarationIndex {
    pub(super) exact: Vec<DeclarationValue>,
    pub(super) projection_omitted: bool,
}

impl EnclosingDeclarationIndex {
    pub(super) fn retain(&mut self, unit: CodeUnit, ranges: impl IntoIterator<Item = Range>) {
        if unit.is_synthetic() || unit.is_file_scope() {
            return;
        }
        let mut retained = false;
        for range in ranges {
            retained = true;
            self.exact.push(DeclarationValue {
                unit: unit.clone(),
                range,
            });
        }
        if !retained {
            self.projection_omitted = true;
        }
    }

    pub(super) fn sort(&mut self) {
        self.exact.sort_by(|left, right| {
            let left_span = left.range.end_byte.saturating_sub(left.range.start_byte);
            let right_span = right.range.end_byte.saturating_sub(right.range.start_byte);
            left_span
                .cmp(&right_span)
                .then_with(|| left.unit.cmp(&right.unit))
                .then_with(|| left.range.start_byte.cmp(&right.range.start_byte))
                .then_with(|| left.range.end_byte.cmp(&right.range.end_byte))
        });
    }

    pub(super) fn enclosing(&self, seed_range: Range) -> Option<DeclarationValue> {
        self.exact
            .iter()
            .find(|declaration| {
                declaration.range.start_byte <= seed_range.start_byte
                    && declaration.range.end_byte >= seed_range.end_byte
            })
            .cloned()
    }

    pub(super) fn exact(&self, seed_range: Range) -> Option<DeclarationValue> {
        self.exact
            .iter()
            .find(|declaration| {
                declaration.range.start_byte == seed_range.start_byte
                    && declaration.range.end_byte == seed_range.end_byte
            })
            .cloned()
    }
}

pub(super) fn seed_range(seed: &SeedMatch) -> Range {
    let fact = seed.facts.node(seed.fact_match.node);
    let span = fact.span();
    Range {
        start_byte: span.start_byte,
        end_byte: span.end_byte,
        start_line: fact.range.start_line,
        end_line: fact.range.end_line,
    }
}

pub(super) fn declaration_index_for_seed<'a>(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    declarations_by_file: &'a mut HashMap<ProjectFile, EnclosingDeclarationIndex>,
) -> &'a EnclosingDeclarationIndex {
    declarations_by_file
        .entry(seed.file.clone())
        .or_insert_with(|| {
            let mut declarations = EnclosingDeclarationIndex::default();
            for unit in analyzer.get_declarations(&seed.file) {
                declarations.retain(unit.clone(), analyzer.ranges_of(&unit));
            }
            declarations.sort();
            declarations
        })
}

pub(super) fn enclosing_declaration_value(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    declarations_by_file: &mut HashMap<ProjectFile, EnclosingDeclarationIndex>,
) -> (Option<DeclarationValue>, bool) {
    let declarations = declaration_index_for_seed(analyzer, seed, declarations_by_file);
    (
        declarations.enclosing(seed_range(seed)),
        declarations.projection_omitted,
    )
}

pub(super) fn exact_callable_declaration_value(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    declarations_by_file: &mut HashMap<ProjectFile, EnclosingDeclarationIndex>,
) -> Option<DeclarationValue> {
    let fact = seed.facts.node(seed.fact_match.node);
    if !matches!(
        fact.kind,
        NormalizedKind::Function | NormalizedKind::Method | NormalizedKind::Constructor
    ) {
        return None;
    }
    declaration_index_for_seed(analyzer, seed, declarations_by_file).exact(seed_range(seed))
}
