//! Graph-traversal expansion primitives for `Callers`/`Callees`,
//! `ReferencesOf`, and `UsedBy` pipeline steps -- moved verbatim out of
//! `search.rs` (#1057 follow-up split). The three entry points
//! (`call_declaration_expansions`, `inbound_reference_expansions`,
//! `scan_outbound_reference_hits`) are `pub(super)` because
//! `apply_pipeline_step` in the parent engine calls them directly.

use super::*;

#[derive(Clone)]
struct CallTraversalWork {
    unit: CodeUnit,
    depth: usize,
    path_tail: Option<usize>,
}

struct CallPathNode {
    value: DeclarationValue,
    via: CallSiteValue,
    parent: Option<usize>,
}

fn finish_call_declaration_expansions(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    diagnostic_start: usize,
    declaration: &DeclarationValue,
    incoming: bool,
    omitted: usize,
    expansions: Vec<PipelineExpansion>,
    exhausted: bool,
) -> (Vec<PipelineExpansion>, bool) {
    if omitted == 0 {
        return (expansions, exhausted);
    }
    let mut traversal_diagnostics = diagnostics.split_off(diagnostic_start.min(diagnostics.len()));
    traversal_diagnostics.retain(|diagnostic| {
        diagnostic.code != CodeQueryDiagnosticCode::CallRelationTargetsAmbiguous
    });
    diagnostics.extend(traversal_diagnostics);
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::CallRelationCandidatesOmitted,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: crate::analyzer::common::language_for_file(declaration.unit.source())
            .config_label(),
        message: format!(
            "{} omitted {omitted} retained call-relation candidate{} for {} because the related declaration had no exact indexed range",
            if incoming { "callers" } else { "callees" },
            if omitted == 1 { "" } else { "s" },
            declaration.unit.fq_name()
        ),
    });
    (expansions, true)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn call_declaration_expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    step: &QueryStep,
    filter: &CallTraversalFilter,
    indexed: &mut IndexedDeclarations,
    cache: &mut CallTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    max_outputs: usize,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    cache_profile: &mut Option<QueryCacheProfile>,
) -> (Vec<PipelineExpansion>, bool) {
    let incoming = matches!(step, QueryStep::Callers(_));
    let diagnostic_start = diagnostics.len();
    let mut queue = VecDeque::from([CallTraversalWork {
        unit: declaration.unit.clone(),
        depth: 0,
        path_tail: None,
    }]);
    let mut paths = Vec::new();
    let mut emitted = HashSet::default();
    let mut expansions = Vec::new();
    let mut exhausted = false;
    let mut omitted = 0usize;
    while let Some(work) = queue.pop_front() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return finish_call_declaration_expansions(
                diagnostics,
                diagnostic_start,
                declaration,
                incoming,
                omitted,
                expansions,
                true,
            );
        }
        let result = cached_call_relation(
            analyzer,
            &work.unit,
            incoming,
            cache,
            budget,
            limits,
            cancellation,
            diagnostics,
            cache_profile,
        );
        exhausted |= result.truncated || result.cancelled;
        for site in result
            .sites
            .into_iter()
            .filter(|site| filter.proof.is_none_or(|proof| proof == site.proof))
        {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return finish_call_declaration_expansions(
                    diagnostics,
                    diagnostic_start,
                    declaration,
                    incoming,
                    omitted,
                    expansions,
                    true,
                );
            }
            let next_unit = if incoming {
                site.caller.clone()
            } else {
                site.callee.clone()
            };
            let Some(next) = indexed.get(analyzer, &next_unit) else {
                omitted = omitted.saturating_add(1);
                continue;
            };
            if !emitted.contains(&next_unit) && emitted.len() >= max_outputs {
                return finish_call_declaration_expansions(
                    diagnostics,
                    diagnostic_start,
                    declaration,
                    incoming,
                    omitted,
                    expansions,
                    true,
                );
            }
            if budget.pipeline_rows >= limits.max_pipeline_rows {
                return finish_call_declaration_expansions(
                    diagnostics,
                    diagnostic_start,
                    declaration,
                    incoming,
                    omitted,
                    expansions,
                    true,
                );
            }
            let cycle = match call_path_contains(
                &paths,
                work.path_tail,
                &declaration.unit,
                &next_unit,
                &mut budget.provenance_steps,
                limits.max_pipeline_rows,
            ) {
                Some(cycle) => cycle,
                None => {
                    return finish_call_declaration_expansions(
                        diagnostics,
                        diagnostic_start,
                        declaration,
                        incoming,
                        omitted,
                        expansions,
                        true,
                    );
                }
            };
            let next_depth = work.depth + 1;
            if budget.provenance_steps.saturating_add(next_depth) > limits.max_pipeline_rows {
                budget.provenance_steps = limits.max_pipeline_rows;
                return finish_call_declaration_expansions(
                    diagnostics,
                    diagnostic_start,
                    declaration,
                    incoming,
                    omitted,
                    expansions,
                    true,
                );
            }
            budget.provenance_steps += next_depth;
            budget.pipeline_rows += 1;
            let call_site = CallSiteValue(site, CallBindingStatus::Unavailable);
            let path_tail = paths.len();
            paths.push(CallPathNode {
                value: next.clone(),
                via: call_site,
                parent: work.path_tail,
            });
            expansions.push(PipelineExpansion {
                value: PipelineValue::Declaration(next),
                trace: call_trace_values(&paths, path_tail, next_depth),
                budgeted: true,
            });
            emitted.insert(next_unit.clone());
            if !cycle && next_depth < filter.depth.get() {
                queue.push_back(CallTraversalWork {
                    unit: next_unit,
                    depth: next_depth,
                    path_tail: Some(path_tail),
                });
            }
        }
    }
    finish_call_declaration_expansions(
        diagnostics,
        diagnostic_start,
        declaration,
        incoming,
        omitted,
        expansions,
        exhausted,
    )
}

fn call_path_contains(
    paths: &[CallPathNode],
    mut tail: Option<usize>,
    seed: &CodeUnit,
    candidate: &CodeUnit,
    work: &mut usize,
    max_work: usize,
) -> Option<bool> {
    if seed == candidate {
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

fn call_trace_values(
    paths: &[CallPathNode],
    mut tail: usize,
    depth: usize,
) -> Vec<(PipelineTraceValue, Option<PipelineVia>)> {
    let mut values = Vec::with_capacity(depth);
    loop {
        let node = &paths[tail];
        values.push((
            PipelineTraceValue::Declaration(node.value.clone()),
            Some(PipelineVia::CallSite(node.via.clone())),
        ));
        let Some(parent) = node.parent else {
            break;
        };
        tail = parent;
    }
    values.reverse();
    values
}

#[allow(clippy::too_many_arguments)]
pub(super) fn inbound_reference_expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    step: &QueryStep,
    filter: &ReferenceTraversalFilter,
    indexed: &mut IndexedDeclarations,
    cache: &mut ReferenceTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    max_hits: usize,
    cancellation: Option<&CancellationToken>,
    cache_profile: &mut Option<QueryCacheProfile>,
) -> (Vec<PipelineExpansion>, bool) {
    let cache_hit = cache.inbound.contains_key(&declaration.unit);
    let mut exhausted = cache_hit && cache.inbound_exhausted.contains(&declaration.unit);
    if let Some(profile) = cache_profile {
        if cache_hit {
            profile.inbound_reference.record_hit(
                Some(!cache.inbound_incomplete.contains(&declaration.unit)),
                cache.inbound.get(&declaration.unit).map_or(0, Vec::len),
            );
        } else {
            profile.inbound_reference.record_miss();
        }
    }
    if !cache_hit {
        let diagnostic_start = diagnostics.len();
        let remaining_files = limits
            .max_scanned_files
            .saturating_sub(budget.scanned_files);
        if remaining_files == 0 {
            push_budget_diagnostic(diagnostics, budget);
            return (Vec::new(), true);
        }
        let remaining_source_bytes = limits
            .max_scanned_source_bytes
            .saturating_sub(budget.scanned_source_bytes);
        if remaining_source_bytes == 0 {
            push_budget_diagnostic(diagnostics, budget);
            return (Vec::new(), true);
        }
        let mut finder = UsageFinder::new();
        if let Some(cancellation) = cancellation {
            finder = finder.with_cancellation(cancellation.clone());
        }
        let query = finder.query_with_source_budget(
            analyzer,
            std::slice::from_ref(&declaration.unit),
            MAX_SCANNED_FILES.min(remaining_files),
            max_hits.max(1),
            remaining_source_bytes,
        );
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return (Vec::new(), true);
        }
        let examined_references = fuzzy_result_examination_count(&query.result);
        if charge_reference_scan(
            budget,
            limits,
            query.candidate_files.len(),
            query.scanned_source_bytes,
            examined_references,
        ) {
            push_budget_diagnostic(diagnostics, budget);
            cache.inbound.insert(declaration.unit.clone(), Vec::new());
            if cache_profile.is_some() {
                cache.inbound_incomplete.insert(declaration.unit.clone());
            }
            cache.inbound_exhausted.insert(declaration.unit.clone());
            if let Some(profile) = cache_profile {
                profile.inbound_reference.record_build(Some(false));
            }
            return (Vec::new(), true);
        }
        let mut hits = Vec::new();
        let report = cache.reported_inbound.insert(declaration.unit.clone());
        if report && query.source_bytes_truncated {
            exhausted = true;
            diagnostics.push(CodeQueryDiagnostic {
                code: CodeQueryDiagnosticCode::ReferenceSourceBytesTruncated,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: crate::analyzer::common::language_for_file(declaration.unit.source())
                    .config_label(),
                message: format!(
                    "references_of source-byte budget truncated candidate files for {}",
                    declaration.unit.fq_name()
                ),
            });
        } else if report && query.candidate_files_truncated {
            exhausted = true;
            diagnostics.push(CodeQueryDiagnostic {
                code: CodeQueryDiagnosticCode::ReferenceCandidateFilesTruncated,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: crate::analyzer::common::language_for_file(declaration.unit.source())
                    .config_label(),
                message: format!(
                    "references_of candidate files were truncated for {}",
                    declaration.unit.fq_name()
                ),
            });
        }
        match query.result {
            FuzzyResult::Success {
                hits_by_overload,
                unproven_by_overload,
                unproven_total_by_overload,
            } => {
                hits.extend(hits_by_overload.into_values().flatten().map(|hit| {
                    reference_hit_for_target(
                        analyzer,
                        hit,
                        declaration.unit.clone(),
                        UsageProof::Proven,
                    )
                }));
                hits.extend(unproven_by_overload.into_values().flatten().map(|hit| {
                    reference_hit_for_target(
                        analyzer,
                        hit,
                        declaration.unit.clone(),
                        UsageProof::Unproven,
                    )
                }));
                if report {
                    let omitted = unproven_total_by_overload
                        .values()
                        .sum::<usize>()
                        .saturating_sub(
                            hits.iter()
                                .filter(|hit| hit.proof == UsageProof::Unproven)
                                .count(),
                        );
                    if omitted > 0 {
                        diagnostics.push(CodeQueryDiagnostic {
                            code: CodeQueryDiagnosticCode::ReferenceCandidatesOmitted,
                            impact: CodeQueryDiagnosticImpact::Incomplete,
                            branch: Vec::new(),
                            language: crate::analyzer::common::language_for_file(
                                declaration.unit.source(),
                            )
                            .config_label(),
                            message: format!(
                                "references_of omitted {omitted} unproven reference candidates for {}",
                                declaration.unit.fq_name()
                            ),
                        });
                    }
                }
            }
            FuzzyResult::Ambiguous {
                hits_by_overload, ..
            } => {
                hits.extend(hits_by_overload.into_values().flatten().map(|hit| {
                    reference_hit_for_target(
                        analyzer,
                        hit,
                        declaration.unit.clone(),
                        UsageProof::Unproven,
                    )
                }));
                if report {
                    diagnostics.push(CodeQueryDiagnostic {
                        code: CodeQueryDiagnosticCode::ReferenceTargetsAmbiguous,
                        impact: CodeQueryDiagnosticImpact::Advisory,
                        branch: Vec::new(),
                        language: crate::analyzer::common::language_for_file(
                            declaration.unit.source(),
                        )
                        .config_label(),
                        message: format!(
                            "references_of emitted ambiguous candidates for {} as unproven",
                            declaration.unit.fq_name()
                        ),
                    });
                }
            }
            FuzzyResult::TooManyCallsites {
                total_callsites,
                limit,
                sample_hits,
                ..
            } => {
                hits.extend(reference_hits_from_bounded_sample(
                    analyzer,
                    sample_hits,
                    declaration.unit.clone(),
                    limit,
                ));
                exhausted = true;
                if report {
                    diagnostics.push(CodeQueryDiagnostic {
                        code: CodeQueryDiagnosticCode::ReferenceCallsiteLimit,
                        impact: CodeQueryDiagnosticImpact::Incomplete,
                        branch: Vec::new(),
                        language: crate::analyzer::common::language_for_file(
                            declaration.unit.source(),
                        )
                        .config_label(),
                        message: format!(
                            "references_of found {total_callsites} call sites for {}, exceeding limit {limit}",
                            declaration.unit.fq_name()
                        ),
                    });
                }
            }
            FuzzyResult::Failure { reason, .. } => {
                if report {
                    diagnostics.push(CodeQueryDiagnostic {
                        code: CodeQueryDiagnosticCode::ReferenceAnalysisFailed,
                        impact: CodeQueryDiagnosticImpact::Incomplete,
                        branch: Vec::new(),
                        language: crate::analyzer::common::language_for_file(
                            declaration.unit.source(),
                        )
                        .config_label(),
                        message: format!(
                            "references_of does not support {}: {reason}",
                            declaration.unit.fq_name()
                        ),
                    });
                }
            }
        }
        let cache_complete = cache_profile.as_ref().map(|_| {
            !exhausted
                && !diagnostics[diagnostic_start..]
                    .iter()
                    .any(|diagnostic| diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete)
        });
        if cache_complete == Some(false) {
            cache.inbound_incomplete.insert(declaration.unit.clone());
        }
        if exhausted {
            cache.inbound_exhausted.insert(declaration.unit.clone());
        }
        if let Some(profile) = cache_profile {
            profile.inbound_reference.record_build(cache_complete);
        }
        cache.inbound.insert(declaration.unit.clone(), hits);
    }

    let mut sites = Vec::new();
    let mut omitted_enclosing_declarations = 0usize;
    for hit in cache
        .inbound
        .get(&declaration.unit)
        .into_iter()
        .flatten()
        .filter(|hit| reference_hit_matches(hit, filter))
    {
        let (site, enclosing_projection_omitted) =
            reference_site_value(analyzer, hit, declaration.clone(), indexed, None);
        omitted_enclosing_declarations = omitted_enclosing_declarations
            .saturating_add(usize::from(enclosing_projection_omitted));
        sites.push(site);
    }
    if omitted_enclosing_declarations > 0 {
        exhausted = true;
        diagnostics.retain(|diagnostic| {
            diagnostic.code != CodeQueryDiagnosticCode::ReferenceTargetsAmbiguous
        });
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::ReferenceCandidatesOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: crate::analyzer::common::language_for_file(declaration.unit.source())
                .config_label(),
            message: format!(
                "{} could not project the exact enclosing declaration for {omitted_enclosing_declarations} retained reference candidate{} of {}",
                step.label(),
                if omitted_enclosing_declarations == 1 {
                    ""
                } else {
                    "s"
                },
                declaration.unit.fq_name()
            ),
        });
    }
    sort_reference_sites(&mut sites);
    sites.dedup();
    let expansions = sites
        .into_iter()
        .filter_map(|site| match step {
            QueryStep::ReferencesOf(_) => {
                Some(pipeline_expansion(PipelineValue::ReferenceSite(site)))
            }
            QueryStep::UsedBy(_) => site
                .enclosing
                .clone()
                .map(|enclosing| reference_expansion(PipelineValue::Declaration(enclosing), site)),
            _ => unreachable!("inbound helper is only used by inbound reference steps"),
        })
        .collect::<Vec<_>>();
    (expansions, exhausted)
}

fn fuzzy_result_examination_count(result: &FuzzyResult) -> usize {
    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_total_by_overload,
            ..
        } => {
            hits_by_overload.values().map(BTreeSet::len).sum::<usize>()
                + unproven_total_by_overload.values().sum::<usize>()
        }
        FuzzyResult::Ambiguous {
            hits_by_overload, ..
        } => hits_by_overload.values().map(BTreeSet::len).sum(),
        FuzzyResult::TooManyCallsites {
            total_callsites, ..
        } => *total_callsites,
        FuzzyResult::Failure { .. } => 0,
    }
}

fn reference_hit_for_target(
    analyzer: &dyn IAnalyzer,
    hit: crate::analyzer::usages::UsageHit,
    target: CodeUnit,
    proof: UsageProof,
) -> ReferenceHit {
    let kind = hit.reference_kind.or_else(|| {
        classify_reference_kind(
            analyzer,
            &hit.file,
            hit.start_offset,
            hit.end_offset,
            &target,
        )
    });
    ReferenceHit {
        file: hit.file,
        range: Range {
            start_byte: hit.start_offset,
            end_byte: hit.end_offset,
            start_line: hit.line,
            end_line: hit.line,
        },
        enclosing_unit: hit.enclosing,
        kind,
        resolved: target,
        confidence: (hit.confidence.clamp(0.0, 1.0) * 1_000_000.0) as u32,
        usage_kind: hit.kind,
        proof,
    }
}

fn reference_hits_from_bounded_sample(
    analyzer: &dyn IAnalyzer,
    sample_hits: impl IntoIterator<Item = UsageHit>,
    target: CodeUnit,
    limit: usize,
) -> Vec<ReferenceHit> {
    sample_hits
        .into_iter()
        .take(limit)
        .map(|hit| reference_hit_for_target(analyzer, hit, target.clone(), UsageProof::Proven))
        .collect()
}

pub(super) fn reference_hits_for_target(
    analyzer: &dyn IAnalyzer,
    result: FuzzyResult,
    target: &CodeUnit,
) -> (Vec<ReferenceHit>, bool) {
    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            ..
        } => (
            hits_by_overload
                .into_values()
                .flatten()
                .map(|hit| {
                    reference_hit_for_target(analyzer, hit, target.clone(), UsageProof::Proven)
                })
                .chain(unproven_by_overload.into_values().flatten().map(|hit| {
                    reference_hit_for_target(analyzer, hit, target.clone(), UsageProof::Unproven)
                }))
                .collect(),
            false,
        ),
        FuzzyResult::Ambiguous {
            hits_by_overload, ..
        } => (
            hits_by_overload
                .into_values()
                .flatten()
                .map(|hit| {
                    reference_hit_for_target(analyzer, hit, target.clone(), UsageProof::Unproven)
                })
                .collect(),
            false,
        ),
        FuzzyResult::TooManyCallsites {
            sample_hits, limit, ..
        } => (
            reference_hits_from_bounded_sample(analyzer, sample_hits, target.clone(), limit),
            true,
        ),
        FuzzyResult::Failure { .. } => (Vec::new(), false),
    }
}

#[derive(Default)]
struct OutboundReferenceSiteExpectation {
    targets: BTreeSet<CodeUnit>,
    ambiguous: bool,
}

pub(super) struct OutboundLookupCandidates {
    by_target: BTreeMap<CodeUnit, BTreeSet<(usize, usize)>>,
    sites: BTreeMap<(usize, usize), OutboundReferenceSiteExpectation>,
    pub(super) ambiguous_sites: usize,
    pub(super) ambiguous_candidates_complete: bool,
    pub(super) omitted_sites: usize,
}

pub(super) fn group_outbound_lookup_candidates(
    outcomes: Vec<DefinitionLookupOutcome>,
) -> OutboundLookupCandidates {
    let mut grouped = OutboundLookupCandidates {
        by_target: BTreeMap::new(),
        sites: BTreeMap::new(),
        ambiguous_sites: 0,
        ambiguous_candidates_complete: true,
        omitted_sites: 0,
    };

    for outcome in outcomes {
        let ambiguous = outcome.status == DefinitionLookupStatus::Ambiguous;
        match outcome.status {
            DefinitionLookupStatus::Resolved | DefinitionLookupStatus::Ambiguous => {}
            _ => {
                grouped.omitted_sites = grouped.omitted_sites.saturating_add(1);
                continue;
            }
        }
        if ambiguous {
            grouped.ambiguous_sites = grouped.ambiguous_sites.saturating_add(1);
        }
        let Some(reference) = outcome.reference else {
            grouped.omitted_sites = grouped.omitted_sites.saturating_add(1);
            grouped.ambiguous_candidates_complete &= !ambiguous;
            continue;
        };
        if outcome.definitions.is_empty() {
            grouped.omitted_sites = grouped.omitted_sites.saturating_add(1);
            grouped.ambiguous_candidates_complete &= !ambiguous;
            continue;
        }

        let range = (reference.focus_start_byte, reference.focus_end_byte);
        let site = grouped.sites.entry(range).or_default();
        site.ambiguous |= ambiguous;
        for resolved in outcome.definitions {
            site.targets.insert(resolved.clone());
            grouped.by_target.entry(resolved).or_default().insert(range);
        }
    }
    grouped
}

pub(super) fn append_outbound_lookup_diagnostics(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    language: Language,
    file: &ProjectFile,
    ambiguous_sites: usize,
    ambiguous_candidates_complete: bool,
    omitted: usize,
) {
    if ambiguous_sites > 0 && ambiguous_candidates_complete {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UsesTargetsAmbiguous,
            impact: CodeQueryDiagnosticImpact::Advisory,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "uses emitted {ambiguous_sites} ambiguous reference site{} in {} as unproven",
                if ambiguous_sites == 1 { "" } else { "s" },
                rel_path_string(file)
            ),
        });
    }
    if omitted > 0 {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UsesCandidatesOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "uses omitted {omitted} candidate reference site{} in {} because the structured usage analyzer did not confirm every exact edge",
                if omitted == 1 { "" } else { "s" },
                rel_path_string(file)
            ),
        });
    }
}

pub(super) fn scan_outbound_reference_hits(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    max_step_outputs: usize,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> (Vec<ReferenceHit>, bool) {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return (Vec::new(), true);
    }
    let language = crate::analyzer::common::language_for_file(file);
    let Some(source) = analyzer.indexed_source(file) else {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UsesCandidatesOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "uses could not inspect {} because its indexed source snapshot was unavailable",
                rel_path_string(file)
            ),
        });
        return (Vec::new(), true);
    };
    let remaining_source_bytes = limits
        .max_scanned_source_bytes
        .saturating_sub(budget.scanned_source_bytes);
    if budget.scanned_files >= limits.max_scanned_files || source.len() > remaining_source_bytes {
        push_budget_diagnostic(diagnostics, budget);
        return (Vec::new(), true);
    }
    budget.scanned_files += 1;
    budget.scanned_source_bytes += source.len();
    let source = Arc::new(source);
    let Some(tree) = parse_tree_for_language(file, language, &source) else {
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UsesParserUnsupported,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!("uses does not support parsing {}", rel_path_string(file)),
        });
        return (Vec::new(), false);
    };
    const MAX_OUTBOUND_SITES_PER_FILE: usize = 50_000;
    let remaining_reference_budget = limits
        .max_fact_nodes
        .saturating_sub(budget.fact_nodes.saturating_add(budget.examined_references));
    if remaining_reference_budget == 0 {
        push_budget_diagnostic(diagnostics, budget);
        return (Vec::new(), true);
    }
    let retained_work_budget = max_step_outputs.saturating_mul(64).max(256);
    let candidate_limit = MAX_OUTBOUND_SITES_PER_FILE
        .min(remaining_reference_budget)
        .min(retained_work_budget);
    let candidate_ranges = match cancellation {
        Some(cancellation) => reference_candidate_ranges_cancellable(
            tree.root_node(),
            language,
            candidate_limit,
            &|| cancellation.is_cancelled(),
        ),
        None => Some(reference_candidate_ranges(
            tree.root_node(),
            language,
            candidate_limit,
        )),
    };
    let Some(candidate_ranges) = candidate_ranges else {
        return (Vec::new(), true);
    };
    let (ranges, mut exhausted) = match candidate_ranges {
        ReferenceCandidateRanges::Complete(ranges) => (ranges, false),
        ReferenceCandidateRanges::LimitExceeded { ranges, .. } => (ranges, true),
    };
    budget.examined_references = budget.examined_references.saturating_add(ranges.len());
    if exhausted {
        if candidate_limit == remaining_reference_budget {
            push_budget_diagnostic(diagnostics, budget);
        } else {
            diagnostics.push(CodeQueryDiagnostic {
                code: CodeQueryDiagnosticCode::UsesCandidateLimit,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "uses returned a bounded partial scan of {} after reaching the structured reference-candidate limit of {candidate_limit}",
                    rel_path_string(file)
                ),
            });
        }
    }
    if candidate_limit == 0 {
        exhausted = true;
        diagnostics.push(CodeQueryDiagnostic {
            code: CodeQueryDiagnosticCode::UsesCandidateLimit,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "uses has no reference-candidate capacity for {}",
                rel_path_string(file)
            ),
        });
    }
    let requests = ranges
        .into_iter()
        .map(|range| DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(range.start_byte),
            end_byte: Some(range.end_byte),
        })
        .collect();
    let outcomes = match cancellation {
        Some(cancellation) => resolve_definition_batch_with_source_and_cancellation(
            analyzer,
            requests,
            file.clone(),
            Arc::clone(&source),
            cancellation,
        ),
        None => resolve_definition_batch_with_source(
            analyzer,
            requests,
            file.clone(),
            Arc::clone(&source),
        ),
    };
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return (Vec::new(), true);
    }
    let grouped = group_outbound_lookup_candidates(outcomes);
    let mut retained_candidates = BTreeSet::new();

    let mut candidate_files = HashSet::default();
    candidate_files.insert(file.clone());
    let provider = ExplicitCandidateProvider::new(Arc::new(candidate_files));
    let mut hits = Vec::new();
    for (target, candidate_ranges) in &grouped.by_target {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return (Vec::new(), true);
        }
        let mut finder = UsageFinder::new();
        if let Some(cancellation) = cancellation {
            finder = finder.with_cancellation(cancellation.clone());
        }
        let result = finder.query_with_provider(
            analyzer,
            std::slice::from_ref(target),
            Some(&provider),
            1,
            candidate_ranges.len().max(1),
        );
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return (Vec::new(), true);
        }
        let (target_hits, target_truncated) =
            reference_hits_for_target(analyzer, result.result, target);
        if target_truncated {
            exhausted = true;
            diagnostics.push(CodeQueryDiagnostic {
                code: CodeQueryDiagnosticCode::UsesCandidateLimit,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "uses retained a bounded positive reference sample for {} after the usage analyzer reached its candidate limit",
                    target.fq_name()
                ),
            });
        }
        for hit in target_hits {
            let range = (hit.range.start_byte, hit.range.end_byte);
            if hit.file == *file && candidate_ranges.contains(&range) {
                retained_candidates.insert((target.clone(), range));
                hits.push(hit);
            }
        }
    }

    let mut omitted = grouped.omitted_sites;
    let mut ambiguous_candidates_complete = grouped.ambiguous_candidates_complete;
    for (range, expectation) in &grouped.sites {
        let fully_retained = expectation
            .targets
            .iter()
            .all(|target| retained_candidates.contains(&(target.clone(), *range)));
        if !fully_retained {
            omitted = omitted.saturating_add(1);
            if expectation.ambiguous {
                ambiguous_candidates_complete = false;
            }
        }
    }
    append_outbound_lookup_diagnostics(
        diagnostics,
        language,
        file,
        grouped.ambiguous_sites,
        ambiguous_candidates_complete,
        omitted,
    );
    (hits, exhausted)
}

fn classify_reference_kind(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    start_byte: usize,
    end_byte: usize,
    target: &CodeUnit,
) -> Option<ReferenceKind> {
    let language = crate::analyzer::common::language_for_file(file);
    let facts = analyzer
        .structural_search_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)?
        .structural_facts(file)?;
    let covers = |span: Span| span.start_byte <= start_byte && end_byte <= span.end_byte;
    let mut candidates = facts
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| {
            node.name.is_some_and(covers)
                && matches!(
                    node.kind,
                    NormalizedKind::Call | NormalizedKind::FieldAccess
                )
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(_, node)| {
        (
            usize::from(node.kind != NormalizedKind::Call),
            node.range.end_byte - node.range.start_byte,
        )
    });
    if let Some((id, node)) = candidates.first().copied() {
        let receiver_role = if node.kind == NormalizedKind::FieldAccess {
            Role::Object
        } else {
            Role::Receiver
        };
        let receiver = facts
            .role_targets(id as u32, receiver_role)
            .next()
            .map(|role| role.span.text(facts.source()).trim());
        if receiver.is_some_and(|text| matches!(text, "super" | "base")) {
            return Some(ReferenceKind::SuperCall);
        }
        let static_receiver = analyzer
            .parent_of(target)
            .filter(|owner| owner.is_class())
            .is_some_and(|owner| receiver == Some(owner.short_name()));
        if static_receiver {
            return Some(ReferenceKind::StaticReference);
        }
        if node.kind == NormalizedKind::Call {
            return Some(
                if target.is_class() || target.kind().display_lowercase() == "constructor" {
                    ReferenceKind::ConstructorCall
                } else {
                    ReferenceKind::MethodCall
                },
            );
        }
        let mut parent = Some(id as u32);
        while let Some(current) = parent {
            let fact = facts.node(current);
            if fact.kind == NormalizedKind::Assignment {
                return Some(
                    if facts
                        .role_targets(current, Role::Left)
                        .any(|role| covers(role.span))
                    {
                        ReferenceKind::FieldWrite
                    } else {
                        ReferenceKind::FieldRead
                    },
                );
            }
            parent = fact.parent;
        }
        return Some(ReferenceKind::FieldRead);
    }
    if target.is_class() {
        let nearest = facts
            .nodes()
            .iter()
            .enumerate()
            .filter(|(_, node)| {
                node.range.start_byte <= start_byte && end_byte <= node.range.end_byte
            })
            .min_by_key(|(_, node)| node.range.end_byte - node.range.start_byte)
            .map(|(id, _)| id as u32);
        let mut current = nearest;
        while let Some(id) = current {
            let node = facts.node(id);
            if node.kind.satisfies(NormalizedKind::Declaration) {
                if node.kind == NormalizedKind::Class && node.name.is_none_or(|name| !covers(name))
                {
                    return Some(ReferenceKind::Inheritance);
                }
                break;
            }
            current = node.parent;
        }
    }
    target.is_class().then_some(ReferenceKind::TypeReference)
}
