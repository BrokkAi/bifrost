//! Graph-traversal expansion primitives for `Callers`/`Callees`,
//! `ReferencesOf`, and `UsedBy` pipeline steps -- moved verbatim out of
//! `search.rs` (#1057 follow-up split). The three entry points
//! (`call_declaration_expansions`, `inbound_reference_expansions`,
//! `scan_outbound_reference_hits`) are `pub(super)` because
//! `apply_pipeline_step` in the parent engine calls them directly.

use super::*;
pub(crate) use crate::structural::reference_edges::reference_hits_for_target;
use crate::structural::reference_edges::{
    reference_hit_for_target, reference_hits_from_bounded_sample,
};
use brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution;

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

#[allow(clippy::too_many_arguments)]
fn finish_call_declaration_expansions(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    diagnostic_start: usize,
    declaration: &DeclarationValue,
    incoming: bool,
    declared_non_exhaustive: bool,
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
    if declared_non_exhaustive {
        reclassify_declared_subset_omissions(&mut traversal_diagnostics);
    }
    diagnostics.extend(traversal_diagnostics);
    diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
        incompleteness: brokk_bifrost_rql::Incompleteness::Operational(brokk_bifrost_rql::DiagnosticExecutionCause::Provider),
        related: Vec::new(),
        source: None,
        code: CodeQueryDiagnosticCode::CallRelationCandidatesOmitted,
        impact: if declared_non_exhaustive {
            CodeQueryDiagnosticImpact::DeclaredNonExhaustive
        } else {
            CodeQueryDiagnosticImpact::Incomplete
        },
        branch: Vec::new(),
        language: crate::analyzer::common::language_for_file(declaration.unit.source())
            .config_label(),
        message: format!(
            "{} omitted {omitted} retained call-relation candidate{} for {} because the related declaration had no exact indexed range",
            if incoming { "callers" } else { "callees" },
            if omitted == 1 { "" } else { "s" },
            declaration.unit.fq_name()
        ),
    exhausted_roots: Vec::new(),
        withheld_rows_path: None,
    }));
    // The explicit proven-subset contract declines only the exhaustive
    // negative claim caused by an unrenderable related declaration. It never
    // hides a real traversal limit, which is carried by `exhausted`.
    (expansions, exhausted || !declared_non_exhaustive)
}

fn reclassify_declared_subset_omissions(diagnostics: &mut [CodeQueryDiagnostic]) {
    for diagnostic in diagnostics {
        if diagnostic.code == CodeQueryDiagnosticCode::CallRelationCandidatesOmitted {
            diagnostic.impact = CodeQueryDiagnosticImpact::DeclaredNonExhaustive;
        }
    }
}

fn call_depth_relation_is_unknown(
    result: &CallRelationResult,
    incoming: bool,
    diagnostics: &[CodeQueryDiagnostic],
) -> bool {
    !call_relation_result_complete(result, incoming)
        || (incoming && result.caller_inventory != CallerInventoryCoverage::Complete)
        || diagnostics
            .iter()
            .any(|diagnostic| diagnostic.impact == CodeQueryDiagnosticImpact::Incomplete)
}

fn proof_filter_omits_ambiguous_calls(
    result: &CallRelationResult,
    proof: Option<UsageProof>,
) -> bool {
    proof == Some(UsageProof::Proven)
        && result
            .sites
            .iter()
            .any(|site| site.proof == UsageProof::Unproven)
        && result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CallRelationDiagnosticCode::TargetsAmbiguous)
}

pub(super) struct CallDepthProbeInput {
    enabled: bool,
    members: HashMap<CodeUnit, (DeclarationValue, usize)>,
    pub(super) answer: Option<units::BoundedCallAnswer>,
    pub(super) undecided: bool,
}

impl Default for CallDepthProbeInput {
    fn default() -> Self {
        Self {
            enabled: true,
            members: HashMap::default(),
            answer: None,
            undecided: false,
        }
    }
}

impl CallDepthProbeInput {
    pub(super) fn for_consumer(enabled: bool) -> Self {
        Self {
            enabled,
            ..Self::default()
        }
    }

    fn observe_relation(
        &mut self,
        result: &CallRelationResult,
        incoming: bool,
        proof: Option<UsageProof>,
    ) {
        if !self.enabled {
            return;
        }
        // Any partial bounded relation can omit members before they become
        // projectable sites, even when it also retains proven edges.
        // Diagnostic emission is deduplicated across operands; membership depends
        // on the retained raw relation and this operand's proof selection.
        self.undecided |= call_depth_relation_is_unknown(result, incoming, &[])
            || proof_filter_omits_ambiguous_calls(result, proof);
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn call_declaration_expansions(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
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
    depth_probe: &mut CallDepthProbeInput,
) -> (Vec<PipelineExpansion>, bool) {
    let incoming = matches!(step, QueryStep::Callers(_));
    if incoming {
        // A newly registered caller can change a negative membership result
        // even when the current caller files and their blobs are unchanged.
        analyzer.record_read(analyzer.workspace_scope_read_key(&Language::ANALYZABLE));
    }
    let declared_non_exhaustive = incoming
        && filter.completeness == brokk_bifrost_rql::CallTraversalCompleteness::ProvenSubset;
    let diagnostic_start = diagnostics.len();
    let mut queue = VecDeque::from([CallTraversalWork {
        unit: declaration.unit.clone(),
        depth: 0,
        path_tail: None,
    }]);
    let mut paths = Vec::new();
    let mut emitted = HashSet::default();
    if depth_probe.enabled {
        depth_probe
            .members
            .insert(declaration.unit.clone(), (declaration.clone(), 0));
    }
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
                declared_non_exhaustive,
                omitted,
                expansions,
                true,
            );
        }
        let relation_diagnostic_start = diagnostics.len();
        let result = cached_call_relation(
            analyzer,
            token,
            &work.unit,
            incoming,
            cache,
            budget,
            limits,
            cancellation,
            diagnostics,
            cache_profile,
        );
        if declared_non_exhaustive {
            reclassify_declared_subset_omissions(&mut diagnostics[relation_diagnostic_start..]);
        } else if filter.proof == Some(UsageProof::Proven) {
            mark_proven_call_ambiguity_incomplete(&result, diagnostics);
        }
        depth_probe.observe_relation(&result, incoming, filter.proof);
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
                    declared_non_exhaustive,
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
                    declared_non_exhaustive,
                    omitted,
                    expansions,
                    true,
                );
            }
            if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
                budget.pipeline_rows,
                limits.max_pipeline_rows,
            )
            .allows(1)
            {
                return finish_call_declaration_expansions(
                    diagnostics,
                    diagnostic_start,
                    declaration,
                    incoming,
                    declared_non_exhaustive,
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
                        declared_non_exhaustive,
                        omitted,
                        expansions,
                        true,
                    );
                }
            };
            let next_depth = work.depth + 1;
            if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
                budget.provenance_steps.saturating_add(next_depth),
                limits.max_pipeline_rows,
            )
            .allows(0)
            {
                budget.provenance_steps = limits.max_pipeline_rows;
                return finish_call_declaration_expansions(
                    diagnostics,
                    diagnostic_start,
                    declaration,
                    incoming,
                    declared_non_exhaustive,
                    omitted,
                    expansions,
                    true,
                );
            }
            budget.provenance_steps += next_depth;
            budget.pipeline_rows += 1;
            let call_site = CallSiteValue::new(
                site,
                CallBindingStatus::Unavailable,
                None,
                CallSiteIdentityFacts::default(),
            );
            let path_tail = paths.len();
            paths.push(CallPathNode {
                value: next.clone(),
                via: call_site,
                parent: work.path_tail,
            });
            expansions.push(PipelineExpansion {
                value: PipelineValue::Declaration(next.clone()),
                trace: call_trace_values(&paths, path_tail, next_depth),
                budgeted: true,
            });
            emitted.insert(next_unit.clone());
            if depth_probe.enabled {
                depth_probe
                    .members
                    .entry(next_unit.clone())
                    .and_modify(|(_, depth)| *depth = (*depth).min(next_depth))
                    .or_insert((next, next_depth));
            }
            if !cycle && next_depth < filter.depth.get() {
                queue.push_back(CallTraversalWork {
                    unit: next_unit,
                    depth: next_depth,
                    path_tail: Some(path_tail),
                });
            }
        }
    }
    depth_probe.undecided |= omitted > 0;
    finish_call_declaration_expansions(
        diagnostics,
        diagnostic_start,
        declaration,
        incoming,
        declared_non_exhaustive,
        omitted,
        expansions,
        exhausted,
    )
}

fn depth_probe_budget_stopped(result: &CallRelationResult) -> bool {
    result.truncated
        || result.diagnostics.iter().any(|diagnostic| {
            matches!(
                diagnostic.code,
                CallRelationDiagnosticCode::BudgetExhausted
                    | CallRelationDiagnosticCode::CandidateLimit
            )
        })
}

#[allow(clippy::too_many_arguments)]
fn cached_depth_probe_relation(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    read_scope: &brokk_bifrost_analysis::analyzer::AnalyzerQueryScope<'_>,
    unit: &CodeUnit,
    incoming: bool,
    cache: &mut CallDepthProbeCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
) -> Arc<CachedDepthProbeRelation> {
    let key = (unit.clone(), incoming);
    cache
        .relations
        .read_mut(&memo_attribution(analyzer), |entries| {
            if let Some(entry) = entries.get_mut(&key) {
                // Advisory scopes isolate completion, so memo attribution alone
                // cannot replay these gaps into a new probe attempt.
                for gap in &entry.read_gaps {
                    analyzer.record_query_incomplete(gap.clone());
                }
                for gap in read_scope.captured_read_incompleteness() {
                    if !entry.read_gaps.contains(&gap) {
                        Arc::make_mut(entry).read_gaps.push(gap);
                    }
                }
                return Arc::clone(entry);
            }
            let mut diagnostics = Vec::new();
            let result = cached_call_relation(
                analyzer,
                token,
                unit,
                incoming,
                &mut CallTraversalCache::default(),
                budget,
                limits,
                cancellation,
                &mut diagnostics,
                &mut None,
            );
            let entry = Arc::new(CachedDepthProbeRelation {
                result,
                diagnostics,
                read_gaps: read_scope.captured_read_incompleteness(),
            });
            // A fair-share retry has a larger allowance: never admit an
            // allowance-dependent partial answer, even without completion opt-in.
            if !depth_probe_budget_stopped(&entry.result) {
                entries.insert(key, Arc::clone(&entry));
            }
            entry
        })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn probe_call_depth_bound(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    step: &QueryStep,
    filter: &CallTraversalFilter,
    cache: &mut CallTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    depth_probe: &mut CallDepthProbeInput,
) -> DepthBoundStatus {
    let mut indexed = IndexedDeclarations::default();
    let incoming = matches!(step, QueryStep::Callers(_));
    let mut frontier = depth_probe
        .members
        .iter()
        .filter_map(|(unit, (_, depth))| (*depth == filter.depth.get()).then_some(unit))
        .collect::<Vec<_>>();
    frontier.sort_unstable();
    let mut members = depth_probe
        .members
        .values()
        .map(|(declaration, depth)| units::BoundedMemberRow {
            identity: units::bounded_member_row(&declaration.unit),
            depth: *depth,
        })
        .collect::<Vec<_>>();
    members.sort_by_cached_key(|key| {
        serde_json::to_string(&key.identity).expect("member identity serializes")
    });
    let mut answer = units::BoundedCallAnswer {
        traversal: String::new(),
        members,
        frontier: Vec::new(),
        bound: filter.depth.get(),
        undecided_frontier: Vec::new(),
        membership_unknown: depth_probe.undecided,
        budget_stopped: false,
    };
    if !depth_probe.undecided {
        let probe = cache
            .depth_probe
            .get_or_insert_with(|| Box::new(CallDepthProbeCache::default()));
        if incoming && !frontier.is_empty() {
            analyzer.record_read(analyzer.workspace_scope_read_key(&Language::ANALYZABLE));
        }
        for unit in frontier {
            let read_scope =
                brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::for_advisory_read(analyzer);
            // Witness enumeration uses the same metered scan lanes in both modes.
            // There is no separate witness cap and no early stop at the first hit.
            let cached = cached_depth_probe_relation(
                analyzer,
                token,
                &read_scope,
                unit,
                incoming,
                probe,
                budget,
                limits,
                cancellation,
            );
            let result = &cached.result;
            let mut diagnostics = cached.diagnostics.clone();
            if filter.proof == Some(UsageProof::Proven) {
                mark_proven_call_ambiguity_incomplete(result, &mut diagnostics);
            }
            let mut uncertain = call_depth_relation_is_unknown(result, incoming, &diagnostics)
                || proof_filter_omits_ambiguous_calls(result, filter.proof);
            answer.budget_stopped |= depth_probe_budget_stopped(result);
            let source = units::bounded_member_row(unit);
            for site in &result.sites {
                if filter.proof.is_some_and(|proof| proof != site.proof) {
                    continue;
                }
                let next = if incoming { &site.caller } else { &site.callee };
                if depth_probe.members.contains_key(next) {
                    continue;
                }
                if let Some(declaration) = indexed.get(analyzer, next) {
                    answer
                        .frontier
                        .push((source.clone(), units::bounded_member_row(&declaration.unit)));
                } else {
                    uncertain = true;
                }
            }
            let read_gaps = read_scope.captured_read_incompleteness();
            if read_gaps
                .iter()
                .any(brokk_bifrost_analysis::analyzer::QueryReadIncomplete::is_execution_dependent)
            {
                analyzer.mark_execution_dependent();
            }
            uncertain |= !read_gaps.is_empty();
            if uncertain {
                answer.undecided_frontier.push(source);
            }
            if answer.budget_stopped {
                break;
            }
        }
    }
    let status = answer.status();
    depth_probe.answer = Some(answer);
    status
}

#[cfg(test)]
mod depth_probe_tests {
    use super::*;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "e0b09002ed4d: partial relations with retained edges falsely certified depth witnesses"
    )]
    fn incomplete_bounded_membership_cannot_certify_a_depth_witness() {
        use super::super::tests::inline_project::InlineTestProject;
        use brokk_bifrost_analysis::analyzer::AnalyzerQueryScope;
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "src/lib.rs",
                "fn root() { middle(); }\nfn middle() { leaf(); }\nfn leaf() {}\n",
            )
            .build();
        let workspace = project.workspace_analyzer(Default::default());
        let analyzer = workspace.analyzer();
        let file = ProjectFile::new(project.root(), "src/lib.rs");
        let root = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.fq_name() == "root")
            .unwrap();
        let declaration = IndexedDeclarations::default().get(analyzer, &root).unwrap();
        let scope = AnalyzerQueryScope::new(analyzer);
        let filter = CallTraversalFilter::default();
        let step = QueryStep::Callees(filter.clone());
        let mut cache = CallTraversalCache::default();
        let mut input = CallDepthProbeInput::default();
        let (_, exhausted) = call_declaration_expansions(
            analyzer,
            scope.token(),
            &declaration,
            &step,
            &filter,
            &mut IndexedDeclarations::default(),
            &mut cache,
            &mut CodeQueryExecutionBudget::default(),
            CodeQueryExecutionLimits::default(),
            16,
            None,
            &mut Vec::new(),
            &mut None,
            &mut input,
        );
        assert!(!exhausted);
        assert_eq!(
            probe_call_depth_bound(
                analyzer,
                scope.token(),
                &step,
                &filter,
                &mut cache,
                &mut CodeQueryExecutionBudget::default(),
                CodeQueryExecutionLimits::default(),
                None,
                &mut input
            ),
            DepthBoundStatus::Reached
        );
        let complete = cache.outgoing.read(&memo_attribution(analyzer), |entries| {
            entries.get(&root).unwrap().clone()
        });
        for code in [
            CallRelationDiagnosticCode::CandidatesOmitted,
            CallRelationDiagnosticCode::AnalysisFailed,
        ] {
            let mut partial = complete.clone();
            assert!(
                !partial.sites.is_empty(),
                "the partial relation retains its edge"
            );
            partial.diagnostics.push(CallRelationDiagnostic {
                code,
                message: "a bounded relation omitted an undecided declaration".into(),
                context: "bounded relation".into(),
                semantic_count: None,
                reason_kind: None,
            });
            cache
                .outgoing
                .read_mut(&memo_attribution(analyzer), |entries| {
                    entries.insert(root.clone(), partial);
                });
            let mut input = CallDepthProbeInput::default();
            let (rows, _) = call_declaration_expansions(
                analyzer,
                scope.token(),
                &declaration,
                &step,
                &filter,
                &mut IndexedDeclarations::default(),
                &mut cache,
                &mut CodeQueryExecutionBudget::default(),
                CodeQueryExecutionLimits::default(),
                16,
                None,
                &mut Vec::new(),
                &mut None,
                &mut input,
            );
            assert!(!rows.is_empty(), "{code:?} must retain the bounded edge");
            assert_eq!(
                probe_call_depth_bound(
                    analyzer,
                    scope.token(),
                    &step,
                    &filter,
                    &mut cache,
                    &mut CodeQueryExecutionBudget::default(),
                    CodeQueryExecutionLimits::default(),
                    None,
                    &mut input
                ),
                DepthBoundStatus::Unknown,
                "{code:?} makes bounded membership uncertain"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "8bd7ac4470bf: omitted relation candidates falsely proved an empty depth frontier"
    )]
    fn relation_level_omission_makes_empty_frontier_unknown() {
        use crate::analyzer::CodeUnitType;
        use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, MultiAnalyzer};

        let analyzer = MultiAnalyzer::default();
        let file = ProjectFile::new(std::env::temp_dir(), "src/lib.rs");
        let unit = CodeUnit::new(file, CodeUnitType::Function, "", "target");
        let declaration = DeclarationValue::new(
            unit.clone(),
            Range {
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
                end_line: 1,
            },
        );
        let result = CallRelationResult {
            diagnostics: vec![CallRelationDiagnostic {
                code: CallRelationDiagnosticCode::CandidatesOmitted,
                message: "unprojectable caller".to_string(),
                context: "caller inventory".to_string(),
                semantic_count: None,
                reason_kind: None,
            }],
            ..CallRelationResult::default()
        };
        let mut cache = CallTraversalCache::default();
        cache
            .incoming
            .read_mut(&memo_attribution(&analyzer), |entries| {
                entries.insert(unit, result);
            });
        let filter = CallTraversalFilter {
            proof: Some(UsageProof::Proven),
            completeness: brokk_bifrost_rql::CallTraversalCompleteness::ProvenSubset,
            ..CallTraversalFilter::default()
        };
        let step = QueryStep::Callers(filter.clone());
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let mut input = CallDepthProbeInput::default();
        let (rows, exhausted) = call_declaration_expansions(
            &analyzer,
            token,
            &declaration,
            &step,
            &filter,
            &mut IndexedDeclarations::default(),
            &mut cache,
            &mut CodeQueryExecutionBudget::default(),
            CodeQueryExecutionLimits::default(),
            8,
            None,
            &mut Vec::new(),
            &mut None,
            &mut input,
        );
        assert!(rows.is_empty());
        assert!(!exhausted);
        let status = probe_call_depth_bound(
            &analyzer,
            token,
            &step,
            &filter,
            &mut cache,
            &mut CodeQueryExecutionBudget::default(),
            CodeQueryExecutionLimits::default(),
            None,
            &mut input,
        );
        assert_eq!(status, DepthBoundStatus::Unknown);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "e0b09002ed4d: cached advisory frontier gaps disappeared on a new attempt"
    )]
    fn probe_gap_is_unknown_with_outer_read_receipt_and_complete_query() {
        use brokk_bifrost_analysis::analyzer::read_ledger::ReadKey;
        use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
        use brokk_bifrost_analysis::analyzer::{
            AnalyzerQueryContext, AnalyzerQueryScope, CodeUnitIndex, MultiAnalyzer,
            QueryReadIncomplete, ReadLedger,
        };
        use std::sync::atomic::{AtomicBool, Ordering};

        struct GapOnProbeAnalyzer {
            inner: MultiAnalyzer,
            armed: AtomicBool,
            key: ReadKey,
        }
        impl CodeUnitIndex for GapOnProbeAnalyzer {
            fn project(&self) -> &dyn crate::analyzer::Project {
                self.inner.project()
            }
            fn languages(&self) -> BTreeSet<Language> {
                CodeUnitIndex::languages(&self.inner)
            }
            fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
                self.inner.all_declarations()
            }
            fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
                self.inner.search_definitions(pattern, auto_quote)
            }
            fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
                self.inner.enclosing_code_unit(file, range)
            }
            fn enclosing_code_unit_for_lines(
                &self,
                file: &ProjectFile,
                start: usize,
                end: usize,
            ) -> Option<CodeUnit> {
                self.inner.enclosing_code_unit_for_lines(file, start, end)
            }
            fn get_skeleton(&self, unit: &CodeUnit) -> Option<String> {
                self.inner.get_skeleton(unit)
            }
            fn get_skeleton_header(&self, unit: &CodeUnit) -> Option<String> {
                self.inner.get_skeleton_header(unit)
            }
            fn get_source(&self, unit: &CodeUnit, comments: bool) -> Option<String> {
                self.inner.get_source(unit, comments)
            }
            fn get_sources(&self, unit: &CodeUnit, comments: bool) -> BTreeSet<String> {
                self.inner.get_sources(unit, comments)
            }
        }
        impl IAnalyzer for GapOnProbeAnalyzer {
            brokk_bifrost_analysis::forward_query_read_ledger!();
            fn update_with_listing(
                &self,
                changed_files: &BTreeSet<ProjectFile>,
                listing: Option<&brokk_bifrost_core::analyzer::project::SharedWorkspaceFileListing>,
            ) -> Self {
                Self {
                    inner: self.inner.update_with_listing(changed_files, listing),
                    armed: AtomicBool::new(self.armed.load(Ordering::Relaxed)),
                    key: self.key.clone(),
                }
            }
            fn update_all(&self) -> Self {
                Self {
                    inner: self.inner.update_all(),
                    armed: AtomicBool::new(self.armed.load(Ordering::Relaxed)),
                    key: self.key.clone(),
                }
            }
            fn begin_query(&self, context: &Arc<AnalyzerQueryContext>) {
                self.inner.begin_query(context);
                if self.armed.swap(false, Ordering::Relaxed) {
                    self.inner.record_read(self.key.clone());
                    self.inner
                        .record_query_incomplete(QueryReadIncomplete::Cancelled);
                }
            }
            fn end_query(&self, context: &Arc<AnalyzerQueryContext>) {
                self.inner.end_query(context);
            }
            fn is_access_expression(&self, file: &ProjectFile, start: usize, end: usize) -> bool {
                self.inner.is_access_expression(file, start, end)
            }
            fn find_nearest_declaration(
                &self,
                file: &ProjectFile,
                start: usize,
                end: usize,
                ident: &str,
            ) -> Option<crate::analyzer::DeclarationInfo> {
                self.inner.find_nearest_declaration(file, start, end, ident)
            }
        }

        let key = ReadKey::Configuration(StableDigest::sha256(b"depth frontier"));
        let analyzer = GapOnProbeAnalyzer {
            inner: MultiAnalyzer::default(),
            armed: AtomicBool::new(false),
            key: key.clone(),
        };
        let ledger = Arc::new(ReadLedger::new());
        let outer = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
        let unit = CodeUnit::new(
            ProjectFile::new(std::env::temp_dir(), "frontier.rs"),
            crate::analyzer::CodeUnitType::Function,
            "",
            "frontier",
        );
        let declaration = DeclarationValue::new(
            unit.clone(),
            Range {
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
                end_line: 1,
            },
        );
        let filter = CallTraversalFilter::default();
        let step = QueryStep::Callees(filter.clone());
        let mut input = CallDepthProbeInput::default();
        input
            .members
            .insert(unit.clone(), (declaration, filter.depth.get()));
        let mut cache = CallTraversalCache::default();
        let probe = cache.depth_probe.get_or_insert_with(Default::default);
        probe
            .relations
            .read_mut(&memo_attribution(&analyzer), |entries| {
                entries.insert((unit, false), Arc::new(CachedDepthProbeRelation::default()));
            });
        // The next scope belongs to probe_call_depth_bound, not this test.
        // Its relation is complete-empty: only the advisory read gap can
        // change NotReached to Unknown.
        analyzer.armed.store(true, Ordering::Relaxed);
        let status = probe_call_depth_bound(
            &analyzer,
            outer.token(),
            &step,
            &filter,
            &mut cache,
            &mut CodeQueryExecutionBudget::default(),
            CodeQueryExecutionLimits::default(),
            None,
            &mut input,
        );
        assert!(!analyzer.armed.load(Ordering::Relaxed));
        assert_eq!(status, DepthBoundStatus::Unknown);
        assert_eq!(input.answer.as_ref().unwrap().undecided_frontier.len(), 1);
        assert!(!input.undecided);
        assert_eq!(
            probe_call_depth_bound(
                &analyzer,
                outer.token(),
                &step,
                &filter,
                &mut cache,
                &mut CodeQueryExecutionBudget::default(),
                CodeQueryExecutionLimits::default(),
                None,
                &mut input,
            ),
            DepthBoundStatus::Unknown,
            "cached advisory gaps survive a new attempt"
        );
        assert_eq!(outer.read_completion(), Ok(()));
        assert!(ledger.keys().contains(&key));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "3b2d094964ec: a larger retry reused a budget-truncated frontier relation"
    )]
    fn depth_probe_retries_with_a_larger_allowance() {
        use super::super::tests::inline_project::InlineTestProject;
        use brokk_bifrost_analysis::analyzer::AnalyzerQueryScope;
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "src/lib.rs",
                "fn root() { middle(); }\nfn middle() { leaf(); }\nfn leaf() {}\n",
            )
            .build();
        let workspace = project.workspace_analyzer(Default::default());
        let analyzer = workspace.analyzer();
        let file = ProjectFile::new(project.root(), "src/lib.rs");
        let root = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.fq_name() == "root")
            .unwrap();
        let declaration = IndexedDeclarations::default().get(analyzer, &root).unwrap();
        let scope = AnalyzerQueryScope::new(analyzer);
        let filter = CallTraversalFilter::default();
        let step = QueryStep::Callees(filter.clone());
        let mut cache = CallTraversalCache::default();
        let mut input = CallDepthProbeInput::default();
        let (_, exhausted) = call_declaration_expansions(
            analyzer,
            scope.token(),
            &declaration,
            &step,
            &filter,
            &mut IndexedDeclarations::default(),
            &mut cache,
            &mut CodeQueryExecutionBudget::default(),
            CodeQueryExecutionLimits::default(),
            16,
            None,
            &mut Vec::new(),
            &mut None,
            &mut input,
        );
        assert!(!exhausted);
        let stopped = probe_call_depth_bound(
            analyzer,
            scope.token(),
            &step,
            &filter,
            &mut cache,
            &mut CodeQueryExecutionBudget::default(),
            CodeQueryExecutionLimits {
                max_scanned_files: 0,
                ..Default::default()
            },
            None,
            &mut input,
        );
        assert_eq!(stopped, DepthBoundStatus::Unknown);
        assert!(input.answer.as_ref().unwrap().budget_stopped);
        assert_eq!(
            probe_call_depth_bound(
                analyzer,
                scope.token(),
                &step,
                &filter,
                &mut cache,
                &mut CodeQueryExecutionBudget::default(),
                CodeQueryExecutionLimits::default(),
                None,
                &mut input,
            ),
            DepthBoundStatus::Reached
        );
        assert!(!input.answer.as_ref().unwrap().budget_stopped);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "69e0507ebf4b: legacy Unknown caller inventory falsely certified bounded membership"
    )]
    fn bounded_membership_and_frontier_require_complete_caller_inventory() {
        for authority in [UsageProofAuthority::Legacy, UsageProofAuthority::Native] {
            for coverage in [
                CallerInventoryCoverage::Unknown,
                CallerInventoryCoverage::Incomplete,
                CallerInventoryCoverage::Complete,
            ] {
                let relation = CallRelationResult {
                    proof_authority: authority,
                    caller_inventory: coverage,
                    ..Default::default()
                };
                for incoming in [false, true] {
                    let expected = incoming && coverage != CallerInventoryCoverage::Complete;
                    let mut bounded = CallDepthProbeInput::default();
                    bounded.observe_relation(&relation, incoming, None);
                    assert_eq!(
                        bounded.undecided, expected,
                        "bounded: {authority:?} {coverage:?} incoming={incoming}"
                    );
                    assert_eq!(
                        call_depth_relation_is_unknown(&relation, incoming, &[]),
                        expected,
                        "frontier: {authority:?} {coverage:?} incoming={incoming}"
                    );
                }
            }
        }
    }

    #[test]
    fn incomplete_inventory_budget_and_cancellation_never_prove_absence() {
        let complete = CallRelationResult {
            caller_inventory: CallerInventoryCoverage::Complete,
            proof_authority: UsageProofAuthority::Native,
            ..CallRelationResult::default()
        };
        assert!(!call_depth_relation_is_unknown(&complete, true, &[]));
        assert!(!call_depth_relation_is_unknown(&complete, false, &[]));

        let incomplete_inventory = CallRelationResult {
            caller_inventory: CallerInventoryCoverage::Incomplete,
            ..complete.clone()
        };
        assert!(call_depth_relation_is_unknown(
            &incomplete_inventory,
            true,
            &[]
        ));
        let budget_stop = CallRelationResult {
            truncated: true,
            ..complete.clone()
        };
        assert!(call_depth_relation_is_unknown(&budget_stop, false, &[]));
        let cancelled = CallRelationResult {
            cancelled: true,
            ..complete
        };
        assert!(call_depth_relation_is_unknown(&cancelled, true, &[]));
    }
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
        if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(*work, max_work)
            .allows(1)
        {
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
    tail: usize,
    depth: usize,
) -> Vec<(PipelineTraceValue, Option<PipelineVia>)> {
    super::parent_path_values(tail, depth, |index| {
        let node = &paths[index];
        (
            (
                PipelineTraceValue::Declaration(node.value.clone()),
                Some(PipelineVia::CallSite(Box::new(node.via.clone()))),
            ),
            node.parent,
        )
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn inbound_reference_expansions(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    step: &QueryStep,
    filter: &ReferenceTraversalFilter,
    indexed: &mut IndexedDeclarations,
    cache: &mut ReferenceTraversalCache,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    max_hits: usize,
    cancellation: Option<&CancellationToken>,
    cache_profile: &mut Option<QueryCacheProfile>,
) -> (Vec<PipelineExpansion>, bool) {
    let inbound = &mut cache.inbound;
    inbound.read_mut(&memo_attribution(analyzer), |inbound| {
    let cache_hit = inbound.contains_key(&declaration.unit);
    let mut exhausted = cache_hit && cache.inbound_exhausted.contains(&declaration.unit);
    if let Some(profile) = cache_profile {
        if cache_hit {
            profile.inbound_reference.record_hit(
                Some(!cache.inbound_incomplete.contains(&declaration.unit)),
                inbound.get(&declaration.unit).map_or(0, Vec::len),
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
            inbound.insert(declaration.unit.clone(), Vec::new());
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
            diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                incompleteness: brokk_bifrost_rql::Incompleteness::Content,
                related: Vec::new(),
                source: None,
                code: CodeQueryDiagnosticCode::ReferenceSourceBytesTruncated,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: crate::analyzer::common::language_for_file(declaration.unit.source())
                    .config_label(),
                message: format!(
                    "references_of source-byte budget truncated candidate files for {}",
                    declaration.unit.fq_name()
                ),
                exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            }));
        } else if report && query.candidate_files_truncated {
            exhausted = true;
            diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                incompleteness: brokk_bifrost_rql::Incompleteness::Content,
                related: Vec::new(),
                source: None,
                code: CodeQueryDiagnosticCode::ReferenceCandidateFilesTruncated,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: crate::analyzer::common::language_for_file(declaration.unit.source())
                    .config_label(),
                message: format!(
                    "references_of candidate files were truncated for {}",
                    declaration.unit.fq_name()
                ),
                exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            }));
        }
        if let FuzzyResult::Incomplete {
            diagnostics: reasons,
            ..
        } = &query.result
            && report
        {
            diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                incompleteness: brokk_bifrost_rql::Incompleteness::Content,
                related: Vec::new(),
                source: None,
                exhausted_roots: Vec::new(),
                code: CodeQueryDiagnosticCode::ReferenceAnalysisFailed,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: crate::analyzer::common::language_for_file(declaration.unit.source())
                    .config_label(),
                message: format!(
                    "references_of analysis is incomplete for {}: {reasons:?}",
                    declaration.unit.fq_name()
                ),
                withheld_rows_path: None,
            }));
        }
        match query.result {
            FuzzyResult::Success {
                hits_by_overload,
                unproven_by_overload,
                unproven_total_by_overload,
            }
            | FuzzyResult::Incomplete {
                hits_by_overload,
                unproven_by_overload,
                unproven_total_by_overload,
                ..
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
                        diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                            incompleteness: brokk_bifrost_rql::Incompleteness::Operational(brokk_bifrost_rql::DiagnosticExecutionCause::Provider),
                            related: Vec::new(),
                            source: None,
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
                        exhausted_roots: Vec::new(),
                            withheld_rows_path: None,
                        }));
                    }
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
                    diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                        incompleteness: brokk_bifrost_rql::Incompleteness::Content,
                        related: Vec::new(),
                        source: None,
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
                    exhausted_roots: Vec::new(),
                        withheld_rows_path: None,
                    }));
                }
            }
            FuzzyResult::Failure { reason, .. } => {
                if report {
                    diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                        incompleteness: brokk_bifrost_rql::Incompleteness::Content,
                        related: Vec::new(),
                        source: None,
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
                        exhausted_roots: Vec::new(),
                        withheld_rows_path: None,
                    }));
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
        inbound.insert(declaration.unit.clone(), hits);
    }

    let mut sites = Vec::new();
    let mut unclassified = Vec::new();
    let mut omitted_enclosing_declarations = 0usize;
    let mut enclosing = filter
        .enclosing
        .as_ref()
        .map(|pattern| EnclosingPatternEvaluator::new(analyzer, pattern));
    for hit in inbound
        .get(&declaration.unit)
        .into_iter()
        .flatten()
        .filter(|hit| reference_hit_matches(hit, filter, &mut unclassified))
    {
        if let Some(enclosing) = enclosing.as_mut() {
            let site = format!(
                "{}:{}@{}",
                crate::path_utils::workspace_relative_slash_path(hit.file.rel_path()),
                hit.range.start_line,
                hit.range.start_byte
            );
            if !enclosing.keeps(
                environment_cache,
                Some(&hit.enclosing_unit),
                site,
                budget,
                limits,
                cancellation,
                diagnostics,
            ) {
                continue;
            }
        }
        let (site, enclosing_projection_omitted) =
            reference_site_value(analyzer, hit, declaration.clone(), indexed, None);
        omitted_enclosing_declarations = omitted_enclosing_declarations
            .saturating_add(usize::from(enclosing_projection_omitted));
        sites.push(site);
    }
    report_unclassified_reference_kinds(
        &filter.reference_kinds,
        unclassified,
        crate::analyzer::common::language_for_file(declaration.unit.source()),
        diagnostics,
    );
    if let Some(enclosing) = enclosing {
        enclosing.finish(
            crate::analyzer::common::language_for_file(declaration.unit.source()),
            diagnostics,
        );
    }
    if omitted_enclosing_declarations > 0 {
        exhausted = true;
        diagnostics.retain(|diagnostic| {
            diagnostic.code != CodeQueryDiagnosticCode::ReferenceTargetsAmbiguous
        });
        diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
            incompleteness: brokk_bifrost_rql::Incompleteness::Operational(brokk_bifrost_rql::DiagnosticExecutionCause::Provider),
            related: Vec::new(),
            source: None,
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
        exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        }));
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
    })
}

fn fuzzy_result_examination_count(result: &FuzzyResult) -> usize {
    match result {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_total_by_overload,
            ..
        }
        | FuzzyResult::Incomplete {
            hits_by_overload,
            unproven_total_by_overload,
            ..
        } => {
            hits_by_overload.values().map(BTreeSet::len).sum::<usize>()
                + unproven_total_by_overload.values().sum::<usize>()
        }
        FuzzyResult::TooManyCallsites {
            total_callsites, ..
        } => *total_callsites,
        FuzzyResult::Failure { .. } => 0,
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
        diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
            incompleteness: brokk_bifrost_rql::Incompleteness::Content,
            related: Vec::new(),
            source: None,
            code: CodeQueryDiagnosticCode::UsesTargetsAmbiguous,
            impact: CodeQueryDiagnosticImpact::Advisory,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "uses emitted {ambiguous_sites} ambiguous reference site{} in {} as unproven",
                if ambiguous_sites == 1 { "" } else { "s" },
                rel_path_string(file)
            ),
            exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        }));
    }
    if omitted > 0 {
        diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
            incompleteness: brokk_bifrost_rql::Incompleteness::Operational(brokk_bifrost_rql::DiagnosticExecutionCause::Provider),
            related: Vec::new(),
            source: None,
            code: CodeQueryDiagnosticCode::UsesCandidatesOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "uses omitted {omitted} candidate reference site{} in {} because the structured usage analyzer did not confirm every exact edge",
                if omitted == 1 { "" } else { "s" },
                rel_path_string(file)
            ),
        exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        }));
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
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "policy.units unbounded origin={}:{} cause=provider:indexed_source",
                file!(),
                line!()
            )
        });
        analyzer.mark_execution_dependent();
        diagnostics.push(super::QueryExecutionState::diagnostic(
            analyzer,
            CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                incompleteness: brokk_bifrost_rql::Incompleteness::Operational(
                    brokk_bifrost_rql::DiagnosticExecutionCause::Provider,
                ),
                related: Vec::new(),
                source: None,
                code: CodeQueryDiagnosticCode::UsesCandidatesOmitted,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "uses could not inspect {} because its indexed source snapshot was unavailable",
                    rel_path_string(file)
                ),
                exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            }),
            Some(DerivationExecutionCause::Provider),
        ));
        return (Vec::new(), true);
    };
    let remaining_source_bytes = limits
        .max_scanned_source_bytes
        .saturating_sub(budget.scanned_source_bytes);
    if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
        budget.scanned_files,
        limits.max_scanned_files,
    )
    .allows(1)
        || !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
            0,
            remaining_source_bytes,
        )
        .allows(source.len())
    {
        push_budget_diagnostic(diagnostics, budget);
        return (Vec::new(), true);
    }
    budget.scanned_files += 1;
    budget.scanned_source_bytes += source.len();
    let source = Arc::<str>::from(source);
    let parsed = crate::analyzer::usages::get_definition::parse_tree_for_language_outcome(
        file, language, &source,
    );
    let incompleteness = match &parsed {
        Err(cause) => Incompleteness::Operational(*cause),
        Ok(_) => Incompleteness::Content,
    };
    let Ok(Some(tree)) = parsed else {
        diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
            incompleteness,
            related: Vec::new(),
            source: None,
            code: CodeQueryDiagnosticCode::UsesParserUnsupported,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!("uses does not support parsing {}", rel_path_string(file)),
            exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        }));
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
            diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                incompleteness: brokk_bifrost_rql::Incompleteness::Content,
                related: Vec::new(),
                source: None,
                code: CodeQueryDiagnosticCode::UsesCandidateLimit,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "uses returned a bounded partial scan of {} after reaching the structured reference-candidate limit of {candidate_limit}",
                    rel_path_string(file)
                ),
            exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            }));
        }
    }
    if candidate_limit == 0 {
        exhausted = true;
        diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
            incompleteness: brokk_bifrost_rql::Incompleteness::Content,
            related: Vec::new(),
            source: None,
            code: CodeQueryDiagnosticCode::UsesCandidateLimit,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: language.config_label(),
            message: format!(
                "uses has no reference-candidate capacity for {}",
                rel_path_string(file)
            ),
            exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        }));
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
        if let FuzzyResult::Incomplete {
            diagnostics: reasons,
            ..
        } = &result.result
        {
            diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                incompleteness: brokk_bifrost_rql::Incompleteness::Content,
                related: Vec::new(),
                source: None,
                exhausted_roots: Vec::new(),
                code: CodeQueryDiagnosticCode::ReferenceAnalysisFailed,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "uses analysis is incomplete for {}: {reasons:?}",
                    target.fq_name()
                ),
                withheld_rows_path: None,
            }));
        }
        let (target_hits, target_truncated) =
            reference_hits_for_target(analyzer, result.result, target);
        if target_truncated {
            exhausted = true;
            diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                incompleteness: brokk_bifrost_rql::Incompleteness::Content,
                related: Vec::new(),
                source: None,
                code: CodeQueryDiagnosticCode::UsesCandidateLimit,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "uses retained a bounded positive reference sample for {} after the usage analyzer reached its candidate limit",
                    target.fq_name()
                ),
            exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            }));
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
