//! Source-root projection for the shared call expansion. No policy names live here.
use super::dispatch::{DispatchArm, DispatchProof};
use super::*;
use crate::analyzer::common::language_for_file;
use crate::analyzer::semantic::ProcedureKind;
use crate::analyzer::usages::get_definition::{
    CallApplicationKind, CallTargetLookupOutcome, DefinitionLookupStatus,
};
use brokk_bifrost_core::analyzer::model::DispatchExtensibility;

pub(super) fn static_call_proof(
    lookup: Option<&CallTargetLookupOutcome>,
    arm: &DispatchArm,
    no_receiver: bool,
) -> Option<StaticCallProof> {
    let lookup = lookup?;
    if lookup.truncated
        || lookup.structure_unavailable
        || lookup.unproven_link_unit
        || arm.proof != DispatchProof::Proven
    {
        return None;
    }
    if let Some(proof) = &lookup.exact_external_call
        && lookup.external_callee_identity.is_some()
        && lookup.external_callee_identity == arm.external_callee_identity
    {
        return match proof.call_application() {
            CallApplicationKind::PackageFunction | CallApplicationKind::ExtensionArgument => {
                Some(StaticCallProof::ExactExternalProcedure)
            }
            CallApplicationKind::BoundReceiver
                if proof.dispatch_extensibility() == Some(DispatchExtensibility::Closed) =>
            {
                Some(StaticCallProof::NonvirtualReceiver)
            }
            _ => None,
        };
    }
    if lookup.outcome.status != DefinitionLookupStatus::Resolved {
        return None;
    }
    let [target] = lookup.outcome.definitions.as_slice() else {
        return None;
    };
    if arm.target_unit.as_ref() != Some(target) {
        return None;
    }
    // This is an exact callee-token declaration binding, not a points-to target.
    // A variable or field containing a callable is not the named function declaration.
    if no_receiver
        && matches!(
            arm.target_kind,
            Some(ProcedureKind::Function | ProcedureKind::LocalFunction)
        )
    {
        return Some(StaticCallProof::DirectDeclaration);
    }
    if matches!(
        lookup.call_application,
        CallApplicationKind::PackageFunction | CallApplicationKind::ExtensionArgument
    ) {
        return Some(StaticCallProof::DirectDeclaration);
    }
    (lookup.call_application == CallApplicationKind::BoundReceiver
        && lookup.dispatch_extensibility == Some(DispatchExtensibility::Closed))
    .then_some(StaticCallProof::NonvirtualReceiver)
}

type SiteKey = (String, usize, usize, String);
pub(super) fn site_key(site: &CallSite) -> SiteKey {
    (
        rel_path_string(&site.file),
        site.range.start_byte,
        site.range.end_byte,
        site.callee.declaration_id().to_string(),
    )
}

pub(super) struct CallPathCandidate {
    site: CallSiteValue,
    path: StaticCallPath,
}
pub(super) struct CallPathProjection<'a, 's> {
    sources: Vec<CallPathSource>,
    root: DeclarationValue,
    root_location: CallPathLocation,
    semantic: &'s mut Option<SemanticQueryContext<'a>>,
    selected_sinks: &'s SinkSelection,
    reached: Option<&'s mut super::reached_sinks::ReachedSinkSites>,
    candidates: Vec<CallPathCandidate>,
    evidence: CallPathEvidence,
    candidate_bytes: usize,
    coordinates: &'s mut PipelineRenderCache,
}

fn location(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    range: Range,
    cache: &mut PipelineRenderCache,
) -> Option<CallPathLocation> {
    let coordinates = cache.coordinates_for(analyzer, file, || analyzer.indexed_source(file))?;
    let source = &coordinates.source;
    if range.start_byte >= range.end_byte || range.end_byte > source.len() {
        return None;
    }
    Some(CallPathLocation {
        rel_path: rel_path_string(file),
        byte_span: range.start_byte..range.end_byte,
        display_range: range_for_offsets(
            source,
            &coordinates.line_starts,
            range.start_byte,
            range.end_byte,
        ),
    })
}

impl CallPathProjection<'_, '_> {
    pub(super) fn observe_relation(&mut self, result: &CallRelationResult, incoming: bool) {
        if !super::relations::call_relation_result_complete(result, incoming) {
            self.evidence.add_gap(if result.cancelled {
                CallPathGap::Cancelled
            } else if result.truncated {
                CallPathGap::ExecutionBudget
            } else {
                CallPathGap::RelationIncomplete
            });
            self.evidence.truncated |= result.truncated || result.cancelled;
        }
    }

    pub(super) fn missing_target_body(
        &mut self,
        target: &CodeUnit,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        self.evidence.add_gap(CallPathGap::ExternalBodyUnavailable);
        diagnostics.push(incomplete_diagnostic(
            CodeQueryDiagnosticCode::SemanticResultsOmitted,
            Incompleteness::Content,
            language_for_file(self.root.unit.source()).config_label(),
            format!(
                "call-reachability boundary: body unavailable for {}",
                target.declaration_id()
            ),
            Vec::new(),
        ));
    }

    pub(super) fn missing_owner(&mut self) {
        self.evidence.add_gap(CallPathGap::UnreadableOwner);
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn visit(
        &mut self,
        analyzer: &dyn IAnalyzer,
        owner: &DeclarationValue,
        prefix: &[CallSiteValue],
        cache: &mut CallTraversalCache,
        budget: &mut CodeQueryExecutionBudget,
        limits: CodeQueryExecutionLimits,
        cancellation: Option<&CancellationToken>,
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) -> HashMap<SiteKey, CallSiteValue> {
        let allowance = limits
            .max_pipeline_rows
            .saturating_sub(budget.pipeline_rows);
        let (sites, stopped) = super::relations::source_call_site_expansions(
            analyzer,
            owner,
            &CallSiteTraversalFilter::default(),
            cache,
            budget,
            limits,
            allowance,
            cancellation,
            diagnostics,
            self.semantic,
            super::relations::SourceCallInventoryMode::Reachability,
        );
        if stopped {
            self.evidence.truncated = true;
            self.evidence.add_gap(CallPathGap::ExecutionBudget);
        }
        let mut certified = HashMap::default();
        let mut sites = sites
            .into_iter()
            .filter_map(|site| match site.value {
                PipelineValue::CallSite(site) => Some(site),
                _ => None,
            })
            .collect::<Vec<_>>();
        sites.sort_by_cached_key(|site| site_key(&site.0));
        for site in sites {
            if budget.provenance_steps >= limits.max_pipeline_rows {
                self.evidence.truncated = true;
                self.evidence.add_gap(CallPathGap::ExecutionBudget);
                break;
            }
            budget.provenance_steps += 1;
            if let Some(reached) = self.reached.as_mut()
                && !reached.insert(&site, budget, limits)
            {
                self.evidence.truncated = true;
                self.evidence.add_gap(CallPathGap::ExecutionBudget);
                break;
            }
            let Some(proof) = site.6.as_ref().and_then(|target| target.static_proof) else {
                self.evidence.add_gap(CallPathGap::UncertifiedDispatch);
                continue;
            };
            let target = if site.0.callee.is_callable() {
                site.0.callee.declaration_id().to_string()
            } else {
                self.evidence.add_gap(CallPathGap::ExternalBodyUnavailable);
                let Some(target) = site.6.as_ref().and_then(|target| target.target_id.clone())
                else {
                    self.evidence.add_gap(CallPathGap::UncertifiedDispatch);
                    continue;
                };
                diagnostics.push(incomplete_diagnostic(
                    CodeQueryDiagnosticCode::SemanticResultsOmitted,
                    Incompleteness::Content,
                    language_for_file(&site.0.file).config_label(),
                    format!(
                        "call-reachability boundary: external body {target} unavailable at {}:{}..{}",
                        rel_path_string(&site.0.file), site.0.range.start_byte, site.0.range.end_byte,
                    ),
                    Vec::new(),
                ));
                target
            };
            // The inventory pass retains no path certificates. Once all
            // reached anchors are known, the ordinary sink plan evaluates
            // its shared dependencies once under that endpoint demand.
            // Every certified edge remains available in both passes.
            if self.reached.is_some() || !self.selected_sinks.contains(analyzer, &site) {
                certified.insert(site_key(&site.0), site);
                continue;
            }
            let Some(call_location) =
                location(analyzer, &site.0.file, site.0.range, self.coordinates)
            else {
                self.evidence
                    .add_gap(CallPathGap::MissingExpansionProvenance);
                continue;
            };
            let mut edges = Vec::with_capacity(prefix.len() + 1);
            for edge in prefix {
                let Some(edge_location) =
                    location(analyzer, &edge.0.file, edge.0.range, self.coordinates)
                else {
                    self.evidence
                        .add_gap(CallPathGap::MissingExpansionProvenance);
                    break;
                };
                edges.push(CallPathEdge {
                    caller: edge.0.caller.declaration_id().to_string(),
                    call_site: edge_location,
                    static_target: edge.0.callee.declaration_id().to_string(),
                    proof: edge
                        .6
                        .as_ref()
                        .and_then(|target| target.static_proof)
                        .expect("only certified edges enter the predecessor arena"),
                });
            }
            if edges.len() != prefix.len() {
                continue;
            }
            edges.push(CallPathEdge {
                caller: owner.unit.declaration_id().to_string(),
                call_site: call_location,
                static_target: target,
                proof,
            });
            for source in &self.sources {
                if budget.pipeline_rows >= limits.max_pipeline_rows
                    || budget.provenance_steps.saturating_add(edges.len())
                        > limits.max_pipeline_rows
                {
                    self.evidence.truncated = true;
                    self.evidence.add_gap(CallPathGap::ExecutionBudget);
                    break;
                }
                budget.pipeline_rows += 1;
                budget.provenance_steps += edges.len();
                let path = StaticCallPath {
                    source: source.clone(),
                    primary_root: self.root_location.clone(),
                    root_identity: self.root.unit.declaration_id().to_string(),
                    edges: edges.clone(),
                };
                let certificate = CallPathEvidence {
                    paths: vec![path],
                    coverage: CallPathCoverage::Complete,
                    truncated: false,
                };
                let bytes = certificate.retained_bytes();
                let retained = budget.retained_evidence_bytes.saturating_add(bytes);
                if retained > limits.semantic.max_retained_bytes {
                    self.evidence.truncated = true;
                    self.evidence.add_gap(CallPathGap::ExecutionBudget);
                    break;
                }
                budget.retained_evidence_bytes = retained;
                self.candidate_bytes = self.candidate_bytes.saturating_add(bytes);
                self.candidates.push(CallPathCandidate {
                    site: site.clone(),
                    path: certificate.paths.into_iter().next().expect("one candidate"),
                });
            }
            certified.insert(site_key(&site.0), site);
        }
        if self.evidence.truncated {
            analyzer.mark_execution_dependent();
        }
        certified
    }
}

// The operator projects selected sink rows back to source roots. Keep advisory
// uncertainty from contributing sink branches at that projection boundary: root
// provenance describes the source plan, not the sink plan's internal branches.
fn lift_projection_advisories(
    diagnostics: &mut [CodeQueryDiagnostic],
    branches: &[&[usize]],
    incomplete_provenance: bool,
) {
    for diagnostic in diagnostics {
        if diagnostic.impact == CodeQueryDiagnosticImpact::Advisory
            && (incomplete_provenance
                || branches
                    .iter()
                    .any(|branch| branch.starts_with(&diagnostic.branch)))
        {
            diagnostic.branch.clear();
        }
    }
}

type SelectedSiteKey = (String, usize, usize, Option<String>);

struct SinkSelection {
    endpoints: SelectionEndpoints,
    truncated: bool,
    diagnostics: std::ops::Range<usize>,
    receipt: Option<(
        Arc<[crate::analyzer::read_ledger::ReadKey]>,
        brokk_bifrost_core::analyzer::memo_attribution::ReadChannels,
    )>,
    #[cfg(any(test, feature = "test-support"))]
    probe: Option<super::reached_sinks::CallReachabilityDemandProbe>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SinkProvenance {
    branches: Vec<Vec<usize>>,
    incomplete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SinkEndpoint {
    pub(super) site: SelectedSiteKey,
    provenance: SinkProvenance,
}

pub(super) fn sink_endpoints(rows: &[PipelineRow]) -> Vec<SinkEndpoint> {
    rows.iter()
        .filter_map(|row| {
            let (file, range, target) = match &row.value {
                PipelineValue::StructuralMatch(seed) => (&seed.file, seed_range(seed), None),
                PipelineValue::CallSite(site) => (
                    &site.0.file,
                    site.0.range,
                    site.6.as_ref().and_then(|target| target.target_id.clone()),
                ),
                PipelineValue::DispatchTarget(target) => (
                    target.file(),
                    target.site.range,
                    Some(target.arm().target_id.clone()),
                ),
                _ => return None,
            };
            Some(SinkEndpoint {
                site: (
                    rel_path_string(file),
                    range.start_byte,
                    range.end_byte,
                    target,
                ),
                provenance: SinkProvenance {
                    branches: row
                        .traces
                        .iter()
                        .map(|trace| trace.branch.clone())
                        .collect(),
                    incomplete: row.provenance_truncated || row.traces.is_empty(),
                },
            })
        })
        .collect()
}

impl SinkEndpoint {
    fn payload_bytes(&self) -> usize {
        self.site.0.capacity()
            + self.site.3.as_ref().map_or(0, String::capacity)
            + self.provenance.branches.capacity() * std::mem::size_of::<Vec<usize>>()
            + self
                .provenance
                .branches
                .iter()
                .map(|branch| branch.capacity() * std::mem::size_of::<usize>())
                .sum::<usize>()
    }
}

enum SelectionEndpoints {
    Owned(Vec<SinkEndpoint>),
    Shared(Arc<units::CallReachabilitySinkProduct>),
}

impl SinkSelection {
    fn retained_bytes(&self) -> usize {
        let SelectionEndpoints::Owned(endpoints) = &self.endpoints else {
            return 0; // The supplied operand owns its storage and accounting.
        };
        endpoints.capacity() * std::mem::size_of::<SinkEndpoint>()
            + endpoints
                .iter()
                .map(SinkEndpoint::payload_bytes)
                .sum::<usize>()
    }

    fn endpoints(&self) -> &[SinkEndpoint] {
        match &self.endpoints {
            SelectionEndpoints::Owned(rows) => rows,
            SelectionEndpoints::Shared(product) => &product.endpoints,
        }
    }

    fn matching(&self, key: &SelectedSiteKey) -> std::ops::Range<usize> {
        let endpoints = self.endpoints();
        let first = endpoints.partition_point(|endpoint| endpoint.site < *key);
        let count = endpoints[first..].partition_point(|endpoint| endpoint.site == *key);
        first..first + count
    }

    fn contains(&self, analyzer: &dyn IAnalyzer, site: &CallSiteValue) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(probe) = &self.probe {
            probe.lookup();
        }
        if let Some((keys, channels)) = &self.receipt {
            brokk_bifrost_analysis::analyzer::i_analyzer::replay_shared_query_read_receipt(
                analyzer, keys, *channels,
            );
        }
        let key = (
            rel_path_string(&site.0.file),
            site.0.range.start_byte,
            site.0.range.end_byte,
            None,
        );
        !self.matching(&key).is_empty()
            || site
                .6
                .as_ref()
                .and_then(|target| target.target_id.clone())
                .is_some_and(|target| {
                    !self
                        .matching(&(key.0, key.1, key.2, Some(target)))
                        .is_empty()
                })
    }
}

fn select_sinks(
    token: QueryToken<'_>,
    sinks: &CodeQueryPlan,
    reached: Arc<super::reached_sinks::ReachedSinkSites>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> SinkSelection {
    let sink_diagnostic_start = diagnostics.len();
    if let Some(product) = state
        .scope
        .reachability_operands
        .as_ref()
        .and_then(|operands| {
            operands
                .sinks
                .get(&units::reachability_operands::operand_key(sinks))
        })
    {
        diagnostics.extend(product.result.diagnostics.clone());
        return SinkSelection {
            endpoints: SelectionEndpoints::Shared(Arc::clone(product)),
            truncated: product.result.completion != CodeQueryCompletion::Complete,
            diagnostics: sink_diagnostic_start..diagnostics.len(),
            receipt: None,
            #[cfg(any(test, feature = "test-support"))]
            probe: state.scope.reachability_probe.clone(),
        };
    }
    let before = state.budget;
    // Keep the same capture identity as the traversal's scoped caches. A
    // nested capture would turn their legitimate hits into unattributed reads.
    let reached = Some(reached);
    #[cfg(any(test, feature = "test-support"))]
    let reached = if super::reached_sinks::call_reachability_global_reference_active(
        state.analyzer.project().root(),
    ) {
        None
    } else {
        reached
    };
    brokk_bifrost_core::profiling::note_with(|| {
        format!(
            "call_reachability.sink_demand reached_sites={}",
            reached.as_ref().map_or(0, |sites| sites.len())
        )
    });
    let selected = execute_sink_plan(token, sinks, reached, state, limits, diagnostics);
    brokk_bifrost_core::profiling::note_with(|| {
        format!(
            "call_reachability.sink_evaluation pipeline_rows={} selected_rows={} truncated={}",
            state
                .budget
                .pipeline_rows
                .saturating_sub(before.pipeline_rows),
            selected.rows.len(),
            selected.is_truncated(),
        )
    });
    // Snapshot the enclosing query's receipt. It conservatively includes the
    // preceding source/traversal reads, all already owned by this continuation.
    // Immutable canonical keys share the ledger's accounted snapshot storage.
    let receipt = state
        .analyzer
        .current_thread_read_ledger()
        .map(|ledger| (ledger.canonical_keys(), ledger.channels()));
    #[cfg(any(test, feature = "test-support"))]
    if let Some(probe) = &state.scope.reachability_probe {
        probe.filled(
            state
                .budget
                .pipeline_rows
                .saturating_sub(before.pipeline_rows),
            state
                .budget
                .scanned_files
                .saturating_sub(before.scanned_files),
        );
    }
    let mut endpoints = sink_endpoints(&selected.rows);
    endpoints.sort_by(|left, right| left.site.cmp(&right.site));
    SinkSelection {
        endpoints: SelectionEndpoints::Owned(endpoints),
        truncated: selected.is_truncated(),
        diagnostics: sink_diagnostic_start..diagnostics.len(),
        receipt,
        #[cfg(any(test, feature = "test-support"))]
        probe: state.scope.reachability_probe.clone(),
    }
}

fn execute_sink_plan(
    token: QueryToken<'_>,
    sinks: &CodeQueryPlan,
    reached: Option<Arc<super::reached_sinks::ReachedSinkSites>>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PlanExecution {
    let query = CodeQuery {
        schema_version: 1,
        plan: sinks.clone(),
        limit: limits.max_pipeline_rows,
        result_detail: CodeQueryResultDetail::Full,
        execution_mode: CodeQueryExecutionMode::Results,
    };
    let logical =
        LogicalQueryPlan::lower(&query).expect("the enclosing query validated its sink plan");
    let physical = PhysicalQueryPlan::select_with_parallel_union(logical, None, 0);
    let old_demand = std::mem::replace(
        &mut state.sink_demand,
        reached.map(|sites| super::reached_sinks::SinkDemandExecution::new(sites, &physical)),
    );
    let old_scope = state.scope.clone();
    state.scope = old_scope.nested_workspace_plan();
    let sink_files = state
        .scope
        .workspace_files()
        .map_or_else(|| state.analyzer.analyzed_files(), <[ProjectFile]>::to_vec);
    let sink_languages = sink_files.iter().map(language_for_file).collect();
    let old_languages = std::mem::replace(&mut state.scanned_languages, sink_languages);
    let old_seed_cache = std::mem::take(&mut state.seed_cache);
    let old_outputs = std::mem::replace(&mut state.step_outputs, vec![0; physical.node_count()]);
    let old_profile = state.profile.take();
    let old_parallel = state.parallel_seed_budget.take();
    let old_anchors = state.call_cache.owned_call_anchors.take();
    let result = execute_plan(
        &physical,
        token,
        physical.root(),
        state,
        limits,
        None,
        diagnostics,
        &mut None,
    );
    state.scope = old_scope;
    state.sink_demand = old_demand;
    state.scanned_languages = old_languages;
    state.seed_cache = old_seed_cache;
    state.step_outputs = old_outputs;
    state.profile = old_profile;
    state.parallel_seed_budget = old_parallel;
    state.call_cache.owned_call_anchors = old_anchors;
    result
}

#[allow(clippy::too_many_arguments)]
fn source_root(
    analyzer: &dyn IAnalyzer,
    value: &PipelineValue,
    declarations: &mut HashMap<ProjectFile, EnclosingDeclarationIndex>,
    coordinates: &mut PipelineRenderCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    reuse: &mut ReuseVerdict,
) -> Option<(DeclarationValue, CallPathSource)> {
    let (root, source_location) = match value {
        PipelineValue::Declaration(root) => (
            root.clone(),
            location(analyzer, root.unit.source(), root.range, coordinates)?,
        ),
        PipelineValue::StructuralMatch(seed) => {
            let root = super::relations::certified_source_declaration_value(
                analyzer,
                seed,
                declarations,
                budget,
                limits,
                cancellation,
                reuse,
            )?;
            (
                root,
                location(analyzer, &seed.file, seed_range(seed), coordinates)?,
            )
        }
        _ => return None,
    };
    if !root.unit.is_callable() || root.unit.is_synthetic() {
        return None;
    }
    let identity = format!(
        "{}:{}:{}",
        source_location.rel_path, source_location.byte_span.start, source_location.byte_span.end
    );
    Some((
        root,
        CallPathSource {
            location: source_location,
            identity,
            expansion_origin: None,
        },
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute(
    token: QueryToken<'_>,
    sources: PlanExecution,
    sinks: &CodeQueryPlan,
    depth: Option<std::num::NonZeroUsize>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    terminal_cap: Option<usize>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PlanExecution {
    type RootKey = (String, usize, usize, String);
    type SourceGroup = (DeclarationValue, Vec<CallPathSource>, PipelineRow);
    let mut grouped: BTreeMap<RootKey, SourceGroup> = BTreeMap::new();
    let mut declarations = HashMap::default();
    let mut coordinates = PipelineRenderCache::default();
    let mut truncated = sources.is_truncated();
    for row in sources.rows {
        let Some((root, source)) = source_root(
            state.analyzer,
            &row.value,
            &mut declarations,
            &mut coordinates,
            &mut state.budget,
            limits,
            state.cancellation,
            &mut state.reuse,
        ) else {
            diagnostics.push(incomplete_diagnostic(
                CodeQueryDiagnosticCode::SemanticResultsOmitted,
                if state
                    .budget
                    .fact_nodes
                    .saturating_add(state.budget.examined_references)
                    >= limits.max_fact_nodes
                {
                    Incompleteness::Operational(DiagnosticExecutionCause::Budget)
                } else {
                    Incompleteness::Content
                },
                "workspace",
                "call-reachability could not certify source ownership".into(),
                Vec::new(),
            ));
            truncated = true;
            continue;
        };
        let key = (
            rel_path_string(root.unit.source()),
            root.range.start_byte,
            root.range.end_byte,
            root.unit.declaration_id().to_string(),
        );
        if let Some((_, sources, retained)) = grouped.get_mut(&key) {
            sources.push(source);
            merge_pipeline_provenance(retained, row.traces, row.provenance_truncated);
        } else {
            grouped.insert(key, (root, vec![source], row));
        }
    }
    // Source provenance is bounded just like ordinary set rows. If that
    // bound clipped a contributing source branch, do not discharge its advice.
    if grouped.values().any(|(_, _, row)| row.provenance_truncated) {
        lift_projection_advisories(diagnostics, &[], true);
    }
    let mut rows = Vec::new();
    // First inventory the reachable sites without allocating source-by-sink
    // path certificates. The second pass uses the same cached relations and
    // predecessor order to construct certificates only for demanded matches.
    let mut reached = super::reached_sinks::ReachedSinkSites::default();
    let inventory_selection = SinkSelection {
        endpoints: SelectionEndpoints::Owned(Vec::new()),
        truncated: false,
        diagnostics: diagnostics.len()..diagnostics.len(),
        receipt: None,
        #[cfg(any(test, feature = "test-support"))]
        probe: None,
    };
    for (root, sources, _) in grouped.values() {
        let Some(root_location) = location(
            state.analyzer,
            root.unit.source(),
            root.range,
            &mut coordinates,
        ) else {
            truncated = true;
            continue;
        };
        let mut inventory = CallPathProjection {
            sources: sources.clone(),
            coordinates: &mut coordinates,
            root: root.clone(),
            root_location,
            semantic: &mut state.semantic,
            selected_sinks: &inventory_selection,
            reached: Some(&mut reached),
            candidates: Vec::new(),
            candidate_bytes: 0,
            evidence: CallPathEvidence {
                paths: Vec::new(),
                coverage: CallPathCoverage::Complete,
                truncated: false,
            },
        };
        let filter = CallTraversalFilter {
            depth: depth.unwrap_or(std::num::NonZeroUsize::MAX),
            proof: Some(UsageProof::Proven),
            ..Default::default()
        };
        let step = QueryStep::Callees(filter.clone());
        let mut probe = expansions::CallDepthProbeInput::for_consumer(depth.is_some());
        let (_, stopped) = expansions::call_declaration_expansions(
            state.analyzer,
            token,
            root,
            &step,
            &filter,
            &mut state.indexed_declarations,
            &mut state.call_cache,
            &mut state.budget,
            limits,
            limits.max_pipeline_rows,
            state.cancellation,
            diagnostics,
            &mut state.cache_profile,
            &mut probe,
            Some(&mut inventory),
        );
        if stopped {
            inventory.evidence.add_gap(
                if state
                    .cancellation
                    .is_some_and(CancellationToken::is_cancelled)
                {
                    CallPathGap::Cancelled
                } else {
                    CallPathGap::RelationIncomplete
                },
            );
        }
        // An incomplete inventory never certifies absence outside its explored
        // region. Keep the same boundary causes even if the second pass cannot
        // reach them under the remaining grant.
        if stopped
            || inventory.evidence.coverage != CallPathCoverage::Complete
            || inventory.evidence.truncated
        {
            truncated = true;
            diagnostics.push(incomplete_diagnostic(
                CodeQueryDiagnosticCode::SemanticResultsOmitted,
                if inventory.evidence.truncated {
                    Incompleteness::Operational(DiagnosticExecutionCause::Budget)
                } else {
                    Incompleteness::Content
                },
                language_for_file(root.unit.source()).config_label(),
                format!(
                    "call-reachability coverage: {:?}",
                    inventory.evidence.coverage
                ),
                Vec::new(),
            ));
        }
    }
    brokk_bifrost_core::profiling::note_with(|| {
        format!(
            "call_reachability.source_inventory source_roots={} reached_sites={} incomplete={truncated}",
            grouped.len(),
            reached.len(),
        )
    });
    let inventory_bytes = reached.retained_bytes();
    let reached = Arc::new(reached);
    let mut sink_selection = (!grouped.is_empty())
        .then(|| select_sinks(token, sinks, reached, state, limits, diagnostics));
    state.budget.retained_evidence_bytes = state
        .budget
        .retained_evidence_bytes
        .saturating_sub(inventory_bytes);
    if let Some(selection) = &mut sink_selection {
        let allowance = limits
            .semantic
            .max_retained_bytes
            .saturating_sub(state.budget.retained_evidence_bytes);
        let refused = selection.retained_bytes() > allowance;
        if refused {
            let SelectionEndpoints::Owned(endpoints) = &mut selection.endpoints else {
                unreachable!("a shared operand has no owned retention charge")
            };
            let mut retained = 0usize;
            let keep = endpoints
                .iter()
                .take_while(|endpoint| {
                    let next = retained
                        .saturating_add(std::mem::size_of::<SinkEndpoint>())
                        .saturating_add(endpoint.payload_bytes());
                    if next > allowance {
                        return false;
                    }
                    retained = next;
                    true
                })
                .count();
            endpoints.truncate(keep);
            endpoints.shrink_to_fit();
        }
        if refused {
            selection.truncated = true;
            state.mark_execution_dependent();
            diagnostics.push(incomplete_diagnostic(
                CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                Incompleteness::Operational(DiagnosticExecutionCause::Budget),
                "workspace",
                "call-reachability boundary: sink membership exceeded the semantic retained-byte allowance".into(),
                Vec::new(),
            ));
        }
    }
    let membership_bytes = sink_selection
        .as_ref()
        .map_or(0, SinkSelection::retained_bytes);
    state.budget.retained_evidence_bytes = state
        .budget
        .retained_evidence_bytes
        .saturating_add(membership_bytes);
    for (_, (root, mut sources, mut row)) in grouped {
        let selected_sinks = sink_selection
            .as_ref()
            .expect("a source group selected sinks");
        sources.sort_by_key(|source| {
            (
                source.location.rel_path.clone(),
                source.location.byte_span.start,
                source.location.byte_span.end,
            )
        });
        sources.dedup();
        let Some(root_location) = location(
            state.analyzer,
            root.unit.source(),
            root.range,
            &mut coordinates,
        ) else {
            truncated = true;
            continue;
        };
        let mut projection = CallPathProjection {
            sources,
            coordinates: &mut coordinates,
            root: root.clone(),
            root_location,
            semantic: &mut state.semantic,
            selected_sinks,
            reached: None,
            candidates: Vec::new(),
            candidate_bytes: 0,
            evidence: CallPathEvidence {
                paths: Vec::new(),
                coverage: CallPathCoverage::Complete,
                truncated: false,
            },
        };
        let filter = CallTraversalFilter {
            depth: depth.unwrap_or(std::num::NonZeroUsize::MAX),
            proof: Some(UsageProof::Proven),
            ..Default::default()
        };
        let step = QueryStep::Callees(filter.clone());
        let mut probe = expansions::CallDepthProbeInput::for_consumer(depth.is_some());
        let (_, stopped) = expansions::call_declaration_expansions(
            state.analyzer,
            token,
            &root,
            &step,
            &filter,
            &mut state.indexed_declarations,
            &mut state.call_cache,
            &mut state.budget,
            limits,
            limits.max_pipeline_rows,
            state.cancellation,
            diagnostics,
            &mut state.cache_profile,
            &mut probe,
            Some(&mut projection),
        );
        if stopped {
            projection.evidence.add_gap(
                if state
                    .cancellation
                    .is_some_and(CancellationToken::is_cancelled)
                {
                    CallPathGap::Cancelled
                } else {
                    CallPathGap::RelationIncomplete
                },
            );
        }
        let CallPathProjection {
            candidates,
            mut evidence,
            candidate_bytes,
            ..
        } = projection;
        if depth.is_some() {
            let status = expansions::probe_call_depth_bound(
                state.analyzer,
                token,
                &step,
                &filter,
                &mut state.call_cache,
                &mut state.budget,
                limits,
                state.cancellation,
                &mut probe,
            );
            join_depth_bound_status(&mut state.depth_bound_status, Some(status));
            if status != DepthBoundStatus::NotReached {
                evidence.add_gap(CallPathGap::DepthBoundReached);
                evidence.truncated = true;
            }
        }
        if selected_sinks.truncated {
            evidence.add_gap(CallPathGap::RelationIncomplete);
        }
        if !candidates.is_empty() {
            let selected = selected_sinks.endpoints();
            let sink_diagnostics = &selected_sinks.diagnostics;
            let mut contributing_rows = BTreeSet::new();
            evidence.paths.extend(
                candidates
                    .into_iter()
                    .filter(|candidate| {
                        let key = (
                            rel_path_string(&candidate.site.0.file),
                            candidate.site.0.range.start_byte,
                            candidate.site.0.range.end_byte,
                        );
                        let raw = selected_sinks.matching(&(key.0.clone(), key.1, key.2, None));
                        let mut matched = !raw.is_empty();
                        contributing_rows.extend(raw);
                        if let Some(target) = candidate
                            .site
                            .6
                            .as_ref()
                            .and_then(|target| target.target_id.clone())
                        {
                            let exact =
                                selected_sinks.matching(&(key.0, key.1, key.2, Some(target)));
                            matched |= !exact.is_empty();
                            contributing_rows.extend(exact);
                        }
                        matched
                    })
                    .map(|candidate| candidate.path),
            );
            let branches = contributing_rows
                .iter()
                .flat_map(|&index| {
                    selected[index]
                        .provenance
                        .branches
                        .iter()
                        .map(Vec::as_slice)
                })
                .collect::<Vec<_>>();
            let incomplete_provenance = contributing_rows
                .iter()
                .any(|&index| selected[index].provenance.incomplete);
            lift_projection_advisories(
                &mut diagnostics[sink_diagnostics.clone()],
                &branches,
                incomplete_provenance,
            );
        }

        evidence.canonicalize();
        evidence.paths.shrink_to_fit();
        // Candidate storage has been consumed. Replace its charge with the
        // complete owned row certificate, including final vector capacity/gaps.
        let retained_base = state
            .budget
            .retained_evidence_bytes
            .saturating_sub(candidate_bytes);
        while !evidence.paths.is_empty()
            && retained_base.saturating_add(evidence.retained_bytes())
                > limits.semantic.max_retained_bytes
        {
            evidence.paths.pop();
            evidence.paths.shrink_to_fit();
            evidence.truncated = true;
            evidence.add_gap(CallPathGap::ExecutionBudget);
        }
        state.budget.retained_evidence_bytes =
            retained_base.saturating_add(if evidence.paths.is_empty() {
                0
            } else {
                evidence.retained_bytes()
            });

        if evidence.coverage != CallPathCoverage::Complete || evidence.truncated {
            diagnostics.push(incomplete_diagnostic(
                CodeQueryDiagnosticCode::SemanticResultsOmitted,
                if evidence.truncated {
                    state.mark_execution_dependent();
                    Incompleteness::Operational(DiagnosticExecutionCause::Budget)
                } else {
                    Incompleteness::Content
                },
                language_for_file(root.unit.source()).config_label(),
                format!("call-reachability coverage: {:?}", evidence.coverage),
                Vec::new(),
            ));
            truncated = true;
        }
        if evidence.paths.is_empty() {
            continue;
        }
        debug_assert!(evidence.validate());
        let mut expansion = pipeline_expansion(PipelineValue::Declaration(root));
        expansion.call_path_evidence = Some(evidence);
        row.value = expansion.value;
        row.call_path_evidence = expansion.call_path_evidence;
        rows.push(row);
    }
    state.budget.retained_evidence_bytes = state
        .budget
        .retained_evidence_bytes
        .saturating_sub(membership_bytes);
    drop(sink_selection);
    if let Some(cap) = terminal_cap
        && rows.len() > cap
    {
        rows.truncate(cap);
        truncated = true;
    }
    if state
        .cancellation
        .is_some_and(CancellationToken::is_cancelled)
    {
        PlanExecution::cancelled(rows)
    } else {
        PlanExecution::new(rows, truncated)
    }
}

#[cfg(test)]
mod selector_uncertainty_tests {
    use super::*;

    #[test]
    fn selected_sink_branch_advisories_survive_root_projection() {
        let diagnostic = |branch, impact| {
            CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                has_non_utf8_refusal: false,
                refusal_sites: Default::default(),
                call_relation_facts: None,
                uses_omissions: Vec::new(),
                incompleteness: Incompleteness::Content,
                related: Vec::new(),
                source: None,
                code: CodeQueryDiagnosticCode::CallRelationTargetsAmbiguous,
                impact,
                branch,
                language: "rust",
                message: "sink predicate uncertainty".into(),
                exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            })
        };
        let mut diagnostics = vec![
            diagnostic(vec![0], CodeQueryDiagnosticImpact::Advisory),
            diagnostic(vec![1], CodeQueryDiagnosticImpact::Advisory),
            diagnostic(vec![1, 2], CodeQueryDiagnosticImpact::Advisory),
            diagnostic(vec![1, 3], CodeQueryDiagnosticImpact::Advisory),
            diagnostic(vec![1], CodeQueryDiagnosticImpact::Incomplete),
        ];
        lift_projection_advisories(&mut diagnostics, &[&[1, 2]], false);
        assert_eq!(
            diagnostics
                .iter()
                .map(|diagnostic| diagnostic.branch.as_slice())
                .collect::<Vec<_>>(),
            vec![&[0][..], &[][..], &[][..], &[1, 3][..], &[1][..]]
        );
        let mut no_contribution = vec![diagnostic(vec![1], CodeQueryDiagnosticImpact::Advisory)];
        lift_projection_advisories(&mut no_contribution, &[], false);
        assert_eq!(no_contribution[0].branch, vec![1]);
        // If selected provenance was clipped, uncertainty cannot be discharged
        // merely because its exact internal branch is no longer retained.
        lift_projection_advisories(&mut no_contribution, &[], true);
        assert!(no_contribution[0].branch.is_empty());
    }
}
