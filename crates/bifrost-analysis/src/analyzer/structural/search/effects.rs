//! Pipeline execution for the `call_effects` and `procedure_effects` steps
//! (issue #2437, slice 2).
//!
//! Both steps consume the analyzer's existing answers and add no new call-graph
//! walker of their own:
//!
//! - the callee set of a call site is
//!   [`crate::analyzer::structural::search::semantic::SemanticQueryContext::dispatch_at_source`],
//!   the exact answer the `dispatch_outcome` and `dispatch_target` rows
//!   publish, so an effect row's proof and its site's candidate coverage are
//!   copied rather than re-derived;
//! - the call sites of a procedure are the facts arena's own call nodes inside
//!   the declaration's range, the same nodes `call_shape` derives from, so an
//!   effect row's `site_id` is literally a `call_shape` row id; and
//! - the effect declarations are the activated semantic-model set the analyzer
//!   already publishes ([`IAnalyzer::active_semantic_models`]), selected by the
//!   canonical `(language, owner, member, receiver, arity)` identity issue
//!   #1978 introduced for data-flow summaries.
//!
//! The algebra over those inputs — certainty meets, timing joins, coverage
//! degradation, the bounded fixpoint — lives in
//! [`crate::analyzer::usages::effects`] and is unit-tested without a workspace.

use super::*;

use crate::analyzer::semantic_model::{
    ResolvedActiveSemanticModels, SemanticModelMatchDisposition,
};
use crate::analyzer::structural::NormalizedKind;
use crate::analyzer::usages::call_shape::call_shape_for_call;
use crate::analyzer::usages::callable_signature::callable_signature_reports;
use crate::analyzer::usages::effects::{
    ArmLookup, BoundDeclaredEffect, CallEffectArm, CallEffectReport, CallEffectSiteStatus,
    EffectCertainty, EffectCoverage, EffectGraph, EffectGraphEdge, EffectGraphProcedure,
    EffectProof, EffectReason, ModeledProcedureKey, ProcedureEffectBudget, ProcedureEffectReport,
    call_effect_report, modeled_procedure_key, summarize_procedure_effects,
};
use brokk_bifrost_core::analyzer::structural::callable::ReceiverContract;

/// How many call nodes one procedure body contributes to the reachable call
/// graph before the walk reports itself truncated.
const MAX_CALL_SITES_PER_PROCEDURE: usize = 512;

/// One derived call-effect report, shared by every row of the site.
#[derive(Debug, Clone)]
pub(super) struct CallEffectValue {
    pub(super) report: Arc<CallEffectReport>,
    /// The workspace declaration behind each dispatch arm, keyed by the arm's
    /// target identity, so rendering never re-resolves a callee.
    pub(super) callees: Arc<BTreeMap<String, DeclarationValue>>,
    pub(super) index: usize,
}

impl CallEffectValue {
    pub(super) fn row(&self) -> &crate::analyzer::usages::effects::CallEffectRow {
        &self.report.rows[self.index]
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.report.file
    }

    pub(super) fn callee_declaration(&self) -> Option<&DeclarationValue> {
        self.callees.get(self.row().target_id.as_deref()?)
    }
}

/// One derived procedure-effect report, shared by every row of the procedure.
#[derive(Debug, Clone)]
pub(super) struct ProcedureEffectSubject {
    pub(super) declaration: DeclarationValue,
    pub(super) report: Arc<ProcedureEffectReport>,
}

/// One row of one procedure's effect summary.
#[derive(Debug, Clone)]
pub(super) struct ProcedureEffectValue {
    pub(super) subject: ProcedureEffectSubject,
    pub(super) index: usize,
}

impl ProcedureEffectValue {
    pub(super) fn row(&self) -> &crate::analyzer::usages::effects::ProcedureEffectRow {
        &self.subject.report.rows[self.index]
    }

    pub(super) fn file(&self) -> &ProjectFile {
        self.subject.declaration.unit.source()
    }
}

/// What the activated pack set says about one canonical procedure identity.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ModelAnswer {
    Declared(Vec<BoundDeclaredEffect>),
    Conflict,
    Empty,
}

/// Per-query state shared by every effect row a single query derives.
#[derive(Default)]
pub(super) struct EffectTraversalCache {
    models: Option<Option<Arc<ResolvedActiveSemanticModels>>>,
    keys: HashMap<CodeUnit, Option<ModeledProcedureKey>>,
    answers: HashMap<ModeledProcedureKey, ModelAnswer>,
    reports: HashMap<String, Arc<ProcedureEffectReport>>,
    facts: HashMap<ProjectFile, Option<Arc<FileFacts>>>,
    /// Whether any derived row so far was not exhaustive, so the query's own
    /// completion can record the incompleteness once.
    pub(super) incomplete: bool,
    /// Whether a bound rather than a missing fact caused the incompleteness.
    pub(super) truncated: bool,
}

impl EffectTraversalCache {
    fn models(&mut self, analyzer: &dyn IAnalyzer) -> Option<Arc<ResolvedActiveSemanticModels>> {
        self.models
            .get_or_insert_with(|| analyzer.active_semantic_models())
            .clone()
    }

    /// The canonical identity of one workspace callable, cached per unit.
    ///
    /// `None` means no key could be built, which is a coverage gap and never a
    /// looser match: the owner must be a qualified prefix of the declaration's
    /// own fully-qualified name, the persisted signature contract must publish
    /// exactly one entry, and that entry must decide the receiver shape.
    fn key_for(
        &mut self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Option<ModeledProcedureKey> {
        if let Some(key) = self.keys.get(unit) {
            return key.clone();
        }
        let key = build_modeled_key(analyzer, unit);
        self.keys.insert(unit.clone(), key.clone());
        key
    }

    fn answer_for(&mut self, analyzer: &dyn IAnalyzer, key: &ModeledProcedureKey) -> ModelAnswer {
        if let Some(answer) = self.answers.get(key) {
            return answer.clone();
        }
        let answer = lookup_declared_effects(self.models(analyzer).as_deref(), key);
        self.answers.insert(key.clone(), answer.clone());
        answer
    }
}

/// Build the canonical `(language, owner, member, receiver, arity)` identity of
/// one workspace callable declaration.
fn build_modeled_key(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<ModeledProcedureKey> {
    if !unit.is_callable() || unit.is_synthetic() {
        return None;
    }
    let entries = analyzer.signature_metadata(unit);
    // An overload set publishes several entries and this slice does not choose
    // between them; a declaration with no entry publishes no arity at all.
    // Either way the identity is not established, so nothing is looked up.
    if entries.len() != 1 {
        return None;
    }
    let mut reports = callable_signature_reports("effect-key", unit, &entries);
    let signature = reports.remove(0).signature;
    let has_receiver = match signature.receiver_contract? {
        ReceiverContract::Instance | ReceiverContract::Extension => true,
        ReceiverContract::None | ReceiverContract::StaticOrCompanion => false,
    };
    let parameter_count = u32::try_from(signature.parameter_count).ok()?;
    let language = crate::analyzer::common::language_for_file(unit.source()).config_label();
    modeled_procedure_key(language, unit, Some(has_receiver), Some(parameter_count))
}

/// Select the activated summary for one canonical identity and project its
/// declarations.
///
/// The disposition is the runtime's own: `Conflict` means several activated
/// packs disagree, which fails closed rather than picking one.
fn lookup_declared_effects(
    models: Option<&ResolvedActiveSemanticModels>,
    key: &ModeledProcedureKey,
) -> ModelAnswer {
    let Some(models) = models else {
        return ModelAnswer::Empty;
    };
    let matched = models.procedure_summaries_for_member(
        crate::analyzer::semantic_model::ProcedureSummaryMemberKey::new(
            &key.language,
            &key.owner,
            &key.member,
            key.has_receiver,
            key.parameter_count,
        ),
    );
    match matched.disposition {
        SemanticModelMatchDisposition::Empty => ModelAnswer::Empty,
        SemanticModelMatchDisposition::Conflict => ModelAnswer::Conflict,
        SemanticModelMatchDisposition::Unique => {
            let Some(selected) = matched.records.first() else {
                return ModelAnswer::Empty;
            };
            let effects = selected
                .declared_effects()
                .iter()
                .map(|effect| {
                    BoundDeclaredEffect::new(
                        effect,
                        selected.shard.manifest.pack_id.clone(),
                        selected.record.model_id.clone(),
                        selected.record.id.clone(),
                    )
                })
                .collect::<Vec<_>>();
            if effects.is_empty() {
                ModelAnswer::Empty
            } else {
                ModelAnswer::Declared(effects)
            }
        }
    }
}

/// Derive the direct effect rows of one already-derived call shape.
pub(super) fn call_effect_expansions(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    shape: &CallShapeValue,
) -> Vec<PipelineExpansion> {
    let outcome = &shape.report.outcome;
    let DispatchedArms {
        status,
        arms,
        callees,
    } = dispatch_arms(analyzer, semantic, cache, &outcome.file, outcome.range);
    let report = Arc::new(call_effect_report(
        &outcome.file,
        &outcome.site_id,
        &outcome.site_ast_id,
        outcome.range,
        status,
        &arms,
    ));
    let rendered_callees = Arc::new(
        callees
            .into_iter()
            .filter_map(|(target_id, unit)| {
                let range = analyzer
                    .ranges_of(&unit)
                    .into_iter()
                    .min_by_key(primary_range_key)?;
                Some((target_id, DeclarationValue::new(unit, range)))
            })
            .collect::<BTreeMap<_, _>>(),
    );
    record_coverage(cache, diagnostics, &outcome.file, report.coverage);
    (0..report.rows.len())
        .map(|index| {
            pipeline_expansion(PipelineValue::CallEffect(Box::new(CallEffectValue {
                report: Arc::clone(&report),
                callees: Arc::clone(&rendered_callees),
                index,
            })))
        })
        .collect()
}

/// Note a derivation's coverage on the query so the result's completion can
/// state the incompleteness once.
///
/// This is what keeps a non-exhaustive effect relation out of a clean absence
/// verdict: the relational evaluator reads the query's `CodeQueryCompletion`,
/// so a row that admits a missing effect must also make the query incomplete.
fn record_coverage(
    cache: &mut EffectTraversalCache,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    file: &ProjectFile,
    coverage: EffectCoverage,
) {
    let language = crate::analyzer::common::language_for_file(file).config_label();
    match coverage {
        EffectCoverage::Exhaustive => {}
        EffectCoverage::Truncated => {
            if !cache.truncated {
                cache.truncated = true;
                diagnostics.push(CodeQueryDiagnostic {
                    code: CodeQueryDiagnosticCode::EffectBudgetExhausted,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language,
                    message:
                        "effect derivation reached a bound; the retained effect set may be missing rows"
                            .to_owned(),
                });
            }
            cache.incomplete = true;
        }
        EffectCoverage::Open | EffectCoverage::Unsupported => {
            if !cache.incomplete {
                cache.incomplete = true;
                diagnostics.push(CodeQueryDiagnostic {
                    code: CodeQueryDiagnosticCode::EffectDerivationIncomplete,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language,
                    message:
                        "an unresolved or unmodeled callee leaves the effect set non-exhaustive"
                            .to_owned(),
                });
            }
        }
    }
}

/// One call site's dispatch answer, reduced to what both row families need.
struct DispatchedArms {
    status: CallEffectSiteStatus,
    arms: Vec<CallEffectArm>,
    /// The workspace callables the answer named, keyed by the arm's target
    /// identity so the order is the arms' own.
    callees: Vec<(String, CodeUnit)>,
}

/// Run dispatch at one call range and pair every arm with its pack answer.
fn dispatch_arms(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    file: &ProjectFile,
    range: Range,
) -> DispatchedArms {
    let answer = semantic.dispatch_at_source(file, range);
    let status = match answer.outcome {
        "resolved" | "ambiguous" => CallEffectSiteStatus::Answered {
            coverage: coverage_for(answer.coverage),
        },
        "unsupported" => CallEffectSiteStatus::Interrupted {
            reason: EffectReason::DispatchUnsupported,
        },
        "cancelled" | "exceeded_budget" => CallEffectSiteStatus::Interrupted {
            reason: EffectReason::DispatchInterrupted,
        },
        _ if answer.arms.is_empty() => CallEffectSiteStatus::Interrupted {
            reason: EffectReason::DispatchUnresolved,
        },
        _ => CallEffectSiteStatus::Answered {
            coverage: coverage_for(answer.coverage),
        },
    };
    let mut arms = Vec::with_capacity(answer.arms.len());
    let mut callees = Vec::new();
    for arm in &answer.arms {
        if let Some(unit) = &arm.target_unit {
            callees.push((arm.target_id.clone(), unit.clone()));
        }
        let proof = if arm.proof == "proven" {
            EffectProof::Proven
        } else {
            EffectProof::Unproven
        };
        let complete = arm.completeness == "complete";
        let (key, lookup, declaration_id) = match &arm.target_unit {
            Some(unit) => {
                let declaration_id = declaration_identity(analyzer, unit);
                match cache.key_for(analyzer, unit) {
                    Some(key) => {
                        let lookup = match cache.answer_for(analyzer, &key) {
                            ModelAnswer::Declared(effects) => ArmLookup::Declared(effects),
                            ModelAnswer::Conflict => ArmLookup::Conflict,
                            // The target is a workspace declaration with a
                            // readable body, so its own effects are reachable
                            // through propagation rather than missing.
                            ModelAnswer::Empty => ArmLookup::Unmodeled { analyzable: true },
                        };
                        (Some(key), lookup, declaration_id)
                    }
                    None => (None, ArmLookup::Unkeyable, declaration_id),
                }
            }
            // The oracle named a target the workspace does not materialize.
            // Slice two does not key an external artifact's symbol, so the
            // callee stays unmodeled and the site's coverage opens.
            None => (None, ArmLookup::Unmodeled { analyzable: false }, None),
        };
        arms.push(CallEffectArm {
            target_id: arm.target_id.clone(),
            callee_declaration_id: declaration_id,
            key,
            proof,
            complete,
            lookup,
        });
    }
    arms.sort_by(|left, right| left.target_id.cmp(&right.target_id));
    callees.sort_by(|left, right| left.0.cmp(&right.0));
    DispatchedArms {
        status,
        arms,
        callees,
    }
}

fn coverage_for(coverage: crate::analyzer::semantic::CandidateCoverage) -> EffectCoverage {
    use crate::analyzer::semantic::CandidateCoverage;
    match coverage {
        CandidateCoverage::Exhaustive => EffectCoverage::Exhaustive,
        CandidateCoverage::Open => EffectCoverage::Open,
        CandidateCoverage::Truncated => EffectCoverage::Truncated,
    }
}

/// The `declaration` domain's own identity for one workspace unit, so an
/// effect row joins a declaration row by id equality.
fn declaration_identity(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Option<String> {
    let range = analyzer
        .ranges_of(unit)
        .into_iter()
        .min_by_key(primary_range_key)?;
    let declaration = DeclarationValue::new(unit.clone(), range);
    Some(render::declaration_id(
        &rel_path_string(unit.source()),
        declaration.identity_kind_label(),
        &unit.fq_name(),
        range,
    ))
}

/// Derive the transitive effect summary of one declaration.
#[allow(clippy::too_many_arguments)]
pub(super) fn procedure_effect_expansions(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    cache_profile: &mut Option<QueryCacheProfile>,
    declaration: &DeclarationValue,
) -> Vec<PipelineExpansion> {
    let Some(identity) = declaration_identity(analyzer, &declaration.unit) else {
        return Vec::new();
    };
    let report = match cache.reports.get(&identity) {
        Some(report) => Arc::clone(report),
        None => {
            let graph = discover_effect_graph(
                analyzer,
                semantic,
                cache,
                budget,
                limits,
                cancellation,
                diagnostics,
                cache_profile,
                declaration,
                ProcedureEffectBudget::default(),
            );
            let reports = summarize_procedure_effects(&graph, ProcedureEffectBudget::default());
            let mut selected = None;
            for report in reports {
                let report = Arc::new(report);
                if report.procedure_declaration_id == identity {
                    selected = Some(Arc::clone(&report));
                }
                cache
                    .reports
                    .insert(report.procedure_declaration_id.clone(), report);
            }
            match selected {
                Some(report) => report,
                None => return Vec::new(),
            }
        }
    };
    record_coverage(
        cache,
        diagnostics,
        declaration.unit.source(),
        report.coverage,
    );
    let subject = ProcedureEffectSubject {
        declaration: declaration.clone(),
        report,
    };
    (0..subject.report.rows.len())
        .map(|index| {
            pipeline_expansion(PipelineValue::ProcedureEffect(Box::new(
                ProcedureEffectValue {
                    subject: subject.clone(),
                    index,
                },
            )))
        })
        .collect()
}

/// Walk the reachable call graph of one declaration, breadth first, bounded.
///
/// Every callee is a workspace callable the dispatch answer named. A call whose
/// target the workspace does not index, an ambiguous dispatch and an exhausted
/// bound each become a typed gap on the *calling* procedure, so the fixpoint
/// can degrade that procedure's coverage rather than losing the fact.
#[allow(clippy::too_many_arguments)]
fn discover_effect_graph(
    analyzer: &dyn IAnalyzer,
    semantic: &mut SemanticQueryContext<'_>,
    cache: &mut EffectTraversalCache,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    cache_profile: &mut Option<QueryCacheProfile>,
    root: &DeclarationValue,
    bounds: ProcedureEffectBudget,
) -> EffectGraph {
    let mut graph = EffectGraph::default();
    let mut index_by_unit: HashMap<CodeUnit, usize> = HashMap::default();
    let mut queue: Vec<(CodeUnit, usize)> = Vec::new();

    let push_node = |graph: &mut EffectGraph,
                     index_by_unit: &mut HashMap<CodeUnit, usize>,
                     cache: &mut EffectTraversalCache,
                     unit: &CodeUnit|
     -> Option<usize> {
        if let Some(index) = index_by_unit.get(unit) {
            return Some(*index);
        }
        if graph.procedures.len() >= bounds.max_procedures {
            graph.truncated = true;
            return None;
        }
        let identity = declaration_identity(analyzer, unit)?;
        let declared = match cache.key_for(analyzer, unit) {
            Some(key) => match cache.answer_for(analyzer, &key) {
                ModelAnswer::Declared(effects) => effects,
                ModelAnswer::Conflict | ModelAnswer::Empty => Vec::new(),
            },
            None => Vec::new(),
        };
        let index = graph.procedures.len();
        graph.procedures.push(EffectGraphProcedure {
            declaration_id: identity,
            display_name: unit.fq_name(),
            declared,
            body_read: false,
            local_gaps: Vec::new(),
        });
        index_by_unit.insert(unit.clone(), index);
        Some(index)
    };

    if push_node(&mut graph, &mut index_by_unit, cache, &root.unit).is_none() {
        return graph;
    }
    queue.push((root.unit.clone(), 0));

    let mut cursor = 0usize;
    while cursor < queue.len() {
        let (unit, depth) = queue[cursor].clone();
        cursor += 1;
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            graph.truncated = true;
            break;
        }
        let Some(node) = index_by_unit.get(&unit).copied() else {
            continue;
        };
        if depth > bounds.max_depth {
            graph.truncated = true;
            continue;
        }
        let file = unit.source().clone();
        let facts = match cache.facts.get(&file) {
            Some(facts) => facts.clone(),
            None => {
                let resolved = match receiver::receiver_facts_for_pipeline_row(
                    analyzer,
                    &[],
                    &file,
                    &mut HashMap::default(),
                    budget,
                    limits,
                    cancellation,
                    diagnostics,
                    cache_profile,
                ) {
                    PipelineReceiverFacts::Available(facts) => Some(facts),
                    PipelineReceiverFacts::Unavailable | PipelineReceiverFacts::Halted => None,
                };
                cache.facts.insert(file.clone(), resolved.clone());
                resolved
            }
        };
        let Some(facts) = facts else {
            continue;
        };
        let ranges = analyzer.ranges_of(&unit);
        let Some(span) = ranges.into_iter().min_by_key(primary_range_key) else {
            continue;
        };
        graph.procedures[node].body_read = true;

        let mut call_nodes = facts
            .nodes()
            .iter()
            .enumerate()
            .filter(|(_, fact)| fact.kind == NormalizedKind::Call)
            .filter(|(_, fact)| {
                fact.range.start_byte >= span.start_byte && fact.range.end_byte <= span.end_byte
            })
            .map(|(id, fact)| (fact.range.start_byte, fact.range.end_byte, id))
            .collect::<Vec<_>>();
        call_nodes.sort_unstable();
        if call_nodes.len() > MAX_CALL_SITES_PER_PROCEDURE {
            call_nodes.truncate(MAX_CALL_SITES_PER_PROCEDURE);
            graph.truncated = true;
        }

        for (_, _, call_id) in call_nodes {
            if graph.edges.len() >= bounds.max_edges {
                graph.truncated = true;
                break;
            }
            let call_id = match u32::try_from(call_id) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let Some(shape) = call_shape_for_call(&facts, &file, call_id) else {
                continue;
            };
            // A curried sequence reports one site from any of its nodes, so
            // only the site whose own outcome range starts here contributes an
            // edge; the rest would be duplicates of it.
            if shape.outcome.range.start_byte != facts.node(call_id).range.start_byte {
                continue;
            }
            let DispatchedArms {
                status,
                arms,
                callees,
            } = dispatch_arms(
                analyzer,
                semantic,
                cache,
                &shape.outcome.file,
                shape.outcome.range,
            );
            let site_coverage = match status {
                CallEffectSiteStatus::Answered { coverage } => coverage,
                CallEffectSiteStatus::Interrupted { reason } => {
                    graph.procedures[node].local_gaps.push(reason);
                    EffectCoverage::Open
                }
            };
            if !site_coverage.is_exhaustive() {
                graph.procedures[node]
                    .local_gaps
                    .push(EffectReason::DispatchUnresolved);
            }
            let exact_site = site_coverage.is_exhaustive() && arms.len() == 1;
            for arm in &arms {
                match &arm.lookup {
                    ArmLookup::Unkeyable => {
                        graph.procedures[node]
                            .local_gaps
                            .push(EffectReason::CalleeUnkeyable);
                    }
                    ArmLookup::Conflict => {
                        graph.procedures[node]
                            .local_gaps
                            .push(EffectReason::ModelConflict);
                    }
                    ArmLookup::Unmodeled { analyzable: false } => {
                        graph.procedures[node]
                            .local_gaps
                            .push(EffectReason::CalleeUnmodeled);
                    }
                    ArmLookup::Declared(_) | ArmLookup::Unmodeled { analyzable: true } => {}
                }
            }
            for (_, callee_unit) in callees {
                let Some(callee) = push_node(&mut graph, &mut index_by_unit, cache, &callee_unit)
                else {
                    graph.procedures[node]
                        .local_gaps
                        .push(EffectReason::ProcedureBudgetExhausted);
                    continue;
                };
                let certainty = if exact_site {
                    EffectCertainty::Definite
                } else {
                    EffectCertainty::Possible
                };
                graph.edges.push(EffectGraphEdge {
                    caller: node,
                    callee,
                    site_id: shape.outcome.site_id.clone(),
                    certainty,
                });
                // A callee already queued is already going to be walked at a
                // depth no greater than this one, so re-queueing it would only
                // repeat work; the fixpoint below, not this walk, is what
                // resolves a cycle.
                if queue.iter().all(|(queued, _)| queued != &callee_unit) {
                    queue.push((callee_unit.clone(), depth.saturating_add(1)));
                }
            }
        }
        graph.procedures[node].local_gaps.sort_unstable();
        graph.procedures[node].local_gaps.dedup();
    }

    graph.edges.sort_by(|left, right| {
        (left.caller, left.callee, &left.site_id).cmp(&(right.caller, right.callee, &right.site_id))
    });
    graph.edges.dedup();
    graph
}
