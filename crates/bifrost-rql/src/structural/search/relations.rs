use super::super::matcher::{
    CallableSignatureFacts, CallableSignatureOracle, DeclarationOwnerOracle,
};
use super::*;
use crate::analyzer::DeclarationKind;
use crate::analyzer::lexical_definitions::formal_parameter_slots;
use crate::analyzer::semantic::LengthDelimitedDigest;
use brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use tree_sitter::Node;

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
        if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
            budget.pipeline_rows,
            max_pipeline_rows,
        )
        .allows(1)
        {
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
        indexed.record_owner(analyzer, &unit, &declaration.unit);
        expansions.push(budgeted_declaration_expansion(child));
    }
    (expansions, exhausted)
}

pub(super) fn reference_expansion(
    value: PipelineValue,
    site: ReferenceSiteValue,
) -> PipelineExpansion {
    super::pipeline_expansion_with_via(
        value,
        Some(PipelineVia::ReferenceSite(site)),
        "reference steps produce a semantic value",
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn call_site_expansions(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
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
    semantic: &mut Option<SemanticQueryContext<'_>>,
) -> (Vec<PipelineExpansion>, bool) {
    let incoming = matches!(step, QueryStep::CallSitesTo(_));
    let result = cached_call_relation(
        analyzer,
        token,
        &declaration.unit,
        incoming,
        cache,
        budget,
        limits,
        cancellation,
        diagnostics,
        cache_profile,
    );
    if filter.proof == Some(UsageProof::Proven) {
        mark_proven_call_ambiguity_incomplete(&result, diagnostics);
    }
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
            let semantic_identity = semantic
                .as_mut()
                .and_then(|semantic| semantic.call_site_identity_at_source(&site.file, site.range));
            let binding = cache
                .bindings
                .read_mut(&memo_attribution(analyzer), |memo| {
                    bind_call_site_arguments(analyzer, &mut site, memo)
                });
            let identity_facts = call_site_identity_facts(analyzer, &site, cancellation);
            if recursive_equals_identity_is_incomplete(&site, &identity_facts)
                && !diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == CodeQueryDiagnosticCode::SemanticResultsOmitted
                        && diagnostic.message.contains("recursive Equals")
                        && diagnostic
                            .message
                            .contains(&site.caller.fq_name().to_string())
                })
            {
                diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                    incompleteness: brokk_bifrost_rql::Incompleteness::Content,
                    related: Vec::new(),
                    source: None,
                    code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: "csharp",
                    message: format!(
                        "recursive Equals argument or receiver identity was incomplete for {}",
                        site.caller.fq_name()
                    ),
                    exhausted_roots: Vec::new(),
                    withheld_rows_path: None,
                }));
            }
            pipeline_expansion(PipelineValue::CallSite(CallSiteValue::new(
                site,
                binding,
                semantic_identity,
                identity_facts,
            )))
        })
        .collect();
    (expansions, truncated)
}

fn recursive_equals_identity_is_incomplete(site: &CallSite, facts: &CallSiteIdentityFacts) -> bool {
    crate::analyzer::common::language_for_file(&site.file) == Language::CSharp
        && site.caller.identifier() == "Equals"
        && site.callee.identifier() == "Equals"
        && !site.arguments.is_empty()
        && (facts.receiver_kind == "unknown"
            || facts
                .argument_identities
                .first()
                .is_none_or(Option::is_none)
            || facts
                .caller_parameter_identities
                .first()
                .is_none_or(Option::is_none))
}

/// Derive the call-site identity facts that relational policies cannot safely
/// reconstruct from rendered source. The resolver supplies lexical binding
/// identity; formal slots supply the enclosing caller's parameter identity.
/// Both are query-local and bounded by this one call site and source file.
fn call_site_identity_facts(
    analyzer: &dyn IAnalyzer,
    site: &CallSite,
    cancellation: Option<&CancellationToken>,
) -> CallSiteIdentityFacts {
    let language = crate::analyzer::common::language_for_file(&site.file);
    let mut facts = CallSiteIdentityFacts {
        receiver_kind: if site.receiver.is_none() {
            "implicit"
        } else if language != Language::CSharp {
            "explicit"
        } else {
            "unknown"
        },
        argument_identities: vec![None; site.arguments.len()],
        caller_parameter_identities: vec![None; site.arguments.len()],
    };
    if language != Language::CSharp {
        return facts;
    }
    let Some(source) = analyzer.indexed_source(&site.file).map(Arc::<str>::from) else {
        return facts;
    };
    let parsed = crate::analyzer::usages::get_definition::parse_tree_for_language_outcome(
        &site.file, language, &source,
    );
    if parsed.is_err() {
        analyzer.mark_execution_dependent();
    }
    let Ok(Some(tree)) = parsed else {
        return facts;
    };
    if let Some(receiver) = site.receiver
        && exact_node_for_range(tree.root_node(), receiver)
            .is_some_and(|node| matches!(node.kind(), "this" | "this_expression"))
    {
        facts.receiver_kind = "this";
    } else if site.receiver.is_some() {
        facts.receiver_kind = "explicit";
    }

    let ordinary_parameters = analyzer
        .ranges_of(&site.caller)
        .into_iter()
        .min_by_key(|range| (range.start_byte, range.end_byte))
        .and_then(|caller_range| {
            formal_parameter_slots(language, tree.root_node(), &source, &caller_range)
        })
        .map(|layout| {
            layout
                .slots
                .into_iter()
                .filter(|slot| !slot.receiver)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for (index, argument) in site.arguments.iter().enumerate() {
        let parameter = argument
            .position
            .and_then(|position| ordinary_parameters.get(position))
            .or_else(|| {
                argument.name.as_deref().and_then(|name| {
                    ordinary_parameters
                        .iter()
                        .find(|slot| slot.names.iter().any(|candidate| candidate == name))
                })
            });
        facts.caller_parameter_identities[index] =
            parameter.map(|slot| lexical_identity(&site.file, slot.declaration_range));
    }

    let mut requests = Vec::new();
    let mut request_indices = Vec::new();
    for (index, argument) in site.arguments.iter().enumerate() {
        let exact = exact_node_for_range(tree.root_node(), argument.range);
        let stripped = exact.and_then(strip_csharp_argument_wrappers);
        let Some(node) = stripped else {
            continue;
        };
        requests.push(DefinitionLookupRequest {
            file: site.file.clone(),
            line: None,
            column: None,
            start_byte: Some(node.start_byte()),
            end_byte: Some(node.end_byte()),
        });
        request_indices.push(index);
    }
    if requests.is_empty() {
        return facts;
    }
    let outcomes = match cancellation {
        Some(cancellation) => resolve_definition_batch_with_source_and_cancellation(
            analyzer,
            requests,
            site.file.clone(),
            source,
            cancellation,
        ),
        None => resolve_definition_batch_with_source(analyzer, requests, site.file.clone(), source),
    };
    for (index, outcome) in request_indices.into_iter().zip(outcomes) {
        facts.argument_identities[index] = outcome.lexical_definition.map(|definition| {
            // A deconstruction pattern can declare several names in one
            // declaration range. Its individual binders have distinct IDs.
            let range = if definition.kind == DeclarationKind::PatternVariable {
                definition.name_range
            } else {
                definition.declaration_range
            };
            lexical_identity(&site.file, range)
        });
    }
    facts
}

fn lexical_identity(file: &ProjectFile, range: Range) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.call_binding_identity.v1");
    digest.push(rel_path_string(file).as_bytes());
    digest.push(&range.start_byte.to_le_bytes());
    digest.push(&range.end_byte.to_le_bytes());
    digest.finish().to_string()
}

fn exact_node_for_range(root: Node<'_>, range: Range) -> Option<Node<'_>> {
    let mut node = root.named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
    while let Some(parent) = node.parent() {
        if parent.start_byte() == range.start_byte && parent.end_byte() == range.end_byte {
            node = parent;
        } else {
            break;
        }
    }
    (node.start_byte() == range.start_byte && node.end_byte() == range.end_byte).then_some(node)
}

fn strip_csharp_argument_wrappers(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        node = match node.kind() {
            "argument" => node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("expression"))
                .or_else(|| {
                    let mut cursor = node.walk();
                    let mut children = node.named_children(&mut cursor);
                    let child = children.next()?;
                    children.next().is_none().then_some(child)
                })?,
            // Unwrap only for binding identity. The call site's original
            // argument (including its target type) remains the authority for
            // overload selection; a cast is not an untyped call argument.
            "cast_expression" => node.child_by_field_name("value")?,
            "parenthesized_expression" => node.child_by_field_name("expression").or_else(|| {
                let mut cursor = node.walk();
                let mut children = node.named_children(&mut cursor);
                let child = children.next()?;
                children.next().is_none().then_some(child)
            })?,
            _ => return Some(node),
        };
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cached_call_relation(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
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
    results.read_mut(&memo_attribution(analyzer), |results| {
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
                CallRelationService::incoming_bounded(
                    analyzer,
                    token,
                    unit,
                    relation_limits,
                    cancellation,
                )
            } else {
                CallRelationService::outgoing_bounded(
                    analyzer,
                    token,
                    unit,
                    relation_limits,
                    cancellation,
                )
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
    })
}

/// A complete candidate relation remains usable by reverse-caller consumers.
/// Selecting only proven targets cannot establish absence from ambiguous edges.
pub(super) fn mark_proven_call_ambiguity_incomplete(
    result: &CallRelationResult,
    diagnostics: &mut [CodeQueryDiagnostic],
) {
    if !result
        .sites
        .iter()
        .any(|site| site.proof == UsageProof::Unproven)
    {
        return;
    }
    for source in result
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == CallRelationDiagnosticCode::TargetsAmbiguous)
    {
        for diagnostic in diagnostics.iter_mut().filter(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::CallRelationTargetsAmbiguous
                && diagnostic.message == source.message
        }) {
            diagnostic.impact = CodeQueryDiagnosticImpact::Incomplete;
        }
    }
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
    CodeQueryDiagnostic::new(CodeQueryDiagnostic {
        incompleteness: brokk_bifrost_rql::Incompleteness::Operational(
            brokk_bifrost_rql::DiagnosticExecutionCause::Provider,
        ),
        related: Vec::new(),
        source: None,
        code,
        impact,
        branch: Vec::new(),
        language,
        message: diagnostic.message,
        exhausted_roots: Vec::new(),
        withheld_rows_path: None,
    })
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
    !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
        budget.scanned_files,
        limits.max_scanned_files,
    )
    .allows(0)
        || !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
            budget.scanned_source_bytes,
            limits.max_scanned_source_bytes,
        )
        .allows(0)
        || !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
            budget.fact_nodes.saturating_add(budget.examined_references),
            limits.max_fact_nodes,
        )
        .allows(0)
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
    let outbound = &mut cache.outbound;
    outbound.read_mut(&memo_attribution(analyzer), |outbound| {
    let source_file = declaration.unit.source();
    let cache_hit = outbound.contains_key(source_file);
    let mut exhausted = cache_hit && cache.outbound_exhausted.contains(source_file);
    if let Some(profile) = cache_profile {
        if cache_hit {
            profile.outbound_reference.record_hit(
                Some(!cache.outbound_incomplete.contains(source_file)),
                outbound.get(source_file).map_or(0, Vec::len),
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
        outbound.insert(source_file.clone(), hits);
    }
    let mut sites = Vec::new();
    let mut omitted = 0usize;
    for hit in outbound
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
        diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
            incompleteness: brokk_bifrost_rql::Incompleteness::Operational(brokk_bifrost_rql::DiagnosticExecutionCause::Provider),
            related: Vec::new(),
            source: None,
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
        exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        }));
    }
    sort_reference_sites(&mut sites);
    sites.dedup();
    let expansions = sites
        .into_iter()
        .map(|site| reference_expansion(PipelineValue::Declaration(site.target.clone()), site))
        .collect();
    (expansions, exhausted)
    })
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
        let answer = match step {
            QueryStep::Supertypes(_) => provider.get_direct_ancestors(&work.unit),
            QueryStep::Subtypes(_) => provider.get_direct_descendants(&work.unit),
            _ => unreachable!("hierarchy expansion requires a hierarchy step"),
        };
        if !answer.is_complete() {
            return (expansions, true);
        }
        let mut related = answer.definite().to_vec();
        related.sort();
        related.dedup();
        for unit in related {
            if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
                budget.pipeline_rows,
                max_pipeline_rows,
            )
            .allows(1)
            {
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
            if !brokk_bifrost_core::analyzer::work_budget::LimitedCounter::from_usage(
                budget.provenance_steps,
                max_pipeline_rows,
            )
            .allows(next_depth)
            {
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
    tail: usize,
    depth: usize,
) -> Vec<PipelineTraceValue> {
    super::parent_path_values(tail, depth, |index| {
        let node = &paths[index];
        (
            PipelineTraceValue::Declaration(node.value.clone()),
            node.parent,
        )
    })
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
        diagnostics.push(incomplete_diagnostic(
            CodeQueryDiagnosticCode::SemanticResultsOmitted,
            brokk_bifrost_rql::Incompleteness::Content,
            language.config_label(),
            format!(
                "{} omitted {count} input{} because {reason}",
                step.label(),
                if count == 1 { "" } else { "s" }
            ),
            Vec::new(),
        ));
    }
}

#[derive(Default)]
pub(super) struct EnclosingDeclarationIndex {
    pub(super) exact: Vec<DeclarationValue>,
    pub(super) projection_omitted: bool,
}

impl EnclosingDeclarationIndex {
    pub(super) fn for_file(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> Self {
        let mut declarations = Self::default();
        for unit in analyzer.get_declarations(file) {
            declarations.retain(unit.clone(), analyzer.ranges_of(&unit));
        }
        declarations.sort();
        declarations
    }

    pub(super) fn retain(&mut self, unit: CodeUnit, ranges: impl IntoIterator<Item = Range>) {
        if unit.is_synthetic() || unit.is_file_scope() {
            return;
        }
        let mut retained = false;
        for range in ranges {
            retained = true;
            self.exact.push(DeclarationValue::new(unit.clone(), range));
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

/// Exact-range lookup from a callable fact onto persisted signature metadata.
pub(super) struct FileCallableSignatureOracle<'a> {
    analyzer: &'a dyn IAnalyzer,
    index: EnclosingDeclarationIndex,
}

impl<'a> FileCallableSignatureOracle<'a> {
    pub(super) fn for_file(analyzer: &'a dyn IAnalyzer, file: &ProjectFile) -> Self {
        Self {
            analyzer,
            index: EnclosingDeclarationIndex::for_file(analyzer, file),
        }
    }
}

impl CallableSignatureOracle for FileCallableSignatureOracle<'_> {
    fn lookup(&self, range: Range) -> Option<CallableSignatureFacts> {
        let declaration = self.index.exact(range)?;
        let entries = self.analyzer.signature_metadata(&declaration.unit);
        // The metadata lookup keys on the whole CodeUnit, including its
        // signature, so overloads with distinct signatures have separate
        // entries. It still returns a list. Read every callable fact from one
        // entry so visibility and parameter types cannot describe two
        // different declarations.
        let Some(recorded) = entries.iter().find(|entry| {
            entry.callable_modifiers_recorded() || entry.callable_parameter_types().is_some()
        }) else {
            return Some(CallableSignatureFacts {
                modifiers_recorded: false,
                visibility: None,
                parameter_types: None,
            });
        };
        Some(CallableSignatureFacts {
            modifiers_recorded: recorded.callable_modifiers_recorded(),
            visibility: recorded.callable_declared_visibility(),
            parameter_types: recorded.callable_parameter_types().map(<[String]>::to_vec),
        })
    }
}

/// Whether a member declaration in `language` can be owned by a type
/// declaration that is not its lexical structural ancestor, possibly in
/// another file.
///
/// Rust writes an inherent or trait `impl` apart from the type it implements.
/// C++ defines a member out of line (`long PriceCalculator::total() {...}`)
/// apart from the class body that declares it, usually in another file
/// (#3458). Declaration extraction reads the owner from structure in both
/// cases: the impl item's `type` field, and the qualified declarator's scope.
/// An owner name is then not a sound source anchor for the member's file
/// either, because an alias can spell the owner.
pub(super) fn declaration_owner_may_be_non_lexical(language: Language) -> bool {
    matches!(language, Language::Rust | Language::Cpp)
}

/// The declaration owner of a member whose owner is not always a lexical
/// structural ancestor (see [`declaration_owner_may_be_non_lexical`]).
/// `parent_of` resolves the member's structured owner identity back to the
/// exact workspace declaration. This oracle joins that declaration to its own
/// normalized fact so `inside-decl` can apply the ordinary pattern verifier.
pub(super) struct NonLexicalDeclarationOwnerOracle<'a> {
    analyzer: &'a dyn IAnalyzer,
    declarations: EnclosingDeclarationIndex,
}

impl<'a> NonLexicalDeclarationOwnerOracle<'a> {
    pub(super) fn for_file(analyzer: &'a dyn IAnalyzer, file: &ProjectFile) -> Self {
        Self {
            analyzer,
            declarations: EnclosingDeclarationIndex::for_file(analyzer, file),
        }
    }
}

impl DeclarationOwnerOracle for NonLexicalDeclarationOwnerOracle<'_> {
    fn owner_matches(
        &self,
        declaration: Range,
        pattern: &Pattern,
        captures: &mut Vec<super::super::matcher::CaptureBinding>,
        examined_facts: &mut u64,
        incomplete: &super::super::matcher::CallableSignatureIncomplete,
    ) -> bool {
        let Some(member) = self.declarations.exact(declaration) else {
            return false;
        };
        let Some(owner) = self
            .analyzer
            .parent_of(&member.unit)
            .filter(CodeUnit::is_class)
        else {
            return false;
        };
        let language = crate::analyzer::common::language_for_file(owner.source());
        if !declaration_owner_may_be_non_lexical(language) {
            return false;
        }
        let Some(facts) = self
            .analyzer
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == language)
            .and_then(|provider| provider.structural_facts(owner.source()))
        else {
            return false;
        };
        let signature_oracle = pattern
            .constrains_callable_signature()
            .then(|| FileCallableSignatureOracle::for_file(self.analyzer, owner.source()));
        let signature_oracle = signature_oracle
            .as_ref()
            .map(|oracle| oracle as &dyn CallableSignatureOracle);
        let owner_ranges = self.analyzer.ranges_of(&owner);
        for (node, fact) in facts.nodes().iter().enumerate() {
            if !fact.kind.satisfies(NormalizedKind::Declaration)
                || !owner_ranges.contains(&fact.range)
            {
                continue;
            }
            let node = u32::try_from(node).expect("FileFacts node ids fit in u32");
            if super::super::matcher::match_owner_pattern(
                pattern,
                &facts,
                node,
                captures,
                super::super::matcher::PatternEvalInputs {
                    examined_facts,
                    oracle: signature_oracle,
                    local_value_oracle: None,
                    incomplete,
                },
            ) {
                return true;
            }
        }
        false
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

fn declaration_index_for_file<'a>(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    declarations_by_file: &'a mut HashMap<ProjectFile, EnclosingDeclarationIndex>,
) -> &'a EnclosingDeclarationIndex {
    declarations_by_file.entry(file.clone()).or_insert_with(|| {
        let mut declarations = EnclosingDeclarationIndex::default();
        for unit in analyzer.get_declarations(file) {
            declarations.retain(unit.clone(), analyzer.ranges_of(&unit));
        }
        declarations.sort();
        declarations
    })
}

pub(super) fn declaration_index_for_seed<'a>(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    declarations_by_file: &'a mut HashMap<ProjectFile, EnclosingDeclarationIndex>,
) -> &'a EnclosingDeclarationIndex {
    declaration_index_for_file(analyzer, &seed.file, declarations_by_file)
}

pub(super) fn enclosing_declaration_for_range(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    range: Range,
    declarations_by_file: &mut HashMap<ProjectFile, EnclosingDeclarationIndex>,
) -> Option<DeclarationValue> {
    declaration_index_for_file(analyzer, file, declarations_by_file).enclosing(range)
}

pub(super) fn enclosing_declaration_value(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    declarations_by_file: &mut HashMap<ProjectFile, EnclosingDeclarationIndex>,
) -> (Option<DeclarationValue>, bool) {
    let declarations = declaration_index_for_seed(analyzer, seed, declarations_by_file);
    (
        declarations
            .enclosing(seed_range(seed))
            .map(|declaration| attach_exact_structural_kind(seed, declaration)),
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
    declaration_index_for_seed(analyzer, seed, declarations_by_file)
        .exact(seed_range(seed))
        .map(|declaration| attach_exact_structural_kind(seed, declaration))
}

fn attach_exact_structural_kind(
    seed: &SeedMatch,
    declaration: DeclarationValue,
) -> DeclarationValue {
    let fact = seed.facts.node(seed.fact_match.node);
    if !refined_declaration_kind(fact.kind) {
        return declaration;
    }

    let mut structural_span = fact.span();
    for decorator in seed
        .facts
        .role_targets(seed.fact_match.node, Role::Decorator)
    {
        structural_span.start_byte = structural_span.start_byte.min(decorator.span.start_byte);
        structural_span.end_byte = structural_span.end_byte.max(decorator.span.end_byte);
    }
    if structural_span.start_byte == declaration.range.start_byte
        && structural_span.end_byte == declaration.range.end_byte
    {
        declaration.with_structural_kind(fact.kind)
    } else {
        declaration
    }
}

/// Exact structural projection may retain a leaf kind that refines the
/// analyzer's coarser `CodeUnitType`, but the generic declaration fact proves
/// no refinement. Keeping it would erase already-specific kinds such as Rust
/// fields or C# properties when their ranges happen to coincide.
pub(super) fn refined_declaration_kind(kind: NormalizedKind) -> bool {
    kind != NormalizedKind::Declaration && kind.satisfies(NormalizedKind::Declaration)
}
