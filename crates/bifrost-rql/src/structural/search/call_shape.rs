//! Pipeline execution for the `call_shape`, `call_argument_groups`, and
//! `call_arguments` steps (issue #1478).
//!
//! The `call_shape` step maps a structural match, call site, or occurrence to
//! the exact facts-arena call node at that position and derives one
//! [`crate::analyzer::usages::call_shape::CallShapeReport`]. Group and
//! argument steps are pure projections over the shared derived report; they
//! never re-derive or re-parse. An input whose position is not inside any
//! call node produces no row: the step is a projection like
//! `occurrence_target`, not a per-input mandatory analysis, and the mandatory
//! outcome contract applies per exact call site, not per arbitrary input.
//!
//! A shape whose `coverage` is not `exact` suppresses the argument-group and
//! argument rows it heads, and every family derived from the same shape --
//! `call_argument_groups`, `call_arguments`, `call_bindings` -- inherits that
//! suppression. Deriving the shape is therefore where the suppression is
//! reported, once per site, as a `call_shape_coverage_incomplete` diagnostic
//! of `incomplete` impact (issue #1949). Reporting it at the derivation point
//! rather than on the bound row is what lets a plan that binds only
//! `call_arguments` see the gap: that plan's legitimately empty argument set
//! and a real zero-argument call are byte-identical, and only the diagnostic
//! separates them.

use super::*;
use brokk_bifrost_core::analyzer::structural::callable::{CallKind, CallShapeCoverage};

/// Derive call-shape expansions for one pipeline input position.
///
/// `known_facts` short-circuits the facts lookup when the input already
/// carries its arena (a structural match); other inputs share the receiver
/// facts cache and its budget accounting. `known_node` is the exact arena
/// node of a structural match, used directly when it is a call node.
#[allow(clippy::too_many_arguments)]
pub(super) fn call_shape_expansions_for_input(
    analyzer: &dyn IAnalyzer,
    traces: &[PipelineTrace],
    file: &ProjectFile,
    range: Range,
    known_facts: Option<&Arc<FileFacts>>,
    known_node: Option<u32>,
    bindings: &mut CallBindingCache,
    receiver_facts: &mut HashMap<ProjectFile, Arc<FileFacts>>,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    reported_suppressed_shapes: &mut HashSet<String>,
    cache_profile: &mut Option<QueryCacheProfile>,
    shared_budget_exhausted: &mut bool,
) -> Vec<PipelineExpansion> {
    let facts = match known_facts {
        Some(facts) => Arc::clone(facts),
        None => match receiver::receiver_facts_for_pipeline_row(
            analyzer,
            traces,
            file,
            receiver_facts,
            budget,
            limits,
            cancellation,
            diagnostics,
            cache_profile,
        ) {
            PipelineReceiverFacts::Available(facts) => facts,
            PipelineReceiverFacts::Unavailable => return Vec::new(),
            PipelineReceiverFacts::Halted => {
                *shared_budget_exhausted = true;
                return Vec::new();
            }
        },
    };
    let call_id = known_node
        .filter(|&node| facts.node(node).kind.satisfies(NormalizedKind::Call))
        .map(|node| spawn_operand_call(&facts, node).unwrap_or(node))
        .or_else(|| innermost_call_for_range(&facts, range));
    let Some(call_id) = call_id else {
        return Vec::new();
    };
    let Some(mut report) =
        crate::analyzer::usages::call_shape::call_shape_for_call(&facts, file, call_id)
    else {
        return Vec::new();
    };
    // A recognized Rust token-tree grammar supplies only a candidate runtime
    // layout. Publish its synthetic ports only after macro dispatch proves
    // the standard identity; a shadowed or unresolved macro stays opaque.
    if crate::analyzer::common::language_for_file(file) == Language::Rust
        && report.outcome.coverage == CallShapeCoverage::ExactMacroDerived
        && bindings
            .resolved_external_call_dispatch(analyzer, file, report.outcome.range, cancellation)
            .is_none()
    {
        report.outcome.coverage = CallShapeCoverage::UnknownMacroDerived;
        report.groups.clear();
        report.arguments.clear();
    }
    // Python's grammar uses the same call expression for functions and
    // classes. Match the resolved-source rule used by the binding relation:
    // only one complete resolver result that names a class upgrades the
    // syntactic function/method kind to a constructor.
    if crate::analyzer::common::language_for_file(file) == Language::Python
        && let Some(callee_range) = report.outcome.callee_range
        && let Some(lookup) =
            bindings.resolved_call_target(analyzer, file, callee_range, cancellation)
        && lookup.outcome.status == DefinitionLookupStatus::Resolved
    {
        let model_definitions = lookup.outcome.modeled_definitions;
        let mut definitions = lookup.outcome.definitions;
        definitions.sort();
        definitions.dedup();
        let unique_source_class = model_definitions.is_empty()
            && matches!(definitions.as_slice(), [class] if class.is_class());
        let unique_model_class = definitions.is_empty()
            && matches!(model_definitions.as_slice(), [class]
                if class.language == Language::Python.config_label()
                    && class.kind == crate::analyzer::semantic_model::SemanticModelSymbolKind::Class
                    && !class.provenance.ambiguous);
        if unique_source_class || unique_model_class {
            report.outcome.call_kind = CallKind::Constructor;
        }
    }
    let outcome = &report.outcome;
    if !outcome.coverage.is_exact()
        && reported_suppressed_shapes.insert(outcome.site_ast_id.clone())
    {
        diagnostics.push(CodeQueryDiagnostic {
            related: Vec::new(),
            source: None,
            code: CodeQueryDiagnosticCode::CallShapeCoverageIncomplete,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: crate::analyzer::common::language_for_file(&outcome.file).config_label(),
            message: format!(
                "call_shape coverage is {} at {}:{} (site_ast_id={}), so the argument-group, argument and binding rows this shape heads were suppressed rather than emitted empty",
                outcome.coverage.label(),
                crate::path_utils::workspace_relative_slash_path(outcome.file.rel_path()),
                outcome.range.start_line,
                outcome.site_ast_id,
            ),
        exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        });
    }
    let value = CallShapeValue {
        report: Arc::new(report),
        seed: traces.first().map(|trace| Arc::clone(&trace.seed)),
        source: Some(Arc::from(facts.source())),
        facts: Some(facts),
        resolved_external_callee: None,
    };
    vec![pipeline_expansion(PipelineValue::CallShape(value))]
}

/// Attach the resolver's exact external identity to a call shape only when a
/// query explicitly requests the `exact_external_callee` relation.
pub(super) fn exact_external_callee_expansions(
    analyzer: &dyn IAnalyzer,
    bindings: &mut CallBindingCache,
    value: &CallShapeValue,
    cancellation: Option<&CancellationToken>,
) -> Vec<PipelineExpansion> {
    let outcome = &value.report.outcome;
    let resolved_external_callee = match crate::analyzer::common::language_for_file(&outcome.file) {
        Language::Python => outcome.callee_range.and_then(|callee_range| {
            bindings.resolved_exact_external_callee(
                analyzer,
                &outcome.file,
                callee_range,
                cancellation,
            )
        }),
        Language::Rust if outcome.coverage == CallShapeCoverage::ExactMacroDerived => bindings
            .resolved_external_call_dispatch(analyzer, &outcome.file, outcome.range, cancellation)
            .map(|target| {
                format!(
                    "{}.{}",
                    target.identity().owner_fqn(),
                    target.identity().member()
                )
            }),
        _ => None,
    };
    let mut value = value.clone();
    value.resolved_external_callee = resolved_external_callee;
    vec![pipeline_expansion(PipelineValue::CallShape(value))]
}

/// A Go `go_statement` wraps the call it starts. Project its call shape onto
/// that exact child call so selectors do not publish the wrapper and call as
/// two independently bindable invocations. Standalone spawn-call expressions
/// (such as Rust `tokio::spawn`) keep their own shape.
fn spawn_operand_call(facts: &FileFacts, node_id: u32) -> Option<u32> {
    let node = facts.node(node_id);
    if node.kind != NormalizedKind::ConcurrentSpawn {
        return None;
    }
    (node_id + 1..node.subtree_end).find(|&candidate_id| {
        let candidate = facts.node(candidate_id);
        candidate.parent == Some(node_id) && candidate.kind == NormalizedKind::Call
    })
}

/// The innermost (smallest) call node whose exact span contains `range`.
///
/// Exact-span equality wins outright, so the whole-call span of a nested call
/// such as `outer(inner())` is never confused with the outer call a cursor
/// range would also land in.
fn innermost_call_for_range(facts: &FileFacts, range: Range) -> Option<u32> {
    facts
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| node.kind.satisfies(NormalizedKind::Call))
        .filter(|(_, node)| {
            node.range.start_byte <= range.start_byte && range.end_byte <= node.range.end_byte
        })
        .min_by_key(|(_, node)| {
            (
                node.range.end_byte - node.range.start_byte,
                node.range.start_byte,
            )
        })
        .map(|(id, _)| u32::try_from(id).expect("facts arena node IDs fit u32"))
}

/// Expand one call shape into its ordered argument-list group rows.
pub(super) fn call_argument_group_expansions(value: &CallShapeValue) -> Vec<PipelineExpansion> {
    (0..value.report.groups.len())
        .map(|group_index| {
            pipeline_expansion(PipelineValue::CallArgumentGroup(CallArgumentGroupValue {
                shape: value.clone(),
                group_index,
            }))
        })
        .collect()
}

/// Expand one argument-list group into its ordered argument rows.
pub(super) fn call_argument_expansions(value: &CallArgumentGroupValue) -> Vec<PipelineExpansion> {
    let group_id = &value.shape.report.groups[value.group_index].id;
    value
        .shape
        .report
        .arguments
        .iter()
        .enumerate()
        .filter(|(_, argument)| &argument.group_id == group_id)
        .map(|(argument_index, _)| {
            pipeline_expansion(PipelineValue::CallArgument(CallArgumentValue {
                shape: value.shape.clone(),
                argument_index,
            }))
        })
        .collect()
}
