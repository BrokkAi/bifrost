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

use super::*;

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
    receiver_facts: &mut HashMap<ProjectFile, Arc<FileFacts>>,
    budget: &mut CodeQueryExecutionBudget,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
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
        .filter(|&node| facts.node(node).kind == NormalizedKind::Call)
        .or_else(|| innermost_call_for_range(&facts, range));
    let Some(call_id) = call_id else {
        return Vec::new();
    };
    let Some(report) =
        crate::analyzer::usages::call_shape::call_shape_for_call(&facts, file, call_id)
    else {
        return Vec::new();
    };
    let value = CallShapeValue {
        report: Arc::new(report),
    };
    vec![pipeline_expansion(PipelineValue::CallShape(value))]
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
        .filter(|(_, node)| node.kind == NormalizedKind::Call)
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
