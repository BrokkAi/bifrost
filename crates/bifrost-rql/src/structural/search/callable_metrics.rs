//! Query-local projection of the shared AST callable metrics.

use super::*;

use brokk_bifrost_core::analyzer::cognitive_complexity::{
    CallableMetrics, CallableMetricsCoverage,
};

#[derive(Debug, Clone)]
pub(super) struct CallableMetricsValue {
    pub(super) declaration: DeclarationValue,
    /// `None` means the analyzer had no provider for this language and the
    /// row is explicitly unrecorded. A present value may still be incomplete.
    pub(super) metrics: Option<CallableMetrics>,
}

impl CallableMetricsValue {
    pub(super) fn file(&self) -> &ProjectFile {
        self.declaration.unit.source()
    }

    pub(super) fn coverage(&self) -> &'static str {
        match self.metrics {
            Some(metrics) => metrics.coverage.label(),
            None => "unrecorded",
        }
    }
}

fn incomplete_metrics() -> CallableMetrics {
    CallableMetrics {
        coverage: CallableMetricsCoverage::Incomplete,
        max_nesting: None,
        cognitive_complexity: None,
        owned_body_span_lines: None,
    }
}

/// Expand one source-backed function declaration into exactly one metrics row.
/// Non-callable and synthetic declarations are outside this relation. Missing
/// provider support remains a visible `unrecorded` row rather than a clean
/// empty result.
pub(super) fn callable_metrics_expansions_for_declaration(
    analyzer: &dyn IAnalyzer,
    declaration: &DeclarationValue,
    cache: &mut HashMap<ProjectFile, Option<Vec<(CodeUnit, CallableMetrics)>>>,
) -> Vec<PipelineExpansion> {
    if !declaration.unit.is_function() || declaration.unit.is_synthetic() {
        return Vec::new();
    }

    let file = declaration.unit.source();
    let language = crate::analyzer::common::language_for_file(file);
    let rows = match cache.entry(file.clone()) {
        std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
        std::collections::hash_map::Entry::Vacant(entry) => {
            let rows = analyzer
                .workspace_fact_indexes()
                .into_iter()
                .find(|index| index.fact_index_language() == language)
                .and_then(|index| index.callable_metrics_for_file(file));
            entry.insert(rows)
        }
    };

    let metrics = match rows {
        Some(rows) => rows
            .iter()
            .find(|(unit, _)| unit == &declaration.unit)
            .map(|(_, metrics)| *metrics)
            .or_else(|| Some(incomplete_metrics())),
        None => None,
    };
    vec![pipeline_expansion(PipelineValue::CallableMetrics(
        Box::new(CallableMetricsValue {
            declaration: declaration.clone(),
            metrics,
        }),
    ))]
}
