//! The analysis-side wrappers over [`brokk_bifrost_php::graph`].
//!
//! The scans themselves moved with the language knowledge. What stays here is
//! the downcast that produces their arguments, the `GraphUsageAnalyzer` /
//! `UsageQueryResolver` / `UsageAnalyzer` strategy shells (all analysis-owned
//! traits), the dead-code eligibility downcast, and the inverted pass's fan-out.

mod shared;

pub(in crate::analyzer::usages) use brokk_bifrost_php::aliases::{
    PhpCallableCandidates, PhpFileContext as FileContext, resolve_php_constant,
    resolve_php_function, resolve_php_type,
};
pub(in crate::analyzer::usages) use brokk_bifrost_php::graph::resolver::{
    node_text as php_node_text, qualified_candidate_text as php_qualified_candidate_text,
};
pub(in crate::analyzer::usages) use brokk_bifrost_php::graph::syntax;

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::php_graph::shared::{PhpEdgeResolver, PhpQueryResolver};
use crate::analyzer::usages::traits::GraphUsageAnalyzer;
use crate::analyzer::usages::traits::{UsageAnalyzer, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, PhpAnalyzer, ProjectFile, resolve_analyzer};
use crate::hash::HashSet;
use brokk_bifrost_php::graph::resolver::{TargetKind, TargetSpec};
use brokk_bifrost_php::graph::{PhpCallableFacts, PhpGraphSource};

/// `UsageFactsIndex` is analysis-owned and its entries are `pub(crate)` here, so
/// the crate line is drawn at the two answers PHP reads out of it rather than at
/// the index.
pub(in crate::analyzer::usages) struct PhpAnalyzerFacts<'a>(
    pub(in crate::analyzer::usages) &'a dyn IAnalyzer,
);

impl PhpCallableFacts for PhpAnalyzerFacts<'_> {
    fn declaration_return_type_fqn(&self, unit: &CodeUnit) -> Option<String> {
        self.0
            .usage_facts_index()
            .fact_for_declaration(unit)
            .and_then(|facts| facts.return_type_fqn.as_deref())
            .map(str::to_string)
    }

    fn callable_return_type_fqn(&self, callable_fqn: &str) -> Option<String> {
        self.0
            .usage_facts_index()
            .callable_return_type(callable_fqn)
            .map(str::to_string)
    }
}

/// The [`PhpGraphSource`] built from the *dispatching* analyzer.
///
/// Deliberately not the PHP analyzer: in a mixed workspace the query is issued
/// against a `MultiAnalyzer`, whose `definitions` merges every language's shards
/// and whose enclosing-unit lookup crosses language boundaries.
pub(in crate::analyzer::usages) fn php_graph_source<'a>(
    analyzer: &'a dyn IAnalyzer,
    facts: &'a dyn PhpCallableFacts,
) -> PhpGraphSource<'a> {
    PhpGraphSource {
        index: analyzer,
        facts,
    }
}

pub(crate) fn build_php_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = PhpEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

pub(crate) fn build_php_usage_edge_weights<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdgeWeights>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = PhpEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edge_weights(analyzer, nodes, keep_file))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PhpDeadCodeBulkEligibility {
    BulkSafe,
    NeedsPrecise,
}

pub(crate) fn dead_code_bulk_eligibility(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
) -> PhpDeadCodeBulkEligibility {
    let Some(php) = resolve_analyzer::<PhpAnalyzer>(analyzer) else {
        return PhpDeadCodeBulkEligibility::NeedsPrecise;
    };
    let Some(spec) = TargetSpec::from_target(php, target) else {
        return PhpDeadCodeBulkEligibility::NeedsPrecise;
    };
    match spec.kind {
        TargetKind::Type | TargetKind::Function | TargetKind::Method => {
            PhpDeadCodeBulkEligibility::BulkSafe
        }
        TargetKind::Constructor | TargetKind::Field | TargetKind::Constant => {
            PhpDeadCodeBulkEligibility::NeedsPrecise
        }
    }
}

#[derive(Default)]
pub struct PhpUsageGraphStrategy {
    _private: (),
}

impl PhpUsageGraphStrategy {
    pub const fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Php
    }
}

impl GraphUsageAnalyzer for PhpUsageGraphStrategy {
    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        if overloads.is_empty() {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        }

        let target = &overloads[0];
        if language_for_target(target) != Language::Php {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not PHP"),
                "PhpUsageGraphStrategy",
            );
        }

        let Some(resolver) = PhpQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose PhpAnalyzer",
                ),
                "PhpUsageGraphStrategy",
            );
        };

        resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
    }
}

impl UsageAnalyzer for PhpUsageGraphStrategy {
    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult {
        let scan_scope = UsageScanScope::new(candidate_files, false);
        self.find_graph_usages(analyzer, overloads, &scan_scope, max_usages)
            .into_fuzzy_result()
    }
}
