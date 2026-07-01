mod extractor;
mod hits;
mod inverted;
mod resolver;
mod shared;

pub(in crate::analyzer::usages) use extractor::{
    is_declaration_name as csharp_is_declaration_name, member_access_name, member_access_receiver,
};
pub(in crate::analyzer::usages) use resolver::{
    argument_count as csharp_argument_count, first_type_child as csharp_first_type_child,
    is_extension_method as csharp_is_extension_method,
    is_type_reference_node as csharp_is_type_reference_node,
    member_declared_type_fq_name as csharp_member_declared_type_fq_name,
    method_return_type_fq_name as csharp_method_return_type_fq_name, node_text as csharp_node_text,
    reference_type_text as csharp_reference_type_text,
    seed_bindings_before as seed_csharp_bindings_before, signature_arity as csharp_signature_arity,
};

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::csharp_graph::shared::{CSharpEdgeResolver, CSharpQueryResolver};
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageAnalyzer, UsageEdgeResolver, UsageQueryResolver};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashSet;

pub(crate) fn build_csharp_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = CSharpEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

#[derive(Default)]
pub struct CSharpUsageGraphStrategy {
    _private: (),
}

impl CSharpUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::CSharp
    }

    pub(crate) fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        if overloads.is_empty() {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        }

        let target = &overloads[0];
        if language_for_target(target) != Language::CSharp {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not C#"),
                "CSharpUsageGraphStrategy",
            );
        }

        let Some(resolver) = CSharpQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose CSharpAnalyzer",
                ),
                "CSharpUsageGraphStrategy",
            );
        };

        resolver.find_usages(analyzer, overloads, candidate_files, max_usages)
    }
}

impl UsageAnalyzer for CSharpUsageGraphStrategy {
    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult {
        self.find_graph_usages(analyzer, overloads, candidate_files, max_usages)
            .into_fuzzy_result()
    }
}
