use super::*;

#[doc(hidden)]
pub fn ecosystem_identity(
    analyzer: &MultiAnalyzer,
    ecosystem: crate::analyzer::usages::workspace_graph::UsageEcosystem,
) -> crate::analyzer::content_identity::WorkspaceContentIdentity {
    analyzer
        .workspace_content_identities()
        .expect("a two-language analyzer states its content identities")
        .scope(|language| {
            crate::analyzer::usages::workspace_graph::UsageEcosystem::of(language) == ecosystem
        })
        .unwrap_or_else(|| panic!("no analyzed content for {ecosystem:?}"))
}

#[doc(hidden)]
pub fn usage_graph_key(
    analyzer: &MultiAnalyzer,
    ecosystem: crate::analyzer::usages::workspace_graph::UsageEcosystem,
) -> crate::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphCacheKey {
    crate::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphCacheKey::new(
        crate::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphKind::Exact,
        [ecosystem],
        ecosystem_identity(analyzer, ecosystem),
    )
}

#[doc(hidden)]
pub fn acquire_usage_graph(
    analyzer: &MultiAnalyzer,
    ecosystem: crate::analyzer::usages::workspace_graph::UsageEcosystem,
) -> crate::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphCacheLifecycle {
    use crate::analyzer::usages::workspace_graph::WorkspaceUsageRankingGraph;
    use crate::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphCacheBuildOutcome;
    let acquisition = analyzer.snapshot_caches.usage_graphs().acquire(
        usage_graph_key(analyzer, ecosystem),
        &crate::cancellation::CancellationToken::default(),
        || {
            WorkspaceUsageGraphCacheBuildOutcome::Complete(WorkspaceUsageRankingGraph {
                nodes: Vec::new(),
                edges: Vec::new(),
                node_indices_by_file: crate::hash::HashMap::default(),
                resolved_ecosystems: vec![ecosystem],
            })
        },
        || true,
    );
    crate::analyzer::usages::workspace_graph_cache::ready_graph(acquisition).1
}
