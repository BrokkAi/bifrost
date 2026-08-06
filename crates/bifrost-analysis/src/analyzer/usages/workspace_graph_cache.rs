//! Snapshot-owned complete usage-ranking graphs.

use super::workspace_graph::{UsageEcosystem, WorkspaceUsageRankingGraph};
use crate::analyzer::complete_value_cache::{
    CompleteValueAcquisition, CompleteValueCache, CompleteValueWait,
};
use crate::cancellation::CancellationToken;
use std::sync::Arc;

const USAGE_GRAPH_REPRESENTATION_VERSION: u32 = 1;
pub(crate) const DEFAULT_MAX_RETAINED_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum WorkspaceUsageGraphKind {
    File,
    Exact,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct WorkspaceUsageGraphCacheKey {
    representation_version: u32,
    kind: WorkspaceUsageGraphKind,
    ecosystems: Box<[UsageEcosystem]>,
    source_generations: Box<[u64]>,
}

impl WorkspaceUsageGraphCacheKey {
    pub(crate) fn new(
        kind: WorkspaceUsageGraphKind,
        ecosystems: impl IntoIterator<Item = UsageEcosystem>,
        source_generations: Box<[u64]>,
    ) -> Self {
        Self {
            representation_version: USAGE_GRAPH_REPRESENTATION_VERSION,
            kind,
            ecosystems: ecosystems.into_iter().collect(),
            source_generations,
        }
    }

    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(
                self.ecosystems
                    .len()
                    .saturating_mul(std::mem::size_of::<UsageEcosystem>()),
            )
            .saturating_add(
                self.source_generations
                    .len()
                    .saturating_mul(std::mem::size_of::<u64>()),
            )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkspaceUsageGraphCacheLifecycle {
    Hit,
    Built,
    UncachedOverBudget,
}

pub(crate) enum WorkspaceUsageGraphCacheBuildOutcome {
    Complete(WorkspaceUsageRankingGraph),
    Cancelled,
}

pub(crate) enum WorkspaceUsageGraphCacheAcquisition {
    Ready {
        graph: Arc<WorkspaceUsageRankingGraph>,
        lifecycle: WorkspaceUsageGraphCacheLifecycle,
        wait: CompleteValueWait,
    },
    Cancelled,
    Stale,
}

pub(crate) struct SnapshotWorkspaceUsageGraphCache {
    max_retained_bytes: u64,
    values: CompleteValueCache<WorkspaceUsageGraphCacheKey, WorkspaceUsageRankingGraph>,
}

impl SnapshotWorkspaceUsageGraphCache {
    pub(crate) fn new(max_retained_bytes: u64) -> Self {
        Self {
            max_retained_bytes,
            values: CompleteValueCache::new(
                max_retained_bytes,
                |key: &WorkspaceUsageGraphCacheKey, graph: &Arc<WorkspaceUsageRankingGraph>| {
                    key.retained_bytes()
                        .saturating_add(graph.retained_bytes())
                        .min(u32::MAX as usize) as u32
                },
            ),
        }
    }

    pub(crate) fn acquire(
        &self,
        key: WorkspaceUsageGraphCacheKey,
        cancellation: &CancellationToken,
        build: impl FnOnce() -> WorkspaceUsageGraphCacheBuildOutcome,
        generation_is_current: impl Fn() -> bool,
    ) -> WorkspaceUsageGraphCacheAcquisition {
        let (acquisition, wait) = self.values.acquire(&key, cancellation);
        match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                if generation_is_current() {
                    WorkspaceUsageGraphCacheAcquisition::Ready {
                        graph: value,
                        lifecycle: WorkspaceUsageGraphCacheLifecycle::Hit,
                        wait,
                    }
                } else {
                    WorkspaceUsageGraphCacheAcquisition::Stale
                }
            }
            CompleteValueAcquisition::Leader { permit } => match build() {
                WorkspaceUsageGraphCacheBuildOutcome::Complete(graph) => {
                    if cancellation.is_cancelled() {
                        return WorkspaceUsageGraphCacheAcquisition::Cancelled;
                    }
                    if !generation_is_current() {
                        return WorkspaceUsageGraphCacheAcquisition::Stale;
                    }
                    let retained_bytes =
                        key.retained_bytes().saturating_add(graph.retained_bytes());
                    let graph = Arc::new(graph);
                    if retained_bytes as u64 > self.max_retained_bytes {
                        return WorkspaceUsageGraphCacheAcquisition::Ready {
                            graph,
                            lifecycle: WorkspaceUsageGraphCacheLifecycle::UncachedOverBudget,
                            wait,
                        };
                    }
                    permit.publish_complete(Arc::clone(&graph));
                    if !generation_is_current() {
                        return WorkspaceUsageGraphCacheAcquisition::Stale;
                    }
                    WorkspaceUsageGraphCacheAcquisition::Ready {
                        graph,
                        lifecycle: WorkspaceUsageGraphCacheLifecycle::Built,
                        wait,
                    }
                }
                WorkspaceUsageGraphCacheBuildOutcome::Cancelled => {
                    WorkspaceUsageGraphCacheAcquisition::Cancelled
                }
            },
            CompleteValueAcquisition::Cancelled => WorkspaceUsageGraphCacheAcquisition::Cancelled,
            CompleteValueAcquisition::Rejected => WorkspaceUsageGraphCacheAcquisition::Stale,
        }
    }

    #[cfg(test)]
    pub(crate) fn len_for_test(&self) -> u64 {
        self.values.len_for_test()
    }

    #[cfg(test)]
    pub(crate) fn waiting_count_for_test(&self) -> usize {
        self.values.waiting_count_for_test()
    }
}

impl Default for SnapshotWorkspaceUsageGraphCache {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_RETAINED_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::workspace_graph::WorkspaceUsageRankingNode;
    use crate::hash::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn key_with_kind(
        generation: u64,
        kind: WorkspaceUsageGraphKind,
    ) -> WorkspaceUsageGraphCacheKey {
        WorkspaceUsageGraphCacheKey::new(kind, [UsageEcosystem::Rust], Box::new([generation]))
    }

    fn key(generation: u64) -> WorkspaceUsageGraphCacheKey {
        key_with_kind(generation, WorkspaceUsageGraphKind::Exact)
    }

    fn empty_graph() -> WorkspaceUsageRankingGraph {
        WorkspaceUsageRankingGraph {
            nodes: Vec::<WorkspaceUsageRankingNode>::new(),
            edges: Vec::new(),
            node_indices_by_file: HashMap::default(),
            resolved_ecosystems: Vec::new(),
        }
    }

    fn ready_graph(
        acquisition: WorkspaceUsageGraphCacheAcquisition,
    ) -> (
        Arc<WorkspaceUsageRankingGraph>,
        WorkspaceUsageGraphCacheLifecycle,
    ) {
        match acquisition {
            WorkspaceUsageGraphCacheAcquisition::Ready {
                graph, lifecycle, ..
            } => (graph, lifecycle),
            WorkspaceUsageGraphCacheAcquisition::Cancelled => panic!("unexpected cancellation"),
            WorkspaceUsageGraphCacheAcquisition::Stale => panic!("unexpected stale result"),
        }
    }

    #[test]
    fn issue_1304_complete_usage_graph_is_reused_warm() {
        let cache = SnapshotWorkspaceUsageGraphCache::default();
        let builds = AtomicUsize::new(0);
        let cancellation = CancellationToken::default();

        let (first, first_lifecycle) = ready_graph(cache.acquire(
            key(1),
            &cancellation,
            || {
                builds.fetch_add(1, Ordering::SeqCst);
                WorkspaceUsageGraphCacheBuildOutcome::Complete(empty_graph())
            },
            || true,
        ));
        let (second, second_lifecycle) = ready_graph(cache.acquire(
            key(1),
            &cancellation,
            || panic!("warm acquisition must not rebuild"),
            || true,
        ));

        assert_eq!(WorkspaceUsageGraphCacheLifecycle::Built, first_lifecycle);
        assert_eq!(WorkspaceUsageGraphCacheLifecycle::Hit, second_lifecycle);
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(1, builds.load(Ordering::SeqCst));
        assert_eq!(1, cache.len_for_test());
    }

    #[test]
    fn issue_1304_cancelled_usage_graph_is_not_published() {
        let cache = SnapshotWorkspaceUsageGraphCache::default();
        let cancellation = CancellationToken::default();

        let cancelled = cache.acquire(
            key(1),
            &cancellation,
            || WorkspaceUsageGraphCacheBuildOutcome::Cancelled,
            || true,
        );
        assert!(matches!(
            cancelled,
            WorkspaceUsageGraphCacheAcquisition::Cancelled
        ));
        assert_eq!(0, cache.len_for_test());

        let (_, lifecycle) = ready_graph(cache.acquire(
            key(1),
            &cancellation,
            || WorkspaceUsageGraphCacheBuildOutcome::Complete(empty_graph()),
            || true,
        ));
        assert_eq!(WorkspaceUsageGraphCacheLifecycle::Built, lifecycle);
    }

    #[test]
    fn issue_1304_source_generation_is_part_of_usage_graph_identity() {
        let cache = SnapshotWorkspaceUsageGraphCache::default();
        let cancellation = CancellationToken::default();
        let builds = AtomicUsize::new(0);

        for generation in [1, 2] {
            let (_, lifecycle) = ready_graph(cache.acquire(
                key(generation),
                &cancellation,
                || {
                    builds.fetch_add(1, Ordering::SeqCst);
                    WorkspaceUsageGraphCacheBuildOutcome::Complete(empty_graph())
                },
                || true,
            ));
            assert_eq!(WorkspaceUsageGraphCacheLifecycle::Built, lifecycle);
        }

        assert_eq!(2, builds.load(Ordering::SeqCst));
        assert_eq!(2, cache.len_for_test());
    }

    #[test]
    fn file_and_exact_graphs_have_separate_cache_entries() {
        let cache = SnapshotWorkspaceUsageGraphCache::default();
        let cancellation = CancellationToken::default();

        for kind in [
            WorkspaceUsageGraphKind::File,
            WorkspaceUsageGraphKind::Exact,
        ] {
            let (_, lifecycle) = ready_graph(cache.acquire(
                key_with_kind(1, kind),
                &cancellation,
                || WorkspaceUsageGraphCacheBuildOutcome::Complete(empty_graph()),
                || true,
            ));
            assert_eq!(WorkspaceUsageGraphCacheLifecycle::Built, lifecycle);
        }

        assert_eq!(2, cache.len_for_test());
    }

    #[test]
    fn issue_1304_generation_change_during_build_prevents_publication() {
        let cache = SnapshotWorkspaceUsageGraphCache::default();
        let cancellation = CancellationToken::default();

        let acquisition = cache.acquire(
            key(1),
            &cancellation,
            || WorkspaceUsageGraphCacheBuildOutcome::Complete(empty_graph()),
            || false,
        );

        assert!(matches!(
            acquisition,
            WorkspaceUsageGraphCacheAcquisition::Stale
        ));
        assert_eq!(0, cache.len_for_test());
    }

    #[test]
    fn issue_1304_concurrent_usage_graph_requests_are_single_flight() {
        let cache = Arc::new(SnapshotWorkspaceUsageGraphCache::default());
        let builds = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let leader_cache = Arc::clone(&cache);
        let leader_builds = Arc::clone(&builds);
        let leader = thread::spawn(move || {
            ready_graph(leader_cache.acquire(
                key(1),
                &CancellationToken::default(),
                || {
                    leader_builds.fetch_add(1, Ordering::SeqCst);
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    WorkspaceUsageGraphCacheBuildOutcome::Complete(empty_graph())
                },
                || true,
            ))
            .0
        });
        started_rx.recv().unwrap();

        let follower_cache = Arc::clone(&cache);
        let follower = thread::spawn(move || {
            ready_graph(follower_cache.acquire(
                key(1),
                &CancellationToken::default(),
                || panic!("same-key follower must not build"),
                || true,
            ))
            .0
        });
        for _ in 0..100 {
            if cache.waiting_count_for_test() == 1 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(1, cache.waiting_count_for_test());
        release_tx.send(()).unwrap();

        let leader_graph = leader.join().unwrap();
        let follower_graph = follower.join().unwrap();
        assert!(Arc::ptr_eq(&leader_graph, &follower_graph));
        assert_eq!(1, builds.load(Ordering::SeqCst));
    }
}
