#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph_cache::SnapshotWorkspaceUsageGraphCache;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

    use brokk_bifrost_analysis::analyzer::content_identity::WorkspaceContentIdentity;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphCacheAcquisition;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphCacheBuildOutcome;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphCacheKey;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphCacheLifecycle;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphKind;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph_cache::WorkspaceUsageGraphProducer;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageRankingGraph;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph_cache::ready_graph;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageRankingNode;

    use brokk_bifrost_core::hash::HashMap;
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;

    fn key_with_kind(
        content_seed: u64,
        kind: WorkspaceUsageGraphKind,
        ecosystem: UsageEcosystem,
    ) -> WorkspaceUsageGraphCacheKey {
        WorkspaceUsageGraphCacheKey::new(
            kind,
            [ecosystem],
            WorkspaceContentIdentity::for_test(content_seed),
        )
    }

    fn key(content_seed: u64) -> WorkspaceUsageGraphCacheKey {
        key_with_kind(
            content_seed,
            WorkspaceUsageGraphKind::Exact,
            UsageEcosystem::Rust,
        )
    }

    fn selected_key(content_seed: u64) -> WorkspaceUsageGraphCacheKey {
        WorkspaceUsageGraphCacheKey::new_with_producer(
            WorkspaceUsageGraphProducer::SelectedCanonical,
            WorkspaceUsageGraphKind::Exact,
            [UsageEcosystem::Jvm],
            WorkspaceContentIdentity::for_test(content_seed),
        )
    }

    fn incumbent_jvm_key(content_seed: u64) -> WorkspaceUsageGraphCacheKey {
        key_with_kind(
            content_seed,
            WorkspaceUsageGraphKind::Exact,
            UsageEcosystem::Jvm,
        )
    }

    fn empty_graph() -> WorkspaceUsageRankingGraph {
        WorkspaceUsageRankingGraph {
            nodes: Vec::<WorkspaceUsageRankingNode>::new(),
            edges: Vec::new(),
            node_indices_by_file: HashMap::default(),
            resolved_ecosystems: Vec::new(),
        }
    }

    #[test]
    #[hardwon(
        "#1317: A completed usage graph is reused by the exact warm key without a second build"
    )]
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
    fn incomplete_usage_graph_is_returned_but_never_cached() {
        let cache = SnapshotWorkspaceUsageGraphCache::default();
        let builds = AtomicUsize::new(0);
        let cancellation = CancellationToken::default();

        for _ in 0..2 {
            let acquisition = cache.acquire(
                key(91),
                &cancellation,
                || {
                    builds.fetch_add(1, Ordering::SeqCst);
                    WorkspaceUsageGraphCacheBuildOutcome::Incomplete(empty_graph())
                },
                || true,
            );
            assert!(matches!(
                acquisition,
                WorkspaceUsageGraphCacheAcquisition::Incomplete(_)
            ));
        }

        assert_eq!(2, builds.load(Ordering::SeqCst));
        assert_eq!(0, cache.len_for_test());
    }

    #[test]
    #[hardwon("#1317: Cancellation does not publish a graph, and a later request can build it")]
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
    fn issue_1304_workspace_content_is_part_of_usage_graph_identity() {
        let cache = SnapshotWorkspaceUsageGraphCache::default();
        let cancellation = CancellationToken::default();
        let builds = AtomicUsize::new(0);

        for content_seed in [1, 2] {
            let (_, lifecycle) = ready_graph(cache.acquire(
                key(content_seed),
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
                key_with_kind(1, kind, UsageEcosystem::Rust),
                &cancellation,
                || WorkspaceUsageGraphCacheBuildOutcome::Complete(empty_graph()),
                || true,
            ));
            assert_eq!(WorkspaceUsageGraphCacheLifecycle::Built, lifecycle);
        }

        assert_eq!(2, cache.len_for_test());
    }

    #[test]
    fn incumbent_and_selected_producers_cannot_cross_hit() {
        let cache = SnapshotWorkspaceUsageGraphCache::default();
        let cancellation = CancellationToken::default();
        let builds = AtomicUsize::new(0);

        for key in [incumbent_jvm_key(1), selected_key(1)] {
            let (_, lifecycle) = ready_graph(cache.acquire(
                key,
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
    fn stale_and_failed_selected_builds_publish_nothing_and_retry() {
        let cache = SnapshotWorkspaceUsageGraphCache::default();
        let cancellation = CancellationToken::default();

        let stale = cache.acquire(
            selected_key(1),
            &cancellation,
            || WorkspaceUsageGraphCacheBuildOutcome::Stale,
            || true,
        );
        assert!(matches!(stale, WorkspaceUsageGraphCacheAcquisition::Stale));
        assert_eq!(0, cache.len_for_test());

        let failed: Result<WorkspaceUsageGraphCacheAcquisition, &str> = cache.acquire_fallible(
            selected_key(1),
            &cancellation,
            || Err("selected graph build failed"),
            || true,
        );
        assert!(matches!(failed, Err("selected graph build failed")));
        assert_eq!(0, cache.len_for_test());

        let (_, lifecycle) = ready_graph(cache.acquire(
            selected_key(1),
            &cancellation,
            || WorkspaceUsageGraphCacheBuildOutcome::Complete(empty_graph()),
            || true,
        ));
        assert_eq!(WorkspaceUsageGraphCacheLifecycle::Built, lifecycle);
        assert_eq!(1, cache.len_for_test());
    }

    #[test]
    fn cancellation_outranks_a_simultaneous_build_error_and_retry_is_fresh() {
        let cache = SnapshotWorkspaceUsageGraphCache::default();
        let cancellation = CancellationToken::default();

        let cancelled: Result<WorkspaceUsageGraphCacheAcquisition, &str> = cache.acquire_fallible(
            selected_key(7),
            &cancellation,
            || {
                cancellation.cancel();
                Err("error raced cancellation")
            },
            || true,
        );
        assert!(matches!(
            cancelled,
            Ok(WorkspaceUsageGraphCacheAcquisition::Cancelled)
        ));
        assert_eq!(0, cache.len_for_test());

        let (_, lifecycle) = ready_graph(cache.acquire(
            selected_key(7),
            &CancellationToken::default(),
            || WorkspaceUsageGraphCacheBuildOutcome::Complete(empty_graph()),
            || true,
        ));
        assert_eq!(WorkspaceUsageGraphCacheLifecycle::Built, lifecycle);
        assert_eq!(1, cache.len_for_test());
    }

    #[test]
    fn issue_1304_content_change_during_build_prevents_publication() {
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
    #[hardwon("#1317: Concurrent usage ranking requests share one in-flight build")]
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
        brokk_bifrost_core::test_support::wait_for_nonzero_count(
            || cache.waiting_count_for_test(),
            "same-key request did not enter the single-flight wait",
        );
        assert_eq!(1, cache.waiting_count_for_test());
        release_tx.send(()).unwrap();

        let leader_graph = leader.join().unwrap();
        let follower_graph = follower.join().unwrap();
        assert!(Arc::ptr_eq(&leader_graph, &follower_graph));
        assert_eq!(1, builds.load(Ordering::SeqCst));
    }
}
