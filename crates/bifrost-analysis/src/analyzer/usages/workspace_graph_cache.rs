//! Snapshot-owned complete usage-ranking graphs.

use super::workspace_graph::{UsageEcosystem, WorkspaceUsageRankingGraph};
use crate::analyzer::complete_value_cache::{
    CompleteValueAcquisition, CompleteValueCache, CompleteValueWait,
};
use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::invalidation::{
    ArtifactVerdict, ArtifactVerdictLog, DerivedArtifactId, DerivedArtifactKind,
    InvalidationReason, RetentionReason,
};
use crate::analyzer::semantic::ids::StableDigest;
use crate::cancellation::CancellationToken;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use std::sync::Arc;

const USAGE_GRAPH_REPRESENTATION_VERSION: u32 = 1;
pub(crate) const DEFAULT_MAX_RETAINED_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum WorkspaceUsageGraphKind {
    File,
    Exact,
}

/// The identity of one complete usage-ranking graph.
///
/// `ecosystems` names what the graph spans and `workspace_content` is the
/// content identity of exactly the languages in those ecosystems (#2449). The
/// pairing is the point: a JVM graph is keyed by JVM content, so editing a
/// Python file cannot retire it. Before this the last field was the process's
/// whole source-generation vector, which moved for every language at once.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct WorkspaceUsageGraphCacheKey {
    representation_version: u32,
    kind: WorkspaceUsageGraphKind,
    ecosystems: Box<[UsageEcosystem]>,
    workspace_content: WorkspaceContentIdentity,
}

impl WorkspaceUsageGraphCacheKey {
    const ARTIFACT_DOMAIN: &[u8] = b"bifrost-workspace-usage-graph-key:v1";

    pub(crate) fn new(
        kind: WorkspaceUsageGraphKind,
        ecosystems: impl IntoIterator<Item = UsageEcosystem>,
        workspace_content: WorkspaceContentIdentity,
    ) -> Self {
        Self {
            representation_version: USAGE_GRAPH_REPRESENTATION_VERSION,
            kind,
            ecosystems: ecosystems.into_iter().collect(),
            workspace_content,
        }
    }

    fn artifact(&self) -> DerivedArtifactId {
        let mut hasher = CanonicalHasher::new(Self::ARTIFACT_DOMAIN);
        hasher.field(
            "representation_version",
            &self.representation_version.to_be_bytes(),
        );
        hasher.field(
            "kind",
            match self.kind {
                WorkspaceUsageGraphKind::File => b"file".as_slice(),
                WorkspaceUsageGraphKind::Exact => b"exact".as_slice(),
            },
        );
        hasher.sequence("ecosystems", &self.ecosystems, |hasher, ecosystem| {
            hasher.value(ecosystem.as_str().as_bytes());
        });
        hasher.field("content", self.workspace_content.digest().as_bytes());
        DerivedArtifactId::new(
            DerivedArtifactKind::WorkspaceUsageGraph,
            StableDigest::from_array(hasher.finish()),
        )
    }

    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(
            self.ecosystems
                .len()
                .saturating_mul(std::mem::size_of::<UsageEcosystem>()),
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
    Incomplete(WorkspaceUsageRankingGraph),
    Cancelled,
}

pub(crate) enum WorkspaceUsageGraphCacheAcquisition {
    Ready {
        graph: Arc<WorkspaceUsageRankingGraph>,
        lifecycle: WorkspaceUsageGraphCacheLifecycle,
        wait: CompleteValueWait,
    },
    /// Useful partial evidence that is deliberately not published to the
    /// complete-value cache.
    Incomplete(Arc<WorkspaceUsageRankingGraph>),
    Cancelled,
    Stale,
}

/// Snapshot-owned complete usage graphs, keyed by the content they were built
/// from.
///
/// The cache survives an analyzer update: an update carries it forward and an
/// ecosystem whose content did not move still answers from it.
pub(crate) struct SnapshotWorkspaceUsageGraphCache {
    max_retained_bytes: u64,
    values: CompleteValueCache<WorkspaceUsageGraphCacheKey, WorkspaceUsageRankingGraph>,
    verdicts: ArtifactVerdictLog,
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
            verdicts: ArtifactVerdictLog::default(),
        }
    }

    pub(crate) fn verdicts(&self) -> &ArtifactVerdictLog {
        &self.verdicts
    }

    /// Record that a caller could not state a content identity for the
    /// ecosystems it needs, so this cache was not consulted at all.
    pub(crate) fn record_missing_content_identity(
        &self,
        kind: WorkspaceUsageGraphKind,
        ecosystems: impl IntoIterator<Item = UsageEcosystem>,
    ) {
        let key = WorkspaceUsageGraphCacheKey::new(
            kind,
            ecosystems,
            WorkspaceContentIdentity::unattested(),
        );
        self.verdicts.record(ArtifactVerdict::Invalidated(
            InvalidationReason::ContentIdentityEvidenceMissing {
                artifact: key.artifact(),
            },
        ));
    }

    pub(crate) fn acquire(
        &self,
        key: WorkspaceUsageGraphCacheKey,
        cancellation: &CancellationToken,
        build: impl FnOnce() -> WorkspaceUsageGraphCacheBuildOutcome,
        content_is_current: impl Fn() -> bool,
    ) -> WorkspaceUsageGraphCacheAcquisition {
        let (acquisition, wait) = self.values.acquire(&key, cancellation);
        match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                if content_is_current() {
                    self.verdicts.record(ArtifactVerdict::Retained(
                        RetentionReason::InputsUnchanged {
                            artifact: key.artifact(),
                        },
                    ));
                    WorkspaceUsageGraphCacheAcquisition::Ready {
                        graph: value,
                        lifecycle: WorkspaceUsageGraphCacheLifecycle::Hit,
                        wait,
                    }
                } else {
                    WorkspaceUsageGraphCacheAcquisition::Stale
                }
            }
            CompleteValueAcquisition::Leader { permit } => {
                self.verdicts.record(ArtifactVerdict::Invalidated(
                    InvalidationReason::NoRetainedArtifact {
                        artifact: key.artifact(),
                    },
                ));
                match build() {
                    WorkspaceUsageGraphCacheBuildOutcome::Complete(graph) => {
                        if cancellation.is_cancelled() {
                            return WorkspaceUsageGraphCacheAcquisition::Cancelled;
                        }
                        if !content_is_current() {
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
                        if !content_is_current() {
                            return WorkspaceUsageGraphCacheAcquisition::Stale;
                        }
                        WorkspaceUsageGraphCacheAcquisition::Ready {
                            graph,
                            lifecycle: WorkspaceUsageGraphCacheLifecycle::Built,
                            wait,
                        }
                    }
                    WorkspaceUsageGraphCacheBuildOutcome::Incomplete(graph) => {
                        WorkspaceUsageGraphCacheAcquisition::Incomplete(Arc::new(graph))
                    }
                    WorkspaceUsageGraphCacheBuildOutcome::Cancelled => {
                        WorkspaceUsageGraphCacheAcquisition::Cancelled
                    }
                }
            }
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
        content_seed: u64,
        kind: WorkspaceUsageGraphKind,
    ) -> WorkspaceUsageGraphCacheKey {
        WorkspaceUsageGraphCacheKey::new(
            kind,
            [UsageEcosystem::Rust],
            WorkspaceContentIdentity::for_test(content_seed),
        )
    }

    fn key(content_seed: u64) -> WorkspaceUsageGraphCacheKey {
        key_with_kind(content_seed, WorkspaceUsageGraphKind::Exact)
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
            WorkspaceUsageGraphCacheAcquisition::Incomplete(_) => {
                panic!("complete test graph unexpectedly incomplete")
            }
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
