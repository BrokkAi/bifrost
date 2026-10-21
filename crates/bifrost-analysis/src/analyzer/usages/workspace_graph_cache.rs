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

pub(crate) const DEFAULT_MAX_RETAINED_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub enum WorkspaceUsageGraphKind {
    File,
    Exact,
}

/// The implementation that produced an exact graph.
///
/// Producer identity is part of the cache key even when two implementations
/// target the same semantics. This prevents a selected-canonical comparison
/// from accidentally measuring a production cache hit, and prevents the
/// production path from consuming an experimental graph before cutover.
///
/// `Production` is whatever the language registry routes today, which is a
/// mixture: Rust answers from the native engine and the other ten families
/// from their legacy passes. The variant used to be spelled `Incumbent`, which
/// stopped being true of the graph it labels at the Rust flip. What separates
/// two production generations is not this label but the graph-authority digest
/// the key folds, so the label only has to separate production from the
/// comparison harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub enum WorkspaceUsageGraphProducer {
    Production,
    #[cfg(any(test, feature = "test-support"))]
    SelectedCanonical,
}

/// The identity of one complete usage-ranking graph.
///
/// `ecosystems` names what the graph spans and `workspace_content` is the
/// content identity of exactly the languages in those ecosystems (#2449). The
/// pairing is the point: a JVM graph is keyed by JVM content, so editing a
/// Python file cannot retire it. Before this the last field was the process's
/// whole source-generation vector, which moved for every language at once.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[doc(hidden)]
pub struct WorkspaceUsageGraphCacheKey {
    /// Which implementation the registry routes each language's graph to.
    ///
    /// A derived-artifact id reaches persistence as a recorded read key, so a
    /// unit that depended on a pre-flip graph must not verify against a
    /// post-flip one built from identical bytes. Folding the live authority is
    /// what says so, and it needs no bump when the next language flips.
    graph_authority: StableDigest,
    producer: WorkspaceUsageGraphProducer,
    kind: WorkspaceUsageGraphKind,
    ecosystems: Box<[UsageEcosystem]>,
    workspace_content: WorkspaceContentIdentity,
}

impl WorkspaceUsageGraphCacheKey {
    const ARTIFACT_DOMAIN: &[u8] = b"bifrost-workspace-usage-graph-key:v1";

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new(
        kind: WorkspaceUsageGraphKind,
        ecosystems: impl IntoIterator<Item = UsageEcosystem>,
        workspace_content: WorkspaceContentIdentity,
    ) -> Self {
        Self::new_with_producer(
            WorkspaceUsageGraphProducer::Production,
            kind,
            ecosystems,
            workspace_content,
        )
    }

    #[doc(hidden)]
    pub fn new_with_producer(
        producer: WorkspaceUsageGraphProducer,
        kind: WorkspaceUsageGraphKind,
        ecosystems: impl IntoIterator<Item = UsageEcosystem>,
        workspace_content: WorkspaceContentIdentity,
    ) -> Self {
        Self {
            graph_authority: crate::analyzer::languages::graph_authority_digest(),
            producer,
            kind,
            ecosystems: ecosystems.into_iter().collect(),
            workspace_content,
        }
    }

    fn artifact(&self) -> DerivedArtifactId {
        let mut hasher = CanonicalHasher::new(Self::ARTIFACT_DOMAIN);
        hasher.field("graph_authority", self.graph_authority.as_bytes());
        hasher.field(
            "producer",
            match self.producer {
                WorkspaceUsageGraphProducer::Production => b"production".as_slice(),
                #[cfg(any(test, feature = "test-support"))]
                WorkspaceUsageGraphProducer::SelectedCanonical => {
                    b"selected-java-canonical".as_slice()
                }
            },
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
#[doc(hidden)]
pub enum WorkspaceUsageGraphCacheLifecycle {
    Hit,
    Built,
    UncachedOverBudget,
}

#[doc(hidden)]
pub enum WorkspaceUsageGraphCacheBuildOutcome {
    Complete(WorkspaceUsageRankingGraph),
    Incomplete(WorkspaceUsageRankingGraph),
    Cancelled,
    // Analysis and its consumers can enable test-support independently. Keep
    // the shared outcome shape stable across those feature combinations.
    Stale,
}

#[doc(hidden)]
pub enum WorkspaceUsageGraphCacheAcquisition {
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
#[doc(hidden)]
pub struct SnapshotWorkspaceUsageGraphCache {
    max_retained_bytes: u64,
    values: CompleteValueCache<WorkspaceUsageGraphCacheKey, WorkspaceUsageRankingGraph>,
    #[doc(hidden)]
    pub verdicts: ArtifactVerdictLog,
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

    #[doc(hidden)]
    pub fn verdicts(&self) -> &ArtifactVerdictLog {
        &self.verdicts
    }

    #[doc(hidden)]
    pub fn record_missing_content_identity_with_producer(
        &self,
        producer: WorkspaceUsageGraphProducer,
        kind: WorkspaceUsageGraphKind,
        ecosystems: impl IntoIterator<Item = UsageEcosystem>,
    ) {
        let key = WorkspaceUsageGraphCacheKey::new_with_producer(
            producer,
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

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn acquire(
        &self,
        key: WorkspaceUsageGraphCacheKey,
        cancellation: &CancellationToken,
        build: impl FnOnce() -> WorkspaceUsageGraphCacheBuildOutcome,
        content_is_current: impl Fn() -> bool,
    ) -> WorkspaceUsageGraphCacheAcquisition {
        match self.acquire_fallible(
            key,
            cancellation,
            || Ok::<_, std::convert::Infallible>(build()),
            content_is_current,
        ) {
            Ok(acquisition) => acquisition,
            Err(unreachable) => match unreachable {},
        }
    }

    #[doc(hidden)]
    pub fn acquire_fallible<E>(
        &self,
        key: WorkspaceUsageGraphCacheKey,
        cancellation: &CancellationToken,
        build: impl FnOnce() -> Result<WorkspaceUsageGraphCacheBuildOutcome, E>,
        content_is_current: impl Fn() -> bool,
    ) -> Result<WorkspaceUsageGraphCacheAcquisition, E> {
        let (acquisition, wait) = self.values.acquire(&key, cancellation);
        Ok(match acquisition {
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
                let build_result = build();
                if cancellation.is_cancelled() {
                    return Ok(WorkspaceUsageGraphCacheAcquisition::Cancelled);
                }
                let build_outcome = build_result?;
                match build_outcome {
                    WorkspaceUsageGraphCacheBuildOutcome::Complete(graph) => {
                        if cancellation.is_cancelled() {
                            return Ok(WorkspaceUsageGraphCacheAcquisition::Cancelled);
                        }
                        if !content_is_current() {
                            return Ok(WorkspaceUsageGraphCacheAcquisition::Stale);
                        }
                        let retained_bytes =
                            key.retained_bytes().saturating_add(graph.retained_bytes());
                        let graph = Arc::new(graph);
                        if retained_bytes as u64 > self.max_retained_bytes {
                            return Ok(WorkspaceUsageGraphCacheAcquisition::Ready {
                                graph,
                                lifecycle: WorkspaceUsageGraphCacheLifecycle::UncachedOverBudget,
                                wait,
                            });
                        }
                        permit.publish_complete(Arc::clone(&graph));
                        if !content_is_current() {
                            return Ok(WorkspaceUsageGraphCacheAcquisition::Stale);
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
                    WorkspaceUsageGraphCacheBuildOutcome::Stale => {
                        WorkspaceUsageGraphCacheAcquisition::Stale
                    }
                }
            }
            CompleteValueAcquisition::Cancelled => WorkspaceUsageGraphCacheAcquisition::Cancelled,
            CompleteValueAcquisition::Rejected => WorkspaceUsageGraphCacheAcquisition::Stale,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn len_for_test(&self) -> u64 {
        self.values.len_for_test()
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn waiting_count_for_test(&self) -> usize {
        self.values.waiting_count_for_test()
    }
}

impl Default for SnapshotWorkspaceUsageGraphCache {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_RETAINED_BYTES)
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn ready_graph(
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
