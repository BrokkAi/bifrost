//! Snapshot-owned complete Java usage evidence.
//!
//! One value is the uncapped semantic scan for one Java file and one exact
//! target set. Request-level file, source-byte, and usage limits deliberately
//! do not appear here: callers project the complete evidence after acquiring
//! it. The cache key therefore binds every semantic identity that can change
//! the scan while keeping request policy out of the reusable value.

use super::model::UsageHit;
use crate::analyzer::complete_value_cache::{
    CompleteValueAcquisition, CompleteValueCache, CompleteValueWait,
};
use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::{CodeUnit, DeclarationId, Language, ProjectFile};
use crate::cancellation::CancellationToken;
use std::collections::BTreeSet;
use std::mem::size_of;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// A bump here invalidates every retained value, including values carried
/// through an analyzer update.
pub(crate) const JAVA_USAGE_EVIDENCE_REPRESENTATION_VERSION: u32 = 1;
pub(crate) const DEFAULT_MAX_RETAINED_BYTES: u64 = 32 * 1024 * 1024;

/// The semantic family named by [`JavaUsageEvidenceCacheKey`]. Keeping the
/// family in the key prevents an accidentally shared cache from treating a
/// different Java representation as the same value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum JavaUsageEvidenceDomain {
    ExactSemanticScan,
}

/// Identity of the active semantic-model publication visible to a Java scan.
///
/// `None` is intentionally distinct from an active model-set hash. A caller
/// that has an active publication must pass its exact
/// `active_model_set_hash()` (including the producer identity folded into the
/// hash by the model runtime); a caller with no publication passes `None`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum JavaUsageEvidenceSemanticModelIdentity {
    None,
    ActiveModelSet(StableDigest),
}

/// Canonical identity of the exact target specification used by one file
/// scan.
///
/// `target_ids` retain every declaration in the target group in sorted order.
/// `structured_target_fingerprint` must be derived by the resolver owner from
/// all remaining structured `TargetSpec` fields (kind, owner, member name,
/// receiver-owner set, callable arities, and any equivalent options). It is
/// intentionally required rather than inferred from rendered names: a
/// rendered spelling is not an exact target identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct JavaUsageEvidenceTargetKey {
    target_ids: Box<[DeclarationId]>,
    structured_target_fingerprint: StableDigest,
}

impl JavaUsageEvidenceTargetKey {
    /// Build a canonical target key from the exact declarations in a target
    /// group. Duplicate declarations are removed because `TargetSpec` stores
    /// its target group as a set.
    pub(crate) fn from_targets(
        targets: &[CodeUnit],
        structured_target_fingerprint: StableDigest,
    ) -> Self {
        assert!(!targets.is_empty(), "Java target key must not be empty");
        let mut target_ids = targets
            .iter()
            .map(CodeUnit::declaration_id)
            .collect::<Vec<_>>();
        target_ids.sort_unstable();
        target_ids.dedup();
        Self {
            target_ids: target_ids.into_boxed_slice(),
            structured_target_fingerprint,
        }
    }

    /// Build a target key when the caller has already computed declaration
    /// identities. This is useful at integration boundaries that retain only
    /// canonical IDs after resolver preparation.
    #[cfg(test)]
    pub(crate) fn from_declaration_ids(
        target_ids: impl IntoIterator<Item = DeclarationId>,
        structured_target_fingerprint: StableDigest,
    ) -> Self {
        let mut target_ids = target_ids.into_iter().collect::<Vec<_>>();
        assert!(!target_ids.is_empty(), "Java target key must not be empty");
        target_ids.sort_unstable();
        target_ids.dedup();
        Self {
            target_ids: target_ids.into_boxed_slice(),
            structured_target_fingerprint,
        }
    }

    fn retained_bytes(&self) -> u64 {
        (size_of::<Self>() as u64).saturating_add(
            self.target_ids
                .iter()
                .map(|id| size_of::<DeclarationId>() as u64 + id.as_str().len() as u64)
                .sum::<u64>(),
        )
    }
}

/// The complete validity identity for one immutable Java file scan.
///
/// `resolution_policy_fingerprint` is mandatory. The caller must include the
/// exact active model/semantic-pack producer identity and any resolver policy
/// that can affect Java's answer. If it cannot attest that identity, it must
/// bypass this cache rather than inventing a weaker key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct JavaUsageEvidenceCacheKey {
    representation_version: u32,
    domain: JavaUsageEvidenceDomain,
    language: Language,
    workspace_content: WorkspaceContentIdentity,
    file: ProjectFile,
    target: JavaUsageEvidenceTargetKey,
    semantic_model_identity: JavaUsageEvidenceSemanticModelIdentity,
    resolution_policy_fingerprint: StableDigest,
}

impl JavaUsageEvidenceCacheKey {
    pub(crate) fn new(
        workspace_content: WorkspaceContentIdentity,
        file: ProjectFile,
        target: JavaUsageEvidenceTargetKey,
        semantic_model_identity: JavaUsageEvidenceSemanticModelIdentity,
        resolution_policy_fingerprint: StableDigest,
    ) -> Self {
        assert_eq!(
            file.language(),
            Language::Java,
            "Java usage evidence keys must name a Java source file"
        );
        Self {
            representation_version: JAVA_USAGE_EVIDENCE_REPRESENTATION_VERSION,
            domain: JavaUsageEvidenceDomain::ExactSemanticScan,
            language: Language::Java,
            workspace_content,
            file,
            target,
            semantic_model_identity,
            resolution_policy_fingerprint,
        }
    }

    fn retained_bytes(&self) -> u64 {
        (size_of::<Self>() as u64)
            .saturating_add(self.file.retained_bytes() as u64)
            .saturating_add(self.target.retained_bytes())
    }
}

/// Immutable, uncapped semantic evidence for one Java file and target set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JavaFileUsageEvidence {
    pub(crate) hits: BTreeSet<UsageHit>,
    pub(crate) unproven_hits: BTreeSet<UsageHit>,
    pub(crate) raw_match_count: usize,
}

impl JavaFileUsageEvidence {
    pub(crate) fn new(
        hits: BTreeSet<UsageHit>,
        unproven_hits: BTreeSet<UsageHit>,
        raw_match_count: usize,
    ) -> Self {
        Self {
            hits,
            unproven_hits,
            raw_match_count,
        }
    }

    fn retained_bytes(&self) -> u64 {
        (size_of::<Self>() as u64)
            .saturating_add(retained_hit_set_bytes(&self.hits))
            .saturating_add(retained_hit_set_bytes(&self.unproven_hits))
    }
}

fn retained_hit_set_bytes(hits: &BTreeSet<UsageHit>) -> u64 {
    size_of::<BTreeSet<UsageHit>>() as u64
        + hits
            .iter()
            .map(|hit| {
                // The payload and owned snippet are direct allocations. The
                // small per-node tree links are counted explicitly so the
                // admission decision does not pretend a set is free.
                size_of::<UsageHit>() as u64
                    + (3 * size_of::<usize>()) as u64
                    + hit.file.retained_bytes() as u64
                    + retained_code_unit_bytes(&hit.enclosing)
                    + hit.snippet.capacity() as u64
            })
            .sum::<u64>()
}

fn retained_code_unit_bytes(unit: &CodeUnit) -> u64 {
    size_of::<CodeUnit>() as u64
        + unit.source().retained_bytes() as u64
        + unit.package_name().len() as u64
        + unit.short_name().len() as u64
        + unit.signature().map_or(0, str::len) as u64
}

/// Typed reason a file could not produce complete exact evidence.
///
/// These values are intentionally not retained. A failed, cancelled, or
/// incomplete leader must leave no ready value for followers to mistake for a
/// complete zero-hit scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JavaUsageEvidenceOmission {
    SourceRead,
    ParserSetup,
    Parse,
    StoreProvider,
    ClassRange,
    RelationalFrontier,
    UnavailableCapability,
    InternalSafetyCap,
    Failed,
}

pub(crate) enum JavaUsageEvidenceBuildOutcome {
    Complete(JavaFileUsageEvidence),
    Omitted(JavaUsageEvidenceOmission),
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JavaUsageEvidenceCacheLifecycle {
    Hit,
    Built,
    UncachedOverBudget,
}

pub(crate) enum JavaUsageEvidenceCacheAcquisition {
    Ready {
        evidence: Arc<JavaFileUsageEvidence>,
        lifecycle: JavaUsageEvidenceCacheLifecycle,
        wait: CompleteValueWait,
    },
    Omitted(JavaUsageEvidenceOmission),
    Cancelled,
    Stale,
}

#[doc(hidden)]
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JavaUsageEvidenceCacheStats {
    pub hits: u64,
    pub builds: u64,
    pub uncached_over_budget: u64,
    pub omitted: u64,
    pub cancelled: u64,
    pub stale: u64,
}

#[derive(Default)]
struct AtomicJavaUsageEvidenceCacheStats {
    hits: AtomicU64,
    builds: AtomicU64,
    uncached_over_budget: AtomicU64,
    omitted: AtomicU64,
    cancelled: AtomicU64,
    stale: AtomicU64,
}

#[cfg(any(test, feature = "test-support"))]
impl AtomicJavaUsageEvidenceCacheStats {
    fn snapshot(&self) -> JavaUsageEvidenceCacheStats {
        JavaUsageEvidenceCacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            builds: self.builds.load(Ordering::Relaxed),
            uncached_over_budget: self.uncached_over_budget.load(Ordering::Relaxed),
            omitted: self.omitted.load(Ordering::Relaxed),
            cancelled: self.cancelled.load(Ordering::Relaxed),
            stale: self.stale.load(Ordering::Relaxed),
        }
    }

    fn reset(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.builds.store(0, Ordering::Relaxed);
        self.uncached_over_budget.store(0, Ordering::Relaxed);
        self.omitted.store(0, Ordering::Relaxed);
        self.cancelled.store(0, Ordering::Relaxed);
        self.stale.store(0, Ordering::Relaxed);
    }
}

/// Snapshot-owned complete Java evidence with cancellation-aware single-flight.
pub(crate) struct SnapshotJavaUsageEvidenceCache {
    max_retained_bytes: u64,
    values: CompleteValueCache<JavaUsageEvidenceCacheKey, JavaFileUsageEvidence>,
    stats: AtomicJavaUsageEvidenceCacheStats,
}

impl SnapshotJavaUsageEvidenceCache {
    pub(crate) fn new(max_retained_bytes: u64) -> Self {
        Self {
            max_retained_bytes,
            values: CompleteValueCache::new(
                max_retained_bytes,
                |key: &JavaUsageEvidenceCacheKey, evidence: &Arc<JavaFileUsageEvidence>| {
                    retained_bytes(key, evidence).clamp(1, u32::MAX as u64) as u32
                },
            ),
            stats: AtomicJavaUsageEvidenceCacheStats::default(),
        }
    }

    /// Acquire exact evidence or build it once for all same-key followers.
    ///
    /// `content_is_current` must compare the captured whole-JVM content
    /// identity with the live analyzer immediately before publication. The
    /// closure must return `Complete` only after all semantic work is complete;
    /// omitted and cancelled outcomes are deliberately uncached.
    pub(crate) fn acquire(
        &self,
        key: JavaUsageEvidenceCacheKey,
        cancellation: &CancellationToken,
        build: impl FnOnce() -> JavaUsageEvidenceBuildOutcome,
        content_is_current: impl Fn() -> bool,
    ) -> JavaUsageEvidenceCacheAcquisition {
        let (acquisition, wait) = self.values.acquire(&key, cancellation);
        match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                if !content_is_current() {
                    self.stats.stale.fetch_add(1, Ordering::Relaxed);
                    JavaUsageEvidenceCacheAcquisition::Stale
                } else {
                    self.stats.hits.fetch_add(1, Ordering::Relaxed);
                    JavaUsageEvidenceCacheAcquisition::Ready {
                        evidence: value,
                        lifecycle: JavaUsageEvidenceCacheLifecycle::Hit,
                        wait,
                    }
                }
            }
            CompleteValueAcquisition::Leader { permit } => {
                self.stats.builds.fetch_add(1, Ordering::Relaxed);
                match build() {
                    JavaUsageEvidenceBuildOutcome::Complete(evidence) => {
                        if cancellation.is_cancelled() {
                            self.stats.cancelled.fetch_add(1, Ordering::Relaxed);
                            return JavaUsageEvidenceCacheAcquisition::Cancelled;
                        }
                        if !content_is_current() {
                            self.stats.stale.fetch_add(1, Ordering::Relaxed);
                            return JavaUsageEvidenceCacheAcquisition::Stale;
                        }
                        let retained_bytes = retained_bytes(&key, &evidence);
                        let evidence = Arc::new(evidence);
                        if retained_bytes > self.max_retained_bytes {
                            self.stats
                                .uncached_over_budget
                                .fetch_add(1, Ordering::Relaxed);
                            return JavaUsageEvidenceCacheAcquisition::Ready {
                                evidence,
                                lifecycle: JavaUsageEvidenceCacheLifecycle::UncachedOverBudget,
                                wait,
                            };
                        }
                        permit.publish_complete(Arc::clone(&evidence));
                        if !content_is_current() {
                            self.stats.stale.fetch_add(1, Ordering::Relaxed);
                            return JavaUsageEvidenceCacheAcquisition::Stale;
                        }
                        JavaUsageEvidenceCacheAcquisition::Ready {
                            evidence,
                            lifecycle: JavaUsageEvidenceCacheLifecycle::Built,
                            wait,
                        }
                    }
                    JavaUsageEvidenceBuildOutcome::Omitted(reason) => {
                        self.stats.omitted.fetch_add(1, Ordering::Relaxed);
                        JavaUsageEvidenceCacheAcquisition::Omitted(reason)
                    }
                    JavaUsageEvidenceBuildOutcome::Cancelled => {
                        self.stats.cancelled.fetch_add(1, Ordering::Relaxed);
                        JavaUsageEvidenceCacheAcquisition::Cancelled
                    }
                }
            }
            CompleteValueAcquisition::Rejected => {
                self.stats.omitted.fetch_add(1, Ordering::Relaxed);
                JavaUsageEvidenceCacheAcquisition::Omitted(JavaUsageEvidenceOmission::Failed)
            }
            CompleteValueAcquisition::Cancelled => {
                self.stats.cancelled.fetch_add(1, Ordering::Relaxed);
                JavaUsageEvidenceCacheAcquisition::Cancelled
            }
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn stats_for_test(&self) -> JavaUsageEvidenceCacheStats {
        self.stats.snapshot()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn reset_stats_for_test(&self) {
        self.stats.reset();
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

fn retained_bytes(key: &JavaUsageEvidenceCacheKey, evidence: &JavaFileUsageEvidence) -> u64 {
    key.retained_bytes()
        .saturating_add(evidence.retained_bytes())
}

impl Default for SnapshotJavaUsageEvidenceCache {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_RETAINED_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::model::CodeUnitType;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::thread;
    use std::time::{Duration, Instant};

    fn digest(seed: u64) -> StableDigest {
        StableDigest::sha256(seed.to_be_bytes())
    }

    fn key(seed: u64) -> JavaUsageEvidenceCacheKey {
        let file = ProjectFile::new(std::env::temp_dir(), "src/Target.java");
        let target = CodeUnit::new(file.clone(), CodeUnitType::Function, "example", "target");
        JavaUsageEvidenceCacheKey::new(
            WorkspaceContentIdentity::for_test(seed),
            file,
            JavaUsageEvidenceTargetKey::from_targets(&[target], digest(101)),
            JavaUsageEvidenceSemanticModelIdentity::None,
            digest(102),
        )
    }

    fn evidence(seed: u64) -> JavaFileUsageEvidence {
        let file = ProjectFile::new(std::env::temp_dir(), format!("Evidence{seed}.java"));
        let enclosing = CodeUnit::new(file.clone(), CodeUnitType::Function, "example", "caller");
        let hit = UsageHit::new(
            file,
            1,
            seed as usize,
            seed as usize + 1,
            enclosing,
            1.0,
            "hit",
        );
        JavaFileUsageEvidence::new(BTreeSet::from([hit]), BTreeSet::new(), 1)
    }

    fn wait_for_follower(cache: &SnapshotJavaUsageEvidenceCache) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while cache.waiting_count_for_test() == 0 {
            assert!(
                Instant::now() < deadline,
                "follower did not enter single-flight wait"
            );
            thread::yield_now();
        }
    }

    fn ready(
        acquisition: JavaUsageEvidenceCacheAcquisition,
    ) -> (Arc<JavaFileUsageEvidence>, JavaUsageEvidenceCacheLifecycle) {
        match acquisition {
            JavaUsageEvidenceCacheAcquisition::Ready {
                evidence,
                lifecycle,
                ..
            } => (evidence, lifecycle),
            JavaUsageEvidenceCacheAcquisition::Omitted(reason) => {
                panic!("unexpected omission: {reason:?}")
            }
            JavaUsageEvidenceCacheAcquisition::Cancelled => panic!("unexpected cancellation"),
            JavaUsageEvidenceCacheAcquisition::Stale => panic!("unexpected stale value"),
        }
    }

    #[test]
    fn same_key_coalesces_and_hands_followers_the_same_evidence_arc() {
        let cache = Arc::new(SnapshotJavaUsageEvidenceCache::new(1024 * 1024));
        let cancellation = CancellationToken::default();
        let key = key(1);
        let (leader, _) = cache.values.acquire(&key, &cancellation);
        let CompleteValueAcquisition::Leader { permit } = leader else {
            panic!("first exact key must lead")
        };

        let follower_cache = Arc::clone(&cache);
        let follower_key = key.clone();
        let follower = thread::spawn(move || {
            follower_cache.acquire(
                follower_key,
                &CancellationToken::default(),
                || panic!("follower must not build"),
                || true,
            )
        });
        wait_for_follower(&cache);

        let built = Arc::new(evidence(1));
        permit.publish_complete(Arc::clone(&built));
        let (received, lifecycle) = ready(follower.join().expect("follower thread"));
        assert!(Arc::ptr_eq(&built, &received));
        assert_eq!(JavaUsageEvidenceCacheLifecycle::Hit, lifecycle);
        assert_eq!(1, received.raw_match_count);
    }

    #[test]
    fn target_content_file_and_policy_dimensions_isolate_entries() {
        let cache = SnapshotJavaUsageEvidenceCache::new(1024 * 1024);
        let cancellation = CancellationToken::default();
        let builds = AtomicUsize::new(0);
        let base = key(1);
        let keys = [
            base.clone(),
            key(2),
            JavaUsageEvidenceCacheKey::new(
                base.workspace_content,
                ProjectFile::new(std::env::temp_dir(), "src/Other.java"),
                base.target.clone(),
                base.semantic_model_identity,
                base.resolution_policy_fingerprint,
            ),
            JavaUsageEvidenceCacheKey::new(
                base.workspace_content,
                base.file.clone(),
                JavaUsageEvidenceTargetKey::from_declaration_ids(
                    base.target.target_ids.iter().cloned(),
                    digest(103),
                ),
                base.semantic_model_identity,
                base.resolution_policy_fingerprint,
            ),
            JavaUsageEvidenceCacheKey::new(
                base.workspace_content,
                base.file.clone(),
                base.target.clone(),
                JavaUsageEvidenceSemanticModelIdentity::ActiveModelSet(digest(105)),
                digest(104),
            ),
        ];
        for (index, key) in keys.into_iter().enumerate() {
            let (_, lifecycle) = ready(cache.acquire(
                key,
                &cancellation,
                || {
                    builds.fetch_add(1, Ordering::SeqCst);
                    JavaUsageEvidenceBuildOutcome::Complete(evidence(index as u64))
                },
                || true,
            ));
            assert_eq!(JavaUsageEvidenceCacheLifecycle::Built, lifecycle);
        }
        assert_eq!(5, builds.load(Ordering::SeqCst));
        assert_eq!(5, cache.len_for_test());
    }

    #[test]
    fn cancelled_leader_and_omitted_value_are_never_published() {
        let cache = SnapshotJavaUsageEvidenceCache::new(1024 * 1024);
        let cancellation = CancellationToken::default();
        let cancelled = cache.acquire(
            key(1),
            &cancellation,
            || JavaUsageEvidenceBuildOutcome::Cancelled,
            || true,
        );
        assert!(matches!(
            cancelled,
            JavaUsageEvidenceCacheAcquisition::Cancelled
        ));
        assert_eq!(0, cache.len_for_test());

        let omissions = [
            JavaUsageEvidenceOmission::SourceRead,
            JavaUsageEvidenceOmission::ParserSetup,
            JavaUsageEvidenceOmission::Parse,
            JavaUsageEvidenceOmission::StoreProvider,
            JavaUsageEvidenceOmission::ClassRange,
            JavaUsageEvidenceOmission::RelationalFrontier,
            JavaUsageEvidenceOmission::UnavailableCapability,
            JavaUsageEvidenceOmission::InternalSafetyCap,
            JavaUsageEvidenceOmission::Failed,
        ];
        for (index, reason) in omissions.into_iter().enumerate() {
            let omitted = cache.acquire(
                key(index as u64 + 2),
                &cancellation,
                || JavaUsageEvidenceBuildOutcome::Omitted(reason),
                || true,
            );
            let JavaUsageEvidenceCacheAcquisition::Omitted(actual) = omitted else {
                panic!("omission {reason:?} was not preserved")
            };
            assert_eq!(reason, actual);
            assert_eq!(0, cache.len_for_test());
        }
    }

    #[test]
    fn stale_content_does_not_publish_and_can_retry_when_current() {
        let cache = SnapshotJavaUsageEvidenceCache::new(1024 * 1024);
        let cancellation = CancellationToken::default();
        let current = AtomicBool::new(false);
        let stale = cache.acquire(
            key(1),
            &cancellation,
            || JavaUsageEvidenceBuildOutcome::Complete(evidence(1)),
            || current.load(Ordering::SeqCst),
        );
        assert!(matches!(stale, JavaUsageEvidenceCacheAcquisition::Stale));
        assert_eq!(0, cache.len_for_test());

        current.store(true, Ordering::SeqCst);
        let (_, lifecycle) = ready(cache.acquire(
            key(1),
            &cancellation,
            || JavaUsageEvidenceBuildOutcome::Complete(evidence(2)),
            || current.load(Ordering::SeqCst),
        ));
        assert_eq!(JavaUsageEvidenceCacheLifecycle::Built, lifecycle);
        assert_eq!(1, cache.len_for_test());
    }

    #[test]
    fn oversized_complete_evidence_is_returned_but_not_retained() {
        let cache = SnapshotJavaUsageEvidenceCache::new(1);
        let cancellation = CancellationToken::default();
        let first = ready(cache.acquire(
            key(1),
            &cancellation,
            || JavaUsageEvidenceBuildOutcome::Complete(evidence(1)),
            || true,
        ));
        assert_eq!(JavaUsageEvidenceCacheLifecycle::UncachedOverBudget, first.1);
        assert_eq!(0, cache.len_for_test());

        let second = ready(cache.acquire(
            key(1),
            &cancellation,
            || JavaUsageEvidenceBuildOutcome::Complete(evidence(2)),
            || true,
        ));
        assert_eq!(
            JavaUsageEvidenceCacheLifecycle::UncachedOverBudget,
            second.1
        );
        assert_eq!(2, cache.stats_for_test().builds);
    }

    #[test]
    fn cancelled_follower_does_not_cancel_a_valid_leader() {
        let cache = Arc::new(SnapshotJavaUsageEvidenceCache::new(1024 * 1024));
        let cancellation = CancellationToken::default();
        let key = key(1);
        let (acquisition, _) = cache.values.acquire(&key, &cancellation);
        let CompleteValueAcquisition::Leader { permit } = acquisition else {
            panic!("first exact key must lead")
        };

        let follower_cancellation = CancellationToken::default();
        let follower_cancel = follower_cancellation.clone();
        let follower_cache = Arc::clone(&cache);
        let follower_key = key.clone();
        let follower = thread::spawn(move || {
            follower_cache.acquire(
                follower_key,
                &follower_cancel,
                || panic!("cancelled follower must not build"),
                || true,
            )
        });
        wait_for_follower(&cache);
        follower_cancellation.cancel();
        assert!(matches!(
            follower.join().expect("cancelled follower thread"),
            JavaUsageEvidenceCacheAcquisition::Cancelled
        ));

        let built = Arc::new(evidence(1));
        permit.publish_complete(Arc::clone(&built));
        let (received, lifecycle) = ready(cache.acquire(
            key,
            &cancellation,
            || panic!("published leader must be ready"),
            || true,
        ));
        assert!(Arc::ptr_eq(&built, &received));
        assert_eq!(JavaUsageEvidenceCacheLifecycle::Hit, lifecycle);
    }

    #[test]
    fn carried_snapshot_cache_reuses_content_keyed_evidence() {
        let caches = crate::analyzer::AnalyzerSnapshotCaches::new(1024 * 1024);
        let key = key(1);
        let cancellation = CancellationToken::default();
        let (_, lifecycle) = ready(caches.java_usage_evidence().acquire(
            key.clone(),
            &cancellation,
            || JavaUsageEvidenceBuildOutcome::Complete(evidence(1)),
            || true,
        ));
        assert_eq!(JavaUsageEvidenceCacheLifecycle::Built, lifecycle);

        let carried = caches.carry_content_keyed_values_forward();
        let (reused, lifecycle) = ready(carried.java_usage_evidence().acquire(
            key,
            &cancellation,
            || panic!("carried cache must hit"),
            || true,
        ));
        assert_eq!(JavaUsageEvidenceCacheLifecycle::Hit, lifecycle);
        assert_eq!(1, reused.raw_match_count);
    }
}
