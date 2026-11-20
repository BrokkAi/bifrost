//! Local adapter for persisted engine hierarchy rows.

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::HierarchyDeclarationFacts;
use brokk_bifrost_core::analyzer::model::{CodeUnit, ImportInfo, Range};

#[repr(transparent)]
#[derive(Clone)]
pub(crate) struct JvmHierarchyFact(pub(crate) HierarchyDeclarationFacts);

impl AsRef<HierarchyDeclarationFacts> for JvmHierarchyFact {
    fn as_ref(&self) -> &HierarchyDeclarationFacts {
        &self.0
    }
}

impl AsMut<HierarchyDeclarationFacts> for JvmHierarchyFact {
    fn as_mut(&mut self) -> &mut HierarchyDeclarationFacts {
        &mut self.0
    }
}

impl brokk_bifrost_jvm::java::hierarchy::JavaHierarchyFact for JvmHierarchyFact {
    fn declaration(&self) -> &CodeUnit {
        &self.0.declaration
    }

    fn primary_range(&self) -> Option<&Range> {
        self.0.primary_range()
    }

    fn imports(&self) -> &[ImportInfo] {
        &self.0.imports
    }

    fn raw_supertypes(&self) -> &[String] {
        &self.0.raw_supertypes
    }
}

impl brokk_bifrost_jvm::kotlin::hierarchy::KotlinHierarchyFact for JvmHierarchyFact {
    fn declaration(&self) -> &CodeUnit {
        &self.0.declaration
    }

    fn primary_range(&self) -> Option<Range> {
        self.0.primary_range().copied()
    }

    fn imports(&self) -> &[ImportInfo] {
        &self.0.imports
    }

    fn raw_supertypes(&self) -> &[String] {
        &self.0.raw_supertypes
    }
}

// Each generation-lived ancestor entry owns its build receipt, including fills
// performed before any policy unit starts capturing reads.
use brokk_bifrost_analysis::analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::common::{
    ReplayableQueryCacheValue, replayable_query_cache_value,
};
use brokk_bifrost_analysis::analyzer::read_ledger::ReadKey;
use brokk_bifrost_analysis::analyzer::store::cache_budget::{RetainedHeap, retained_read_key};
use brokk_bifrost_analysis::analyzer::workspace_authority::{
    ReplayingMemo, ReplayingMemoEntry, memo_attribution,
};
use brokk_bifrost_core::analyzer::weighted_cache::build_weighted_cache;
use moka::sync::Cache;
use std::sync::Arc;

pub(crate) type AncestorMemo = DerivedMemo<CodeUnit, Vec<CodeUnit>>;

pub(crate) fn ancestor_memo(budget: u64) -> AncestorMemo {
    derived_memo(budget)
}

pub(crate) fn memoized_ancestors(
    memo: &AncestorMemo,
    analyzer: &dyn JvmDerivedAnalyzer,
    owner: &CodeUnit,
    build: impl FnOnce() -> Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    let ancestors = derived_read(memo, analyzer, owner, || {
        // Hydrated builders received their owner facts before this capture.
        // Name their source again inside the entry's receipt.
        analyzer.get_declarations(owner.source());
        let ancestors = Arc::new(build());
        let bytes = std::mem::size_of::<Vec<CodeUnit>>()
            + brokk_bifrost_analysis::analyzer::cache_weight::estimate_code_unit(owner) as usize
            + ancestors
                .iter()
                .map(|unit| {
                    brokk_bifrost_analysis::analyzer::cache_weight::estimate_code_unit(unit)
                        as usize
                })
                .sum::<usize>();
        (ancestors, bytes)
    });
    (*ancestors).clone()
}

type DerivedEntries<K, V> = Cache<K, Arc<ReplayingMemoEntry<V, ReadKey>>>;

type WeightedDerivedMemo<K, V> = ReplayingMemo<DerivedEntries<K, V>>;

pub(crate) type RawDerivedMemo<K, V> = WeightedDerivedMemo<K, Arc<V>>;

pub(crate) fn raw_derived_memo<K, V>(budget: u64) -> RawDerivedMemo<K, V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    ReplayingMemo::new(derived_entries(budget))
}

/// A bounded derived projection carries the reads of the entry it returns.
pub(crate) type DerivedMemo<K, V> =
    ReplayingMemo<DerivedCells<K, ReplayableQueryCacheValue<Arc<V>>>>;

/// The entries of one derived memo that any later request may replay, and the
/// memo's identity among the request-local entries.
///
/// An entry whose inputs a later request cannot verify, such as one read
/// through an explicitly configured jar, refuses reuse across requests, but it
/// is still the answer for the request that built it. Without a request-local
/// home every later call in that request rebuilt it: an external root's
/// descendant walk visits every workspace type, so a policy run did that walk
/// once per call (#14322). Those entries live in the active request's memo
/// registry, a region charged to the analyzer's own budget and retired with
/// the request. `identity` keeps memos of the same key and value types apart
/// there.
#[derive(Clone)]
pub(crate) struct DerivedCells<K, V> {
    identity: u64,
    shared: DerivedEntries<K, V>,
}

impl<K, V> DerivedCells<K, V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// The entry any later request may replay, if one is retained.
    #[cfg(test)]
    pub(crate) fn shared_entry(&self, key: &K) -> Option<Arc<ReplayingMemoEntry<V, ReadKey>>> {
        self.shared.get(key)
    }
}

/// A JVM analyzer whose derived memos can keep request-local entries.
pub(crate) trait JvmDerivedAnalyzer: IAnalyzer {
    /// The active request's memo registry, or none outside a request.
    fn request_memos(&self) -> Option<Arc<brokk_bifrost_core::domain_memo::DomainMemoRegistry>>;
}

/// A request-local entry's key: the outer request that pinned its inputs, the
/// memo, the analysis generation it was built under, and the memo's own key.
/// Overlapping requests on one analyzer share the query's memo registry, so
/// the request identity keeps one request's pinned answer from another, which
/// pins its own selection.
#[derive(Clone, PartialEq, Eq, Hash)]
struct RequestDerivedKey<K> {
    request: u64,
    memo: u64,
    generation: u64,
    key: K,
}

impl<K> brokk_bifrost_core::retention_budget::RetainedBytes for RequestDerivedKey<K> {
    // The entry's build bytes already count the key's heap, as in `shared`.
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

struct RequestDerivedEntry<V>(Arc<ReplayingMemoEntry<V, ReadKey>>);

// The derived memo replays the entry's reads on every hit.
impl<V> brokk_bifrost_core::domain_memo::ReplayEntry for RequestDerivedEntry<V> {}

impl<V> brokk_bifrost_core::retention_budget::RetainedBytes for RequestDerivedEntry<V> {
    fn retained_bytes(&self) -> usize {
        self.0.retained_bytes(|key| {
            let mut heap = RetainedHeap::default();
            retained_read_key(&mut heap, key);
            heap.total()
        })
    }
}

type RequestDerivedRegion<K, V> =
    brokk_bifrost_core::domain_memo::ReplayingRegion<RequestDerivedKey<K>, RequestDerivedEntry<V>>;

pub(crate) fn derived_memo<K, V>(budget: u64) -> DerivedMemo<K, V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    static NEXT_IDENTITY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    ReplayingMemo::new(DerivedCells {
        identity: NEXT_IDENTITY.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        shared: derived_entries(budget),
    })
}

fn derived_entries<K, V>(budget: u64) -> DerivedEntries<K, V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    build_weighted_cache(budget, |_, entry: &Arc<ReplayingMemoEntry<V, ReadKey>>| {
        u32::try_from(entry.retained_bytes(|key| {
            let mut heap = RetainedHeap::default();
            retained_read_key(&mut heap, key);
            heap.total()
        }))
        .unwrap_or(u32::MAX)
    })
}

pub(crate) fn derived_read<K, V>(
    memo: &DerivedMemo<K, V>,
    analyzer: &dyn JvmDerivedAnalyzer,
    key: &K,
    build: impl FnOnce() -> (Arc<V>, usize),
) -> Arc<V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    derived_read_retaining(memo, analyzer, key, || {
        let (value, bytes) = build();
        (value, bytes, true)
    })
}

/// [`derived_read`] for a build that can decline retention, such as a walk
/// that stopped on its caller's cancellation: the answer serves its own caller
/// and the next caller builds again.
pub(crate) fn derived_read_retaining<K, V>(
    memo: &DerivedMemo<K, V>,
    analyzer: &dyn JvmDerivedAnalyzer,
    key: &K,
    build: impl FnOnce() -> (Arc<V>, usize, bool),
) -> Arc<V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    let request_memos = analyzer.request_memos();
    let analyzer: &dyn IAnalyzer = analyzer;
    let result = memo
        .read(&memo_attribution(analyzer), |cells, capture| {
            if let Some(entry) = cells.shared.get(key) {
                return Ok::<_, std::convert::Infallible>(entry);
            }
            let request = request_memos.as_ref().and_then(|registry| {
                Some((
                    registry
                        .memo::<RequestDerivedRegion<K, ReplayableQueryCacheValue<Arc<V>>>>()?,
                    RequestDerivedKey {
                        request:
                            brokk_bifrost_analysis::analyzer::i_analyzer::current_outer_request()?
                                .id(),
                        memo: cells.identity,
                        generation: analyzer.project().analysis_generation(),
                        key: key.clone(),
                    },
                ))
            });
            // The memo replays the entry's reads, so the region only looks up.
            if let Some(entry) = request.as_ref().and_then(|(region, key)| region.peek(key)) {
                return Ok(Arc::clone(&entry.0));
            }
            let mut publish = false;
            let mut retain = false;
            let mut request_pinned = false;
            // The outer replay entry retains ledger channels too. Isolate
            // before its capture so caller store failures cannot mark it.
            let _fill =
                brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::for_retained_fill(analyzer);
            let entry = Arc::new(capture.build_weighted(|| {
                let mut bytes = 0;
                let attempt = replayable_query_cache_value(analyzer, || {
                    let built = build();
                    bytes = built.1;
                    retain = built.2;
                    built.0
                });
                publish = attempt.is_ok() && retain;
                request_pinned = retain
                    && attempt
                        .as_ref()
                        .is_err_and(|value| value.request_pinned_memo_admissible());
                let value = attempt.unwrap_or_else(|value| value);
                bytes += value.retained_receipt_bytes();
                (value, bytes)
            }));
            if publish {
                cells.shared.insert(key.clone(), Arc::clone(&entry));
            } else if request_pinned && let Some((region, key)) = request {
                // Every hit replays the entry's reads, the request-pinned
                // dependence among them, so no consumer can retain the value
                // as a product. A refused admission leaves it request-only.
                drop(region.insert(key, RequestDerivedEntry(Arc::clone(&entry))));
            }
            Ok(entry)
        })
        .expect("derived memo build is infallible");
    Arc::clone(result.replay())
}

#[cfg(test)]
mod memo_tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::{capture_query_reads, store::StoreError};

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#8184: the outer JVM replay entry retained an unrelated caller store failure"
    )]
    fn retained_derived_entry_excludes_enclosing_execution_failure() {
        let project = crate::inline_project::InlineTestProject::with_language(
            brokk_bifrost_core::analyzer::model::Language::Java,
        )
        .file("Example.java", "class Example {}\n")
        .build();
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(project.project_arc());
        let memo = derived_memo(64 * 1024);
        {
            let _outer = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer.record_query_failure(StoreError::new("unrelated"));
            assert_eq!(
                *derived_read(&memo, &analyzer, &"complete", || (Arc::new(17), 4)),
                17
            );
        }
        let (_, warm) = capture_query_reads(&analyzer, || {
            assert_eq!(
                *derived_read(&memo, &analyzer, &"complete", || panic!("must hit")),
                17
            );
        });
        assert_eq!(warm.execution_dependences(), 0, "{warm:?}");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7496: an incomplete memo build must remain unpublishable on warm hits"
    )]
    fn incomplete_builds_are_recomputed_for_successive_captures() {
        let project = crate::inline_project::InlineTestProject::with_language(
            brokk_bifrost_core::analyzer::model::Language::Java,
        )
        .file("Example.java", "class Example {}\n")
        .build();
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(project.project_arc());
        let memo = derived_memo(64 * 1024);
        let builds = std::cell::Cell::new(0);
        let read = || {
            let value = derived_read(&memo, &analyzer, &"incomplete", || {
                builds.set(builds.get() + 1);
                analyzer.record_query_failure(StoreError::new("injected memo build failure"));
                (Arc::new(17), std::mem::size_of::<i32>())
            });
            assert_eq!(*value, 17);
        };
        let (_, first) = capture_query_reads(&analyzer, read);
        let (_, next) = capture_query_reads(&analyzer, read);
        assert_eq!(builds.get(), 2, "an incomplete default is never retained");
        assert!(first.execution_dependences() > 0, "{first:?}");
        assert!(next.execution_dependences() > 0, "{next:?}");
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#14322: a fill that read a request-pinned JVM selection was rebuilt on every call in its own request"
    )]
    fn a_request_pinned_fill_serves_its_own_request_only() {
        use brokk_bifrost_analysis::analyzer::AnalyzerQueryScope;
        use brokk_bifrost_analysis::analyzer::i_analyzer::{
            record_request_pinned_input, refuse_request_row_read_reuse,
        };
        let project = crate::inline_project::InlineTestProject::with_language(
            brokk_bifrost_core::analyzer::model::Language::Java,
        )
        .file("Example.java", "class Example {}\n")
        .build();
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(project.project_arc());
        let memo = derived_memo(64 * 1024);
        let builds = std::cell::Cell::new(0);
        let read = |key: &'static str, build: &dyn Fn()| {
            capture_query_reads(&analyzer, || {
                *derived_read(&memo, &analyzer, &key, || {
                    builds.set(builds.get() + 1);
                    build();
                    (Arc::new(17), 4)
                })
            })
        };
        let pinned = || record_request_pinned_input();
        let refused = || refuse_request_row_read_reuse();
        let failed =
            || analyzer.record_query_failure(StoreError::new("injected memo build failure"));
        {
            let _request = AnalyzerQueryScope::new(&analyzer);
            for _ in 0..3 {
                let (value, reads) = read("pinned", &pinned);
                assert_eq!(value, 17);
                assert!(
                    !reads.is_bounded(),
                    "a hit must replay the pinned input: {reads:?}"
                );
                assert_eq!(
                    reads.request_pinned_dependences(),
                    reads.execution_dependences()
                );
                assert_eq!(
                    reads.ambient_verdict(),
                    brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::ExecutionDependent(
                        brokk_bifrost_core::analyzer::reuse_verdict::ExecutionCause::RequestPinned
                    ),
                    "a hit keeps the pinned cause"
                );
            }
            assert_eq!(builds.get(), 1, "the request replays its own pinned fill");
            read("refused", &refused);
            read("refused", &refused);
            assert_eq!(
                builds.get(),
                3,
                "an unexplained reuse refusal is never kept"
            );
            read("failed", &failed);
            read("failed", &failed);
            assert_eq!(
                builds.get(),
                5,
                "a fill bound to its execution is never kept"
            );
        }
        let _next = AnalyzerQueryScope::new(&analyzer);
        read("pinned", &pinned);
        assert_eq!(
            builds.get(),
            6,
            "another request cannot reuse a pinned fill"
        );
    }
}
