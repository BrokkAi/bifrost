use brokk_bifrost_analysis::analyzer::common::QueryCacheCell;
use brokk_bifrost_analysis::analyzer::read_ledger::ReadKey;
use brokk_bifrost_analysis::analyzer::read_ledger::WorkspaceFactFamily;
use brokk_bifrost_analysis::analyzer::workspace_authority::WorkspaceAuthorityMemo;
use brokk_bifrost_analysis::analyzer::workspace_authority::{ReplayingMemo, ReplayingMemoEntry};
use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::capabilities::DescendantIndexVariant;

use brokk_bifrost_core::analyzer::capabilities::DirectDescendantIndex;

use brokk_bifrost_core::analyzer::pool_memo::KeyedPoolSafeMemo;

use brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::estimate_collection_bytes;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::hash::Hash;
use std::mem::size_of;
use std::sync::Arc;
#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::AtomicUsize;

use brokk_bifrost_semantic::analyzer::semantic::ids::StableDigest;

use brokk_bifrost_analysis::analyzer::cache_weight::estimate_code_unit;

use brokk_bifrost_analysis::analyzer::cache_weight::estimate_project_file;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgesCache;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::weight_usage_edges;

use brokk_bifrost_core::analyzer::weighted_cache::build_weighted_cache;

use brokk_bifrost_core::analyzer::weighted_cache::weight_bytes;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PersistedFqnLookup {
    pub(crate) name: String,
    pub(crate) normalized: bool,
}

/// A bounded generation cache with one pool-independent store build per
/// same-key miss wave.
///
/// A wave shares its value and typed failure receipt with every holder. Each
/// holder replays failures into its own context. Failed attempts leave no
/// bounded value and the keyed coordinator is retired after publication.
/// Identity-conditional removal preserves a replacement coordinator (#2795).
struct SingleFlightRead<V> {
    value: Option<Arc<V>>,
    receipt: brokk_bifrost_analysis::analyzer::common::QueryCacheBuildReceipt,
}

pub(crate) struct BoundedSingleFlightCache<K, V> {
    values: Cache<K, Arc<V>>,
    builds: KeyedPoolSafeMemo<K, SingleFlightRead<V>>,
}

impl<K, V> BoundedSingleFlightCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    fn new(values: Cache<K, Arc<V>>) -> Self {
        Self {
            values,
            builds: KeyedPoolSafeMemo::new(),
        }
    }

    pub(crate) fn get_or_try_build(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
        key: &K,
        build: impl FnOnce() -> Option<V>,
    ) -> Option<Arc<V>> {
        self.get_or_try_build_inner(analyzer, key, || {}, || {}, build)
    }

    fn get_or_try_build_inner(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
        key: &K,
        after_cell: impl FnOnce(),
        after_result: impl FnOnce(),
        build: impl FnOnce() -> Option<V>,
    ) -> Option<Arc<V>> {
        if let Some(value) = self.values.get(key) {
            return Some(value);
        }

        let cell = self.builds.cell(key);
        if let Some(value) = self.values.get(key) {
            // Do not remove `cell` here. A delayed holder of an older cell can
            // publish this moka value after the replacement cell has begun a
            // build. Detaching that replacement would permit another build if
            // the bounded value is immediately evicted. Its builder owns
            // cleanup; if it is still empty, a later post-eviction ask will
            // use and remove it.
            return Some(value);
        }
        after_cell();

        let built = cell.get_or_build_pool_independent(|| {
            let (value, receipt) =
                brokk_bifrost_analysis::analyzer::common::capture_query_cache_build(
                    analyzer,
                    || build().map(Arc::new),
                );
            SingleFlightRead { value, receipt }
        });
        after_result();
        built.receipt.replay();
        if built.receipt.is_complete()
            && let Some(value) = &built.value
        {
            self.values.insert(key.clone(), Arc::clone(value));
        }
        // Every existing holder still owns this cell and its typed receipt.
        // A later caller gets a fresh wave; stale holders cannot remove it.
        self.builds.remove_cell(key, &cell);
        built.value.clone()
    }

    #[cfg(test)]
    fn get_or_try_build_with_hooks(
        &self,
        analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
        key: &K,
        after_cell: impl FnOnce(),
        after_result: impl FnOnce(),
        build: impl FnOnce() -> Option<V>,
    ) -> Option<Arc<V>> {
        self.get_or_try_build_inner(analyzer, key, after_cell, after_result, build)
    }
}

type AncestorMemoEntry = Arc<ReplayingMemoEntry<Arc<Vec<CodeUnit>>, ReadKey>>;
type StatementFactsEntry = Arc<
    ReplayingMemoEntry<
        Arc<brokk_bifrost_core::analyzer::statement_facts::StatementFactRows>,
        ReadKey,
    >,
>;

pub(crate) struct CSharpMemoCaches {
    budget_bytes: u64,
    /// Source-local rows, capped at memo budget / 16 bytes (16 MiB by default),
    /// with the same key and retained-byte weighting as Java's statement cache.
    pub(crate) statement_facts: ReplayingMemo<
        Cache<(brokk_bifrost_analysis::analyzer::Oid, ProjectFile), StatementFactsEntry>,
    >,
    /// Immutable candidate and target facts, shared by all queries in this
    /// generation. Updates and project overlays replace the entire memo bundle.
    pub(crate) reachability: WorkspaceAuthorityMemo<
        PoolSafeMemo<
            HashMap<ProjectFile, brokk_bifrost_csharp::graph_support::CSharpReachabilityFacts>,
        >,
    >,
    /// Shared by `namespace_of_file` and `namespace_of_file_limited`. Sound
    /// only because both answer the one rule in
    /// `file_namespace_from_top_level_declarations`; a spelling that computed
    /// its own answer would be served the other's from here (#1726).
    pub(crate) namespace_by_file: WorkspaceAuthorityMemo<Cache<ProjectFile, Arc<String>>>,
    pub(crate) using_namespaces: WorkspaceAuthorityMemo<Cache<ProjectFile, Arc<Vec<String>>>>,
    /// The non-global tier of a file's `using` directives, the visible-type
    /// search's per-probe ask (#2679). Distinct from `using_namespaces`, which
    /// folds the workspace `global using` set in.
    pub(crate) file_using_namespaces: WorkspaceAuthorityMemo<Cache<ProjectFile, Arc<Vec<String>>>>,
    /// Whether the workspace declares anything in a namespace, by namespace.
    ///
    /// The visible-type search asks this of every namespace a probe would
    /// qualify a name with, which is one store query per ancestor namespace and
    /// per `using` of every file it resolves a name in. The answer depends on
    /// the generation alone, and this analyzer is one generation (#1806).
    pub(crate) namespace_exists: WorkspaceAuthorityMemo<BoundedSingleFlightCache<String, bool>>,
    /// Persisted exact/normalized declaration probes used by visible-type
    /// resolution. A large workspace asks for the same qualified names from
    /// thousands of files; retaining one answer per generation avoids a
    /// pooled-reader checkout and hydration for every repeated ask (#2795).
    pub(crate) persisted_fqn_candidates:
        WorkspaceAuthorityMemo<BoundedSingleFlightCache<PersistedFqnLookup, BTreeSet<CodeUnit>>>,
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) namespace_exists_build_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) persisted_fqn_candidate_build_count: AtomicUsize,
    pub(crate) using_aliases:
        WorkspaceAuthorityMemo<Cache<ProjectFile, Arc<HashMap<String, String>>>>,
    pub(crate) imported_code_units:
        WorkspaceAuthorityMemo<Cache<ProjectFile, Arc<HashSet<CodeUnit>>>>,
    pub(crate) referencing_files:
        WorkspaceAuthorityMemo<Cache<ProjectFile, Arc<HashSet<ProjectFile>>>>,
    pub(crate) direct_ancestors: ReplayingMemo<Cache<CodeUnit, AncestorMemoEntry>>,
    /// `PoolSafeMemo`, not `QueryCacheCell`, for the same reason as the two sibling
    /// cells below: this whole-workspace build is reached from rayon workers
    /// during cold scans, and a blocking `get_or_init` parks every one of them
    /// behind the single initializer for its full duration.
    /// Keyed by [`DescendantIndexVariant`]: a request that excluded test files
    /// gets an index that was never built over them (issue #1748). Two cells at
    /// most, because the exclusion verdict is a pure function of the analyzer
    /// and the file.
    pub(crate) direct_descendant_index:
        WorkspaceAuthorityMemo<KeyedPoolSafeMemo<DescendantIndexVariant, DirectDescendantIndex>>,
    pub(crate) reverse_import_index:
        WorkspaceAuthorityMemo<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    pub(crate) implicit_reference_index:
        WorkspaceAuthorityMemo<PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>>,
    /// Files declaring at least one C# type, grouped by namespace.
    ///
    /// The coarse file graph consumes paths, not `CodeUnit`s. Building this
    /// once avoids expanding every `using Namespace;` into all type objects in
    /// that namespace for every importing file, only to project them back to
    /// paths (#1194's shape at whole-workspace scale).
    pub(crate) file_dependencies_by_namespace:
        WorkspaceAuthorityMemo<PoolSafeMemo<HashMap<String, Arc<Vec<ProjectFile>>>>>,
    /// C# files whose declared types directly own, or structurally inherit,
    /// runner-attributed test methods. Built once from the generation's bulk
    /// hierarchy facts before coarse graph construction enters its parallel
    /// edge-resolution pass.
    pub(crate) hierarchy_test_files: WorkspaceAuthorityMemo<PoolSafeMemo<HashSet<ProjectFile>>>,
    /// One fixed-size digest of the generation's build configuration, for
    /// snapshot cache identity. Published only when the identity is known.
    pub(crate) compilation_config_digest: WorkspaceAuthorityMemo<PoolSafeMemo<StableDigest>>,
    /// Real source files that declare at least one `global using` directive.
    /// The coarse graph factors workspace-global visibility through these
    /// configuration files instead of expanding every directive in every file.
    pub(crate) global_using_namespaces:
        WorkspaceAuthorityMemo<QueryCacheCell<Arc<HashSet<String>>>>,
    /// [`Self::global_using_namespaces`] sorted once for the visible-type
    /// search's deterministic candidate order (#2679).
    pub(crate) sorted_global_using_namespaces:
        WorkspaceAuthorityMemo<QueryCacheCell<Arc<Vec<String>>>>,
    pub(crate) global_using_aliases:
        WorkspaceAuthorityMemo<QueryCacheCell<Arc<HashMap<String, String>>>>,
    pub(crate) global_static_using_type_names:
        WorkspaceAuthorityMemo<QueryCacheCell<Arc<Vec<String>>>>,
    pub(crate) global_static_using_types:
        WorkspaceAuthorityMemo<QueryCacheCell<Arc<Vec<CodeUnit>>>>,
    pub(crate) usage_global_static_using_types:
        WorkspaceAuthorityMemo<QueryCacheCell<Arc<Vec<CodeUnit>>>>,
    /// Complete dead-code inbound graphs, keyed by the requested target FQNs.
    /// This cache is owned by the generation's memo bundle and therefore
    /// cannot outlive a C# update or project overlay.
    pub(crate) dead_code_usage_edges: WorkspaceAuthorityMemo<UsageEdgesCache>,
}

impl CSharpMemoCaches {
    pub(crate) fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            statement_facts: ReplayingMemo::new(build_weighted_cache(
                budget_bytes / 16,
                |key: &(brokk_bifrost_analysis::analyzer::Oid, ProjectFile),
                 rows: &StatementFactsEntry| {
                    weight_bytes(
                        estimate_project_file(&key.1)
                            + rows.retained_bytes(|key| {
                                let mut heap = brokk_bifrost_analysis::analyzer::store::cache_budget::RetainedHeap::default();
                                brokk_bifrost_analysis::analyzer::store::cache_budget::retained_read_key(&mut heap, key);
                                heap.total()
                            }) as u64,
                    )
                },
            )),
            reachability: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpReachability,
                PoolSafeMemo::new(),
            ),
            namespace_by_file: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpNamespaceByFile,
                build_weighted_cache(budget_bytes / 16, weight_string),
            ),
            using_namespaces: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpUsingNamespaces,
                build_weighted_cache(budget_bytes / 8, weight_string_vec),
            ),
            file_using_namespaces: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpFileUsingNamespaces,
                build_weighted_cache(budget_bytes / 8, weight_string_vec),
            ),
            // Inline because moka's weigher takes the key as `&K`, and `K` here
            // is `String`: a named function would have to spell `&String`,
            // which `clippy::ptr_arg` rejects.
            namespace_exists: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpNamespaceExists,
                BoundedSingleFlightCache::new(build_weighted_cache(
                    budget_bytes / 16,
                    |namespace: &String, _: &Arc<bool>| {
                        weight_bytes(
                            size_of::<String>() as u64
                                + namespace.len() as u64
                                + size_of::<bool>() as u64,
                        )
                    },
                )),
            ),
            persisted_fqn_candidates: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpPersistedFqnCandidates,
                BoundedSingleFlightCache::new(build_weighted_cache(
                    budget_bytes / 4,
                    weight_persisted_fqn_candidates,
                )),
            ),
            #[cfg(any(test, feature = "test-support"))]
            namespace_exists_build_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            persisted_fqn_candidate_build_count: AtomicUsize::new(0),
            using_aliases: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpUsingAliases,
                build_weighted_cache(budget_bytes / 8, weight_string_map),
            ),
            imported_code_units: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpImportedCodeUnits,
                build_weighted_cache(budget_bytes / 4, weight_project_code_unit_set),
            ),
            referencing_files: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpReferencingFiles,
                build_weighted_cache(budget_bytes / 8, weight_project_file_set),
            ),
            direct_ancestors: ReplayingMemo::new(build_weighted_cache(
                budget_bytes / 8,
                |_key, entry: &AncestorMemoEntry| {
                    weight_bytes(entry.retained_bytes(|key| {
        let mut heap = brokk_bifrost_analysis::analyzer::store::cache_budget::RetainedHeap::default();
        brokk_bifrost_analysis::analyzer::store::cache_budget::retained_read_key(&mut heap, key);
        heap.total()
    }) as u64)
                },
            )),
            direct_descendant_index: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpDirectDescendantIndex,
                KeyedPoolSafeMemo::new(),
            ),
            reverse_import_index: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpReverseImportIndex,
                PoolSafeMemo::new(),
            ),
            implicit_reference_index: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpImplicitReferenceIndex,
                PoolSafeMemo::new(),
            ),
            file_dependencies_by_namespace: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpFileDependenciesByNamespace,
                PoolSafeMemo::new(),
            ),
            hierarchy_test_files: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpHierarchyTestFiles,
                PoolSafeMemo::new(),
            ),
            compilation_config_digest: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpCompilationConfiguration,
                PoolSafeMemo::new(),
            ),
            global_using_namespaces: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpGlobalUsingNamespaces,
                QueryCacheCell::new(),
            ),
            sorted_global_using_namespaces: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpSortedGlobalUsingNamespaces,
                QueryCacheCell::new(),
            ),
            global_using_aliases: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpGlobalUsingAliases,
                QueryCacheCell::new(),
            ),
            global_static_using_type_names: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpGlobalStaticUsingTypeNames,
                QueryCacheCell::new(),
            ),
            global_static_using_types: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpGlobalStaticUsingTypes,
                QueryCacheCell::new(),
            ),
            usage_global_static_using_types: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpUsageGlobalStaticUsingTypes,
                QueryCacheCell::new(),
            ),
            dead_code_usage_edges: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::CSharpDeadCodeUsageEdges,
                build_weighted_cache(budget_bytes / 8, weight_usage_edges),
            ),
        }
    }

    pub(crate) fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }
}

fn weight_persisted_fqn_candidates(
    key: &PersistedFqnLookup,
    value: &Arc<BTreeSet<CodeUnit>>,
) -> u32 {
    weight_bytes(
        size_of::<PersistedFqnLookup>() as u64
            + key.name.len() as u64
            + size_of::<BTreeSet<CodeUnit>>() as u64
            + value.iter().map(estimate_code_unit).sum::<u64>(),
    )
}

fn weight_string(_key: &ProjectFile, value: &Arc<String>) -> u32 {
    weight_string_payload(size_of::<String>(), value.len() as u64)
}

fn weight_string_vec(_key: &ProjectFile, value: &Arc<Vec<String>>) -> u32 {
    weight_string_payload(
        size_of::<Vec<String>>(),
        value.iter().map(|item| item.len() as u64).sum(),
    )
}

fn weight_string_map(_key: &ProjectFile, value: &Arc<HashMap<String, String>>) -> u32 {
    weight_string_payload(
        size_of::<HashMap<String, String>>(),
        value
            .iter()
            .map(|(key, value)| key.len() as u64 + value.len() as u64)
            .sum(),
    )
}

fn weight_string_payload(container_size: usize, payload_bytes: u64) -> u32 {
    weight_bytes(container_size as u64 + payload_bytes)
}

fn weight_project_code_unit_set(_key: &ProjectFile, value: &Arc<HashSet<CodeUnit>>) -> u32 {
    weight_bytes(estimate_code_unit_set(value.as_ref()))
}

fn weight_project_file_set(_key: &ProjectFile, value: &Arc<HashSet<ProjectFile>>) -> u32 {
    weight_bytes(estimate_project_file_set(value.as_ref()))
}

fn estimate_code_unit_set(values: &HashSet<CodeUnit>) -> u64 {
    estimate_collection_bytes(
        size_of::<HashSet<CodeUnit>>() as u64,
        values,
        estimate_code_unit,
    )
}

pub(super) fn estimate_code_unit_vec(values: &[CodeUnit]) -> u64 {
    estimate_collection_bytes(
        size_of::<Vec<CodeUnit>>() as u64,
        values,
        estimate_code_unit,
    )
}

fn estimate_project_file_set(files: &HashSet<ProjectFile>) -> u64 {
    size_of::<HashSet<ProjectFile>>() as u64 + files.iter().map(estimate_project_file).sum::<u64>()
}

#[cfg(test)]
mod tests {

    use crate::analyzer::csharp::cache::BoundedSingleFlightCache;
    use brokk_bifrost_test_macros::hardwon;
    use moka::sync::Cache;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Barrier, Condvar, Mutex};
    use std::thread;
    use std::time::Duration;

    /// Force both callers past the initial moka miss and onto C1, reject C1's
    /// value with a zero-capacity cache, install C2, then let the delayed C1
    /// holder run cleanup. Its identity-conditional removal must preserve C2.
    #[test]
    #[hardwon("#2795: a late single-flight holder could remove a replacement cache cell")]
    fn rejected_value_does_not_let_a_stale_holder_remove_the_replacement_cell() {
        let cache = Arc::new(BoundedSingleFlightCache::new(Cache::new(0)));
        let after_cell = Arc::new(Barrier::new(2));
        let result_order = Arc::new(AtomicUsize::new(0));
        let builds = Arc::new(AtomicUsize::new(0));
        let release_late = Arc::new((Mutex::new(false), Condvar::new()));
        let (completed_tx, completed_rx) = mpsc::channel();

        let threads: Vec<_> = (0..2)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let after_cell = Arc::clone(&after_cell);
                let result_order = Arc::clone(&result_order);
                let builds = Arc::clone(&builds);
                let release_late = Arc::clone(&release_late);
                let completed_tx = completed_tx.clone();
                thread::spawn(move || {
                    let analyzer = brokk_bifrost_analysis::analyzer::MultiAnalyzer::default();
                    let value = cache.get_or_try_build_with_hooks(
                        &analyzer,
                        &"hot",
                        || {
                            after_cell.wait();
                        },
                        || {
                            if result_order.fetch_add(1, Ordering::SeqCst) == 1 {
                                let (released, ready) = &*release_late;
                                let mut released = released.lock().expect("release lock poisoned");
                                while !*released {
                                    released = ready.wait(released).expect("release lock poisoned");
                                }
                            }
                        },
                        || {
                            builds.fetch_add(1, Ordering::SeqCst);
                            Some(7)
                        },
                    );
                    completed_tx
                        .send(value.expect("successful C1 wave"))
                        .expect("report completion");
                })
            })
            .collect();
        drop(completed_tx);

        assert_eq!(
            *completed_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("first C1 holder did not publish"),
            7
        );
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert!(cache.values.get(&"hot").is_none());

        let replacement = cache.builds.cell(&"hot");
        let (released, ready) = &*release_late;
        *released.lock().expect("release lock poisoned") = true;
        ready.notify_all();
        assert_eq!(
            *completed_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("delayed C1 holder did not finish"),
            7
        );
        assert!(Arc::ptr_eq(&replacement, &cache.builds.cell(&"hot")));

        for thread in threads {
            thread.join().expect("C1 holder should finish");
        }
    }

    /// A failed build is shared by the whole wave and replayed into each
    /// waiter's request, without affecting a concurrent nonconsumer.
    #[test]
    #[hardwon("#2795: concurrent failed builds were not shared or retried exactly once")]
    fn failed_wave_is_shared_and_the_next_wave_retries_once() {
        use brokk_bifrost_analysis::analyzer::{
            AnalyzerQueryScope, IAnalyzer, MultiAnalyzer, ReadKey, ReadLedger, store::StoreError,
        };
        const WORKERS: usize = 8;

        let analyzer = MultiAnalyzer::default();
        let unrelated_reads = Arc::new(ReadLedger::new());
        let unrelated =
            AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&unrelated_reads));
        let cache = BoundedSingleFlightCache::new(Cache::new(16));
        let builds = AtomicUsize::new(0);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(WORKERS)
            .build()
            .expect("rayon pool");

        let first_miss = Barrier::new(WORKERS);
        let failed = pool.broadcast(|_| {
            let _independent = brokk_bifrost_core::analyzer::carried_context::push(None);
            let scope = AnalyzerQueryScope::new(&analyzer);
            let value = cache.get_or_try_build_with_hooks(
                &analyzer,
                &"hot",
                || {
                    first_miss.wait();
                },
                || {},
                || {
                    builds.fetch_add(1, Ordering::SeqCst);
                    analyzer.record_read(ReadKey::Configuration(
                        brokk_bifrost_semantic::analyzer::semantic::ids::StableDigest::sha256(
                            b"failed-wave",
                        ),
                    ));
                    analyzer.record_query_failure(StoreError::new("shared failed store wave"));
                    None
                },
            );
            assert!(
                scope.store_error().is_some(),
                "every waiter records its own failure"
            );
            assert!(scope.read_completion().is_err());
            value
        });
        assert!(failed.iter().all(Option::is_none));
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert!(unrelated.read_completion().is_ok());
        assert!(unrelated.store_error().is_none());
        assert!(unrelated_reads.keys().is_empty());
        assert_eq!(unrelated_reads.execution_dependences(), 0);
        assert_eq!(unrelated_reads.unattributed_reads(), 0);

        let retry_miss = Barrier::new(WORKERS);
        let retried = pool.broadcast(|_| {
            let _independent = brokk_bifrost_core::analyzer::carried_context::push(None);
            let scope = AnalyzerQueryScope::new(&analyzer);
            let value = cache.get_or_try_build_with_hooks(
                &analyzer,
                &"hot",
                || {
                    retry_miss.wait();
                },
                || {},
                || {
                    builds.fetch_add(1, Ordering::SeqCst);
                    Some(7)
                },
            );
            assert!(scope.read_completion().is_ok());
            value
        });
        assert!(retried.iter().all(|value| value.as_deref() == Some(&7)));
        assert_eq!(builds.load(Ordering::SeqCst), 2);
        assert_eq!(
            *cache
                .get_or_try_build(&analyzer, &"hot", || panic!("warm value must not rebuild"))
                .expect("retry must publish"),
            7
        );
        assert!(unrelated.read_completion().is_ok());
        // A failed maintenance fill has no caller context. Its capture still
        // refuses publication, but replay must not fall back to other ledgers.
        let maintenance_ran = std::sync::atomic::AtomicBool::new(false);
        thread::scope(|threads| {
            threads
                .spawn(|| {
                    assert!(
                        cache
                            .get_or_try_build(&analyzer, &"maintenance", || {
                                maintenance_ran.store(true, Ordering::SeqCst);
                                analyzer.record_query_failure(StoreError::new(
                                    "maintenance store failure",
                                ));
                                None
                            })
                            .is_none()
                    );
                })
                .join()
                .expect("maintenance caller panicked");
        });
        assert!(maintenance_ran.load(Ordering::SeqCst));
        assert!(unrelated.read_completion().is_ok());
        assert!(unrelated_reads.keys().is_empty());
        assert_eq!(unrelated_reads.execution_dependences(), 0);
        assert_eq!(unrelated_reads.unattributed_reads(), 0);
    }
}
