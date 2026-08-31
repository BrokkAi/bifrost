use crate::analyzer::{
    CodeUnit, DescendantIndexVariant, DirectDescendantIndex, KeyedPoolSafeMemo, PoolSafeMemo,
    ProjectFile,
};
use crate::hash::{HashMap, HashSet};
use moka::sync::Cache;
use std::collections::BTreeSet;
use std::hash::Hash;
use std::mem::size_of;
#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, OnceLock};

use super::compilation::CSharpCompilationIndex;
use crate::analyzer::usages::inverted_edges::{UsageEdgesCache, weight_usage_edges};
use crate::analyzer::weighted_cache::build_weighted_cache;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct PersistedFqnLookup {
    pub(super) name: String,
    pub(super) normalized: bool,
}

/// A bounded generation cache with one pool-independent store build per
/// same-key miss wave.
///
/// The coordinator stores `Option<Arc<V>>`: `None` is a failed store wave, not
/// a cached negative answer. Publishing it inside the cell wakes every holder
/// with the same failure instead of making each waiter retry serially. The
/// exact cell is removed afterward so a later wave can retry, while
/// [`KeyedPoolSafeMemo::remove_cell`] prevents an old holder from detaching a
/// replacement coordinator after moka rejection or eviction (#2795).
pub(super) struct BoundedSingleFlightCache<K, V> {
    values: Cache<K, Arc<V>>,
    builds: KeyedPoolSafeMemo<K, Option<Arc<V>>>,
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

    pub(super) fn get_or_try_build(
        &self,
        key: &K,
        build: impl FnOnce() -> Option<V>,
    ) -> Option<Arc<V>> {
        self.get_or_try_build_inner(key, || {}, || {}, build)
    }

    fn get_or_try_build_inner(
        &self,
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

        let built = cell.get_or_build_pool_independent(|| build().map(Arc::new));
        after_result();
        if let Some(value) = built.as_ref() {
            self.values.insert(key.clone(), Arc::clone(value));
            self.builds.remove_cell(key, &cell);
            Some(Arc::clone(value))
        } else {
            // `None` was published to every holder of this cell. Retire that
            // exact failed wave only after publication so the next caller can
            // retry without leaking one coordinator per failed key.
            self.builds.remove_cell(key, &cell);
            None
        }
    }

    #[cfg(test)]
    fn get_or_try_build_with_hooks(
        &self,
        key: &K,
        after_cell: impl FnOnce(),
        after_result: impl FnOnce(),
        build: impl FnOnce() -> Option<V>,
    ) -> Option<Arc<V>> {
        self.get_or_try_build_inner(key, after_cell, after_result, build)
    }
}

pub(super) struct CSharpMemoCaches {
    budget_bytes: u64,
    /// Shared by `namespace_of_file` and `namespace_of_file_limited`. Sound
    /// only because both answer the one rule in
    /// `file_namespace_from_top_level_declarations`; a spelling that computed
    /// its own answer would be served the other's from here (#1726).
    pub(super) namespace_by_file: Cache<ProjectFile, Arc<String>>,
    pub(super) using_namespaces: Cache<ProjectFile, Arc<Vec<String>>>,
    /// The non-global tier of a file's `using` directives, the visible-type
    /// search's per-probe ask (#2679). Distinct from `using_namespaces`, which
    /// folds the workspace `global using` set in.
    pub(super) file_using_namespaces: Cache<ProjectFile, Arc<Vec<String>>>,
    /// Whether the workspace declares anything in a namespace, by namespace.
    ///
    /// The visible-type search asks this of every namespace a probe would
    /// qualify a name with, which is one store query per ancestor namespace and
    /// per `using` of every file it resolves a name in. The answer depends on
    /// the generation alone, and this analyzer is one generation (#1806).
    pub(super) namespace_exists: BoundedSingleFlightCache<String, bool>,
    /// Persisted exact/normalized declaration probes used by visible-type
    /// resolution. A large workspace asks for the same qualified names from
    /// thousands of files; retaining one answer per generation avoids a
    /// pooled-reader checkout and hydration for every repeated ask (#2795).
    pub(super) persisted_fqn_candidates:
        BoundedSingleFlightCache<PersistedFqnLookup, BTreeSet<CodeUnit>>,
    #[cfg(any(test, feature = "test-support"))]
    pub(super) namespace_exists_build_count: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    pub(super) persisted_fqn_candidate_build_count: AtomicUsize,
    pub(super) using_aliases: Cache<ProjectFile, Arc<HashMap<String, String>>>,
    pub(super) imported_code_units: Cache<ProjectFile, Arc<HashSet<CodeUnit>>>,
    pub(super) referencing_files: Cache<ProjectFile, Arc<HashSet<ProjectFile>>>,
    pub(super) direct_ancestors: Cache<CodeUnit, Arc<Vec<CodeUnit>>>,
    /// `PoolSafeMemo`, not `OnceLock`, for the same reason as the two sibling
    /// cells below: this whole-workspace build is reached from rayon workers
    /// during cold scans, and a blocking `get_or_init` parks every one of them
    /// behind the single initializer for its full duration.
    /// Keyed by [`DescendantIndexVariant`]: a request that excluded test files
    /// gets an index that was never built over them (issue #1748). Two cells at
    /// most, because the exclusion verdict is a pure function of the analyzer
    /// and the file.
    pub(super) direct_descendant_index:
        KeyedPoolSafeMemo<DescendantIndexVariant, DirectDescendantIndex>,
    pub(super) reverse_import_index: PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>,
    pub(super) implicit_reference_index:
        PoolSafeMemo<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>>,
    /// Files declaring at least one C# type, grouped by namespace.
    ///
    /// The coarse file graph consumes paths, not `CodeUnit`s. Building this
    /// once avoids expanding every `using Namespace;` into all type objects in
    /// that namespace for every importing file, only to project them back to
    /// paths (#1194's shape at whole-workspace scale).
    pub(super) file_dependencies_by_namespace: PoolSafeMemo<HashMap<String, Arc<Vec<ProjectFile>>>>,
    /// C# files whose declared types directly own, or structurally inherit,
    /// runner-attributed test methods. Built once from the generation's bulk
    /// hierarchy facts before coarse graph construction enters its parallel
    /// edge-resolution pass.
    pub(super) hierarchy_test_files: PoolSafeMemo<HashSet<ProjectFile>>,
    /// Build-declared C# source-to-compilation membership and its configuration
    /// identity. Shared by file-graph edges and snapshot cache identity.
    pub(super) compilation_index: PoolSafeMemo<CSharpCompilationIndex>,
    /// Real source files that declare at least one `global using` directive.
    /// The coarse graph factors workspace-global visibility through these
    /// configuration files instead of expanding every directive in every file.
    pub(super) global_using_files: OnceLock<Vec<ProjectFile>>,
    pub(super) global_using_namespaces: OnceLock<HashSet<String>>,
    /// [`Self::global_using_namespaces`] sorted once for the visible-type
    /// search's deterministic candidate order (#2679).
    pub(super) sorted_global_using_namespaces: OnceLock<Vec<String>>,
    pub(super) global_using_aliases: OnceLock<HashMap<String, String>>,
    pub(super) global_static_using_type_names: OnceLock<Vec<String>>,
    pub(super) global_static_using_types: OnceLock<Vec<CodeUnit>>,
    pub(super) usage_global_static_using_types: OnceLock<Vec<CodeUnit>>,
    /// Complete dead-code inbound graphs, keyed by the requested target FQNs.
    /// This cache is owned by the generation's memo bundle and therefore
    /// cannot outlive a C# update or project overlay.
    pub(super) dead_code_usage_edges: UsageEdgesCache,
}

impl CSharpMemoCaches {
    pub(super) fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            namespace_by_file: build_weighted_cache(budget_bytes / 16, weight_string),
            using_namespaces: build_weighted_cache(budget_bytes / 8, weight_string_vec),
            file_using_namespaces: build_weighted_cache(budget_bytes / 8, weight_string_vec),
            // Inline because moka's weigher takes the key as `&K`, and `K` here
            // is `String`: a named function would have to spell `&String`,
            // which `clippy::ptr_arg` rejects.
            namespace_exists: BoundedSingleFlightCache::new(build_weighted_cache(
                budget_bytes / 16,
                |namespace: &String, _: &Arc<bool>| {
                    weight_bytes(
                        size_of::<String>() as u64
                            + namespace.len() as u64
                            + size_of::<bool>() as u64,
                    )
                },
            )),
            persisted_fqn_candidates: BoundedSingleFlightCache::new(build_weighted_cache(
                budget_bytes / 4,
                weight_persisted_fqn_candidates,
            )),
            #[cfg(any(test, feature = "test-support"))]
            namespace_exists_build_count: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            persisted_fqn_candidate_build_count: AtomicUsize::new(0),
            using_aliases: build_weighted_cache(budget_bytes / 8, weight_string_map),
            imported_code_units: build_weighted_cache(
                budget_bytes / 4,
                weight_project_code_unit_set,
            ),
            referencing_files: build_weighted_cache(budget_bytes / 8, weight_project_file_set),
            direct_ancestors: build_weighted_cache(budget_bytes / 8, weight_code_unit_vec),
            direct_descendant_index: KeyedPoolSafeMemo::new(),
            reverse_import_index: PoolSafeMemo::new(),
            implicit_reference_index: PoolSafeMemo::new(),
            file_dependencies_by_namespace: PoolSafeMemo::new(),
            hierarchy_test_files: PoolSafeMemo::new(),
            compilation_index: PoolSafeMemo::new(),
            global_using_files: OnceLock::new(),
            global_using_namespaces: OnceLock::new(),
            sorted_global_using_namespaces: OnceLock::new(),
            global_using_aliases: OnceLock::new(),
            global_static_using_type_names: OnceLock::new(),
            global_static_using_types: OnceLock::new(),
            usage_global_static_using_types: OnceLock::new(),
            dead_code_usage_edges: build_weighted_cache(budget_bytes / 8, weight_usage_edges),
        }
    }

    pub(super) fn budget_bytes(&self) -> u64 {
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
    weight_bytes(size_of::<String>() as u64 + value.len() as u64)
}

fn weight_string_vec(_key: &ProjectFile, value: &Arc<Vec<String>>) -> u32 {
    weight_bytes(
        size_of::<Vec<String>>() as u64 + value.iter().map(|item| item.len() as u64).sum::<u64>(),
    )
}

fn weight_string_map(_key: &ProjectFile, value: &Arc<HashMap<String, String>>) -> u32 {
    weight_bytes(
        size_of::<HashMap<String, String>>() as u64
            + value
                .iter()
                .map(|(key, value)| key.len() as u64 + value.len() as u64)
                .sum::<u64>(),
    )
}

fn weight_project_code_unit_set(_key: &ProjectFile, value: &Arc<HashSet<CodeUnit>>) -> u32 {
    weight_bytes(estimate_code_unit_set(value.as_ref()))
}

fn weight_code_unit_vec(_key: &CodeUnit, value: &Arc<Vec<CodeUnit>>) -> u32 {
    weight_bytes(estimate_code_unit_vec(value.as_ref()))
}

fn weight_project_file_set(_key: &ProjectFile, value: &Arc<HashSet<ProjectFile>>) -> u32 {
    weight_bytes(estimate_project_file_set(value.as_ref()))
}

fn weight_bytes(bytes: u64) -> u32 {
    bytes.clamp(1, u32::MAX as u64) as u32
}

fn estimate_project_file(file: &ProjectFile) -> u64 {
    size_of::<ProjectFile>() as u64
        + file.root().as_os_str().to_string_lossy().len() as u64
        + file.rel_path().as_os_str().to_string_lossy().len() as u64
}

fn estimate_code_unit(code_unit: &CodeUnit) -> u64 {
    size_of::<CodeUnit>() as u64
        + estimate_project_file(code_unit.source())
        + code_unit.package_name().len() as u64
        + code_unit.short_name().len() as u64
        + code_unit
            .signature()
            .map_or(0, |signature| signature.len() as u64)
}

fn estimate_code_unit_set(values: &HashSet<CodeUnit>) -> u64 {
    size_of::<HashSet<CodeUnit>>() as u64 + values.iter().map(estimate_code_unit).sum::<u64>()
}

fn estimate_code_unit_vec(values: &[CodeUnit]) -> u64 {
    size_of::<Vec<CodeUnit>>() as u64 + values.iter().map(estimate_code_unit).sum::<u64>()
}

fn estimate_project_file_set(files: &HashSet<ProjectFile>) -> u64 {
    size_of::<HashSet<ProjectFile>>() as u64 + files.iter().map(estimate_project_file).sum::<u64>()
}

#[cfg(test)]
mod tests {
    use super::BoundedSingleFlightCache;
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
                    let value = cache.get_or_try_build_with_hooks(
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

    /// A failed store read is published as `None` to the whole C1 wave. All
    /// eight callers return that one failure, then C1 is retired and the next
    /// forced miss wave retries once through C2 and publishes the value.
    #[test]
    fn failed_wave_is_shared_and_the_next_wave_retries_once() {
        const WORKERS: usize = 8;

        let cache = BoundedSingleFlightCache::new(Cache::new(16));
        let builds = AtomicUsize::new(0);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(WORKERS)
            .build()
            .expect("rayon pool");

        let first_miss = Barrier::new(WORKERS);
        let failed = pool.broadcast(|_| {
            cache.get_or_try_build_with_hooks(
                &"hot",
                || {
                    first_miss.wait();
                },
                || {},
                || {
                    builds.fetch_add(1, Ordering::SeqCst);
                    None
                },
            )
        });
        assert!(failed.iter().all(Option::is_none));
        assert_eq!(builds.load(Ordering::SeqCst), 1);

        let retry_miss = Barrier::new(WORKERS);
        let retried = pool.broadcast(|_| {
            cache.get_or_try_build_with_hooks(
                &"hot",
                || {
                    retry_miss.wait();
                },
                || {},
                || {
                    builds.fetch_add(1, Ordering::SeqCst);
                    Some(7)
                },
            )
        });
        assert!(retried.iter().all(|value| value.as_deref() == Some(&7)));
        assert_eq!(builds.load(Ordering::SeqCst), 2);
        assert_eq!(
            *cache
                .get_or_try_build(&"hot", || panic!("warm value must not rebuild"))
                .expect("retry must publish"),
            7
        );
    }
}
