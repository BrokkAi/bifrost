use crate::analyzer::python::*;

use brokk_bifrost_core::analyzer::usages::model::ImportBinder;

use brokk_bifrost_core::analyzer::usages::model::ImportBinding;
use std::mem::size_of;
use std::sync::Arc;

#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct PythonUsageEdgesKey {
    caller_nodes: Arc<[String]>,
    callee_targets: Arc<[String]>,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct PythonClassMutationKey {
    identity_groups: Arc<[Arc<[String]>]>,
    member: String,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct PythonModuleMemberMutationKey {
    module: String,
    member: String,
}

impl PythonUsageEdgesKey {
    pub(crate) fn new(nodes: &HashSet<String>, targets: &HashSet<String>) -> Self {
        Self {
            caller_nodes: sorted_names(nodes),
            callee_targets: sorted_names(targets),
        }
    }
}

impl PythonClassMutationKey {
    pub(crate) fn new(identity_groups: &[Vec<&str>], member: &str) -> Self {
        let mut identity_groups = identity_groups
            .iter()
            .map(|group| {
                let mut identities = group
                    .iter()
                    .map(|identity| (*identity).to_owned())
                    .collect::<Vec<_>>();
                identities.sort_unstable();
                identities.dedup();
                Arc::<[String]>::from(identities)
            })
            .collect::<Vec<_>>();
        identity_groups.sort_unstable_by(|left, right| left.as_ref().cmp(right.as_ref()));
        identity_groups.dedup_by(|left, right| left.as_ref() == right.as_ref());
        Self {
            identity_groups: identity_groups.into(),
            member: member.to_owned(),
        }
    }
}

pub(crate) type PythonClassMutationCache = Cache<
    PythonClassMutationKey,
    Arc<
        brokk_bifrost_analysis::analyzer::workspace_authority::ReplayingMemoEntry<
            bool,
            brokk_bifrost_analysis::analyzer::ReadKey,
        >,
    >,
>;

pub(crate) fn build_python_class_mutation_cache() -> PythonClassMutationCache {
    Cache::builder()
        .max_capacity(4 * 1024 * 1024)
        .weigher(
            |key: &PythonClassMutationKey,
             entry: &Arc<
                brokk_bifrost_analysis::analyzer::workspace_authority::ReplayingMemoEntry<
                    bool,
                    brokk_bifrost_analysis::analyzer::ReadKey,
                >,
            >| {
                use brokk_bifrost_analysis::analyzer::store::cache_budget::{
                    RetainedHeap, retained_read_key,
                };
                let bytes = entry.retained_bytes(|key| {
                    let mut heap = RetainedHeap::default();
                    retained_read_key(&mut heap, key);
                    heap.total()
                }) + std::mem::size_of::<PythonClassMutationKey>()
                    + std::mem::size_of_val(key.identity_groups.as_ref())
                    + 2 * std::mem::size_of::<usize>()
                    + key.member.capacity()
                    + key
                        .identity_groups
                        .iter()
                        .map(|group| {
                            std::mem::size_of_val(group.as_ref())
                                + 2 * std::mem::size_of::<usize>()
                                + group.iter().map(String::capacity).sum::<usize>()
                        })
                        .sum::<usize>();
                // A minimum charge also preserves the original 4,096-entry cap.
                u32::try_from(bytes.max(1024)).unwrap_or(u32::MAX)
            },
        )
        .build()
}

pub(crate) fn build_python_module_member_mutation_cache()
-> Cache<PythonModuleMemberMutationKey, bool> {
    Cache::builder().max_capacity(4_096).build()
}

impl PythonModuleMemberMutationKey {
    pub(crate) fn new(module: &str, member: &str) -> Self {
        Self {
            module: module.to_owned(),
            member: member.to_owned(),
        }
    }
}

pub(crate) fn weight_module_global_source_facts(
    _key: &(
        brokk_bifrost_analysis::analyzer::store::GenerationId,
        git2::Oid,
        ProjectFile,
    ),
    value: &Arc<brokk_bifrost_python::source_facts::PythonModuleGlobalSourceFacts>,
) -> u32 {
    u32::try_from(value.estimated_retained_bytes()).unwrap_or(u32::MAX)
}

pub(crate) fn weight_import_binder(_key: &ProjectFile, value: &Arc<ImportBinder>) -> u32 {
    let bindings_size = value
        .bindings
        .iter()
        .map(|(local_name, binding)| {
            local_name.len()
                + binding.module_specifier.len()
                + binding
                    .namespace_imported_module
                    .as_deref()
                    .map_or(0, str::len)
                + binding.imported_name.as_deref().map_or(0, str::len)
                + size_of::<ImportBinding>()
        })
        .sum::<usize>();
    (bindings_size + size_of::<ImportBinder>()).min(u32::MAX as usize) as u32
}

pub(crate) fn weight_python_usage_edges(
    key: &PythonUsageEdgesKey,
    edges: &Arc<brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges>,
) -> u32 {
    let key_bytes = names_weight(&key.caller_nodes) + names_weight(&key.callee_targets);
    brokk_bifrost_analysis::analyzer::usages::inverted_edges::weight_usage_edge_contents(
        key_bytes, edges,
    )
}

fn sorted_names(names: &HashSet<String>) -> Arc<[String]> {
    let mut sorted_names = names.iter().cloned().collect::<Vec<_>>();
    sorted_names.sort_unstable();
    sorted_names.into()
}

fn names_weight(names: &Arc<[String]>) -> usize {
    size_of::<Arc<[String]>>()
        + names
            .iter()
            .map(|item| size_of::<String>() + item.len())
            .sum::<usize>()
}

/// A bounded derived value retains its complete input receipt on every hit.
pub(crate) type PythonMemo<K, V> =
    ReplayingMemo<Cache<K, Arc<ReplayingMemoEntry<Arc<V>, ReadKey>>>>;

fn read_key_heap(key: &ReadKey) -> usize {
    use brokk_bifrost_analysis::analyzer::store::cache_budget::{RetainedHeap, retained_read_key};
    let mut heap = RetainedHeap::default();
    retained_read_key(&mut heap, key);
    heap.total()
}

pub(crate) fn replaying_cache<K, V>(budget: u64) -> PythonMemo<K, V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    ReplayingMemo::new(build_weighted_cache(
        budget,
        |_, value: &Arc<ReplayingMemoEntry<Arc<V>, ReadKey>>| {
            u32::try_from(value.retained_bytes(read_key_heap)).unwrap_or(u32::MAX)
        },
    ))
}

pub(crate) fn read_memo<K, V>(
    analyzer: &PythonAnalyzer,
    memo: &PythonMemo<K, V>,
    key: K,
    build: impl FnOnce() -> Arc<V>,
    weight: impl Fn(&K, &Arc<V>) -> u32,
) -> Arc<V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    let value = memo
        .read(&memo_attribution(analyzer), |memo, capture| {
            let entry = memo
                .try_get_with(key.clone(), || {
                    let (attempt, receipt) =
                        brokk_bifrost_analysis::analyzer::common::capture_query_cache_build(
                            analyzer,
                            || {
                                brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(
                                    analyzer,
                                    || {
                                        Arc::new(capture.build_weighted(|| {
                                            let value = build();
                                            let bytes = weight(&key, &value) as usize;
                                            (value, bytes)
                                        }))
                                    },
                                )
                            },
                        );
                    attempt.map_err(|value| (value, receipt))
                })
                .unwrap_or_else(|failure| {
                    failure.1.replay();
                    Arc::clone(&failure.0)
                });
            Ok::<_, std::convert::Infallible>(entry)
        })
        .unwrap();
    Arc::clone(&value)
}

/// File-local syntax values have an explicit entry cap. Keeping ownership here
/// lets the same replay wrapper retain language-independent read receipts.
pub(crate) fn syntax_memo<V: Send + Sync + 'static>() -> PythonMemo<ProjectFile, V> {
    ReplayingMemo::new(Cache::builder().max_capacity(128).build())
}

pub(crate) fn read_optional_memo<K, V>(
    analyzer: &PythonAnalyzer,
    memo: &PythonMemo<K, V>,
    key: K,
    build: impl FnOnce() -> Option<Arc<V>>,
    weight: impl Fn(&K, &Arc<V>) -> u32,
) -> Option<Arc<V>>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    let value = memo
        .read(&memo_attribution(analyzer), |memo, capture| {
            memo.try_get_with(key.clone(), || {
                let (attempt, receipt) =
                    brokk_bifrost_analysis::analyzer::common::capture_query_cache_build(
                        analyzer,
                        || {
                            brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(
                                analyzer,
                                || {
                                    capture
                                        .try_build_weighted(|| {
                                            let value = build().ok_or(())?;
                                            let bytes = weight(&key, &value) as usize;
                                            Ok::<_, ()>((value, bytes))
                                        })
                                        .map(Arc::new)
                                },
                            )
                        },
                    );
                match attempt {
                    Ok(Ok(entry)) => Ok(entry),
                    Err(Ok(entry)) => Err((Some(entry), receipt)),
                    Ok(Err(())) | Err(Err(())) => Err((None, receipt)),
                }
            })
            .or_else(|failure| {
                failure.1.replay();
                failure.0.clone().ok_or(())
            })
        })
        .ok()?;
    Some(Arc::clone(&value))
}

#[cfg(test)]
mod tests {

    use crate::analyzer::python::cache::*;

    use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges;

    use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::project::TestProject;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use brokk_bifrost_test_macros::hardwon;
    #[test]
    #[hardwon(
        "#1320: Regression from sustained warm Python benchmark latency: cached exact-target edges must be reused and invalidated with analyzer generation"
    )]
    fn usage_edges_are_reused_per_target_set_and_reset_on_update() {
        let root = tempfile::tempdir().expect("temporary project root");
        let file = ProjectFile::new(root.path(), "module.py");
        file.write("def target(): pass\n")
            .expect("write Python fixture");
        let analyzer = PythonAnalyzer::new(Arc::new(TestProject::new(
            root.path().to_path_buf(),
            Language::Python,
        )));
        let nodes = HashSet::from_iter(["module.target".to_string(), "module.other".to_string()]);
        let first_targets = HashSet::from_iter(["module.target".to_string()]);
        let second_targets = HashSet::from_iter(["module.target".to_string()]);
        let builds = AtomicUsize::new(0);

        let first = analyzer
            .usage_edges_for_targets(&nodes, &first_targets, || {
                builds.fetch_add(1, Ordering::Relaxed);
                Some(UsageEdges::default())
            })
            .expect("first Python usage graph build");
        let second = analyzer
            .usage_edges_for_targets(&nodes, &second_targets, || {
                panic!("warm Python usage graph must reuse the cached edges")
            })
            .expect("cached Python usage graph");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(1, builds.load(Ordering::Relaxed));

        let different_targets = HashSet::from_iter(["module.other".to_string()]);
        analyzer.usage_edges_for_targets(&nodes, &different_targets, || {
            builds.fetch_add(1, Ordering::Relaxed);
            Some(UsageEdges::default())
        });
        assert_eq!(
            2,
            builds.load(Ordering::Relaxed),
            "different callee targets need a separately resolved graph"
        );

        let updated = analyzer.update(&std::collections::BTreeSet::from([file]));
        updated.usage_edges_for_targets(&nodes, &first_targets, || {
            builds.fetch_add(1, Ordering::Relaxed);
            Some(UsageEdges::default())
        });
        assert_eq!(3, builds.load(Ordering::Relaxed));
    }

    #[test]
    fn unavailable_usage_edges_are_not_cached() {
        let root = tempfile::tempdir().expect("temporary project root");
        let analyzer = PythonAnalyzer::new(Arc::new(TestProject::new(
            root.path().to_path_buf(),
            Language::Python,
        )));
        let nodes = HashSet::from_iter(["module.target".to_string()]);
        let targets = HashSet::from_iter(["module.target".to_string()]);
        let builds = AtomicUsize::new(0);

        let missing = analyzer.usage_edges_for_targets(&nodes, &targets, || {
            builds.fetch_add(1, Ordering::Relaxed);
            None
        });
        assert!(missing.is_none());

        let available = analyzer.usage_edges_for_targets(&nodes, &targets, || {
            builds.fetch_add(1, Ordering::Relaxed);
            Some(UsageEdges::default())
        });
        assert!(available.is_some());
        assert_eq!(2, builds.load(Ordering::Relaxed));

        analyzer.usage_edges_for_targets(&nodes, &targets, || {
            panic!("available Python usage graph must be cached")
        });
        assert_eq!(2, builds.load(Ordering::Relaxed));
    }

    #[test]
    #[hardwon("#4598: constructor member lookups repeated the same full-workspace mutation scan")]
    fn class_mutation_scan_cache_keys_sorted_inputs_and_resets_on_update() {
        let root = tempfile::tempdir().expect("temporary project root");
        let file = ProjectFile::new(root.path(), "module.py");
        file.write("class Widget: pass\n")
            .expect("write Python fixture");
        let analyzer = PythonAnalyzer::new(Arc::new(TestProject::new(
            root.path().to_path_buf(),
            Language::Python,
        )));
        let identity_groups = vec![
            vec!["pkg.Widget", "alias.Widget"],
            vec!["pkg.Other", "other"],
        ];
        let reordered_groups = vec![
            vec!["other", "pkg.Other"],
            vec!["alias.Widget", "pkg.Widget"],
        ];
        let changed_groups = vec![
            vec!["pkg.Widget", "alias.Widget"],
            vec!["pkg.Renamed", "other"],
        ];
        let scans = AtomicUsize::new(0);

        assert!(
            analyzer.cached_class_member_mutation_free(&identity_groups, "run", || {
                scans.fetch_add(1, Ordering::Relaxed);
                true
            },)
        );
        assert!(
            analyzer.cached_class_member_mutation_free(&reordered_groups, "run", || panic!(
                "permuted identity groups must reuse the full-workspace scan"
            ),)
        );
        assert_eq!(1, scans.load(Ordering::Relaxed));

        assert!(
            !analyzer.cached_class_member_mutation_free(&changed_groups, "run", || {
                scans.fetch_add(1, Ordering::Relaxed);
                false
            },)
        );
        assert!(
            !analyzer.cached_class_member_mutation_free(&changed_groups, "run", || panic!(
                "the cached negative proof must be reused"
            ),)
        );
        assert_eq!(2, scans.load(Ordering::Relaxed));

        assert!(
            !analyzer.cached_class_member_mutation_free(&identity_groups, "close", || {
                scans.fetch_add(1, Ordering::Relaxed);
                false
            },)
        );
        assert_eq!(3, scans.load(Ordering::Relaxed));

        file.write("class Widget:\n    pass\n")
            .expect("update Python fixture");
        let updated = analyzer.update(&std::collections::BTreeSet::from([file]));
        assert!(
            updated.cached_class_member_mutation_free(&identity_groups, "run", || {
                scans.fetch_add(1, Ordering::Relaxed);
                true
            },)
        );
        assert_eq!(4, scans.load(Ordering::Relaxed));
    }

    #[test]
    #[hardwon(
        "#4622: repeated module-global class reads must reuse the bounded cross-file write scan"
    )]
    fn module_member_mutation_scan_cache_is_bounded_by_generation_and_name() {
        let root = tempfile::tempdir().expect("temporary project root");
        let file = ProjectFile::new(root.path(), "module.py");
        file.write("value = object()\n")
            .expect("write Python fixture");
        let analyzer = PythonAnalyzer::new(Arc::new(TestProject::new(
            root.path().to_path_buf(),
            Language::Python,
        )));
        let scans = AtomicUsize::new(0);

        assert!(
            analyzer.cached_module_member_mutation_free("module", "value", || {
                scans.fetch_add(1, Ordering::Relaxed);
                Some(true)
            })
        );
        assert!(
            analyzer.cached_module_member_mutation_free("module", "value", || panic!(
                "the same module and name must reuse its completed scan"
            ))
        );
        assert_eq!(1, scans.load(Ordering::Relaxed));

        assert!(
            !analyzer.cached_module_member_mutation_free("module", "other", || {
                scans.fetch_add(1, Ordering::Relaxed);
                Some(false)
            })
        );
        assert!(
            !analyzer.cached_module_member_mutation_free("module", "other", || panic!(
                "a completed open result must be memoized"
            ))
        );
        assert_eq!(2, scans.load(Ordering::Relaxed));

        assert!(!analyzer.cached_module_member_mutation_free("module", "retry", || None));
        assert!(
            analyzer.cached_module_member_mutation_free("module", "retry", || {
                scans.fetch_add(1, Ordering::Relaxed);
                Some(true)
            })
        );
        assert_eq!(3, scans.load(Ordering::Relaxed));

        file.write("value = object()\n# updated\n")
            .expect("update Python fixture");
        let updated = analyzer.update(&std::collections::BTreeSet::from([file]));
        assert!(
            updated.cached_module_member_mutation_free("module", "value", || {
                scans.fetch_add(1, Ordering::Relaxed);
                Some(true)
            })
        );
        assert_eq!(4, scans.load(Ordering::Relaxed));
    }
    #[test]
    #[hardwon(
        "ddf65ec23b34: repeated graph queries rebuilt generation-stable Python binding facts"
    )]
    fn module_binding_timeline_is_reused_within_index_generation() {
        let root = tempfile::tempdir().expect("temporary project root");
        let file = ProjectFile::new(root.path(), "consumer.py");
        file.write("value = 0\n")
            .expect("write syntax memo fixture");
        let index = PythonAnalyzer::new(Arc::new(TestProject::new(
            root.path().to_path_buf(),
            Language::Python,
        )));
        let first = index.module_binding_timeline(&file, &mut || {
            brokk_bifrost_python::usage_index::ModuleBindingTimeline::from_iter([(
                "target".to_string(),
                vec![brokk_bifrost_python::usage_index::ModuleBindingEvent {
                    visible_from: 12,
                    conditional: false,
                    kind: brokk_bifrost_python::usage_index::ModuleBindingEventKind::Other,
                }],
            )])
        });
        let second = index.module_binding_timeline(&file, &mut || {
            panic!("cached timeline should avoid rebuilding the file")
        });

        assert!(Arc::ptr_eq(&first, &second));

        let first_facts = index
            .scope_facts(&file, &mut || {
                Some(brokk_bifrost_python::usage_index::PythonScopeFacts::default())
            })
            .unwrap();
        let second_facts = index
            .scope_facts(&file, &mut || {
                panic!("cached scope facts should avoid rebuilding the file")
            })
            .unwrap();
        assert!(Arc::ptr_eq(&first_facts, &second_facts));
    }
}
