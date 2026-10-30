//! Read receipts for immutable products shared by a row-family session.

use crate::analyzer::IAnalyzer;
use crate::hash::HashMap;
use brokk_bifrost_analysis::analyzer::ReadKey;
use brokk_bifrost_analysis::analyzer::workspace_authority::{
    ReplayingMemo, ReplayingMemoEntry, memo_attribution,
};
use std::hash::Hash;
use std::sync::{Arc, Mutex};

pub(super) struct Entries<K, V> {
    values: HashMap<K, Arc<ReplayingMemoEntry<V, ReadKey>>>,
    /// Receipt allocations only; the pre-existing product holder remains unbounded.
    receipt_bytes: usize,
}

impl<K, V> Default for Entries<K, V> {
    fn default() -> Self {
        Self {
            values: HashMap::default(),
            receipt_bytes: 0,
        }
    }
}

impl<K, V> Drop for Entries<K, V> {
    fn drop(&mut self) {
        brokk_bifrost_core::profiling::note_with(|| {
            format!(
                "rql.row_family.retained_receipt_bytes={}",
                self.receipt_bytes
            )
        });
    }
}

fn receipt_bytes<V>(entry: &ReplayingMemoEntry<V, ReadKey>) -> usize {
    use crate::analyzer::store::cache_budget::{RetainedHeap, retained_read_key};
    // Both Arc control blocks plus the receipt-bearing entry and its key slice.
    std::mem::size_of::<ReplayingMemoEntry<V, ReadKey>>()
        .saturating_add(4 * std::mem::size_of::<usize>())
        .saturating_add(entry.retained_read_bytes(|key| {
            let mut heap = RetainedHeap::default();
            retained_read_key(&mut heap, key);
            heap.total()
        }))
}
pub(super) type TraversalMemo<K, V> = ReplayingMemo<Mutex<Entries<K, V>>>;

pub(super) fn new<K, V>() -> TraversalMemo<K, V> {
    ReplayingMemo::new(Mutex::new(Entries::default()))
}

pub(super) fn cached<K: Eq + Hash, V: Clone>(
    memo: &TraversalMemo<K, V>,
    analyzer: &dyn IAnalyzer,
    key: &K,
) -> Option<V> {
    memo.read(&memo_attribution(analyzer), |entries, _| {
        entries
            .lock()
            .expect("row-family memo lock poisoned")
            .values
            .get(key)
            .cloned()
            .ok_or(())
    })
    .ok()
    .map(|value| (*value).clone())
}

/// Return the chosen product and whether this call derived it. Incomplete
/// products still carry their receipt but stay outside the shared store.
pub(super) fn derive<K: Eq + Hash, V: Clone, E>(
    memo: &TraversalMemo<K, V>,
    analyzer: &dyn IAnalyzer,
    key: K,
    build: impl FnOnce() -> Result<V, E>,
    complete: impl FnOnce(&V) -> bool,
) -> Result<(V, bool), E> {
    let mut built = false;
    let value = memo.read(&memo_attribution(analyzer), |entries, capture| {
        let mut entries = entries.lock().expect("row-family memo lock poisoned");
        if let Some(entry) = entries.values.get(&key) {
            return Ok(Arc::clone(entry));
        }
        let mut cacheable = false;
        let entry = Arc::new(capture.try_build(|| {
            let value = build()?;
            cacheable = complete(&value);
            built = true;
            Ok(value)
        })?);
        if cacheable {
            entries.receipt_bytes = entries.receipt_bytes.saturating_add(receipt_bytes(&entry));
            entries.values.insert(key, Arc::clone(&entry));
        }
        Ok(entry)
    })?;
    let result = (*value).clone();
    Ok((result, built))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalyzerConfig, Language};
    use crate::structural::occurrence_rows::OccurrenceDerivationOptions;
    use crate::structural::occurrences::OccurrenceRole;
    use crate::structural::search::environment::{
        EnvironmentTraversalCache, EnvironmentTraversalStore,
    };
    use crate::structural::search::occurrences::{
        OccurrenceTraversalCache, OccurrenceTraversalStore,
    };
    use crate::structural::search::tests::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::capture_query_reads;
    use brokk_bifrost_rql::OccurrenceFilter;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#2445: row-family stores retained read receipts without accounting for their bytes")]
    fn retained_row_receipts_count_key_storage_and_heap_once_per_cached_fill() {
        let analyzer = crate::analyzer::MultiAnalyzer::default();
        let memo = new::<u8, usize>();
        let path = "nested/receipt/input.py";
        let read = || {
            analyzer.record_read(ReadKey::path_absent(Language::Python, path));
            Ok::<_, std::convert::Infallible>(7usize)
        };
        let (_, fill) = capture_query_reads(&analyzer, || {
            derive(&memo, &analyzer, 1, read, |_| true).unwrap()
        });
        assert_eq!(fill.keys().len(), 1);
        let expected = std::mem::size_of::<ReplayingMemoEntry<usize, ReadKey>>()
            + 4 * std::mem::size_of::<usize>()
            + std::mem::size_of::<ReadKey>()
            + path.len();
        let weight = || memo.account(|entries| entries.lock().unwrap().receipt_bytes);
        assert_eq!(weight(), expected);
        let ((value, built), hit) = capture_query_reads(&analyzer, || {
            derive(
                &memo,
                &analyzer,
                1,
                || -> Result<usize, std::convert::Infallible> {
                    panic!("cached rows must not rebuild")
                },
                |_| true,
            )
            .unwrap()
        });
        assert_eq!(value, 7);
        assert!(!built);
        assert_eq!(hit.keys(), fill.keys());
        assert_eq!(weight(), expected);
        assert_eq!(
            derive(&memo, &analyzer, 2, read, |_| false).unwrap(),
            (7, true)
        );
        assert_eq!(
            weight(),
            expected,
            "incomplete products retain no shared receipt"
        );
        assert_eq!(
            derive(&memo, &analyzer, 3, read, |_| true).unwrap(),
            (7, true)
        );
        assert_eq!(weight(), expected * 2);
        assert_eq!(
            memo.account(|entries| entries.lock().unwrap().values.len()),
            2
        );
    }

    #[test]
    #[hardwon("#2445: correlated scope joins have no producing query read receipt")]
    fn correlated_scopes_refuse_capture_without_a_producing_receipt() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("example.py", "value = 1\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("example.py");
        let shared = Arc::new(Mutex::new(EnvironmentTraversalStore::default()));
        let mut cache = EnvironmentTraversalCache::with_shared_store(shared, true);
        let (_, fill) = capture_query_reads(workspace.analyzer(), || {
            cache.record_joined_scope(workspace.analyzer(), &file, 0);
        });
        let (scopes, hit) = capture_query_reads(workspace.analyzer(), || {
            cache.joined_scopes(workspace.analyzer(), &file)
        });
        assert_eq!(scopes, Some([0].into_iter().collect()));
        assert_eq!(fill.unattributed_reads(), 1);
        assert_eq!(hit.unattributed_reads(), 1);
    }

    #[test]
    #[hardwon("#2445: row-family sessions omitted the inputs of products reused by later captures")]
    fn shared_row_family_products_replay_inputs_into_later_captures() {
        let project = InlineTestProject::with_language(Language::Python)
            .with_git()
            .file(
                "example.py",
                "def identity(value):\n    return value\n\nresult = identity(1)\n",
            )
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let file = project.file("example.py");
        let environments = Arc::new(Mutex::new(EnvironmentTraversalStore::default()));
        let occurrences = Arc::new(Mutex::new(OccurrenceTraversalStore::default()));
        let filter = OccurrenceFilter {
            roles: vec![OccurrenceRole::ValueReference],
            ..Default::default()
        };
        let read = || {
            let mut environment =
                EnvironmentTraversalCache::with_shared_store(Arc::clone(&environments), false);
            let mut occurrence = OccurrenceTraversalCache::with_shared_store(
                OccurrenceDerivationOptions::IDENTITY_ONLY,
                Arc::clone(&occurrences),
                None,
            );
            let scopes = environment.environment_for(analyzer, &file);
            let rows = occurrence
                .rows_for_file(analyzer, &file, &filter, None)
                .expect("fixture occurrence derivation");
            let mut targets = rows.rows.clone();
            assert!(
                !targets.is_empty(),
                "the fixture must exercise target resolution"
            );
            assert!(occurrence.resolve_targets_for_rows(analyzer, &file, &mut targets, None));
            (scopes, rows, targets)
        };
        let (first, fill) = capture_query_reads(analyzer, read);
        let (second, hit) = capture_query_reads(analyzer, read);
        assert!(
            Arc::ptr_eq(&first.0, &second.0),
            "the environment must be reused"
        );
        assert!(
            Arc::ptr_eq(&first.1, &second.1),
            "the occurrences must be reused"
        );
        assert_eq!(format!("{:?}", first.2), format!("{:?}", second.2));
        assert_eq!(occurrences.lock().unwrap().stats(), (1, 1));
        let environment_stats = environments.lock().unwrap().stats();
        assert_eq!((environment_stats.0, environment_stats.1), (1, 1));
        let keys = hit.keys();
        assert!(
            !fill.keys().is_empty(),
            "the fixture must record actual inputs"
        );
        assert!(
            fill.keys().iter().all(|key| keys.contains(key)),
            "the later capture must inherit the fill's full receipt: {keys:?}"
        );
        assert!(hit.unattributed_reads() >= fill.unattributed_reads());
    }
}

#[cfg(test)]
mod render_tests {
    use crate::analyzer::{AnalyzerConfig, Language, ReadKey, capture_query_reads};
    use crate::structural::search::tests::inline_project::InlineTestProject;
    use crate::structural::search::{DeclarationValue, PipelineRenderCache};
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#2445: witness captures shared rendering caches without replaying their retained source"
    )]
    fn render_cache_hits_name_the_exact_retained_source() {
        let source = "pub fn root() {}\n";
        let project = InlineTestProject::with_language(Language::Rust)
            .with_git()
            .file("lib.rs", source)
            .build();
        let base = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("lib.rs");
        let unit = base
            .analyzer()
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.terminal_name() == "root")
            .expect("fixture declaration");
        let range = base
            .analyzer()
            .ranges(&unit)
            .into_iter()
            .next()
            .expect("fixture range");
        let declaration = DeclarationValue::new(unit, range);
        let mut cache = PipelineRenderCache::default();
        cache.seal_source_loads();
        let (_, skipped) = capture_query_reads(base.analyzer(), || {
            for _ in 0..2 {
                assert!(
                    cache
                        .range_for_declaration(base.analyzer(), &declaration)
                        .is_none()
                );
            }
        });
        assert!(cache.sources.is_empty());
        assert!(cache.declaration_ranges.is_empty());
        assert!(skipped.keys().is_empty());
        assert_eq!(skipped.unattributed_reads(), 0);
        assert!(cache.retain_source_snapshot(&file, source));
        let blob = git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
        let key = ReadKey::file(Language::Rust, "lib.rs", blob);
        let (first_range, first) = capture_query_reads(base.analyzer(), || {
            assert_eq!(cache.source_snapshot(base.analyzer(), &file), Some(source));
            cache.range_for_declaration(base.analyzer(), &declaration)
        });
        let (second_range, second) = capture_query_reads(base.analyzer(), || {
            assert_eq!(cache.source_snapshot(base.analyzer(), &file), Some(source));
            cache.range_for_declaration(base.analyzer(), &declaration)
        });
        assert!(first_range.is_some());
        assert_eq!(second_range, first_range);
        assert_eq!(first.keys(), vec![key.clone()]);
        assert_eq!(second.keys(), first.keys());
        project
            .file("lib.rs")
            .write("// shifted\npub fn root() {}\n")
            .unwrap();
        let head = project.workspace_analyzer(AnalyzerConfig::default());
        let (_, retained) = capture_query_reads(head.analyzer(), || {
            assert_eq!(cache.source_snapshot(head.analyzer(), &file), Some(source));
        });
        assert_eq!(retained.keys(), vec![key]);
        assert_ne!(head.analyzer().indexed_blob_oid(&file), Some(blob));
        let empty = PipelineRenderCache::default();
        let (_, absent) = capture_query_reads(head.analyzer(), || {
            assert!(empty.source_snapshot(head.analyzer(), &file).is_none());
        });
        assert_eq!(absent.unattributed_reads(), 1);
    }
}
