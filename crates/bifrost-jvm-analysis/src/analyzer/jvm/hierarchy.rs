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
    analyzer: &dyn IAnalyzer,
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

/// A bounded derived projection carries the reads of the entry it returns.
pub(crate) type DerivedMemo<K, V> =
    ReplayingMemo<Cache<K, Arc<ReplayingMemoEntry<Arc<V>, ReadKey>>>>;

pub(crate) fn derived_memo<K, V>(budget: u64) -> DerivedMemo<K, V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    ReplayingMemo::new(build_weighted_cache(
        budget,
        |_, entry: &Arc<ReplayingMemoEntry<Arc<V>, ReadKey>>| {
            u32::try_from(entry.retained_bytes(|key| {
                let mut heap = RetainedHeap::default();
                retained_read_key(&mut heap, key);
                heap.total()
            }))
            .unwrap_or(u32::MAX)
        },
    ))
}

pub(crate) fn derived_read<K, V>(
    memo: &DerivedMemo<K, V>,
    analyzer: &dyn IAnalyzer,
    key: &K,
    build: impl FnOnce() -> (Arc<V>, usize),
) -> Arc<V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    let result = memo
        .read(&memo_attribution(analyzer), |cache, capture| {
            Ok::<_, std::convert::Infallible>(cache.get(key).unwrap_or_else(|| {
                let attempt = brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(
                    analyzer,
                    || Arc::new(capture.build_weighted(build)),
                );
                match attempt {
                    Ok(entry) => {
                        cache.insert(key.clone(), Arc::clone(&entry));
                        entry
                    }
                    Err(entry) => entry,
                }
            }))
        })
        .expect("derived memo build is infallible");
    Arc::clone(&result)
}

#[cfg(test)]
mod memo_tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::{capture_query_reads, store::StoreError};

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
}
