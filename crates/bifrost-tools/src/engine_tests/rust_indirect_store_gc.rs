#[cfg(test)]
mod rust_indirect_table_tests {
    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_analysis::analyzer::store::gc::run_gc;

    use brokk_bifrost_analysis::analyzer::store::test_adapters::fixtures::two_revision_collection_fixture;

    /// A collection that dropped rows leaves this store's pooled readers
    /// planning against statistics the collection invalidated, so the
    /// collection recycles them (issue #3029).
    ///
    /// This is the case the build hook does not cover: the first `ANALYZE` of a
    /// store's life creates `sqlite_stat1`, which is a schema change every
    /// connection notices, while a collection rewrites rows in a table that
    /// already exists.
    ///
    /// The setup makes one persisted blob unreachable the same way
    /// `a_collection_that_drops_rows_refreshes_the_statistics` does: two
    /// commits, each built, then the branch moves back to the first and the
    /// working tree with it, and the retained workspace projection is released.
    #[test]
    #[hardwon(
        "d78f9a16030c: readers kept stale query plans after garbage collection changed planner statistics"
    )]
    fn a_collection_that_drops_rows_recycles_this_stores_readers() {
        let _statistics = brokk_bifrost_core::cache_gc::planner_statistics_test_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _tuning = brokk_bifrost_core::cache_gc::set_tuning_for_test(0, 0);
        let fixture = two_revision_collection_fixture();
        let store = &fixture.store;
        drop(store.read_conn().expect("warm one pooled reader"));
        assert_eq!(
            store.readers.idle_len(),
            1,
            "the warmed reader must be back in the pool before the collection"
        );

        let outcome = run_gc(store, &fixture.repository, &fixture.root).expect("collection");
        assert!(
            outcome.analyzer_dropped > 0,
            "the setup must leave the second content collectable: {outcome:?}"
        );
        assert_eq!(
            store.readers.idle_len(),
            0,
            "a collection that dropped {} rows must close the readers that planned before it",
            outcome.analyzer_dropped
        );
    }
}
