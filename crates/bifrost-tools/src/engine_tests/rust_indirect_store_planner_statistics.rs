#[cfg(test)]
mod rust_indirect_table_tests {

    use brokk_bifrost_analysis::analyzer::store::planner_statistics::rust_tests_test_support::statistics_env_lock;
    use brokk_bifrost_core::cache_gc::planner_statistics_row_count;
    use rusqlite::Connection;

    use crate::store_test_support::collection_fixtures::two_revision_collection_fixture;

    /// `BIFROST_STORE_STATISTICS=off` leaves the store with no statistics at
    /// all, which is how a statistics-free plan is reproduced.
    ///
    /// The environment variable is process-wide, so this test sets it around
    /// one build and restores it; it does not run beside the test above.
    /// A collection that dropped rows refreshes the statistics it invalidated.
    ///
    /// The setup makes one persisted blob genuinely unreachable: two commits,
    /// each built, then the branch is moved back to the first and the working
    /// tree is restored to the first content and the retained workspace
    /// projection is released, so nothing owns the second blob any more.
    #[test]
    fn a_collection_that_drops_rows_refreshes_the_statistics() {
        let _guard = statistics_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fixture = two_revision_collection_fixture();
        let db_path = &fixture.db_path;
        drop(fixture.store);

        let statistics = Connection::open(db_path).unwrap();
        statistics
            .execute(
                "INSERT INTO sqlite_stat1(tbl, idx, stat) VALUES('zzz_3016_sentinel', NULL, '1')",
                [],
            )
            .unwrap();
        drop(statistics);

        let outcome =
            brokk_bifrost_core::cache_gc::force_gc(db_path, &fixture.repository, &fixture.root)
                .expect("forced collection");
        assert!(
            outcome.analyzer_dropped > 0,
            "the setup must leave the second content collectable: {outcome:?}"
        );
        let statistics = Connection::open(db_path).unwrap();
        let sentinel: i64 = statistics
            .query_row(
                "SELECT count(*) FROM sqlite_stat1 WHERE tbl = 'zzz_3016_sentinel'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            sentinel, 0,
            "a collection that dropped {} rows must re-run ANALYZE",
            outcome.analyzer_dropped
        );
        assert!(
            planner_statistics_row_count(&statistics).unwrap() > 0,
            "and must leave real statistics behind"
        );
    }
}
