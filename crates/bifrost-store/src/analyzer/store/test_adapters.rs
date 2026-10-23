//! Test-only adapters and feature-gated persisted-store recovery fixtures.

#[cfg(test)]
pub(crate) use fixtures::*;

/// Test-only store hooks that put the cache into a state only recovery code
/// should see, for cases `AnalyzerStore`'s own test hooks cannot express.
impl crate::analyzer::store::AnalyzerStore {
    /// Test hook: drop one blob's Rust route witness.
    ///
    /// `rust_published_fact_blobs` is strictly stronger than
    /// `source_fact_readiness`: on top of the sealed manifests it requires the
    /// blob's root occurrence, its ordinal-0 module scope and its ordinal-0
    /// module inventory -- the witnesses that a blob has usable native route
    /// facts. Removing the inventory row is therefore a blob whose facts are
    /// published but not usable, which is exactly the gap
    /// `RustAnalyzer::rust_files_without_facts` reports and the only state in
    /// which a preflight has anything to say: readiness stays available, so
    /// the file remains an analyzed file and a request can still name it.
    ///
    /// `AnalyzerStore::delete_rust_facts_for_test` cannot express this. It
    /// loses the whole module family of *every* Rust blob, which also fails
    /// readiness and so takes those files out of the analyzed set entirely.
    #[doc(hidden)]
    pub fn drop_rust_route_witness_for_blob_for_test(&self, lang: &str, blob_oid: git2::Oid) {
        let lang = lang.to_string();
        let blob_oid = blob_oid.to_string();
        self.conn.execute(move |conn| {
            // The seal guard is dropped and restored around the deliberate
            // loss, as `delete_rust_facts_for_test` does, and foreign keys stay
            // enabled: nothing references the inventory, so an intact database
            // is still an intact database afterwards.
            let tx = conn.transaction().expect("route witness loss transaction");
            let guard = "source_rust_module_inventory_no_delete_after_seal";
            let sql: String = tx
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                    [guard],
                    |row| row.get(0),
                )
                .expect("module inventory deletion guard");
            tx.execute_batch(&format!("DROP TRIGGER {guard}"))
                .expect("allow deliberate route witness loss");
            let removed = tx
                .execute(
                    "DELETE FROM source_rust_module_inventory WHERE blob_id IN (
                         SELECT id FROM blobs WHERE lang = ?1 AND blob_oid = ?2)",
                    [&lang, &blob_oid],
                )
                .expect("remove one blob's module inventory rows");
            assert!(removed > 0, "the blob had a module inventory to lose");
            tx.execute_batch(&sql)
                .expect("restore module inventory deletion guard");
            tx.commit()
                .expect("route witness loss preserves foreign keys");
        });
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod fixtures {

    #[cfg(test)]
    use crate::analyzer::store::AnalyzerStore;

    #[cfg(test)]
    use rusqlite::params;

    /// Insert one complete Python blob for class-set store fixtures.
    #[cfg(test)]
    pub(crate) fn insert_complete_python_blob(store: &AnalyzerStore, oid: &str, generation: i64) {
        let conn = store.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'python', ?2)",
            params![oid, generation],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blob_meta(
           blob_id, lang, contains_tests, content_package, stored_unit_count,
           range_count, signature_count, signature_metadata_count, supertype_count,
           child_count, import_statement_count, type_identifier_count, is_complete
         )
         SELECT id, lang, 0, '', 0, 0, 0, 0, 0, 0, 0, 0, 1
         FROM blobs WHERE blob_oid = ?1 AND lang = 'python'",
            params![oid],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blob_payload_costs(blob_id, payload_bytes)
         SELECT id, 0 FROM blobs WHERE blob_oid = ?1 AND lang = 'python'",
            params![oid],
        )
        .unwrap();
    }

    #[cfg(test)]
    pub(crate) fn ephemeral_store_with_complete_python_blob(
        oid: &str,
        generation: i64,
    ) -> AnalyzerStore {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        insert_complete_python_blob(&store, oid, generation);
        store
    }

    #[cfg(test)]
    pub(crate) fn stored_blob_cascade_costs(store: &AnalyzerStore, oid: &str) -> (usize, usize) {
        let conn = store.conn.lock().unwrap();
        conn.query_row(
            &crate::analyzer::store::stored_blob_cascade_costs_sql(1),
            params![oid, "python"],
            |row| Ok((row.get(3)?, row.get::<_, Option<usize>>(4)?.unwrap())),
        )
        .unwrap()
    }
}
