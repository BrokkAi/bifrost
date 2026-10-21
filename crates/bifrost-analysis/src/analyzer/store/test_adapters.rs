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
    use crate::analyzer::cognitive_complexity;
    use crate::analyzer::java::JavaAdapter;
    #[cfg(any(test, feature = "test-support"))]
    use crate::analyzer::store::{AnalyzerStore, WorkspaceId};
    use crate::analyzer::tree_sitter_analyzer::{LanguageAdapter, ParsedFile};
    #[cfg(any(test, feature = "test-support"))]
    use crate::analyzer::workspace::WorkspaceAnalyzer;
    #[cfg(any(test, feature = "test-support"))]
    use crate::analyzer::{AnalyzerConfig, Project, TestProject};
    use crate::analyzer::{FqName, Language, ProjectFile};
    #[cfg(any(test, feature = "test-support"))]
    use crate::gitblob::test_repo::{commit_all, init_repo};
    #[cfg(test)]
    use rusqlite::params;
    #[cfg(any(test, feature = "test-support"))]
    use std::path::PathBuf;
    #[cfg(any(test, feature = "test-support"))]
    use std::sync::Arc;
    use tree_sitter::Tree;

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

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub struct TwoRevisionCollectionFixture {
        #[doc(hidden)]
        pub root: PathBuf,
        #[doc(hidden)]
        pub repository: git2::Repository,
        #[doc(hidden)]
        pub db_path: PathBuf,
        #[doc(hidden)]
        pub store: AnalyzerStore,
        _temp: tempfile::TempDir,
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn two_revision_collection_fixture() -> TwoRevisionCollectionFixture {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let first = "pub fn widget() -> u32 { 1 }\n";
        let second = "pub fn widget() -> u32 { 2 }\npub fn extra() -> u32 { 3 }\n";
        std::fs::write(root.join(".gitignore"), ".bifrost/cache/\n").unwrap();
        std::fs::write(root.join("app.rs"), first).unwrap();
        let repository = init_repo(&root);
        let first_commit = commit_all(&repository, "first content");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
            Arc::clone(&project),
            AnalyzerConfig::default(),
        )
        .expect("persisted analyzer should build");
        let db_path = workspace
            .persisted_store_path()
            .expect("a persisted build reports its store path");
        drop(workspace);

        std::fs::write(root.join("app.rs"), second).unwrap();
        commit_all(&repository, "second content");
        drop(
            WorkspaceAnalyzer::build_persisted_without_automatic_gc(
                Arc::clone(&project),
                AnalyzerConfig::default(),
            )
            .expect("persisted analyzer should rebuild"),
        );

        let head = repository.head().unwrap();
        let branch = head.name().expect("a named branch").to_string();
        repository
            .reference(&branch, first_commit, true, "drop the second commit")
            .unwrap();
        drop(head);
        std::fs::write(root.join("app.rs"), first).unwrap();

        let store = AnalyzerStore::open_persistent(&db_path).expect("open the collected store");
        assert!(
            store
                .delete_workspace_projection(&WorkspaceId::for_root(&root))
                .expect("release the workspace projection")
                > 0
        );

        TwoRevisionCollectionFixture {
            _temp: temp,
            root,
            repository,
            db_path,
            store,
        }
    }

    /// Java behavior with the pre-canonical source-publication contract.
    ///
    /// Hand-built resolution fixtures can contain synthetic native identities that
    /// do not correspond to the source declarations from their small parse. They
    /// must therefore remain explicitly legacy fixtures rather than inventing
    /// source declaration bridges merely to satisfy the current Java adapter.
    #[derive(Debug, Clone, Copy, Default)]
    #[doc(hidden)]
    pub struct LegacyJavaFixtureAdapter;

    impl LanguageAdapter for LegacyJavaFixtureAdapter {
        fn source_fact_storage(
            &self,
        ) -> Option<&'static crate::analyzer::store::SourceFactStorage> {
            JavaAdapter.source_fact_storage()
        }

        fn language(&self) -> Language {
            JavaAdapter.language()
        }

        fn query_directory(&self) -> &'static str {
            JavaAdapter.query_directory()
        }

        fn file_extension(&self) -> &'static str {
            JavaAdapter.file_extension()
        }

        fn normalize_full_name(&self, fq_name: &str) -> String {
            JavaAdapter.normalize_full_name(fq_name)
        }

        fn normalize_fq_name(&self, fq_name: &FqName) -> FqName {
            JavaAdapter.normalize_fq_name(fq_name)
        }

        fn is_anonymous_structure(&self, fq_name: &str) -> bool {
            JavaAdapter.is_anonymous_structure(fq_name)
        }

        fn extract_call_receiver(&self, reference: &str) -> Option<String> {
            JavaAdapter.extract_call_receiver(reference)
        }

        fn contains_tests(
            &self,
            file: &ProjectFile,
            source: &str,
            tree: &Tree,
            parsed: &ParsedFile,
        ) -> bool {
            JavaAdapter.contains_tests(file, source, tree, parsed)
        }

        fn parse_file(&self, file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
            JavaAdapter.parse_file(file, source, tree)
        }

        fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
            JavaAdapter.cognitive_complexity_config()
        }

        fn produces_canonical_source_facts(&self) -> bool {
            false
        }

        fn declaration_visibility_facts_version(&self) -> Option<i64> {
            None
        }
    }
}
