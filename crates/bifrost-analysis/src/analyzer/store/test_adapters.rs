//! Test-only adapters for persisted store fixtures.

use crate::analyzer::cognitive_complexity;
use crate::analyzer::java::JavaAdapter;
use crate::analyzer::tree_sitter_analyzer::{LanguageAdapter, ParsedFile};
use crate::analyzer::{FqName, Language, ProjectFile};
use tree_sitter::Tree;

/// Java behavior with the pre-canonical source-publication contract.
///
/// Hand-built resolution fixtures can contain synthetic native identities that
/// do not correspond to the source declarations from their small parse. They
/// must therefore remain explicitly legacy fixtures rather than inventing
/// source declaration bridges merely to satisfy the current Java adapter.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LegacyJavaFixtureAdapter;

impl LanguageAdapter for LegacyJavaFixtureAdapter {
    fn source_fact_storage(&self) -> Option<&'static crate::analyzer::store::SourceFactStorage> {
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
    /// This hook lives here because `store/mod.rs` is not this lane's to edit.
    pub(crate) fn drop_rust_route_witness_for_blob_for_test(
        &self,
        lang: &str,
        blob_oid: git2::Oid,
    ) {
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
