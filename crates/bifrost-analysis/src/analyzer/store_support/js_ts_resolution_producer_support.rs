use crate::analyzer::store::*;
use crate::analyzer::store_bridge::AnalyzerStoreEngineExt;

use git2::Oid;
use rusqlite::params;
use std::sync::Arc;
use tree_sitter::Parser;

use crate::analyzer::store::resolution::PreparedResolutionBundle;
use crate::analyzer::store::resolution::RESOLUTION_MANIFEST_COUNT_COLUMNS;

use crate::analyzer::store::file_state::FileState;
use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;
use crate::analyzer::tree_sitter_analyzer::ParsedFile;
use crate::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

use crate::analyzer::ProjectFile;

#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct ManifestSnapshot {
    #[doc(hidden)]
    pub semantic_language: String,
    #[doc(hidden)]
    pub producer_epoch: String,
    #[doc(hidden)]
    pub interior_digest: [u8; 32],
    #[doc(hidden)]
    pub publication_state: String,
    #[doc(hidden)]
    pub family_counts: [usize; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()],
    #[doc(hidden)]
    pub logical_rows: usize,
    #[doc(hidden)]
    pub payload_bytes: usize,
}
impl ManifestSnapshot {
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn expected(bundle: &PreparedResolutionBundle) -> Self {
        Self {
            semantic_language: bundle.semantic_language().config_label().to_owned(),
            producer_epoch: bundle.producer_epoch().to_owned(),
            interior_digest: bundle.interior_digest(),
            publication_state: "complete".to_owned(),
            family_counts: bundle.family_counts(),
            logical_rows: bundle.logical_rows(),
            payload_bytes: bundle.payload_bytes(),
        }
    }
}
#[doc(hidden)]
pub fn parsed_fixture_state<A: LanguageAdapter>(
    adapter: &A,
    relative_path: &str,
    source: &str,
) -> Arc<FileState> {
    let file = ProjectFile::new(
        std::env::current_dir()
            .expect("resolve producer fixture root")
            .join("resolution-producer-fixture-does-not-touch-disk"),
        relative_path,
    );
    let mut parser = Parser::new();
    parser
        .set_language(&adapter.parser_language_for_file(&file))
        .expect("configure producer fixture grammar");
    let tree = parser
        .parse(source, None)
        .expect("parse producer fixture source");
    let mut parsed: ParsedFile = adapter.parse_file(&file, source, &tree);
    parsed.add_file_scope(&file, source);
    let contains_tests = adapter.contains_tests(&file, source, &tree, &parsed);
    Arc::new(TreeSitterAnalyzer::<A>::file_state_from_parsed(
        source.to_owned(),
        parsed,
        contains_tests,
        Some(Vec::new()),
        true,
    ))
}
#[doc(hidden)]
pub fn manifest_snapshot(store: &AnalyzerStore, oid: Oid, lang: &str) -> ManifestSnapshot {
    let count_columns = RESOLUTION_MANIFEST_COUNT_COLUMNS
        .iter()
        .map(|column| format!("interior.{column}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT interior.semantic_language, interior.producer_epoch,
                interior.interior_digest, interior.publication_state,
                interior.logical_rows, interior.payload_bytes, {count_columns}
         FROM blobs
         JOIN resolution_fragment_interiors AS interior ON interior.blob_id = blobs.id
         WHERE blobs.blob_oid = ?1 AND blobs.lang = ?2"
    );
    let oid = oid.to_string();
    let lang = lang.to_owned();
    store.conn.execute(move |conn| {
        conn.query_row(&sql, params![oid, lang], |row| {
            let digest = row.get::<_, Vec<u8>>(2)?;
            let mut family_counts = [0; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()];
            for (index, count) in family_counts.iter_mut().enumerate() {
                *count = row.get(6 + index)?;
            }
            Ok(ManifestSnapshot {
                semantic_language: row.get(0)?,
                producer_epoch: row.get(1)?,
                interior_digest: digest
                    .try_into()
                    .expect("resolution interior digest is exactly 32 bytes"),
                publication_state: row.get(3)?,
                logical_rows: row.get(4)?,
                payload_bytes: row.get(5)?,
                family_counts,
            })
        })
        .expect("persisted resolution manifest")
    })
}
#[doc(hidden)]
pub fn persist_alias_fixture<A: LanguageAdapter>(
    store: &AnalyzerStore,
    oid: Oid,
    storage_language: &str,
    adapter: &A,
    relative_path: &str,
    source: &str,
) -> ManifestSnapshot {
    let generation = store
        .ensure_language_epoch_value(storage_language, "resolution-alias-test-v1")
        .expect("alias generation");
    let state = parsed_fixture_state(adapter, relative_path, source);
    store
        .write_parsed_blob_at_generation(
            &crate::analyzer::store::test_blob_file(),
            oid,
            storage_language,
            generation,
            adapter,
            &state,
        )
        .expect("persist alias fixture");
    let first = manifest_snapshot(store, oid, storage_language);
    assert_eq!(
        first.semantic_language,
        adapter.language().config_label(),
        "storage alias must retain semantic language metadata"
    );
    assert!(store.content_row_count(oid, storage_language).unwrap() > 0);
    store
        .write_parsed_blob_at_generation(
            &crate::analyzer::store::test_blob_file(),
            oid,
            storage_language,
            generation,
            adapter,
            &state,
        )
        .expect("repeat alias fixture persistence");
    assert_eq!(manifest_snapshot(store, oid, storage_language), first);
    assert!(store.contains_parsed_blob(oid, storage_language).unwrap());
    first
}
