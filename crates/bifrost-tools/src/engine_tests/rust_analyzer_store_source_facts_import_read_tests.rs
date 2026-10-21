#[cfg(test)]
mod rust_departing_tests_tests {

    use brokk_bifrost_analysis::analyzer::store::source_facts::import_read::read_source_imports;

    use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;

    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_analysis::analyzer::store::test_support::blob_id;

    use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;
    use rusqlite::params;
    const IMPORT_SOURCE: &str = concat!(
        "use crate::service::{self as svc, run as execute, *};\n",
        "use crate::{};\n",
        "mod local { use super::{Local, LocalAlias as LocalName}; }\n",
        "macro_rules! wrap { ($($item:item)*) => { $($item)* }; }\n",
        "wrap! { use crate::Embedded; }\n",
        "wrap! { use crate::{}; }\n",
    );

    #[test]
    fn canonical_import_readback_preserves_embedded_local_grouped_and_empty_inputs() {
        let fixture = InlineTestProject::new()
            .file("src/lib.rs", IMPORT_SOURCE)
            .build();
        let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
        let expected = state
            .source_facts
            .as_ref()
            .expect("Rust source facts")
            .imports
            .clone();
        assert!(
            expected.len() >= 6,
            "fixture should retain grouped, local, and embedded leaves: {expected:?}"
        );
        assert_eq!(
            expected
                .iter()
                .filter(|import| import.statement.contains("service"))
                .count(),
            3,
            "grouped leaves retain producer order and normalized statements"
        );
        assert!(
            expected.iter().any(|import| import
                .path
                .as_ref()
                .is_some_and(|path| !path.lexical_scopes.is_empty())),
            "local or embedded import must retain lexical source scopes"
        );
        assert!(
            expected
                .iter()
                .any(|import| import.statement.contains("Embedded")),
            "embedded macro import must be source-owned"
        );
        assert!(
            expected
                .iter()
                .all(|import| import.statement != "use crate::{};"),
            "empty import groups do not create leaf facts"
        );

        let oid = oid_for(IMPORT_SOURCE.as_bytes());
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral analyzer store");
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .expect("canonical import fixture publishes");
        let actual = store.conn.execute(move |conn| {
            let id = blob_id(conn, oid);
            read_source_imports(conn, id, &|| true)
        });
        assert_eq!(actual.unwrap().unwrap(), expected);
    }

    #[test]
    fn canonical_import_readback_cancellation_and_manifest_corruption_are_reported() {
        let fixture = InlineTestProject::new()
            .file("src/lib.rs", IMPORT_SOURCE)
            .build();
        let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
        let oid = oid_for(IMPORT_SOURCE.as_bytes());
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral analyzer store");
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .expect("canonical import fixture publishes");

        let cancelled = store.conn.execute(move |conn| {
            let id = blob_id(conn, oid);
            read_source_imports(conn, id, &|| false)
        });
        assert!(cancelled.unwrap().is_none());

        let corrupted = store.conn.execute(move |conn| {
            let id = blob_id(conn, oid);
            conn.execute_batch(
                "SAVEPOINT import_reader_corruption;
                 DROP TRIGGER source_import_segments_no_delete_after_seal;",
            )
            .expect("open canonical import corruption savepoint");
            let changed = conn
                .execute(
                    "DELETE FROM source_import_segments
                      WHERE blob_id = ?1
                        AND import_id = (SELECT MIN(import_id)
                                           FROM source_import_segments WHERE blob_id = ?1)
                        AND ordinal = (SELECT MAX(ordinal)
                                         FROM source_import_segments
                                        WHERE blob_id = ?1
                                          AND import_id = (SELECT MIN(import_id)
                                                             FROM source_import_segments
                                                            WHERE blob_id = ?1))",
                    params![id],
                )
                .expect("delete one canonical import segment inside savepoint");
            assert_eq!(changed, 1, "fixture must publish a canonical segment");
            let result = read_source_imports(conn, id, &|| true);
            conn.execute_batch(
                "ROLLBACK TO import_reader_corruption;
                 RELEASE import_reader_corruption;",
            )
            .expect("restore canonical import rows");
            result
        });
        let error = corrupted.expect_err("manifest segment count mismatch must fail readback");
        assert!(
            error
                .to_string()
                .contains("source import segment count mismatch")
        );
    }
}
