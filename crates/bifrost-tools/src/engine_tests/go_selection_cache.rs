#[cfg(test)]
mod tests {

    use go_selection_fixture as SelectionFixture;
    mod go_selection_fixture {
        use crate::selection_fixture_support::write_fixture_blob;
        use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;
        use brokk_bifrost_analysis::analyzer::store::{AnalyzerStore, GenerationId};
use brokk_bifrost_analysis::analyzer::store::resolution_selection::selection_test_support::{SelectionFixture, parsed_fixture_state};
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;
        pub(super) fn with_store(
            store: AnalyzerStore,
            mount_count: usize,
            storage_language: &str,
            semantic_language: Language,
            shared_blob: bool,
            bootstrap: bool,
            source: Option<&str>,
        ) -> SelectionFixture {
            assert!(
                source.is_none(),
                "the exact-selection regression uses the default source"
            );
            SelectionFixture::with_blob_writer(
                store,
                mount_count,
                storage_language,
                semantic_language,
                shared_blob,
                bootstrap,
                |store, oid, storage_language, semantic_language, generation: GenerationId| {
                    if semantic_language == Language::Go {
                        let state = parsed_fixture_state(
                            &GoAdapter,
                            "src/model.go",
                            "package demo\ntype Model struct {}\n",
                        );
                        store
                            .write_parsed_blob_at_generation(
                                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                                git2::Oid::from_str(oid).unwrap(),
                                storage_language,
                                generation,
                                &GoAdapter,
                                &state,
                            )
                            .expect("persist selected-resolution fixture blob");
                    } else if semantic_language == Language::Rust {
                        crate::engine_tests::rust_selection_fixture::write_rust_fixture_blob(
                            store,
                            oid,
                            storage_language,
                            generation,
                        );
                    } else {
                        write_fixture_blob(
                            store,
                            oid,
                            storage_language,
                            semantic_language,
                            generation,
                        );
                    }
                },
            )
        }
    }

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionOverlayMask;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionRevalidationOutcome;

    use brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::selected_resolution_temp_schema_sql;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("d629d480653d: lazy generic TEMP schema discarded the first retained selection")]
    fn single_reader_exact_selection_key_reuses_materialization_and_changed_mask_rebuilds() {
        let mut receipts = Vec::new();
        for (storage_language, semantic_language) in
            [("go", Language::Go), ("rust", Language::Rust)]
        {
            let temp = tempfile::tempdir().unwrap();
            // Mount reuse does not depend on unique source contents. Publish
            // one blob so the regression measures inventory work, not parsing.
            let mut fixture = SelectionFixture::with_store(
                AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap(),
                256,
                storage_language,
                semantic_language,
                true,
                false,
                None,
            );
            // Force eviction to certify rematerialization separately from the
            // multi-reader pool's retention of alternating exact selections.
            fixture.store.active_readers.capacity = 1;
            {
                let conn = fixture.store.active_read_conn().unwrap();
                ensure_revisioned_workspace_views(&conn).unwrap();
                conn.execute_batch(selected_resolution_temp_schema_sql())
                    .unwrap();
                conn.execute_batch(
                    "CREATE TEMP TABLE selection_materialization_probe(insertions INTEGER NOT NULL);
                     CREATE TEMP TRIGGER count_selected_resolution_materialization
                     AFTER INSERT ON selected_resolution_context
                     BEGIN
                       INSERT INTO selection_materialization_probe VALUES(1);
                     END;",
                ).unwrap();
            }
            let (original, formals, defaults) = {
                let mut ready = fixture.open_ready(&[]);
                let original = ready.read_change_stamp().unwrap();
                ready
                    .ensure_generic_formals_schema(ready.connection())
                    .unwrap();
                let formals = ready.read_change_stamp().unwrap();
                ready
                    .ensure_generic_formal_defaults_schema(ready.connection())
                    .unwrap();
                let defaults = ready.read_change_stamp().unwrap();
                assert!(matches!(
                    ready.revalidate(&CancellationToken::default()).unwrap(),
                    SelectedResolutionRevalidationOutcome::Current
                ));
                (original, formals, defaults)
            };
            for run in 0..3 {
                let start = std::time::Instant::now();
                let ready = fixture.open_ready(&[]);
                eprintln!(
                    "{storage_language} open {run}: {:?}; materializations={}",
                    start.elapsed(),
                    ready
                        .connection()
                        .query_row(
                            "SELECT COUNT(*) FROM temp.selection_materialization_probe",
                            [],
                            |row| row.get::<_, usize>(0)
                        )
                        .unwrap()
                );
                drop(ready);
            }
            eprintln!(
                "{storage_language} generic schema stamps: original={original:?}, formals={formals:?}, defaults={defaults:?}"
            );
            let removal = SelectedResolutionOverlayMask::removal(storage_language, "src/0000.java");
            drop(fixture.open_ready(std::slice::from_ref(&removal)));
            drop(fixture.open_ready(std::slice::from_ref(&removal)));
            let conn = fixture.store.active_read_conn().unwrap();
            receipts.push((
                storage_language,
                conn.query_row(
                    "SELECT COUNT(*) FROM temp.selection_materialization_probe",
                    [],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap(),
                formals == original,
                defaults == original,
            ));
        }
        assert_eq!(
            receipts,
            [("go", 2, true, true), ("rust", 2, true, true)],
            "only each distinct exact selection key may materialize, including after owned generic schema initialization"
        );
    }
}
