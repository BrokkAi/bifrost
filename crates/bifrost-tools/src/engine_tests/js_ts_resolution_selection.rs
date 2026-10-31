#[cfg(test)]
mod js_ts_selection_tests {
    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::selection_test_support as support;
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_js_ts_analysis::analyzer::typescript::TypescriptAdapter;

    struct SelectionFixture;

    impl SelectionFixture {
        fn with_language(
            mount_count: usize,
            storage_language: &str,
            semantic_language: Language,
            shared_blob: bool,
        ) -> support::SelectionFixture {
            support::SelectionFixture::with_blob_writer(
                brokk_bifrost_analysis::analyzer::store::AnalyzerStore::open_ephemeral().unwrap(),
                mount_count,
                storage_language,
                semantic_language,
                shared_blob,
                false,
                |store, oid, storage_language, semantic_language, generation| {
                    if semantic_language == Language::TypeScript {
                        let state = support::parsed_fixture_state(
                            &TypescriptAdapter,
                            "src/Model.tsx",
                            "export class Model {}\n",
                        );
                        store
                            .write_parsed_blob_at_generation(
                                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                                &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                                    git2::Oid::from_str(oid).unwrap(),
                                    storage_language,
                                ),
                                generation,
                                &TypescriptAdapter,
                                &state,
                            )
                            .expect("persist selected-resolution fixture blob");
                    } else if semantic_language == Language::Cpp {
                        let adapter =
                            brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter;
                        let state = support::parsed_fixture_state(
                            &adapter,
                            "src/Model.c",
                            "class Model {};\n",
                        );
                        store
                            .write_parsed_blob_at_generation(
                                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                                &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                                    git2::Oid::from_str(oid).unwrap(),
                                    storage_language,
                                ),
                                generation,
                                &adapter,
                                &state,
                            )
                            .expect("persist selected-resolution fixture blob");
                    } else {
                        crate::selection_fixture_support::write_fixture_blob(
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

    #[test]
    fn duplicate_blob_mounts_and_storage_aliases_retain_distinct_fragment_identity() {
        let fixture =
            SelectionFixture::with_language(2, "typescript:tsx", Language::TypeScript, true);
        let ready = fixture.open_ready(&[]);
        assert_eq!(
            ready.mounts().unwrap()[0].blob_id(),
            ready.mounts().unwrap()[1].blob_id()
        );
        // Two paths holding the same blob are two mounts of one content, so
        // what separates them is the mount's content key; the ordinal
        // separates them too, but only because they are two positions.
        assert_ne!(
            ready.mounts().unwrap()[0].fragment_digest(),
            ready.mounts().unwrap()[1].fragment_digest()
        );
        assert!(
            ready
                .mounts()
                .unwrap()
                .iter()
                .all(|mount| mount.storage_language() == "typescript:tsx"
                    && mount.semantic_language() == Language::TypeScript)
        );

        let c_fixture = SelectionFixture::with_language(1, "cpp:c", Language::Cpp, false);
        let c_ready = c_fixture.open_ready(&[]);
        assert_eq!(c_ready.mounts().unwrap()[0].storage_language(), "cpp:c");
        assert_eq!(
            c_ready.mounts().unwrap()[0].semantic_language(),
            Language::Cpp
        );
    }
}
