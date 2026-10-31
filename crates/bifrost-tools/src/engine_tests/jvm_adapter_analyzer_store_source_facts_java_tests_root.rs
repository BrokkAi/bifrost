#[cfg(test)]
mod jvm_extraction_tests {
    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    use brokk_bifrost_analysis::analyzer::store::source_facts::java_tests::SOURCE;

    use brokk_bifrost_jvm_analysis::analyzer::java::source_storage::JavaSourceStorage;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;
    #[test]
    fn java_source_reader_rejects_corrupt_type_edges_without_panicking() {
        let fixture = InlineTestProject::with_language(Language::Java)
            .file("Types.java", SOURCE)
            .build();
        let file = fixture.file("Types.java");
        let state = parse_state(&JavaAdapter, &file);
        let oid = oid_for(SOURCE.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store.current_generation("java").unwrap();
        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "java"),
                &JavaAdapter,
                &state,
            )
            .unwrap();
        store
            .conn
            .execute(|conn| {
                assert!(
                    conn.execute(
                        "UPDATE source_java_types SET child_id=type_id WHERE kind=2",
                        []
                    )
                    .is_err()
                );
                // Simulate damaged storage, not an allowed publication operation.
                conn.execute_batch(
                    "DROP TRIGGER source_java_types_no_update_after_seal;
            PRAGMA ignore_check_constraints=ON;
            UPDATE source_java_types SET child_id=type_id WHERE kind=2;
            PRAGMA ignore_check_constraints=OFF;",
                )?;
                Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
            })
            .unwrap();
        assert!(
            store
                .java_source_facts(oid, generation, &JavaAdapter, &file, &|| true)
                .is_err()
        );
    }
    #[test]
    fn java_source_lookup_seeks_populated_publications_before_and_after_statistics() {
        use rusqlite::params;
        let fixture = InlineTestProject::with_language(Language::Java)
            .file("types.java", SOURCE)
            .build();
        let file = fixture.file("types.java");
        let state = parse_state(&JavaAdapter, &file);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store.current_generation("java").unwrap();
        let oid = oid_for(SOURCE.as_bytes());
        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "java"),
                &JavaAdapter,
                &state,
            )
            .unwrap();
        // Distinct content identities populate the publication inventory without
        // introducing extra parser work into a query-planner regression.
        for index in 0..32 {
            let other = oid_for(format!("planner publication {index}").as_bytes());
            store
                .write_parsed_blob(
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(other, "java"),
                    &JavaAdapter,
                    &state,
                )
                .unwrap();
        }
        brokk_bifrost_analysis::analyzer::store::source_facts::assert_source_lookup_plan(
            &store,
            |conn| {
                conn.prepare(&format!(
                "EXPLAIN QUERY PLAN {}",
                brokk_bifrost_jvm_analysis::analyzer::java::source_storage::JAVA_SOURCE_HEADER_SQL
            ))
                .unwrap()
                .query_map(
                    params![
                        oid.to_string(),
                        generation.get(),
                        1,
                        brokk_bifrost_analysis::analyzer::store::source_facts::SOURCE_FACTS_VERSION
                    ],
                    |row| row.get::<_, String>(3),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
            },
            || {
                store
                    .java_source_facts(oid, generation, &JavaAdapter, &file, &|| true)
                    .unwrap()
                    .is_some()
            },
        );
        store
            .conn
            .execute(|conn| {
                conn.execute("DELETE FROM blobs", [])?;
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM source_java_declaration_manifests",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(
                    count, 0,
                    "blob deletion must cascade sealed source publications"
                );
                Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
            })
            .unwrap();
    }
    #[test]
    fn java_declaration_source_facts_reopen_without_source_and_mount_exact_bridges() {
        let fixture = InlineTestProject::with_language(Language::Java)
            .file("first/types.java", SOURCE)
            .file("second/types.java", SOURCE)
            .build();
        let file = fixture.file("first/types.java");
        let second = fixture.file("second/types.java");
        let state = parse_state(&JavaAdapter, &file);
        let expected = state.source_facts.as_ref().unwrap().java.as_ref().unwrap();
        assert!(!expected.callable_returns.is_empty());
        assert!(!expected.type_parameters.is_empty());
        use brokk_bifrost_core::analyzer::java_facts::{
            JavaAnonymousReturnStatus, JavaTypeSyntaxShape,
        };
        assert!(
            expected.anonymous_returns.iter().any(|fact| {
                fact.status == JavaAnonymousReturnStatus::AllAnonymous && !fact.returns.is_empty()
            }),
            "earlier incomplete generic syntax must not poison an unrelated anonymous return"
        );
        assert!(
            expected.types.iter().any(|fact| match &fact.shape {
                JavaTypeSyntaxShape::Generic { base, arguments } => {
                    matches!(&expected.types[base.index()].shape,
                JavaTypeSyntaxShape::Named { name, .. } if name.path() == ["List"])
                        && arguments.iter().any(|id| {
                            matches!(
                                expected.types[id.index()].shape,
                                JavaTypeSyntaxShape::Unknown
                            )
                        })
                }
                _ => false,
            }),
            "an unknown wildcard must not erase its known generic base"
        );
        assert!(
            expected
                .types
                .iter()
                .any(|fact| matches!(fact.shape, JavaTypeSyntaxShape::Array { dimensions: 2, .. })),
            "source arrays must preserve every written dimension"
        );
        let oid = oid_for(SOURCE.as_bytes());
        let path = fixture.root().join("java-source.db");
        {
            let store = AnalyzerStore::open_persistent(&path).unwrap();
            store
                .write_parsed_blob(
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "java"),
                    &JavaAdapter,
                    &state,
                )
                .unwrap();
        }
        std::fs::remove_file(file.abs_path()).unwrap();
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let generation = store.current_generation("java").unwrap();
        let (first, mounted) = brokk_bifrost_analysis::analyzer::store::source_facts::assert_source_facts_match_across_mounts(
        &store,
        generation,
        &file,
        &second,
        |store, generation, file, cancellation| {
            store.java_source_facts(oid, generation, &JavaAdapter, file, cancellation)
        },
        |read| &read.facts,
    );
        assert_eq!(&first.facts, expected);
        assert_eq!(
            first.source,
            state.source_facts.as_ref().unwrap().occurrences
        );
        assert!(
            first
                .declaration_units
                .values()
                .flatten()
                .all(|unit| unit.source() == &file)
        );
        assert!(
            mounted
                .declaration_units
                .values()
                .flatten()
                .all(|unit| unit.source() == &second)
        );
        brokk_bifrost_analysis::analyzer::store::source_facts::assert_source_read_cancellation_retries(|cancellation| {
        store.java_source_facts(oid, generation, &JavaAdapter, &file, cancellation)
    });
    }
    #[test]
    fn java_source_publication_distinguishes_empty_missing_and_sealed() {
        let fixture = InlineTestProject::with_language(Language::Java)
            .file("empty.java", "package example;\n")
            .build();
        let file = fixture.file("empty.java");
        let mut state = parse_state(&JavaAdapter, &file);
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store.current_generation("java").unwrap();
        let facts = state.source_facts.as_mut().unwrap().java.take().unwrap();
        assert!(
            store
                .write_parsed_blob(
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "java"),
                    &JavaAdapter,
                    &state
                )
                .is_err()
        );
        state.source_facts.as_mut().unwrap().java = Some(facts);
        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "java"),
                &JavaAdapter,
                &state,
            )
            .unwrap();
        let read = store
            .java_source_facts(oid, generation, &JavaAdapter, &file, &|| true)
            .unwrap()
            .unwrap();
        assert!(read.facts.type_parameters.is_empty());
        assert!(read.facts.callable_returns.is_empty());
        store
            .conn
            .execute(|conn| {
                assert!(
                conn.execute(
                    "UPDATE source_java_declaration_manifests SET payload_bytes = payload_bytes",
                    []
                )
                .is_err()
            );
                conn.execute("UPDATE blob_meta SET is_complete = 0", [])?;
                assert!(
                    conn.execute("UPDATE blob_meta SET java_source_version = NULL", [])
                        .is_err()
                );
                conn.execute("UPDATE blob_meta SET is_complete = 1", [])?;
                conn.execute_batch(
                    "DROP TRIGGER source_java_declaration_manifests_no_delete_after_seal;
                            DELETE FROM source_java_declaration_manifests;",
                )?;
                Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
            })
            .unwrap();
        brokk_bifrost_analysis::analyzer::store::source_facts::assert_missing_then_republished(
            || store.java_source_facts(oid, generation, &JavaAdapter, &file, &|| true),
            || {
                store.write_parsed_blob(
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "java"),
                    &JavaAdapter,
                    &state,
                )
            },
        );
    }
}
