#[cfg(test)]
mod jvm_extraction_tests {
    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    use brokk_bifrost_analysis::analyzer::store::source_facts::declaration_visibility_tests::JAVA_SOURCE;

    use brokk_bifrost_analysis::analyzer::store::source_facts::declaration_visibility_tests::VisibilitySnapshot;

    use brokk_bifrost_analysis::analyzer::store::source_facts::declaration_visibility_tests::assert_metadata_read_plan;

    use brokk_bifrost_analysis::analyzer::store::source_facts::declaration_visibility_tests::assert_source_visibility_properties;

    use brokk_bifrost_analysis::analyzer::store::source_facts::declaration_visibility_tests::blob_id;

    use brokk_bifrost_analysis::analyzer::store::source_facts::declaration_visibility_tests::by_declaration_visibility;

    use brokk_bifrost_analysis::analyzer::store::source_facts::declaration_visibility_tests::visibility_snapshot;

    use brokk_bifrost_analysis::analyzer::store::source_facts::declaration_visibility_tests::visibility_workspace;

    use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
    use brokk_bifrost_core::hash::HashMap as CoreHashMap;
    use rusqlite::{Connection, params};

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

    use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_analysis::analyzer::store::stored_unit_keys;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState;
    #[test]
    fn java_visibility_publication_is_exact_across_reopen_reader_shapes_and_native_projection() {
        let (fixture, file, state) = java_fixture();
        assert_source_visibility_properties(&state);
        let oid = oid_for(JAVA_SOURCE.as_bytes());
        let path = fixture.root().join("java-declaration-visibility.db");
        let store = AnalyzerStore::open_persistent(&path).expect("open Java visibility store");
        let generation = store.current_generation("java").expect("Java generation");
        let mut stale_projection = state.clone();
        for (unit, alternatives) in &mut stale_projection.signature_metadata {
            if unit.is_synthetic() {
                continue;
            }
            for metadata in alternatives {
                let stale = if metadata.callable_declared_visibility()
                    == Some(DeclaredVisibility::Private)
                {
                    DeclaredVisibility::Public
                } else {
                    DeclaredVisibility::Private
                };
                *metadata = metadata.clone().with_source_declared_visibility(stale);
            }
        }
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "java",
                generation,
                &JavaAdapter,
                &stale_projection,
            )
            .expect("publish complete Java visibility family");
        {
            let conn = store.read_conn().expect("read Java visibility publication");
            let id = blob_id(&conn, oid);
            let first = assert_persisted_rows_match_state(&conn, id, &state);
            assert_metadata_read_plan(&conn, &state, oid);
            assert_reader_coherence(&store, &file, &state, oid, generation);
            drop(conn);
            store
                .refresh_planner_statistics()
                .expect("refresh Java visibility planner statistics");
            let conn = store
                .read_conn()
                .expect("read Java visibility after ANALYZE");
            let id = blob_id(&conn, oid);
            let after_statistics = visibility_snapshot(&conn, id);
            assert_metadata_read_plan(&conn, &state, oid);
            assert_eq!(
                after_statistics, first,
                "ANALYZE preserves canonical visibility"
            );
            drop(conn);
        }
        drop(store);

        let reopened = AnalyzerStore::open_persistent(&path).expect("reopen Java visibility store");
        let generation = reopened
            .current_generation("java")
            .expect("reopened Java generation");
        let conn = reopened
            .read_conn()
            .expect("read reopened Java visibility publication");
        let id = blob_id(&conn, oid);
        let reopened_snapshot = assert_persisted_rows_match_state(&conn, id, &state);
        drop(conn);
        assert_reader_coherence(&reopened, &file, &state, oid, generation);
        let conn = reopened
            .read_conn()
            .expect("read final Java visibility publication");
        assert_eq!(visibility_snapshot(&conn, id), reopened_snapshot);
    }
    #[test]
    fn empty_java_visibility_publication_is_present_and_distinct_from_legacy() {
        let fixture = InlineTestProject::with_language(Language::Java)
            .file("Empty.java", "")
            .build();
        let file = fixture.file("Empty.java");
        let state = parse_state(&JavaAdapter, &file);
        let facts = state
            .source_facts
            .as_ref()
            .expect("empty Java source facts");
        assert!(matches!(
            facts.declaration_visibilities.as_deref(),
            Some(visibilities) if visibilities.is_empty()
        ));
        assert!(state.source_declaration_metadata.is_empty());
        assert!(facts.native_declaration_sources.is_empty());
        let oid = oid_for(b"empty-java-visibility");
        let store = AnalyzerStore::open_ephemeral().expect("empty Java visibility store");
        let generation = store.current_generation("java").expect("Java generation");
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "java",
                generation,
                &JavaAdapter,
                &state,
            )
            .expect("publish empty Java visibility family");
        let conn = store.read_conn().expect("read empty Java publication");
        let id = blob_id(&conn, oid);
        let marker: (i64, i64, i64, i64) = conn
            .query_row(
                "SELECT facts_version, visibility_count, native_bridge_count,
                    metadata_bridge_count
               FROM source_declaration_visibility_manifests
              WHERE blob_id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("empty marker");
        assert_eq!(marker, (1, 0, 0, 0));
        assert_eq!(
            conn.query_row(
                "SELECT declaration_visibility_version FROM blob_meta WHERE blob_id = ?1",
                [id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .expect("empty visibility requirement"),
            Some(1)
        );
        assert_eq!(
            conn.query_row(
                "SELECT available FROM source_declaration_visibility_readiness WHERE blob_id = ?1",
                [id],
                |row| row.get::<_, i64>(0),
            )
            .expect("empty visibility readiness"),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM legacy_resolution_declaration_visibility_properties
              WHERE blob_id = ?1",
                [id],
                |row| row.get::<_, i64>(0),
            )
            .expect("empty legacy visibility count"),
            0
        );
    }
    #[test]
    fn incomplete_java_visibility_bridges_fail_atomically_without_legacy_fallback() {
        for missing in ["metadata", "native"] {
            let (_fixture, _file, mut state) = java_fixture();
            if missing == "metadata" {
                assert!(state.source_declaration_metadata.pop().is_some());
            } else {
                let facts = state.source_facts.as_mut().expect("Java facts");
                let visibility_declarations = facts
                    .declaration_visibilities
                    .as_ref()
                    .expect("Java visibility facts")
                    .iter()
                    .map(|fact| fact.declaration)
                    .collect::<std::collections::HashSet<_>>();
                let native_index = facts
                    .native_declaration_sources
                    .iter()
                    .position(|(_, declaration)| visibility_declarations.contains(declaration))
                    .expect("fixture has a native bridge with source visibility");
                facts.native_declaration_sources.remove(native_index);
            }
            let store = AnalyzerStore::open_ephemeral().expect("failed Java publication store");
            let oid = oid_for(format!("failed-{missing}-java-visibility").as_bytes());
            let generation = store.current_generation("java").expect("Java generation");
            let error = store
                .write_parsed_blob_at_generation(
                    &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                    oid,
                    "java",
                    generation,
                    &JavaAdapter,
                    &state,
                )
                .expect_err("missing canonical bridge must fail publication");
            assert!(
                error.to_string().contains("visibility")
                    || error.to_string().contains("bridge")
                    || error.to_string().contains("source"),
                "unexpected publication error: {error:?}"
            );
            assert_eq!(
                store
                    .content_row_count(oid, "java")
                    .expect("failed row count"),
                0
            );
            let conn = store.read_conn().expect("read failed Java publication");
            let canonical_rows: i64 = conn
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM source_declaration_visibility_manifests
                      WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))
                  + (SELECT COUNT(*) FROM source_declaration_visibilities
                      WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))
                  + (SELECT COUNT(*) FROM source_native_declaration_bridges
                      WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))
                  + (SELECT COUNT(*) FROM source_declaration_metadata_bridges
                      WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))",
                [oid.to_string()],
                |row| row.get(0),
            )
            .expect("failed canonical row count");
            assert_eq!(
                canonical_rows, 0,
                "failed publication leaves no source family rows"
            );
            assert_eq!(
                conn.query_row(
                    "SELECT COUNT(*) FROM legacy_resolution_declaration_visibility_properties
                  WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java')",
                    [oid.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("failed legacy row count"),
                0
            );
        }
    }
    #[test]
    fn legacy_visibility_rows_cannot_override_a_canonical_java_publication() {
        let (_fixture, _file, state) = java_fixture();
        let store = AnalyzerStore::open_ephemeral().expect("legacy projection store");
        let oid = oid_for(b"legacy-does-not-win-java-visibility");
        let generation = store.current_generation("java").expect("Java generation");
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "java",
                generation,
                &JavaAdapter,
                &state,
            )
            .expect("publish Java visibility");
        let conn = store.read_conn().expect("read canonical Java visibility");
        let id = blob_id(&conn, oid);
        let before = visibility_snapshot(&conn, id);
        let (semantic_key, canonical): (i64, String) = conn
            .query_row(
                "SELECT definition_semantic_key, visibility
               FROM resolution_declaration_visibility_properties
              WHERE blob_id = ?1
              ORDER BY definition_semantic_key
              LIMIT 1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("canonical native visibility row");
        drop(conn);
        let stale = if canonical == "private" {
            "public"
        } else {
            "private"
        };
        store
            .conn
            .execute(move |conn| {
                conn.execute_batch(
            "DROP TRIGGER legacy_resolution_declaration_visibility_properties_no_canonical_insert;",
        )?;
                conn.execute(
                    "INSERT INTO legacy_resolution_declaration_visibility_properties(
                 blob_id, definition_semantic_key, visibility
             ) VALUES(?1, ?2, ?3)",
                    params![id, semantic_key, stale],
                )?;
                Ok::<(), brokk_bifrost_analysis::analyzer::store::StoreError>(())
            })
            .expect("inject controlled stale legacy row");
        let conn = store
            .read_conn()
            .expect("read canonical projection after legacy injection");
        let after = visibility_snapshot(&conn, id);
        assert_eq!(after.legacy_rows, 1);
        assert_eq!(after.native_visibility, before.native_visibility);
    }
    #[test]
    fn damaged_java_visibility_publication_is_unavailable_not_legacy() {
        use brokk_bifrost_core::analyzer::{
            DefinitionLanguageScope, RelationalDefinitionQuery, RelationalDefinitionRequest,
            RelationalName,
        };

        use brokk_bifrost_core::cancellation::CancellationToken;
        for corruption in ["marker", "source", "property", "version"] {
            let (fixture, file, state) = java_fixture();
            let store = AnalyzerStore::open_ephemeral().expect("corruption test store");
            let oid = oid_for(format!("corrupt-{corruption}-java-visibility").as_bytes());
            let generation = store.current_generation("java").expect("Java generation");
            store
                .write_parsed_blob_at_generation(
                    &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                    oid,
                    "java",
                    generation,
                    &JavaAdapter,
                    &state,
                )
                .expect("publish Java visibility");
            let (_, snapshots) = visibility_workspace(&store, oid);
            let conn = store.read_conn().expect("read Java corruption fixture");
            let id = blob_id(&conn, oid);
            let target_metadata: (i64, i64) = conn
                .query_row(
                    "SELECT unit_key, metadata_ordinal
                   FROM source_declaration_metadata_bridges
                  WHERE blob_id = ?1
                  ORDER BY unit_key, metadata_ordinal
                  LIMIT 1",
                    [id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("fixture has a metadata bridge for targeted corruption");
            drop(conn);
            let target = stored_unit_keys(&JavaAdapter, &state)
                .into_iter()
                .find(|(_, key)| *key == target_metadata.0)
                .unwrap()
                .0;
            let requests = [RelationalDefinitionRequest {
                ordinal: 0,
                language_scope: DefinitionLanguageScope::Language(Language::Java),
                name: RelationalName::stable(target.fq().clone()),
                query: RelationalDefinitionQuery::CallableFacts,
            }];
            let generations = CoreHashMap::from_iter([("java".to_owned(), generation)]);
            let read_callable = || {
                store.relational_definition_values(
                    &JavaAdapter,
                    fixture.root(),
                    &generations,
                    &["java".to_owned()],
                    &snapshots,
                    &requests,
                    &CancellationToken::default(),
                    |_| {},
                )
            };
            assert!(
                matches!(read_callable().unwrap(),
            crate::analyzer::store::relational_query::RelationalStoreOutcome::Complete(values)
            if matches!(values.as_slice(), [brokk_bifrost_core::analyzer::RelationalDefinitionValue::CallableFacts(facts)]
                if !facts.is_empty())),
                "canonical callable is initially present and available"
            );
            let sql = match corruption {
                "marker" => format!(
                    "DROP TRIGGER source_declaration_visibility_manifests_no_delete;
                 DELETE FROM source_declaration_visibility_manifests WHERE blob_id = {id};"
                ),
                "source" => format!(
                    "PRAGMA foreign_keys = OFF;
                 DROP TRIGGER source_fact_manifests_no_direct_delete;
                 DELETE FROM source_fact_manifests WHERE blob_id = {id};
                 PRAGMA foreign_keys = ON;"
                ),
                "property" => format!(
                    "DROP TRIGGER source_declaration_visibilities_no_delete_after_seal;
                 DELETE FROM source_declaration_visibilities
                  WHERE blob_id = {id}
                    AND declaration_id = (SELECT declaration_id
                                            FROM source_declaration_metadata_bridges
                                           WHERE blob_id = {id}
                                           ORDER BY unit_key, metadata_ordinal
                                           LIMIT 1);"
                ),
                "version" => format!(
                    "DROP TRIGGER source_declaration_visibility_manifests_require_expected_update;
                 DROP TRIGGER source_declaration_visibility_manifests_no_update;
                 PRAGMA ignore_check_constraints = ON;
                 UPDATE source_declaration_visibility_manifests
                    SET facts_version = 0 WHERE blob_id = {id};
                 PRAGMA ignore_check_constraints = OFF;"
                ),
                _ => unreachable!("listed corruption case"),
            };
            store
                .conn
                .execute(move |conn| {
                    conn.execute_batch(&sql)?;
                    Ok::<(), brokk_bifrost_analysis::analyzer::store::StoreError>(())
                })
                .expect("apply controlled visibility corruption");
            assert!(
                read_callable().is_err(),
                "{corruption} must not become a complete empty callable answer"
            );
            assert!(
                store
                    .signature_metadata_for_unit(oid, "java", generation, &target)
                    .is_err(),
                "{corruption} must fail the known-unit metadata read"
            );
            let conn = store.read_conn().expect("read damaged Java visibility");
            if corruption == "property" {
                let metadata_available: i64 = conn
                    .query_row(
                        "SELECT metadata_available
                       FROM unit_signature_metadata_values
                      WHERE blob_id = ?1 AND unit_key = ?2 AND ordinal = ?3",
                        rusqlite::params![id, target_metadata.0, target_metadata.1],
                        |row| row.get(0),
                    )
                    .expect("targeted metadata row after visibility corruption");
                assert_eq!(
                    metadata_available, 0,
                    "missing visibility is not non-private"
                );
            } else {
                assert_eq!(
                    conn.query_row(
                        "SELECT COUNT(*) FROM live_parsed_blobs WHERE blob_id = ?1",
                        [id],
                        |row| row.get::<_, i64>(0),
                    )
                    .expect("damaged live membership"),
                    0,
                    "{corruption} corruption must not become legacy membership"
                );
                assert!(
                    store
                        .hydrate_file_state_with_source(
                            oid,
                            "java",
                            generation,
                            &JavaAdapter,
                            &file,
                            JAVA_SOURCE,
                        )
                        .expect("damaged visibility hydration")
                        .is_none(),
                    "{corruption} corruption must report unavailable hydration"
                );
            }
        }
    }
    fn java_fixture() -> (
        crate::inline_project::BuiltInlineTestProject,
        brokk_bifrost_core::analyzer::model::ProjectFile,
        FileState,
    ) {
        let fixture = InlineTestProject::with_language(Language::Java)
            .file("src/Container.java", JAVA_SOURCE)
            .build();
        let file = fixture.file("src/Container.java");
        let state = parse_state(&JavaAdapter, &file);
        (fixture, file, state)
    }
    fn assert_persisted_rows_match_state(
        conn: &Connection,
        id: i64,
        state: &FileState,
    ) -> VisibilitySnapshot {
        let facts = state.source_facts.as_ref().expect("Java source facts");
        let visibilities = facts
            .declaration_visibilities
            .as_ref()
            .expect("Java visibility facts");
        let mut expected_visibilities = visibilities
            .iter()
            .map(|fact| {
                (
                    i64::from(fact.declaration.get()),
                    fact.visibility.label().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        expected_visibilities.sort_unstable();

        let mut expected_native = facts
            .native_declaration_sources
            .iter()
            .map(|(site, declaration)| (i64::from(site.get()), i64::from(declaration.get())))
            .collect::<Vec<_>>();
        expected_native.sort_unstable();

        let unit_keys = stored_unit_keys(&JavaAdapter, state);
        let mut expected_metadata = state
            .source_declaration_metadata
            .iter()
            .map(|link| {
                (
                    i64::from(link.declaration.get()),
                    unit_keys[&link.unit],
                    i64::try_from(link.metadata_ordinal).expect("metadata ordinal fits SQLite"),
                )
            })
            .collect::<Vec<_>>();
        expected_metadata.sort_unstable();

        let snapshot = visibility_snapshot(conn, id);
        assert_eq!(
            snapshot.marker,
            (
                brokk_bifrost_core::analyzer::source_facts::SOURCE_DECLARATION_VISIBILITY_VERSION,
                i64::try_from(visibilities.len()).unwrap(),
                i64::try_from(facts.native_declaration_sources.len()).unwrap(),
                i64::try_from(state.source_declaration_metadata.len()).unwrap(),
            )
        );
        assert_eq!(snapshot.visibilities, expected_visibilities);
        assert_eq!(snapshot.native_bridges, expected_native);
        assert_eq!(snapshot.metadata_bridges, expected_metadata);
        assert_eq!(
            snapshot.legacy_rows, 0,
            "new Java must not write legacy visibility"
        );

        let expected_metadata_values = state
            .signature_metadata
            .iter()
            .flat_map(|(unit, entries)| {
                let unit_keys = &unit_keys;
                let unit_key = unit_keys[unit];
                entries.iter().enumerate().map(move |(ordinal, metadata)| {
                    let coordinate = (unit_key, ordinal);
                    let linked_visibilities = state
                        .source_declaration_metadata
                        .iter()
                        .filter(|link| {
                            unit_keys[&link.unit] == coordinate.0
                                && link.metadata_ordinal == coordinate.1
                        })
                        .map(|link| by_declaration_visibility(facts, link.declaration))
                        .collect::<Vec<_>>();
                    let (value, available) = if unit.is_synthetic() {
                        (
                            metadata
                                .callable_declared_visibility()
                                .map(|visibility| visibility.label().to_owned()),
                            1,
                        )
                    } else if linked_visibilities.is_empty() {
                        (None, 0)
                    } else {
                        assert!(
                            linked_visibilities
                                .windows(2)
                                .all(|pair| pair[0] == pair[1]),
                            "one canonical metadata ordinal cannot have conflicting visibility"
                        );
                        (Some(linked_visibilities[0].label().to_owned()), 1)
                    };
                    (
                        coordinate.0,
                        i64::try_from(coordinate.1).unwrap(),
                        value,
                        available,
                    )
                })
            })
            .collect::<Vec<_>>();
        let mut expected_metadata_values = expected_metadata_values;
        expected_metadata_values.sort_unstable_by_key(|row| (row.0, row.1));
        assert_eq!(snapshot.metadata_values, expected_metadata_values);

        let canonical_native_count: i64 = conn
            .query_row(
                "SELECT COUNT(*)
               FROM resolution_semantic_sites AS site
               JOIN source_native_declaration_bridges AS bridge
                 ON bridge.blob_id = site.blob_id
                AND bridge.source_site = site.source_site
               JOIN source_declaration_visibilities AS visibility
                 ON visibility.blob_id = bridge.blob_id
                AND visibility.declaration_id = bridge.declaration_id
              WHERE site.blob_id = ?1 AND site.semantic_role = 'definition'",
                [id],
                |row| row.get(0),
            )
            .expect("count canonical native visibility");
        let expected_native_visibility = conn
            .prepare(
                "SELECT site.semantic_key, visibility.visibility
               FROM resolution_semantic_sites AS site
               JOIN source_native_declaration_bridges AS bridge
                 ON bridge.blob_id = site.blob_id
                AND bridge.source_site = site.source_site
               JOIN source_declaration_visibilities AS visibility
                 ON visibility.blob_id = bridge.blob_id
                AND visibility.declaration_id = bridge.declaration_id
              WHERE site.blob_id = ?1 AND site.semantic_role = 'definition'
              ORDER BY site.semantic_key",
            )
            .expect("prepare expected canonical native visibility")
            .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("read expected canonical native visibility")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect expected canonical native visibility");
        assert_eq!(snapshot.native_visibility, expected_native_visibility);
        assert_eq!(
            snapshot.native_visibility.len() as i64,
            canonical_native_count,
            "the legacy logical name projects canonical native visibility"
        );
        snapshot
    }
    fn assert_reader_coherence(
        store: &AnalyzerStore,
        file: &brokk_bifrost_core::analyzer::model::ProjectFile,
        state: &FileState,
        oid: git2::Oid,
        generation: brokk_bifrost_analysis::analyzer::store::GenerationId,
    ) {
        let expected = &state.signature_metadata;
        let hydrated = store
            .hydrate_file_state_with_source(
                oid,
                "java",
                generation,
                &JavaAdapter,
                file,
                JAVA_SOURCE,
            )
            .expect("full Java hydration")
            .expect("complete Java visibility publication");
        assert_eq!(hydrated.signature_metadata, *expected, "full reader");

        let bulk = store
            .hydrate_file_states(
                &[(file.clone(), oid)],
                "java",
                &JavaAdapter,
                &CoreHashMap::from_iter([(file.clone(), JAVA_SOURCE.to_owned())]),
            )
            .expect("bulk Java hydration");
        assert_eq!(bulk[file].signature_metadata, *expected, "bulk reader");

        let (target, target_metadata) = state
            .signature_metadata
            .iter()
            .find(|(_, metadata)| metadata.len() > 1)
            .map(|(unit, metadata)| (unit.clone(), metadata.clone()))
            .expect("fixture must retain divergent metadata alternatives");
        assert_eq!(
            store
                .signature_metadata_for_unit(oid, "java", generation, &target)
                .expect("unbounded metadata reader"),
            target_metadata,
            "unbounded reader preserves every canonical metadata alternative"
        );
        let bounded = store
            .signature_metadata_for_unit_limited(oid, "java", generation, &target, 1)
            .expect("bounded metadata reader");
        assert!(
            !bounded.complete,
            "one row cannot prove all alternatives exist"
        );
        assert_eq!(bounded.rows, target_metadata[..1].to_vec());

        let unit_keys = stored_unit_keys(&JavaAdapter, state);
        let target_key = unit_keys[&target];
        let usage = store
            .usage_fact_rows_by_lang("java")
            .expect("usage metadata reader")
            .into_iter()
            .find(|row| row.candidate.unit_key == target_key)
            .expect("usage row for divergent Java callable");
        let signature_ordinal = state.signature_metadata_signature_ordinals[&target]
            .iter()
            .position(|&ordinal| ordinal == 0)
            .expect("target has a metadata alternative paired with signature zero");
        assert_eq!(
            usage.signature_metadata,
            Some(target_metadata[signature_ordinal].clone())
        );
    }
}
