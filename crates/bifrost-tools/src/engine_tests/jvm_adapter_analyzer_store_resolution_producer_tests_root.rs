#[cfg(test)]
mod jvm_extraction_tests {
    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_analysis::analyzer::store::CompleteAnalysisBlobRequest;

    use brokk_bifrost_analysis::analyzer::store::GenerationId;

    use brokk_bifrost_analysis::analyzer::store::js_ts_resolution_producer_support::ManifestSnapshot;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::producer_test_support::PRIMARY;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::producer_test_support::PROJECTION;

    use brokk_bifrost_analysis::analyzer::store::PersistBatchStats;

    use brokk_bifrost_analysis::analyzer::store::PersistBatchTargets;

    use brokk_bifrost_analysis::analyzer::store::PreparedParsedBlob;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::producer_test_support::generations;

    use brokk_bifrost_analysis::analyzer::store::js_ts_resolution_producer_support::manifest_snapshot;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::measured_resolution_payload;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::payload_cost;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::persist_one;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::persisted_physical_logical_rows;

    use crate::engine_tests::jvm_producer_helper::fixture::prepare;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::producer_test_support::prepare_with_adapter;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::rewrite_payload_cost;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::with_projection;

    #[cfg(test)]
    use brokk_bifrost_core::cancellation::CancellationToken;
    #[cfg(test)]
    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;

    #[cfg(test)]
    use git2::Oid;
    #[cfg(test)]
    use rusqlite::params;
    #[cfg(test)]
    use std::sync::Arc;
    #[cfg(test)]
    use tree_sitter::Parser;

    #[cfg(test)]
    use crate::engine_tests::jvm_legacy_adapter::jvm_adapter_helper::LegacyJavaFixtureAdapter;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::resolution::rich_java_resolution_facts_for_test;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::resolution::RESOLUTION_MANIFEST_COUNT_COLUMNS;

    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::resolution_prepare::ResolutionInteriorPreparation;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::resolution_prepare::prepare_resolution_bundle_with_unit_keys;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState;
    #[cfg(test)]
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

    #[cfg(test)]
    use brokk_bifrost_core::analyzer::model::Language;
    #[cfg(test)]
    use brokk_bifrost_core::analyzer::model::ProjectFile;
    #[cfg(test)]
    use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
    #[cfg(test)]
    use brokk_bifrost_core::hash::HashMap;

    #[cfg(test)]
    #[test]
    fn primary_and_projection_publish_the_declared_family_bundle_atomically() {
        let temp = tempfile::tempdir().expect("test directory");
        let base = java_state(temp.path(), true);
        let projected = with_projection(&base);
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let generations = generations(&store);
        let published_oid = oid(b"rich primary and projection");
        let prepared = prepare_legacy_java(published_oid, projected, &generations, &[]);

        let lowered =
            brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                BindingFragmentId::unmounted(),
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                Language::Java,
                &base.resolution_facts,
            );
        let ResolutionInteriorPreparation::Prepared(expected) =
            prepare_resolution_bundle_with_unit_keys(&lowered, None, &CancellationToken::default())
        else {
            panic!("uncancelled resolution preparation must finish")
        };
        assert_eq!(
            prepared.resolution.family_counts().len(),
            RESOLUTION_MANIFEST_COUNT_COLUMNS.len()
        );
        for family in [
            "expected_semantic_site_count",
            "expected_path_endpoint_header_count",
            "expected_declaration_visibility_property_count",
            "expected_member_scope_property_count",
            "expected_member_owner_property_count",
        ] {
            let index = RESOLUTION_MANIFEST_COUNT_COLUMNS
                .iter()
                .position(|column| *column == family)
                .expect("rich manifest family");
            assert!(
                prepared.resolution.family_counts()[index] > 0,
                "rich producer must exercise {family} insertion"
            );
        }
        assert_eq!(prepared.fragment_count(), 2);
        assert_eq!(prepared.resolution, *expected);
        assert_eq!(prepared.additional[0].resolution, *expected);
        let mut primary_manifest = ManifestSnapshot::expected(&prepared.resolution);
        let mut projection_manifest =
            ManifestSnapshot::expected(&prepared.additional[0].resolution);
        let primary_estimate = prepared.resolution.payload_bytes() + PRIMARY.len();
        let projection_estimate =
            prepared.additional[0].resolution.payload_bytes() + PROJECTION.len();
        let expected_rows = prepared.mutation_logical_rows();
        let expected_bytes = prepared.mutation_payload_bytes();

        let stats = persist_one(&store, prepared);

        assert_eq!(stats.transactions, 1);
        assert_eq!(stats.committed_blobs, 1);
        assert_eq!(stats.committed_fragments, 2);
        assert_eq!(stats.logical_rows, expected_rows);
        assert_eq!(stats.payload_bytes, expected_bytes);
        primary_manifest.payload_bytes =
            measured_resolution_payload(&store, published_oid, PRIMARY);
        projection_manifest.payload_bytes =
            measured_resolution_payload(&store, published_oid, PROJECTION);
        assert!(primary_estimate >= primary_manifest.payload_bytes);
        assert!(
            projection_estimate >= projection_manifest.payload_bytes,
            "prewrite budget includes the distinct storage alias length"
        );
        assert_eq!(
            manifest_snapshot(&store, published_oid, PRIMARY),
            primary_manifest
        );
        assert_eq!(
            manifest_snapshot(&store, published_oid, PROJECTION),
            projection_manifest
        );

        let primary_blob_id = store.conn.execute({
            let oid = published_oid.to_string();
            move |conn| {
                conn.query_row(
                    "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2",
                    params![oid, PRIMARY],
                    |row| row.get::<_, i64>(0),
                )
                .expect("published primary blob id")
            }
        });
        // Nodes, reference sites and path bodies are interior detail. What the
        // publication owns for a reference is its semantic site, and the tier-1
        // root-route family is what a crate derivation reads back, so both are
        // sought by their primary key with no scan and no sorter.
        let plans = store.conn.execute(move |conn| {
            [
                (
                    "resolution_semantic_sites",
                    "SELECT source_site FROM resolution_semantic_sites
                 WHERE blob_id = ?1 AND source_site > -1
                 ORDER BY source_site LIMIT 256",
                ),
                (
                    "resolution_root_route_segments",
                    "SELECT path_key FROM resolution_root_route_segments
                 WHERE blob_id = ?1 AND path_key > -1
                 ORDER BY path_key LIMIT 256",
                ),
            ]
            .map(|(table, sql)| {
                let details = conn
                    .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                    .expect("prepare resolution endpoint query plan")
                    .query_map([primary_blob_id], |row| row.get::<_, String>(3))
                    .expect("query resolution endpoint plan")
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .expect("read resolution endpoint plan");
                (table, details)
            })
        });
        for (table, details) in plans {
            assert!(
                details
                    .iter()
                    .any(|detail| detail.contains(&format!("SEARCH {table} USING PRIMARY KEY"))),
                "expected a primary-key seek of {table}: {details:?}"
            );
            assert!(
                details
                    .iter()
                    .all(|detail| !detail.contains(&format!("SCAN {table}"))
                        && !detail.contains("USE TEMP B-TREE")),
                "endpoint lookup must seek without a sorter: {details:?}"
            );
        }

        store.conn.execute(move |conn| {
            conn.execute("DELETE FROM blobs WHERE id = ?1", [primary_blob_id])
                .expect("delete published primary blob");
            for table in [
                "resolution_fragment_interiors",
                "resolution_semantic_sites",
                "resolution_root_route_segments",
                "resolution_path_endpoint_headers",
                "resolution_member_owner_properties",
            ] {
                let count = conn
                    .query_row(
                        &format!("SELECT COUNT(*) FROM {table} WHERE blob_id = ?1"),
                        [primary_blob_id],
                        |row| row.get::<_, usize>(0),
                    )
                    .expect("query cascaded resolution family");
                assert_eq!(count, 0, "{table} must cascade from its blob");
            }
        });
    }
    #[cfg(test)]
    #[test]
    fn complete_analysis_repairs_legacy_and_optional_rows_once_with_directional_ownership() {
        let temp = tempfile::tempdir().expect("test directory");
        let state = java_state(temp.path(), false);
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let generations = generations(&store);

        for count in [300, 301] {
            let expected = (0..count)
                .map(|index| oid(format!("carrier-{count}-{index}")))
                .collect::<Vec<_>>();
            let mut requests = expected
                .iter()
                .copied()
                .map(|oid| CompleteAnalysisBlobRequest::new(oid, PRIMARY, [PROJECTION.to_owned()]))
                .collect::<Vec<_>>();
            requests.push(requests[17].clone());
            let missing = store
                .missing_published_complete_analysis_blob_keys_at_generations(
                    &requests,
                    &generations,
                    Language::Java,
                    None,
                )
                .expect("chunked complete-analysis carrier");
            assert_eq!(
                missing
                    .iter()
                    .map(|missing| missing.oid())
                    .collect::<Vec<_>>(),
                expected,
                "the 300-row TEMP carrier boundary must preserve first-seen order and deduplicate"
            );
        }

        let legacy_oid = oid(b"legacy parsed only");
        store
            .register_blobs(&[legacy_oid], PRIMARY, generations[PRIMARY])
            .expect("register legacy parsed blob");
        let legacy_oid_text = legacy_oid.to_string();
        store.conn.execute(move |conn| {
            let blob_id = conn
                .query_row(
                    "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'",
                    [&legacy_oid_text],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap();
            conn.execute(
                "INSERT INTO blob_meta(
               blob_id, lang, contains_tests, content_package,
               stored_unit_count, range_count, signature_count,
               signature_metadata_count, supertype_count, child_count,
               import_statement_count, type_identifier_count, is_complete
             ) VALUES(?1, 'java', 0, '', 0, 0, 0, 0, 0, 0, 0, 0, 1)",
                [blob_id],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO blob_payload_costs(blob_id, payload_bytes) VALUES(?1, 0)",
                [blob_id],
            )
            .unwrap();
        });
        let legacy_request = [CompleteAnalysisBlobRequest::new(
            legacy_oid,
            PRIMARY,
            Vec::new(),
        )];
        let missing = store
            .missing_published_complete_analysis_blob_keys_at_generations(
                &legacy_request,
                &generations,
                Language::Java,
                None,
            )
            .expect("legacy complete-analysis predicate");
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].oid(), legacy_oid);
        assert!(
            missing[0]
                .required_existing_additional_storage_languages()
                .is_empty()
        );
        persist_one(
            &store,
            prepare(legacy_oid, Arc::clone(&state), &generations, &[]),
        );
        assert!(
            store
                .missing_published_complete_analysis_blob_keys_at_generations(
                    &legacy_request,
                    &generations,
                    Language::Java,
                    None,
                )
                .unwrap()
                .is_empty()
        );

        let absent_optional_oid = oid(b"never materialized optional projection");
        persist_one(
            &store,
            prepare(absent_optional_oid, Arc::clone(&state), &generations, &[]),
        );
        let absent_optional_request = [CompleteAnalysisBlobRequest::new(
            absent_optional_oid,
            PRIMARY,
            [PROJECTION.to_owned()],
        )];
        assert!(
            store
                .missing_published_complete_analysis_blob_keys_at_generations(
                    &absent_optional_request,
                    &generations,
                    Language::Java,
                    None,
                )
                .unwrap()
                .is_empty(),
            "an optional projection that never existed is identical to its primary"
        );

        let optional_oid = oid(b"stale optional projection");
        persist_one(
            &store,
            prepare(optional_oid, with_projection(&state), &generations, &[]),
        );
        let optional_oid_text = optional_oid.to_string();
        store.conn.execute(move |conn| {
            conn.execute(
                "UPDATE resolution_fragment_interiors
             SET producer_epoch = 'legacy-resolution-bundle'
             WHERE blob_id = (
               SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java:projection'
             )",
                [&optional_oid_text],
            )
            .unwrap();
        });
        let owner_request =
            CompleteAnalysisBlobRequest::new(optional_oid, PRIMARY, [PROJECTION.to_owned()]);
        let missing = store
            .missing_published_complete_analysis_blob_keys_at_generations(
                std::slice::from_ref(&owner_request),
                &generations,
                Language::Java,
                None,
            )
            .unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].storage_language(), PRIMARY);
        assert_eq!(
            missing[0].required_existing_additional_storage_languages(),
            &[PROJECTION.to_owned()]
        );
        let repaired = prepare(
            optional_oid,
            Arc::clone(&state),
            &generations,
            missing[0].required_existing_additional_storage_languages(),
        );
        assert_eq!(repaired.fragment_count(), 2);
        assert_eq!(repaired.additional[0].lang(), PROJECTION);
        assert!(repaired.additional[0].state().source.is_empty());
        persist_one(&store, repaired);
        assert!(
            store
                .missing_published_complete_analysis_blob_keys_at_generations(
                    std::slice::from_ref(&owner_request),
                    &generations,
                    Language::Java,
                    None,
                )
                .unwrap()
                .is_empty(),
            "one catch-up publication must make the next build warm"
        );

        let optional_oid_text = optional_oid.to_string();
        store.conn.execute(move |conn| {
            conn.execute(
                "UPDATE resolution_fragment_interiors
             SET producer_epoch = 'legacy-resolution-bundle-again'
             WHERE blob_id = (
               SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java:projection'
             )",
                [&optional_oid_text],
            )
            .unwrap();
        });
        let independent_request =
            CompleteAnalysisBlobRequest::new(optional_oid, PROJECTION, Vec::new());
        for requests in [
            vec![owner_request.clone(), independent_request.clone()],
            vec![independent_request.clone(), owner_request.clone()],
        ] {
            let missing = store
                .missing_published_complete_analysis_blob_keys_at_generations(
                    &requests,
                    &generations,
                    Language::Java,
                    None,
                )
                .unwrap();
            assert_eq!(missing.len(), 1);
            assert_eq!(missing[0].storage_language(), PROJECTION);
            assert!(
                missing[0]
                    .required_existing_additional_storage_languages()
                    .is_empty()
            );
        }
    }
    #[cfg(test)]
    #[test]
    fn production_writer_stale_generation_and_epoch_are_typed_terminal_failures() {
        let temp = tempfile::tempdir().expect("test directory");
        let state = java_state(temp.path(), false);
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let generations = generations(&store);
        let published_oid = oid(b"production stale writer");

        let stale_epoch = prepare(published_oid, Arc::clone(&state), &generations, &[]);
        store.conn.execute(|conn| {
            conn.execute(
                "UPDATE resolution_producer_epochs
             SET producer_epoch = 'future'
             WHERE lang = 'java'",
                [],
            )
            .expect("make producer epoch stale");
        });
        let (outcomes, stats) = store.persist_prepared_blobs_with_cancellation(
            vec![stale_epoch],
            &CancellationToken::default(),
            PersistBatchTargets::PRODUCTION,
        );
        assert!(
            outcomes[0]
                .error
                .as_ref()
                .is_some_and(|error| error.is_stale_resolution())
        );
        assert_eq!(stats.failed_transaction_attempts, 1);
        assert!(!store.contains_parsed_blob(published_oid, PRIMARY).unwrap());

        store
            .ensure_resolution_producer_epoch(PRIMARY, Language::Java)
            .expect("restore current producer epoch");
        let newer_generation = store
            .ensure_language_epoch_value(PRIMARY, "resolution-stale-writer-v2")
            .expect("advance current generation");
        assert_ne!(generations[PRIMARY], newer_generation);
        let stale_generation = prepare(published_oid, state, &generations, &[]);
        let (outcomes, stats) = store.persist_prepared_blobs_with_cancellation(
            vec![stale_generation],
            &CancellationToken::default(),
            PersistBatchTargets::PRODUCTION,
        );
        assert!(
            outcomes[0]
                .error
                .as_ref()
                .is_some_and(|error| error.is_stale_generation())
        );
        assert_eq!(stats.failed_transaction_attempts, 1);
        assert!(!store.contains_parsed_blob(published_oid, PRIMARY).unwrap());
    }
    #[cfg(test)]
    #[test]
    fn production_writer_duplicate_inputs_preserve_submission_order_and_reject_conflicts() {
        let temp = tempfile::tempdir().expect("test directory");
        let state = java_state(temp.path(), false);
        let rich_state = java_state(temp.path(), true);
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let generations = generations(&store);
        let duplicate_oid = oid(b"duplicate production input");
        let good_oid = oid(b"good production input");
        let (outcomes, stats) = store.persist_prepared_blobs(
            vec![
                prepare(duplicate_oid, Arc::clone(&state), &generations, &[]),
                prepare(good_oid, Arc::clone(&state), &generations, &[]),
                prepare_legacy_java(duplicate_oid, rich_state, &generations, &[]),
            ],
            PersistBatchTargets::PRODUCTION,
        );
        assert_eq!(
            outcomes
                .iter()
                .map(|outcome| outcome.prepared.oid())
                .collect::<Vec<_>>(),
            vec![duplicate_oid, good_oid, duplicate_oid]
        );
        assert!(outcomes[0].error.is_some());
        assert!(outcomes[2].error.is_some());
        assert!(
            outcomes[1].error.is_none(),
            "good input must survive bisection"
        );
        assert_eq!((stats.committed_blobs, stats.failed_blobs), (1, 2));
        assert!(!store.contains_parsed_blob(duplicate_oid, PRIMARY).unwrap());
        assert!(store.contains_parsed_blob(good_oid, PRIMARY).unwrap());
    }
    #[cfg(test)]
    #[test]
    fn production_writer_repairs_corrupt_payload_costs_on_retry() {
        let temp = tempfile::tempdir().expect("test directory");
        let state = java_state(temp.path(), false);
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let generation = store
            .ensure_language_epoch_value(PRIMARY, "resolution-payload-repair-v1")
            .expect("payload repair generation");
        let published_oid = oid(b"production payload repair");
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                published_oid,
                PRIMARY,
                generation,
                &JavaAdapter,
                &state,
            )
            .expect("initial production persistence");
        let expected_cost = payload_cost(&store, published_oid, PRIMARY);
        let expected_manifest = manifest_snapshot(&store, published_oid, PRIMARY);
        for corrupt in [Some(999_999usize), None] {
            rewrite_payload_cost(&store, published_oid, PRIMARY, corrupt);
            store
                .write_parsed_blob_at_generation(
                    &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                    published_oid,
                    PRIMARY,
                    generation,
                    &JavaAdapter,
                    &state,
                )
                .expect("retry production persistence");
            assert_eq!(payload_cost(&store, published_oid, PRIMARY), expected_cost);
            assert_eq!(
                manifest_snapshot(&store, published_oid, PRIMARY),
                expected_manifest
            );
        }
    }
    #[cfg(test)]
    #[test]
    fn production_writer_failed_and_cancelled_same_key_replacements_preserve_previous_bundle() {
        let temp = tempfile::tempdir().expect("test directory");
        let state = java_state(temp.path(), false);
        let rich_state = java_state(temp.path(), true);
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let generations = generations(&store);
        let published_oid = oid(b"production replacement rollback");
        persist_one(
            &store,
            prepare(published_oid, Arc::clone(&state), &generations, &[]),
        );
        let first_manifest = manifest_snapshot(&store, published_oid, PRIMARY);
        let first_payload_cost = payload_cost(&store, published_oid, PRIMARY);
        let targets = PersistBatchTargets {
            max_blobs: 1,
            max_rows: 1,
            max_payload_bytes: 1,
        };

        let mut failed_replacement =
            prepare_legacy_java(published_oid, Arc::clone(&rich_state), &generations, &[]);
        failed_replacement.inject_invalid_range_for_test();
        let (outcomes, stats) = store.persist_prepared_blobs(vec![failed_replacement], targets);
        assert!(outcomes[0].error.is_some());
        assert_eq!(stats.failed_blobs, 1);
        assert_eq!(
            manifest_snapshot(&store, published_oid, PRIMARY),
            first_manifest
        );
        assert_eq!(
            payload_cost(&store, published_oid, PRIMARY),
            first_payload_cost
        );

        let cancellation = CancellationToken::cancel_after_checks_for_test(4);
        let cancelled_replacement =
            prepare_legacy_java(published_oid, rich_state, &generations, &[]);
        let (outcomes, stats) = store.persist_prepared_blobs_with_cancellation(
            vec![cancelled_replacement],
            &cancellation,
            targets,
        );
        assert!(outcomes[0].error.is_some());
        assert!(cancellation.is_cancelled());
        assert_eq!(stats.failed_blobs, 1);
        assert_eq!(
            manifest_snapshot(&store, published_oid, PRIMARY),
            first_manifest
        );
        assert_eq!(
            payload_cost(&store, published_oid, PRIMARY),
            first_payload_cost
        );
    }
    #[cfg(test)]
    #[test]
    fn combined_writer_targets_groups_and_rolls_back_cancelled_or_failed_envelopes() {
        let temp = tempfile::tempdir().expect("test directory");
        let state = java_state(temp.path(), false);
        let projected = with_projection(&state);
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let generations = generations(&store);
        let two_fragment_limits = PersistBatchTargets {
            max_blobs: 2,
            max_rows: usize::MAX,
            max_payload_bytes: usize::MAX,
        };

        let (outcomes, stats) = store.persist_prepared_blobs(Vec::new(), two_fragment_limits);
        assert!(outcomes.is_empty());
        assert_eq!(stats, PersistBatchStats::default());

        let one_oid = oid(b"one fragment");
        let stats = persist_one(
            &store,
            prepare(one_oid, Arc::clone(&state), &generations, &[]),
        );
        assert_eq!((stats.transactions, stats.committed_fragments), (1, 1));

        let max_oid = oid(b"two fragment exact maximum");
        let (outcomes, stats) = store.persist_prepared_blobs(
            vec![prepare(max_oid, Arc::clone(&projected), &generations, &[])],
            two_fragment_limits,
        );
        assert!(outcomes[0].error.is_none());
        assert_eq!((stats.transactions, stats.committed_fragments), (1, 2));

        let (outcomes, stats) = store.persist_prepared_blobs(
            vec![
                prepare(
                    oid(b"three fragments projected"),
                    Arc::clone(&projected),
                    &generations,
                    &[],
                ),
                prepare(
                    oid(b"three fragments primary"),
                    Arc::clone(&state),
                    &generations,
                    &[],
                ),
            ],
            two_fragment_limits,
        );
        assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));
        assert_eq!((stats.transactions, stats.committed_fragments), (2, 3));
        assert_eq!(stats.peak_batch_fragments, 2);

        let exact_oid = oid(b"exact row and byte caps");
        let exact = prepare(exact_oid, Arc::clone(&projected), &generations, &[]);
        let exact_expected_fragment_rows =
            vec![exact.logical_rows(), exact.additional[0].logical_rows()];
        let exact_expected_rows = exact.mutation_logical_rows();
        let exact_limits = PersistBatchTargets {
            max_blobs: exact.fragment_count(),
            max_rows: exact_expected_rows,
            max_payload_bytes: exact.mutation_payload_bytes(),
        };
        let (outcomes, stats) = store.persist_prepared_blobs(vec![exact], exact_limits);
        assert!(outcomes[0].error.is_none());
        assert_eq!(stats.transactions, 1);
        let physical_fragment_rows = persisted_physical_logical_rows(
            &store,
            &[(exact_oid, PRIMARY), (exact_oid, PROJECTION)],
        );
        assert_eq!(physical_fragment_rows, exact_expected_fragment_rows);
        let physical_rows = physical_fragment_rows
            .into_iter()
            .fold(0usize, usize::saturating_add);
        assert_eq!(physical_rows, exact_expected_rows);
        assert_eq!(stats.logical_rows, physical_rows);
        assert_eq!(stats.payload_bytes, exact_limits.max_payload_bytes);

        for (label, limits) in [
            (
                b"one fragment over".as_slice(),
                PersistBatchTargets {
                    max_blobs: 1,
                    ..exact_limits
                },
            ),
            (
                b"one row over".as_slice(),
                PersistBatchTargets {
                    max_rows: exact_limits.max_rows - 1,
                    ..exact_limits
                },
            ),
            (
                b"one byte over".as_slice(),
                PersistBatchTargets {
                    max_payload_bytes: exact_limits.max_payload_bytes - 1,
                    ..exact_limits
                },
            ),
        ] {
            let oversized_oid = oid(label);
            let peer_oid = oid([label, b"peer"].concat());
            let (outcomes, stats) = store.persist_prepared_blobs(
                vec![
                    prepare(oversized_oid, Arc::clone(&projected), &generations, &[]),
                    prepare(peer_oid, Arc::clone(&state), &generations, &[]),
                ],
                limits,
            );
            assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));
            assert_eq!(
                stats.transactions, 2,
                "oversized OID must not absorb its peer"
            );
            assert_eq!((stats.committed_fragments, stats.failed_fragments), (3, 0));
            assert_eq!(stats.peak_batch_fragments, 2);
            assert_eq!(stats.peak_batch_rows, exact_expected_rows);
            assert_eq!(
                stats.peak_batch_payload_bytes,
                exact_limits.max_payload_bytes
            );
            assert!(store.contains_parsed_blob(oversized_oid, PRIMARY).unwrap());
            assert!(
                store
                    .contains_parsed_blob(oversized_oid, PROJECTION)
                    .unwrap()
            );
            assert_eq!(
                persisted_physical_logical_rows(
                    &store,
                    &[(oversized_oid, PRIMARY), (oversized_oid, PROJECTION)]
                ),
                exact_expected_fragment_rows,
            );
        }

        let cancelled_oid = oid(b"cancelled combined envelope");
        let starts = store.parsed_blob_transaction_starts_for_test();
        let cancellation = CancellationToken::cancel_after_checks_for_test(4);
        let (mut outcomes, stats) = store.persist_prepared_blobs_with_cancellation(
            vec![prepare(
                cancelled_oid,
                Arc::clone(&projected),
                &generations,
                &[],
            )],
            &cancellation,
            PersistBatchTargets {
                max_blobs: 1,
                max_rows: 1,
                max_payload_bytes: 1,
            },
        );
        assert!(outcomes[0].error.is_some());
        assert!(cancellation.is_cancelled());
        assert_eq!(stats.failed_fragments, 2);
        assert_eq!(store.parsed_blob_transaction_starts_for_test(), starts + 1);
        assert!(!store.contains_parsed_blob(cancelled_oid, PRIMARY).unwrap());
        assert!(
            !store
                .contains_parsed_blob(cancelled_oid, PROJECTION)
                .unwrap()
        );
        let cancelled = outcomes.pop().expect("cancelled outcome").prepared;
        let retry = persist_one(&store, cancelled);
        assert_eq!(retry.committed_fragments, 2);

        let good_a_oid = oid(b"bisection good a");
        let bad_oid = oid(b"bisection bad combined envelope");
        let good_b_oid = oid(b"bisection good b");
        let mut bad = prepare(bad_oid, Arc::clone(&projected), &generations, &[]);
        bad.additional[0].inject_invalid_range_for_test();
        let (outcomes, stats) = store.persist_prepared_blobs(
            vec![
                prepare(good_a_oid, Arc::clone(&state), &generations, &[]),
                bad,
                prepare(good_b_oid, Arc::clone(&state), &generations, &[]),
            ],
            PersistBatchTargets::PRODUCTION,
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.error.is_some())
                .count(),
            1
        );
        assert_eq!((stats.committed_blobs, stats.failed_blobs), (2, 1));
        assert_eq!((stats.committed_fragments, stats.failed_fragments), (2, 2));
        assert!(store.contains_parsed_blob(good_a_oid, PRIMARY).unwrap());
        assert!(store.contains_parsed_blob(good_b_oid, PRIMARY).unwrap());
        assert!(!store.contains_parsed_blob(bad_oid, PRIMARY).unwrap());
        assert!(!store.contains_parsed_blob(bad_oid, PROJECTION).unwrap());
        let retry = persist_one(&store, prepare(bad_oid, projected, &generations, &[]));
        assert_eq!(retry.committed_fragments, 2);
    }
    #[cfg(test)]
    fn java_state(root: &std::path::Path, rich_resolution: bool) -> Arc<FileState> {
        let file = ProjectFile::new(root.to_path_buf(), "src/Model.java");
        file.write("package demo; class Model { int value; }\n")
            .expect("write Java source");
        let source = file.read_to_string().expect("read Java source");
        let adapter = JavaAdapter;
        let mut parser = Parser::new();
        parser
            .set_language(&adapter.parser_language_for_file(&file))
            .expect("set Java grammar");
        let tree = parser.parse(&source, None).expect("parse Java source");
        let mut parsed: ParsedFile = adapter.parse_file(&file, &source, &tree);
        parsed.add_file_scope(&file, &source);
        let contains_tests = adapter.contains_tests(&file, &source, &tree, &parsed);
        let declarations = parsed.declarations().clone();
        let mut state = FileState {
            source,
            package_name: parsed.package_name,
            content_qualifier: parsed.content_qualifier,
            top_level_declarations: parsed.top_level_declarations,
            declarations,
            definition_lookup_units: parsed.definition_lookup_units,
            imports: parsed.imports,
            scala_exports: parsed.scala_exports,
            rust_usage_facts: parsed.rust_usage_facts,
            source_facts: parsed.source_facts,
            source_declaration_units: parsed.source_declaration_units,
            source_declaration_metadata: parsed.source_declaration_metadata,
            resolution_facts: parsed.resolution_facts,
            raw_supertypes: parsed.raw_supertypes,
            supertype_lookup_paths: parsed.supertype_lookup_paths,
            type_identifiers: parsed.type_identifiers,
            signatures: parsed.signatures,
            signature_metadata: parsed.signature_metadata,
            signature_metadata_signature_ordinals: parsed.signature_metadata_signature_ordinals,
            cpp_template_metadata: parsed.cpp_template_metadata,
            ruby_method_dispatch_modes: parsed.ruby_method_dispatch_modes,
            ranges: parsed.ranges,
            children: parsed.children,
            scala_traits: parsed.scala_traits,
            type_aliases: parsed.type_aliases,
            contains_tests,
            test_region_units: parsed.test_region_units,
            materialization_records: parsed.materialization_records,
            parse_errors: Some(Vec::new()),
            completeness: parsed.completeness,
            parse_complete: true,
            additional_projections: Vec::new(),
        };
        if rich_resolution {
            state.resolution_facts = rich_java_resolution_facts_for_test();
            // This is a synthetic bundle-law fixture, not source extraction. Its
            // native site IDs cannot refer to the unrelated parsed Java arena.
            state.source_facts = None;
            state.source_declaration_units.clear();
        }
        Arc::new(state)
    }
    #[cfg(test)]
    fn prepare_legacy_java(
        oid: Oid,
        state: Arc<FileState>,
        generations: &HashMap<String, GenerationId>,
        required_projections: &[String],
    ) -> PreparedParsedBlob {
        prepare_with_adapter(
            oid,
            state,
            generations,
            required_projections,
            &LegacyJavaFixtureAdapter,
        )
    }
    use brokk_bifrost_analysis::analyzer::store::js_ts_resolution_producer_support::parsed_fixture_state;

    #[cfg(test)]
    #[test]
    fn neutral_lookup_requests_round_trip_source_references_without_changing_bindings() {
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let source = "class Model { int value; int read() { return value; } }";
        let content = oid(source);
        let generation = store
            .ensure_language_epoch_value("java", "lookup-request-test")
            .unwrap();
        let mut state = parsed_fixture_state(&JavaAdapter, "Model.java", source);
        let state_mut = Arc::get_mut(&mut state).unwrap();
        let reads = state_mut
            .resolution_facts
            .identifiers
            .iter()
            .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
            .map(|identifier| identifier.site)
            .collect::<Vec<_>>();
        assert!(!reads.is_empty());
        let before = state_mut.resolution_facts.clone();
        state_mut
            .resolution_facts
            .reference_lookup_requests
            .extend(reads.iter().copied());
        // Explicit requests may overlap an existing owner/prefix row or each other.
        state_mut
            .resolution_facts
            .reference_lookup_requests
            .extend(reads.iter().copied());
        let fragment = brokk_bifrost_analysis::analyzer::resolution::BindingFragmentId::for_test(
            b"lookup-requests",
        );
        let before_lowered =
            brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                fragment,
                Language::Java,
                &before,
            );
        let after_lowered =
            brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                fragment,
                Language::Java,
                &state_mut.resolution_facts,
            );
        assert_eq!(before_lowered.lexical(), after_lowered.lexical());
        assert_eq!(before_lowered.typed(), after_lowered.typed());
        let expected = reads
            .iter()
            .map(|site| {
                let identifier = before
                    .identifiers
                    .iter()
                    .find(|identifier| identifier.site == *site)
                    .unwrap();
                (
                    before.name(identifier.name).to_owned(),
                    i64::from(site.get()),
                )
            })
            .collect::<std::collections::BTreeSet<_>>();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                content,
                "java",
                generation,
                &JavaAdapter,
                &state,
            )
            .unwrap();
        let content = content.to_string();
        let actual = store.conn.execute(move |conn| {
            // Source-site authority does not require optional presentation metadata.
            let mut stmt = conn.prepare("SELECT identity.spelling,reference.source_site
            FROM blobs blob
            JOIN resolution_reference_lookup_identities names ON names.blob_id=blob.id
            JOIN resolution_identities identity ON identity.id=names.identity_id
            JOIN resolution_semantic_sites reference ON reference.blob_id=names.blob_id AND reference.semantic_role='reference' AND reference.semantic_key=names.semantic_key
            JOIN resolution_sites sites ON sites.blob_id=reference.blob_id AND sites.site=reference.source_site AND sites.role=0
            WHERE blob.blob_oid=?1 AND blob.lang='java'")?;
            stmt.query_map([content], |row| Ok((row.get::<_,String>(0)?,row.get::<_,i64>(1)?)))?
                .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()
        }).unwrap();
        assert_eq!(actual, expected);
    }
}
