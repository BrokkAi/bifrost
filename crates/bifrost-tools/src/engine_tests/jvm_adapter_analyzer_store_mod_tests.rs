#[cfg(test)]
mod jvm_extraction_tests {
    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    use brokk_bifrost_analysis::analyzer::store::ActiveSearchBlob;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::store::CANDIDATE_ROWS_PER_CANCELLATION_POLL;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::CodeUnitType;

    use std::time::Duration;

    use brokk_bifrost_analysis::analyzer::store::GenerationId;

    use brokk_bifrost_core::hash::HashMap;

    use brokk_bifrost_core::hash::HashSet;

    use brokk_bifrost_analysis::analyzer::store::HydratedMountedCandidatePrimaryRangeRow;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::store::MAX_LIMITED_QUERY_ROW_BYTES;

    use git2::Oid;

    use brokk_bifrost_analysis::analyzer::store::PathSymbolRow;

    use brokk_bifrost_analysis::analyzer::store::PersistBatchTargets;

    use brokk_bifrost_analysis::analyzer::store::PersistedMutationCost;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::store::StoreError;

    use brokk_bifrost_analysis::analyzer::store::StoredCascadeCost;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceFileRow;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceId;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshots;

    use brokk_bifrost_analysis::analyzer::store::test_support::assert_file_state_equivalent;

    use brokk_bifrost_jvm_analysis::epoch_test_support as epoch;

    use brokk_bifrost_analysis::analyzer::store::tests::measured_persisted_payload_bytes;

    use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

    use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

    use brokk_bifrost_analysis::analyzer::store::persisted_blob_mutation_cost_fallback_sql;

    use brokk_bifrost_analysis::analyzer::store::persisted_blob_mutation_cost_fallback_statement;

    use brokk_bifrost_analysis::analyzer::store::read_blob_meta;

    use brokk_bifrost_analysis::analyzer::store::read_unit_rows;

    use brokk_bifrost_analysis::analyzer::store::require_current_generation;

    use brokk_bifrost_analysis::analyzer::store::usage_fact_rows_by_lang_sql;

    use brokk_bifrost_analysis::analyzer::store::usize_to_i64;

    use brokk_bifrost_analysis::analyzer::store::test_support::assert_prior_parsed_blob_invalidated;

    use brokk_bifrost_core::test_support::write_file;

    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;

    use brokk_bifrost_jvm_analysis::analyzer::kotlin::adapter::KotlinAdapter;

    use brokk_bifrost_jvm_analysis::analyzer::scala::adapter::ScalaAdapter;

    use git2::ObjectType;
    #[test]
    fn signature_metadata_pairs_round_trip_for_java_synthetic_units() {
        let source = "interface Dual { void run() {} }\nclass Dual { void run() {} Object make() { return new Object() { void inside() {} }; } }\n";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("Dual.java", source)
            .build();
        let file = fixture.file("Dual.java");
        let state = parse_state(&JavaAdapter, &file);
        let synthetic = state
            .signature_metadata_signature_ordinals
            .keys()
            .find(|unit| unit.is_synthetic())
            .cloned()
            .expect("Java fixture should produce a synthetic metadata unit");
        let expected_pairs = state
            .signature_metadata_signature_ordinals
            .get(&synthetic)
            .cloned()
            .expect("synthetic metadata should have captured pairs");
        assert!(!expected_pairs.is_empty());
        let expected_pair_count = state
            .signature_metadata_signature_ordinals
            .values()
            .map(Vec::len)
            .sum::<usize>();
        let oid = oid_for(source.as_bytes());
        let store_path = fixture.root().join("signature-metadata-pairs.db");
        let store = AnalyzerStore::open_persistent(&store_path).unwrap();
        let generation = store
            .ensure_language_epoch_value("java", "signature-metadata-pairs")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "java",
                generation,
                &JavaAdapter,
                &state,
            )
            .unwrap();
        drop(store);

        let store = AnalyzerStore::open_persistent(&store_path).unwrap();
        let hydrated = store
            .hydrate_file_state_with_source(oid, "java", generation, &JavaAdapter, &file, source)
            .unwrap()
            .expect("single-file hydration");
        assert_eq!(
            hydrated
                .signature_metadata_signature_ordinals
                .get(&synthetic),
            Some(&expected_pairs)
        );
        let bulk = store
            .hydrate_file_states(
                &[(file.clone(), oid)],
                "java",
                &JavaAdapter,
                &HashMap::from_iter([(file.clone(), source.to_string())]),
            )
            .unwrap();
        assert_eq!(
            bulk[&file]
                .signature_metadata_signature_ordinals
                .get(&synthetic),
            Some(&expected_pairs)
        );
        let conn = store.read_conn().unwrap();
        let pair_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM unit_signature_metadata_signatures
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java')",
                [oid.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pair_count, i64::try_from(expected_pair_count).unwrap());
        drop(conn);

        let prepared = AnalyzerStore::prepare_parsed_blob(
            oid,
            "java",
            generation,
            &JavaAdapter,
            Arc::new(state.clone()),
        )
        .unwrap();
        store.conn.execute(move |conn| {
            conn.execute(
                "DELETE FROM blob_payload_costs
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java')",
                [oid.to_string()],
            )
            .unwrap();
            let mut statement = conn
                .prepare_cached(persisted_blob_mutation_cost_fallback_sql())
                .unwrap();
            assert_eq!(
                persisted_blob_mutation_cost_fallback_statement(
                    &mut statement,
                    oid.to_string().as_str(),
                    "java",
                )
                .unwrap(),
                PersistedMutationCost {
                    logical_rows: prepared.logical_rows().saturating_sub(1),
                    payload_bytes: measured_persisted_payload_bytes(conn, &prepared),
                },
                "fallback cost must include the persisted signature/metadata pair rows"
            );
        });

        let explain_usage_pair_index = || {
            let conn = store.read_conn().unwrap();
            let mut statement = conn
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN {}",
                    usage_fact_rows_by_lang_sql()
                ))
                .unwrap();
            statement
                .query_map(["java"], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let before_analyze = explain_usage_pair_index();
        store.refresh_planner_statistics().unwrap();
        let after_analyze = explain_usage_pair_index();
        for (phase, plan) in [
            ("before ANALYZE", before_analyze),
            ("after ANALYZE", after_analyze),
        ] {
            assert!(
                plan.iter().any(|detail| {
                    detail.contains("idx_unit_signature_metadata_signatures_signature")
                }),
                "{phase}: usage projection must seek the populated signature-pair index: {plan:?}"
            );
        }
    }
    /// Plain SQL over the persisted table answers a question about real parsed
    /// source, with no Rust decoding step in between.
    ///
    /// This is what the promotion bought and the only test that proves it: the
    /// round-trip test above reads back values it built itself, and would still
    /// pass if the columns held anything self-consistent. Here a Java field with
    /// an initializer and a Java field without one are told apart by a `SUM`
    /// over one column of an on-disk store file, which is precisely what a
    /// consumer had to decode two million bincode blobs to learn before.
    #[test]
    fn a_persisted_java_field_initializer_is_readable_as_plain_sql() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Config.java",
            "class Config { static final int LIMIT = 7; int unset; }\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let state = parse_state(&JavaAdapter, &file);
        let store = AnalyzerStore::open_persistent(
            &temp
                .path()
                .join(brokk_bifrost_core::cache_db::cache_db_file_name()),
        )
        .unwrap();
        let generation = store
            .ensure_language_epoch_value("java", "field-initializer-observation")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "java",
                generation,
                &JavaAdapter,
                &state,
            )
            .unwrap();

        let conn = store.read_conn().unwrap();
        let (rows, initialized, labels): (i64, i64, String) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(field_has_initializer), 0),
                        COALESCE(GROUP_CONCAT(label, ' | '), '')
                 FROM unit_signature_metadata",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(
            rows >= 2,
            "the fixture's two fields must persist signature rows: {labels}"
        );
        assert_eq!(
            initialized, 1,
            "exactly the initialized field must report one: {labels}"
        );
    }
    #[test]
    fn resource_bound_oversized_current_epoch_content_package_fails_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Target.java",
            "package demo;\nclass Target {}\n",
        );
        let state = parse_state(&JavaAdapter, &file);
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("java", "limited-content-package-row-bytes-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "java",
                generation,
                &JavaAdapter,
                &state,
            )
            .unwrap();

        let ordinary = store
            .content_package_limited(oid, "java", generation, 1)
            .unwrap();
        assert!(ordinary.complete);
        assert_eq!(ordinary.rows, vec!["demo".to_string()]);
        assert_eq!(ordinary.inspected, 1);

        {
            let conn = store.conn.lock().unwrap();
            assert_eq!(
                conn.execute(
                    "UPDATE blob_meta
                     SET content_package = CAST(zeroblob(?3) AS TEXT)
                     WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)",
                    params![
                        oid.to_string(),
                        "java",
                        usize_to_i64(MAX_LIMITED_QUERY_ROW_BYTES + 1).unwrap(),
                    ],
                )
                .unwrap(),
                1
            );
        }

        let limited = store
            .content_package_limited(oid, "java", generation, 1)
            .unwrap();
        assert!(!limited.complete);
        assert!(limited.rows.is_empty());
        assert_eq!(limited.inspected, 1);
    }
    #[test]
    fn resource_bound_oversized_current_epoch_fallback_qualifier_fails_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Target.java",
            "package demo;\nclass Target {}\n",
        );
        let state = parse_state(&JavaAdapter, &file);
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("java", "limited-fallback-qualifier-row-bytes-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "java",
                generation,
                &JavaAdapter,
                &state,
            )
            .unwrap();

        let ordinary = store
            .first_declaration_content_qualifier_for_key_limited(
                oid,
                "java",
                generation,
                usize::MAX,
            )
            .unwrap();
        assert!(ordinary.complete);
        assert_eq!(ordinary.rows, vec!["demo".to_string()]);
        assert!(ordinary.inspected > 0);
        let rows_before_qualifier = ordinary.inspected;

        {
            let conn = store.conn.lock().unwrap();
            assert_eq!(
                conn.execute(
                    "UPDATE blob_meta
                     SET content_package = ''
                     WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)",
                    params![oid.to_string(), "java"],
                )
                .unwrap(),
                1
            );
            assert_eq!(
                conn.execute(
                    "UPDATE code_units
                     SET content_qualifier = CAST(zeroblob(?3) AS TEXT)
                     WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
                       AND unit_key = (
                         SELECT MIN(candidate.unit_key)
                         FROM code_units AS candidate
                         WHERE candidate.blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
                           AND candidate.content_qualifier <> ''
                       )",
                    params![
                        oid.to_string(),
                        "java",
                        usize_to_i64(MAX_LIMITED_QUERY_ROW_BYTES + 1).unwrap(),
                    ],
                )
                .unwrap(),
                1
            );
        }

        let package = store
            .content_package_limited(oid, "java", generation, 1)
            .unwrap();
        assert!(package.complete);
        assert_eq!(package.rows, vec![String::new()]);
        assert_eq!(package.inspected, 1);

        let limited = store
            .first_declaration_content_qualifier_for_key_limited(
                oid,
                "java",
                generation,
                usize::MAX,
            )
            .unwrap();
        assert!(!limited.complete);
        assert!(limited.rows.is_empty());
        assert_eq!(limited.inspected, rows_before_qualifier);
    }
    /// The fallback scans top-level declarations in source order (#1726), so
    /// the fixture needs two of them and the qualifiers are staged by
    /// `top_level_ordinal` rather than by `unit_key`. A file with one class and
    /// two methods would offer the scan a single eligible row.
    #[brokk_bifrost_test_macros::hardwon(
        "#1726: fallback qualifier scans skipped empty earlier declarations in their work budget"
    )]
    #[test]
    fn limited_fallback_qualifier_charges_empty_rows_before_evidence() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Target.java",
            "class First { void first() {} }\nclass Target { void second() {} }\n",
        );
        let state = parse_state(&JavaAdapter, &file);
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("java", "limited-fallback-qualifier-scan-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "java",
                generation,
                &JavaAdapter,
                &state,
            )
            .unwrap();

        {
            let conn = store.conn.lock().unwrap();
            let top_level_count: usize = conn
                .query_row(
                    "SELECT COUNT(*) FROM code_units
                     WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2) AND top_level_ordinal IS NOT NULL",
                    params![oid.to_string(), "java"],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                top_level_count, 2,
                "fixture needs two ordered top-level declarations"
            );
            assert_eq!(
                conn.execute(
                    "UPDATE code_units
                     SET content_qualifier = CASE
                         WHEN top_level_ordinal = 0 THEN ''
                         ELSE 'late.namespace'
                     END
                     WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
                       AND top_level_ordinal IS NOT NULL",
                    params![oid.to_string(), "java"],
                )
                .unwrap(),
                top_level_count
            );
        }

        let tiny = store
            .first_declaration_content_qualifier_for_key_limited(oid, "java", generation, 1)
            .unwrap();
        assert!(!tiny.complete);
        assert!(tiny.rows.is_empty());
        assert_eq!(tiny.inspected, 1);

        let sufficient = store
            .first_declaration_content_qualifier_for_key_limited(oid, "java", generation, 2)
            .unwrap();
        assert!(sufficient.complete);
        assert_eq!(sufficient.rows, vec!["late.namespace".to_string()]);
        assert_eq!(sufficient.inspected, 2);
    }
    #[test]
    fn resource_bound_oversized_current_epoch_supertype_rows_fail_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Hierarchy.scala",
            "package demo\nclass Parent\nclass Child extends Parent\n",
        );
        let state = parse_state(&ScalaAdapter, &file);
        let target = state
            .raw_supertypes
            .iter()
            .find(|(_, supertypes)| !supertypes.is_empty())
            .map(|(unit, _)| unit.clone())
            .expect("fixture should persist a raw supertype");
        assert!(
            state
                .supertype_lookup_paths
                .get(&target)
                .is_some_and(|paths| !paths.is_empty()),
            "fixture should persist a supertype lookup path"
        );
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("scala", "limited-supertype-row-bytes-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "scala",
                generation,
                &ScalaAdapter,
                &state,
            )
            .unwrap();
        let oversized = usize_to_i64(MAX_LIMITED_QUERY_ROW_BYTES + 1).unwrap();

        {
            let conn = store.conn.lock().unwrap();
            assert_eq!(
                conn.execute(
                    "UPDATE unit_supertypes
                     SET raw = CAST(zeroblob(?3) AS TEXT)
                     WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)",
                    params![oid.to_string(), "scala", oversized],
                )
                .unwrap(),
                1
            );
        }
        let raw = store
            .raw_supertypes_for_unit_limited(oid, "scala", generation, &target, usize::MAX)
            .unwrap();
        assert!(!raw.complete);
        assert!(raw.rows.is_empty());
        assert_eq!(raw.inspected, 1);

        {
            let conn = store.conn.lock().unwrap();
            assert_eq!(
                conn.execute(
                    "UPDATE unit_supertypes
                     SET lookup_path = CAST(zeroblob(?3) AS TEXT)
                     WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)",
                    params![oid.to_string(), "scala", oversized],
                )
                .unwrap(),
                1
            );
        }
        let lookup_paths = store
            .supertype_lookup_paths_for_unit_limited(oid, "scala", generation, &target, usize::MAX)
            .unwrap();
        assert!(!lookup_paths.complete);
        assert!(lookup_paths.rows.is_empty());
        assert_eq!(lookup_paths.inspected, 1);
    }
    #[test]
    fn resource_bound_oversized_current_epoch_candidate_row_fails_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Target.java",
            "class Target { void run() {} }\n",
        );
        let state = parse_state(&JavaAdapter, &file);
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("java", "limited-candidate-row-bytes-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "java",
                generation,
                &JavaAdapter,
                &state,
            )
            .unwrap();

        {
            let conn = store.conn.lock().unwrap();
            assert_eq!(
                conn.execute(
                    "UPDATE code_units
                     SET signature = CAST(zeroblob(?3) AS TEXT)
                     WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2) AND identifier = 'Target'",
                    params![
                        oid.to_string(),
                        "java",
                        usize_to_i64(MAX_LIMITED_QUERY_ROW_BYTES + 1).unwrap(),
                    ],
                )
                .unwrap(),
                1
            );
        }

        let langs = vec!["java".to_string()];
        let generations = HashMap::from_iter([("java".to_string(), generation)]);
        let limited = store
            .declaration_candidate_rows_by_identifier_for_langs_limited(
                &langs,
                &generations,
                "Target",
                usize::MAX,
            )
            .unwrap();
        assert!(!limited.complete);
        assert!(limited.rows.is_empty());
        assert_eq!(limited.inspected, 1);
    }
    #[test]
    fn concurrent_mixed_reads_against_one_warm_persistent_store() {
        use std::sync::Barrier;

        const EXTRA_BLOBS: u32 = 64;
        const READER_THREADS: usize = 8;

        // A persistent store exercises the reader pool (`source = Some`): pure
        // reads run on checked-out read-only connections, not the writer mutex.
        let temp = tempfile::TempDir::new().unwrap();
        let db_path = temp.path().join("bifrost_cache.db");
        let store = Arc::new(AnalyzerStore::open_persistent(&db_path).unwrap());

        // Warm the store with one committed Java blob.
        let file = write_file(
            temp.path(),
            "Widget.java",
            "class Widget { int value; void run() {} }\n",
        );
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let oid = oid_for(state.source.as_bytes());
        let generation = store
            .ensure_language_epoch_value("java", "concurrent-smoke-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "java",
                generation,
                &JavaAdapter,
                state.as_ref(),
            )
            .unwrap();

        let langs = vec!["java".to_string()];
        let mut generations = HashMap::default();
        generations.insert("java".to_string(), generation);

        // Single-threaded baseline: the warm reads return the expected rows.
        let baseline = store
            .declaration_candidate_rows_by_short_name_for_langs(&langs, &generations, "Widget")
            .unwrap();
        assert!(baseline.iter().any(|row| row.short_name == "Widget"));

        let start = Arc::new(Barrier::new(READER_THREADS + 1));

        // Writer thread: persist a bounded set of distinct blobs through the
        // single writer connection while the readers hammer their pooled
        // readers. Keeping the corpus fixed prevents the whole-language search
        // workload from growing according to thread scheduling and SQLite
        // throughput.
        let writer = {
            let store = Arc::clone(&store);
            let start = Arc::clone(&start);
            let root = temp.path().to_path_buf();
            std::thread::spawn(move || {
                start.wait();
                for index in 0..EXTRA_BLOBS {
                    let src = format!("class Extra{index} {{ int f{index}; }}\n");
                    let extra = write_file(&root, &format!("Extra{index}.java"), &src);
                    let extra_state = parse_state(&JavaAdapter, &extra);
                    let extra_oid = oid_for(extra_state.source.as_bytes());
                    store
                        .write_parsed_blob_at_generation(
                            &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                            extra_oid,
                            "java",
                            generation,
                            &JavaAdapter,
                            &extra_state,
                        )
                        .unwrap();
                }
            })
        };

        // Reader threads: mixed definitions lookup + hydration + search, each
        // asserting the warm Widget rows are always visible.
        let mut readers = Vec::new();
        for _ in 0..READER_THREADS {
            let store = Arc::clone(&store);
            let start = Arc::clone(&start);
            let langs = langs.clone();
            let generations = generations.clone();
            let file = file.clone();
            readers.push(std::thread::spawn(move || {
                start.wait();
                for _ in 0..200 {
                    let rows = store
                        .declaration_candidate_rows_by_short_name_for_langs(
                            &langs,
                            &generations,
                            "Widget",
                        )
                        .unwrap();
                    assert!(rows.iter().any(|row| row.short_name == "Widget"));

                    let hydrated = store
                        .hydrate_file_states(
                            &[(file.clone(), oid)],
                            "java",
                            &JavaAdapter,
                            &HashMap::default(),
                        )
                        .unwrap();
                    assert!(hydrated.contains_key(&file));

                    let search = store.search_candidate_rows_by_lang("java").unwrap();
                    assert!(
                        search
                            .iter()
                            .any(|row| row.candidate.short_name == "Widget")
                    );
                }
            }));
        }

        for reader in readers {
            reader.join().expect("reader thread panicked");
        }
        writer.join().expect("writer thread panicked");

        // The concurrently persisted blobs are all visible after the fact.
        let candidates = store.search_candidate_rows_by_lang("java").unwrap();
        let names = candidates
            .iter()
            .map(|row| row.candidate.short_name.as_str())
            .collect::<HashSet<_>>();
        assert!(names.contains("Widget"));
        for index in 0..EXTRA_BLOBS {
            assert!(names.contains(format!("Extra{index}").as_str()));
        }
    }
    #[brokk_bifrost_test_macros::hardwon(
        "#1104: Scala empty block lambdas were parsed incorrectly while old cache rows stayed current"
    )]
    #[test]
    fn scala_empty_lambda_parser_epoch_invalidates_prior_parsed_blobs() {
        // This is the Scala epoch immediately before issue #1068's parser-table
        // change. The change does not add an ABI, node-kind, or field name, so
        // the manual parser-release salt must invalidate old parsed blobs.
        const PRE_EMPTY_LAMBDA_EPOCH: &str =
            "68da221d12ed704b76c78dfe72b57f6eca7064aaa95ca39af8bcdcca1c2d1a29";

        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "VCSSpec.scala",
            "class VCSSpec { def run(): Unit = simulation.run() { _ => }; def after = 1 }\n",
        );
        let state = Arc::new(parse_state(&ScalaAdapter, &file));
        assert_prior_parsed_blob_invalidated(&ScalaAdapter, state.as_ref(), PRE_EMPTY_LAMBDA_EPOCH);
    }
    #[test]
    fn kotlin_type_alias_identity_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Tags.kt",
            "package example\n\ntypealias MaxVal = Int\n\nval MaxVal = 1\n",
        );
        let state = Arc::new(parse_state(&KotlinAdapter, &file));
        let alias = state
            .declarations
            .iter()
            .find(|unit| unit.fq_name() == "example.MaxVal" && unit.is_class())
            .expect("the current walk mints the alias as a type declaration");
        assert!(
            state
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "example.MaxVal" && unit.is_field()),
            "the val keeps its own field declaration beside {alias:?}: {:?}",
            state.declarations
        );
        let prior_epoch = epoch::kotlin_epoch_before_type_alias_type_identity();
        assert_prior_parsed_blob_invalidated(&KotlinAdapter, state.as_ref(), &prior_epoch);
    }
    /// #3453: Kotlin now records callable modifier metadata, and it recorded
    /// none before. A blob persisted under the prior epoch deserializes as
    /// "nobody read the modifiers", which is indistinguishable from a callable
    /// whose adapter honestly never looked, so `receiver_contract_of` reports
    /// no contract and every Kotlin procedure summary stays inert. The salt is
    /// the only thing that retires those rows.
    #[brokk_bifrost_test_macros::hardwon(
        "#3453: persisted Kotlin callables lacked modifier metadata needed for receiver contracts"
    )]
    #[test]
    fn kotlin_callable_modifier_metadata_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Registry.kt",
            "package example\n\nobject Registry {\n    fun register(spec: String): String = spec\n}\n\nclass Widget {\n    fun render(target: String): String = target\n}\n",
        );
        let state = Arc::new(parse_state(&KotlinAdapter, &file));
        let prior_epoch = epoch::epoch_before_bump(
            epoch::TestEpochLanguage::Kotlin,
            "kotlin-callable-modifier-metadata-2026-09",
        );
        assert_prior_parsed_blob_invalidated(&KotlinAdapter, state.as_ref(), &prior_epoch);
    }
    #[test]
    fn kotlin_call_navigation_receiver_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "ExactFlowFixture.kt",
            r#"object ExactFlowFixture {
    fun relay(value: String): String = value

    fun run(input: String) {
        ExactFlowFixture.relay(input)
    }
}
"#,
        );
        let state = Arc::new(parse_state(&KotlinAdapter, &file));
        let prior_epoch = epoch::kotlin_epoch_before_call_navigation_receiver_facts();
        assert_prior_parsed_blob_invalidated(&KotlinAdapter, state.as_ref(), &prior_epoch);
    }
    #[test]
    fn kotlin_scalar_additive_facts_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Arithmetic.kt",
            "package example\nfun decrement(depth: Int) = depth - 1\n",
        );
        let state = Arc::new(parse_state(&KotlinAdapter, &file));
        let prior_epoch = epoch::epoch_before_bump(
            epoch::TestEpochLanguage::Kotlin,
            "kotlin-labeled-this-receiver-2026-10",
        );
        assert_prior_parsed_blob_invalidated(&KotlinAdapter, state.as_ref(), &prior_epoch);
    }
    #[test]
    fn scala_type_alias_identity_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Tags.scala",
            "package example\n\nobject Tags:\n  type MaxVal = Int\n  val MaxVal = 1\n",
        );
        let state = Arc::new(parse_state(&ScalaAdapter, &file));
        let alias = state
            .declarations
            .iter()
            .find(|unit| unit.fq_name() == "example.Tags$.MaxVal" && unit.is_class())
            .expect("the current walk mints the alias as a type declaration");
        assert!(
            state
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "example.Tags$.MaxVal" && unit.is_field()),
            "the val keeps its own field declaration beside {alias:?}: {:?}",
            state.declarations
        );
        let prior_epoch = epoch::scala_epoch_before_type_alias_type_identity();
        assert_prior_parsed_blob_invalidated(&ScalaAdapter, state.as_ref(), &prior_epoch);
    }
    #[test]
    fn scala_native_root_route_facts_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Use.scala",
            "package example\nobject Use { val value: Outer.Inner = null }\n",
        );
        let state = Arc::new(parse_state(&ScalaAdapter, &file));
        let prior_epoch = epoch::scala_epoch_before_native_root_route_facts();
        assert_prior_parsed_blob_invalidated(&ScalaAdapter, state.as_ref(), &prior_epoch);
    }
    #[test]
    fn scala_published_parser_epoch_invalidates_vendored_parser_rows() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Syntax.scala",
            "object Syntax:\n  extension (value: String)\n    def twice: String = value + value\n",
        );
        let state = Arc::new(parse_state(&ScalaAdapter, &file));
        let prior_epoch = epoch::scala_epoch_before_tree_sitter_scala_0_26_2();
        assert_prior_parsed_blob_invalidated(&ScalaAdapter, state.as_ref(), &prior_epoch);
    }
    #[test]
    fn active_symbol_candidate_tables_are_isolated_between_concurrent_readers() {
        let temp = tempfile::TempDir::new().unwrap();
        let alpha_file = write_file(
            temp.path(),
            "alpha/AlphaService.java",
            "package alpha; class AlphaService { void run() {} }\n",
        );
        let beta_file = write_file(
            temp.path(),
            "beta/BetaService.java",
            "package beta; class BetaService { void run() {} }\n",
        );
        let alpha_oid = oid_for(alpha_file.read_to_string().unwrap().as_bytes());
        let beta_oid = oid_for(beta_file.read_to_string().unwrap().as_bytes());
        let store =
            Arc::new(AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap());
        for (oid, file) in [(alpha_oid, &alpha_file), (beta_oid, &beta_file)] {
            store
                .write_parsed_blob(oid, "java", &JavaAdapter, &parse_state(&JavaAdapter, file))
                .unwrap();
        }
        let generations = Arc::new(
            [("java".to_string(), GenerationId::BOOTSTRAP)]
                .into_iter()
                .collect::<HashMap<_, _>>(),
        );
        let barrier = Arc::new(std::sync::Barrier::new(2));

        std::thread::scope(|scope| {
            for expected_oid in [alpha_oid, beta_oid] {
                let store = Arc::clone(&store);
                let generations = Arc::clone(&generations);
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    for _ in 0..10 {
                        let rows = store
                            .search_candidate_name_rows_for_langs(
                                &["java".to_string()],
                                &generations,
                                &[ActiveSearchBlob::unfiltered(expected_oid)],
                                Some(&[vec!["Service".to_string()]]),
                                None,
                            )
                            .unwrap();
                        assert!(rows.complete);
                        assert!(!rows.rows.is_empty());
                        assert!(rows.rows.iter().all(|row| row.blob_oid == expected_oid));
                    }
                });
            }
        });
    }
    /// Issue #2316: the candidate scan is prefiltered by the literals every
    /// pattern requires, and the two live-name channels a persisted column
    /// cannot express keep their declarations.
    #[brokk_bifrost_test_macros::hardwon(
        "#2316: required-literal prefiltering dropped valid package and exempt-channel candidates"
    )]
    #[test]
    fn active_symbol_candidate_scan_prefilters_on_required_literals() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "demo/AlphaService.java",
            "package demo; class AlphaService { void run() {} }\nclass BetaWorker { void work() {} }\n",
        );
        let oid = oid_for(file.read_to_string().unwrap().as_bytes());
        let store = AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap();
        store
            .write_parsed_blob(oid, "java", &JavaAdapter, &parse_state(&JavaAdapter, &file))
            .unwrap();
        let languages = vec!["java".to_string()];
        let generations = HashMap::from_iter([("java".to_string(), GenerationId::BOOTSTRAP)]);
        let scan = |blob: ActiveSearchBlob, literals: Option<&[Vec<String>]>| {
            store
                .search_candidate_name_rows_for_langs(
                    &languages,
                    &generations,
                    &[blob],
                    literals,
                    None,
                )
                .unwrap()
                .rows
                .into_iter()
                .map(|row| row.short_name)
                .collect::<std::collections::BTreeSet<_>>()
        };

        let all = scan(ActiveSearchBlob::unfiltered(oid), None);
        assert!(
            all.contains("AlphaService")
                && all.contains("BetaWorker")
                && all.contains("AlphaService.run"),
            "{all:?}"
        );

        let beta = scan(
            ActiveSearchBlob::unfiltered(oid),
            Some(&[vec!["betaworker".to_string()]]),
        );
        assert!(
            beta.contains("BetaWorker") && !beta.contains("AlphaService"),
            "a required literal must narrow the scan: {beta:?}"
        );
        assert!(beta.len() < all.len(), "{beta:?} vs {all:?}");

        assert!(
            scan(
                ActiveSearchBlob::unfiltered(oid),
                Some(&[vec!["zzz".to_string()]])
            )
            .is_empty(),
            "a literal no name contains must leave nothing to match"
        );

        // The blob's live path supplies a package prefix no persisted column
        // spells out, so its declarations survive a literal only that prefix has.
        assert_eq!(
            scan(
                ActiveSearchBlob {
                    oid,
                    package_literals: "zzz".to_string(),
                    prefilter_exempt: false,
                },
                Some(&[vec!["zzz".to_string()]])
            ),
            all
        );

        // A blob whose package prefixes cannot be enumerated is never filtered.
        assert_eq!(
            scan(
                ActiveSearchBlob {
                    oid,
                    package_literals: String::new(),
                    prefilter_exempt: true,
                },
                Some(&[vec!["zzz".to_string()]])
            ),
            all
        );
    }
    #[test]
    fn package_prefix_pages_are_literal_and_cursor_bounded() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let adapter = JavaAdapter;
        let store = AnalyzerStore::open_ephemeral().unwrap();
        for (path, source) in [
            ("src/a_b/One.java", "package a_b; class One {}\n"),
            (
                "src/a_b/child/Two.java",
                "package a_b.child; class Two {}\n",
            ),
            ("src/aXb/Other.java", "package aXb; class Other {}\n"),
        ] {
            let file = write_file(root, path, source);
            let oid = oid_for(source.as_bytes());
            store
                .write_parsed_blob(oid, "java", &adapter, &parse_state(&adapter, &file))
                .unwrap();
        }

        let first = store
            .declaration_rows_by_package_prefix_page(
                "java",
                GenerationId::BOOTSTRAP,
                "a_b",
                None,
                1,
            )
            .unwrap();
        assert_eq!(first.len(), 1);
        assert!(matches!(
            first[0].content_qualifier.as_str(),
            "a_b" | "a_b.child"
        ));
        let cursor = (
            first[0].content_qualifier.as_str(),
            first[0].blob_oid,
            first[0].unit_key,
        );
        let second = store
            .declaration_rows_by_package_prefix_page(
                "java",
                GenerationId::BOOTSTRAP,
                "a_b",
                Some(cursor),
                16,
            )
            .unwrap();
        let qualifiers = first
            .iter()
            .chain(&second)
            .map(|row| row.content_qualifier.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(
            qualifiers,
            ["a_b", "a_b.child"].into_iter().collect::<HashSet<_>>()
        );
        assert!(!qualifiers.contains("aXb"));
    }
    #[test]
    fn summary_projection_matches_required_file_state_rows_and_rejects_missing_ranges() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(
            root,
            "src/demo/Example.java",
            "package demo; class Example { String name; void run() {} }\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();

        let projection = store
            .summary_file_projection(
                oid,
                "java",
                GenerationId::BOOTSTRAP,
                &adapter,
                &file,
                &source,
            )
            .unwrap()
            .expect("complete summary projection");
        let hydrated = store
            .hydrate_file_state(oid, "java", &adapter, &file)
            .unwrap()
            .expect("complete file state");
        let hydrated_top_level: Vec<_> = hydrated
            .top_level_declarations
            .into_iter()
            .filter(|unit| !unit.is_file_scope())
            .collect();
        assert_eq!(projection.top_level_declarations, hydrated_top_level);
        for (unit, signatures) in &projection.signatures {
            assert_eq!(hydrated.signatures.get(unit), Some(signatures));
        }
        for (unit, ranges) in &projection.ranges {
            assert_eq!(hydrated.ranges.get(unit), Some(ranges));
        }
        for (unit, children) in &projection.children {
            assert_eq!(hydrated.children.get(unit), Some(children));
        }

        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM unit_ranges WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java')",
                [oid.to_string()],
            )
            .unwrap();
        }
        assert!(
            store
                .summary_file_projection(
                    oid,
                    "java",
                    GenerationId::BOOTSTRAP,
                    &adapter,
                    &file,
                    &source,
                )
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn bulk_import_facts_include_complete_files_without_import_rows() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(
            root,
            "src/demo/NoImports.java",
            "package demo; class NoImports {}\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();

        let facts = store
            .hydrate_import_facts_by_key(
                &[(file.clone(), oid, "java".to_string())],
                &HashMap::from_iter([("java".to_string(), GenerationId::BOOTSTRAP)]),
                &adapter,
            )
            .unwrap();
        let facts = facts.get(&file).expect("complete persisted import facts");
        assert_eq!(facts.package_name, "demo");
        assert!(facts.imports.is_empty());
    }
    #[test]
    fn literal_substring_candidates_keep_members_of_matching_java_types() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(
            root,
            "src/demo/Gson.java",
            "package demo; class Gson { void fromJson() {} } class Other { void unrelated() {} }\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();

        let candidates = store
            .declaration_candidate_rows_by_literal_substring("java", "Gson")
            .unwrap();
        assert!(
            candidates
                .iter()
                .any(|row| row.short_name.ends_with(".fromJson")),
            "Java persists member selectors with their owning type in short_name"
        );
        assert!(candidates.iter().all(|row| {
            row.short_name.to_ascii_lowercase().contains("gson")
                || row.content_qualifier.to_ascii_lowercase().contains("gson")
        }));
        assert!(
            !candidates
                .iter()
                .any(|row| row.short_name.contains("unrelated"))
        );

        let search_candidates = store.search_candidate_rows_by_lang("java").unwrap();
        let method = search_candidates
            .iter()
            .find(|row| row.candidate.short_name.ends_with(".fromJson"))
            .expect("method search candidate");
        assert!(method.primary_range.is_some());
        assert!(!method.in_test_region);
    }
    #[test]
    fn definition_order_candidates_use_minimum_persisted_range_and_allow_absent_range() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(
            root,
            "src/demo/Sample.java",
            "package demo; class Sample {}\n",
        );
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();
        store
            .sync_workspace_snapshot(
                "java",
                GenerationId::BOOTSTRAP,
                &[WorkspaceFileRow {
                    rel_path: brokk_bifrost_core::path_utils::rel_path_string(&file),
                    blob_oid: oid,
                }],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();

        let unit_key = {
            let conn = store.conn.lock().unwrap();
            let unit_key = conn
                .query_row(
                    "SELECT unit_key FROM code_units
                     WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java')
                       AND short_name = 'Sample' AND in_declarations = 1",
                    [oid.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap();
            conn.execute(
                "DELETE FROM unit_ranges
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java') AND unit_key = ?2",
                params![oid.to_string(), unit_key],
            )
            .unwrap();
            for (ordinal, start_byte) in [(0_i64, 20_i64), (1, 5)] {
                conn.execute(
                    "INSERT INTO unit_ranges(
                       blob_id, lang, unit_key, ordinal,
                       start_byte, end_byte, start_line, end_line
                     ) VALUES((SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'), 'java', ?2, ?3, ?4, ?5, 0, 0)",
                    params![
                        oid.to_string(),
                        unit_key,
                        ordinal,
                        start_byte,
                        start_byte + 1
                    ],
                )
                .unwrap();
            }
            conn.execute(
                "UPDATE blob_meta
                 SET range_count = (
                   SELECT COUNT(*) FROM unit_ranges
                   WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java')
                 )
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java')",
                [oid.to_string()],
            )
            .unwrap();
            unit_key
        };

        let generations = HashMap::from_iter([("java".to_string(), GenerationId::BOOTSTRAP)]);
        let rows = store
            .declaration_order_candidate_rows_by_short_name_for_langs(
                &["java".to_string()],
                &generations,
                "Sample",
                None,
            )
            .unwrap();
        assert!(rows.complete);
        assert_eq!(rows.rows.len(), 1);
        assert_eq!(rows.rows[0].first_start_byte, Some(5));

        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM unit_ranges
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java') AND unit_key = ?2",
                params![oid.to_string(), unit_key],
            )
            .unwrap();
            conn.execute(
                "UPDATE blob_meta
                 SET range_count = (
                   SELECT COUNT(*) FROM unit_ranges
                   WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java')
                 )
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java')",
                [oid.to_string()],
            )
            .unwrap();
        }
        let rows = store
            .declaration_order_candidate_rows_by_short_name_for_langs(
                &["java".to_string()],
                &generations,
                "Sample",
                None,
            )
            .unwrap();
        assert!(rows.complete);
        assert_eq!(rows.rows.len(), 1);
        assert_eq!(rows.rows[0].first_start_byte, None);
    }
    #[brokk_bifrost_test_macros::hardwon(
        "#3035+888ce79b9d65: declaration catalog reads returned ranges from a non-selected workspace revision"
    )]
    #[test]
    fn mounted_declaration_primary_ranges_follow_the_selected_revision() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "src/demo/Sample.java",
            "package demo; class Old { void before() {} }\n",
        );
        let adapter = JavaAdapter;
        let old_source = file.read_to_string().unwrap();
        let old_oid = oid_for(old_source.as_bytes());
        let old_state = parse_state(&adapter, &file);

        let new_source = "package demo; class New { void after() {} }\n";
        write_file(temp.path(), "src/demo/Sample.java", new_source);
        let new_oid = oid_for(new_source.as_bytes());
        let new_state = parse_state(&adapter, &file);

        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(old_oid, "java", &adapter, &old_state)
            .unwrap();
        store
            .write_parsed_blob(new_oid, "java", &adapter, &new_state)
            .unwrap();
        let old_snapshot = store
            .sync_workspace_snapshot(
                "java",
                GenerationId::BOOTSTRAP,
                &[WorkspaceFileRow {
                    rel_path: "src/demo/Sample.java".to_string(),
                    blob_oid: old_oid,
                }],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        let new_snapshot = store
            .sync_workspace_snapshot(
                "java",
                GenerationId::BOOTSTRAP,
                &[WorkspaceFileRow {
                    rel_path: "src/demo/Sample.java".to_string(),
                    blob_oid: new_oid,
                }],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        let languages = ["java".to_string()];
        let generations = HashMap::from_iter([("java".to_string(), GenerationId::BOOTSTRAP)]);
        let read = |snapshot: WorkspaceSnapshotId| {
            store
                .mounted_declaration_rows_with_primary_ranges_for_langs(
                    &WorkspaceSnapshots::from_iter([("java".to_string(), snapshot)]),
                    &languages,
                    &generations,
                    &CancellationToken::new(),
                )
                .unwrap()
                .expect("uncancelled mounted inventory")
        };

        let old_rows = read(old_snapshot);
        let new_rows = read(new_snapshot);
        let names = |rows: &[HydratedMountedCandidatePrimaryRangeRow]| {
            rows.iter()
                .map(|row| row.candidate.short_name.clone())
                .collect::<HashSet<_>>()
        };
        let old_names = names(&old_rows);
        assert!(old_names.contains("Old"));
        assert!(old_names.contains("Old.before"));
        assert!(!old_names.contains("New"));
        assert!(!old_names.contains("New.after"));
        let new_names = names(&new_rows);
        assert!(new_names.contains("New"));
        assert!(new_names.contains("New.after"));
        assert!(!new_names.contains("Old"));
        assert!(!new_names.contains("Old.before"));
        for row in old_rows.iter().chain(&new_rows) {
            assert_eq!(row.rel_path, "src/demo/Sample.java");
            assert!(
                row.primary_range.is_some(),
                "every parsed declaration in this fixture has a primary range: {row:?}"
            );
        }
    }
    #[brokk_bifrost_test_macros::hardwon(
        "#3035+888ce79b9d65: cancelled mounted declaration reads exposed a partial row prefix"
    )]
    #[test]
    fn mounted_declaration_primary_range_read_discards_a_cancelled_prefix() {
        const BLOBS: usize = CANDIDATE_ROWS_PER_CANCELLATION_POLL + 1;
        let (_temp, store) = store_with_repeated_short_name(BLOBS);
        let languages = ["java".to_string()];
        let generations = HashMap::from_iter([("java".to_string(), GenerationId::BOOTSTRAP)]);
        let snapshots = store
            .workspace_snapshots_for_langs(
                &WorkspaceId(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                ),
                &languages,
                &generations,
            )
            .unwrap();

        // The first two checks enter the statement. The third occurs after
        // one complete row block, so `None` proves that prefix never escapes.
        let cancellation = CancellationToken::cancel_after_checks_for_test(3);
        assert!(
            store
                .mounted_declaration_rows_with_primary_ranges_for_langs(
                    &snapshots,
                    &languages,
                    &generations,
                    &cancellation,
                )
                .unwrap()
                .is_none()
        );
    }
    /// A candidate-row seek must observe its caller's deadline *inside* the
    /// statement, not only around it.
    ///
    /// The seek for one short name is a single read, and for a hot name it is
    /// the longest single thing a `scan_usages` request does -- 1.14 s for
    /// `main` on the rustc tree, issued from inside a candidate walk that polls
    /// its own deadline once per file. The walk stopped on time; the read it had
    /// already started did not, and that one read was the whole of the measured
    /// 0.57 s overshoot of a 3 s budget.
    ///
    /// Without the in-statement poll this returns all 1,200 rows and reports
    /// `complete`.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn a_cancelled_candidate_row_seek_stops_inside_the_statement() {
        const BLOBS: usize = 1_200;
        let (_temp, store) = store_with_repeated_short_name(BLOBS);
        let generations = HashMap::from_iter([("java".to_string(), GenerationId::BOOTSTRAP)]);
        let langs = ["java".to_string()];

        let complete = store
            .declaration_order_candidate_rows_by_short_name_for_langs(
                &langs,
                &generations,
                "Sample",
                None,
            )
            .unwrap();
        assert!(complete.complete);
        assert_eq!(
            BLOBS,
            complete.rows.len(),
            "the fixture must hold more rows than one poll interval"
        );

        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let stopped = store
            .declaration_order_candidate_rows_by_short_name_for_langs(
                &langs,
                &generations,
                "Sample",
                Some(&cancellation),
            )
            .unwrap();
        assert!(
            !stopped.complete,
            "a seek that stopped at its deadline must not report a complete row set"
        );
        assert_eq!(
            0,
            stopped.rows.len(),
            "an incomplete identity batch must not escape"
        );
        assert_eq!(
            CANDIDATE_ROWS_PER_CANCELLATION_POLL, stopped.inspected,
            "the parent seek must stop at its first poll, not run the statement out"
        );
    }
    /// The poll is per row block, not per row: a completing seek of 1,200 rows
    /// must cost a handful of deadline checks, so the deadline costs nothing
    /// measurable on the path that answers.
    ///
    /// The token trips on its eighth check, which is generous against the three
    /// this seek needs (`1200 / 512` blocks plus the end-of-language check) and
    /// far under the 1,200 a per-row poll would spend.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[brokk_bifrost_test_macros::hardwon(
        "946710c44839: per-row cancellation polling exhausted the budget on successful candidate reads"
    )]
    #[test]
    fn a_completing_candidate_row_seek_polls_once_per_row_block() {
        const BLOBS: usize = 1_200;
        // Three parent checks, one check after the segment load, and one
        // check per 512 relational segment rows. The fixture has three
        // segments per candidate, so twelve leaves ample headroom while
        // remaining far below a per-row polling strategy.
        const GENEROUS_CHECK_BUDGET: usize = 12;
        let (_temp, store) = store_with_repeated_short_name(BLOBS);
        let generations = HashMap::from_iter([("java".to_string(), GenerationId::BOOTSTRAP)]);
        let cancellation = CancellationToken::cancel_after_checks_for_test(GENEROUS_CHECK_BUDGET);

        let rows = store
            .declaration_order_candidate_rows_by_short_name_for_langs(
                &["java".to_string()],
                &generations,
                "Sample",
                Some(&cancellation),
            )
            .unwrap();

        assert!(
            rows.complete,
            "a seek that polls per row would spend its whole check budget and report incomplete"
        );
        assert_eq!(BLOBS, rows.rows.len());
    }
    #[test]
    fn relational_fq_corruption_fails_closed_without_a_fallback() {
        let read_error_after = |mutation: &str| {
            let (_temp, store) = store_with_repeated_short_name(1);
            {
                let conn = store.conn.lock().expect("store mutex");
                conn.execute_batch(mutation).unwrap();
            }
            let generations = HashMap::from_iter([("java".to_string(), GenerationId::BOOTSTRAP)]);
            store
                .declaration_candidate_rows_by_short_name_for_langs(
                    &["java".to_string()],
                    &generations,
                    "Sample",
                )
                .unwrap_err()
                .to_string()
        };

        assert!(
            read_error_after("DELETE FROM code_unit_fq_segments WHERE seg_ordinal = 1")
                .contains("segments but loaded")
        );
        assert!(
            read_error_after(
                "UPDATE code_unit_fq_segments SET seg_ordinal = 4 WHERE seg_ordinal = 0"
            )
            .contains("segments are not dense")
        );
        assert!(
            read_error_after(
                "PRAGMA ignore_check_constraints = ON;
                 UPDATE code_unit_fq_segments SET seg_kind = 'invalid' WHERE seg_ordinal = 0;
                 PRAGMA ignore_check_constraints = OFF;"
            )
            .contains("unknown relational FqName segment kind")
        );
        assert!(
            read_error_after("UPDATE code_units SET fq_segment_count = fq_segment_count + 1")
                .contains("segments but loaded")
        );
        assert!(
            read_error_after("UPDATE code_units SET fq_segment_bytes = fq_segment_bytes + 1")
                .contains("segment bytes but loaded")
        );
        assert!(
            read_error_after(
                "PRAGMA ignore_check_constraints = ON;
                 UPDATE code_units SET fq_anchor_kind = 'crate_root', fq_anchor_pop = 2;
                 PRAGMA ignore_check_constraints = OFF;"
            )
            .contains("invalid anchor pair")
        );
        assert!(
            read_error_after("UPDATE code_units SET fq_package_tail_segments = fq_segment_count")
                .contains("leaves no declaration tail")
        );

        let (_temp, store) = store_with_repeated_short_name(1);
        let conn = store.conn.lock().expect("store mutex");
        assert!(
            conn.execute_batch(
                "INSERT INTO code_unit_fq_segments(
                     blob_id, lang, unit_key, seg_ordinal, seg_kind, segment)
                 SELECT blob_id, lang, unit_key, seg_ordinal, seg_kind, segment
                 FROM code_unit_fq_segments WHERE seg_ordinal = 0"
            )
            .is_err(),
            "the relational primary key must reject duplicate ordinals"
        );
    }
    #[test]
    fn definition_headers_hydrate_only_the_identity_that_survives_name_narrowing() {
        let temp = tempfile::TempDir::new().unwrap();
        let adapter = JavaAdapter;
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let mut oids = Vec::new();
        let mut workspace_files = Vec::new();
        for package in ["wanted", "loser"] {
            let file = write_file(
                temp.path(),
                &format!("{package}/Sample.java"),
                &format!("package {package}; class Sample {{}}\n"),
            );
            let source = file.read_to_string().unwrap();
            let oid = oid_for(source.as_bytes());
            let state = parse_state(&adapter, &file);
            store
                .write_parsed_blob(oid, "java", &adapter, &state)
                .unwrap();
            oids.push((package, oid));
            workspace_files.push(WorkspaceFileRow {
                rel_path: brokk_bifrost_core::path_utils::rel_path_string(&file),
                blob_oid: oid,
            });
        }
        store
            .sync_workspace_snapshot(
                "java",
                GenerationId::BOOTSTRAP,
                &workspace_files,
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        let generations = HashMap::from_iter([("java".to_string(), GenerationId::BOOTSTRAP)]);
        let rows = store
            .declaration_order_candidate_rows_by_short_name_for_langs(
                &["java".to_string()],
                &generations,
                "Sample",
                None,
            )
            .unwrap();
        assert!(rows.complete);
        assert_eq!(rows.rows.len(), 2);
        let wanted = rows
            .rows
            .into_iter()
            .filter(|row| {
                row.candidate
                    .fq
                    .as_ref()
                    .is_some_and(|header| header.exact_tail == "wanted.Sample")
            })
            .collect::<Vec<_>>();
        assert_eq!(wanted.len(), 1);

        let loser_oid = oids
            .iter()
            .find_map(|(package, oid)| (*package == "loser").then_some(*oid))
            .unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM code_unit_fq_segments
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java')",
                [loser_oid.to_string()],
            )
            .unwrap();

        let hydrated = store
            .hydrate_definition_order_candidate_rows(wanted, &generations, None)
            .unwrap();
        assert!(hydrated.complete);
        assert_eq!(hydrated.rows.len(), 1);
        assert_eq!(
            hydrated.rows[0]
                .candidate
                .fq
                .as_ref()
                .unwrap()
                .segments
                .len(),
            2
        );
    }
    #[test]
    fn scala_top_level_extension_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Ext.scala",
            "package example\n\nextension (s: String)\n  def asInt: Int = s.toInt\n",
        );
        let mut state = parse_state(&ScalaAdapter, &file);
        assert!(
            state
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "example.asInt"),
            "the current walk records the top-level extension method: {:?}",
            state.declarations
        );
        // The walk used before this epoch handled `extension` only inside a
        // template body, so a file whose members are all top-level extension
        // methods persisted no declaration but its file scope.
        state
            .declarations
            .retain(|unit| unit.fq_name() != "example.asInt");
        state
            .top_level_declarations
            .retain(|unit| unit.fq_name() != "example.asInt");
        let state = Arc::new(state);
        let prior_epoch = epoch::scala_epoch_before_top_level_extension_declarations();
        assert_prior_parsed_blob_invalidated(&ScalaAdapter, state.as_ref(), &prior_epoch);
    }
    #[brokk_bifrost_test_macros::hardwon(
        "9bf090ac306f: Scala recovery changed declaration identities without retiring stale rows"
    )]
    #[test]
    fn scala_scalachess_fqn_recovery_epoch_invalidates_stale_rows_and_reuses_current() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "src/main/scala/chess/tiebreak/Tiebreak.scala",
            "package chess\npackage tiebreak\n\nimport Tiebreak.*\n\ntrait Tournament:\n  def players: Set[String]\n  def gamesById(id: String): List[String]\n  def opponentsOf: String => List[String]\n  def scoreOf: String => Float\n  def lastRoundId: Option[String]\n\n  lazy val maxRounds = players.map(_.length).maxOption.getOrElse(0)\n\nobject Tournament:\n  private final class Impl extends Tournament:\n    override def players: Set[String] = Set.empty\n    override def gamesById(id: String): List[String] = Nil\n    override def opponentsOf: String => List[String] = _ => Nil\n    override def scoreOf: String => Float = _ => 0f\n    override def lastRoundId: Option[String] = None\n\n  def apply(value: Int): Tournament =\n    new Tournament {}\n\nobject Tiebreak:\n  def compute(value: Int): Tournament =\n    Tournament(value)\n",
        );
        let state = Arc::new(parse_state(&ScalaAdapter, &file));
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();

        // Commit 20f61961 recovered declarations that tree-sitter attaches to
        // malformed significant-indentation template bodies. That changed
        // Scala FQNs without changing the grammar vocabulary covered by the
        // automatic epoch fingerprint. Do not pin the helper's literal hash:
        // the fingerprint includes the live grammar fingerprint and query
        // contents, so a literal breaks whenever either shifts. The generation
        // inequality below proves the cutover.
        let prior_epoch = epoch::scala_epoch_before_scalachess_fqn_recovery();
        let prior_generation = store
            .ensure_language_epoch_value("scala", &prior_epoch)
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "scala",
                prior_generation,
                &ScalaAdapter,
                state.as_ref(),
            )
            .unwrap();
        assert!(store.contains_parsed_blob(oid, "scala").unwrap());

        let current_generation = store
            .ensure_language_epoch(
                Language::Scala,
                &brokk_bifrost_jvm_analysis::analyzer::scala::language::LANGUAGE.into(),
            )
            .unwrap();
        assert_ne!(current_generation, prior_generation);
        assert!(!store.contains_parsed_blob(oid, "scala").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "scala".to_string())])
                .unwrap(),
            vec![(oid, "scala".to_string())]
        );

        // Once the current epoch has been populated, reopening the same
        // version must reuse its generation and keep the semantic state warm.
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "scala",
                current_generation,
                &ScalaAdapter,
                state.as_ref(),
            )
            .unwrap();
        let reused_generation = store
            .ensure_language_epoch(
                Language::Scala,
                &brokk_bifrost_jvm_analysis::analyzer::scala::language::LANGUAGE.into(),
            )
            .unwrap();
        assert_eq!(reused_generation, current_generation);
        assert!(store.contains_parsed_blob(oid, "scala").unwrap());
        let hydrated = store
            .hydrate_file_state(oid, "scala", &ScalaAdapter, &file)
            .unwrap()
            .expect("current-generation Scala rows should hydrate");
        assert!(
            hydrated
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "chess.tiebreak.Tournament$.apply"),
            "hydrated declarations should retain the top-level companion apply: {:?}",
            hydrated.declarations
        );
        assert!(
            hydrated
                .declarations
                .iter()
                .all(|unit| unit.fq_name() != "chess.tiebreak.Tournament.Tournament$.apply"),
            "hydrated declarations must not retain the stale duplicate owner: {:?}",
            hydrated.declarations
        );
    }
    #[test]
    fn cpp_epoch_change_hides_old_rows_without_synchronous_physical_deletion() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model { int value; }\n");
        let oid = oid_for(file.read_to_string().unwrap().as_bytes());
        // Epoch visibility is keyed by storage language independently of the parser adapter.
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store.ensure_language_epoch_value("cpp", "epoch-a").unwrap();
        store
            .write_parsed_blob(oid, "cpp", &adapter, &state)
            .unwrap();

        let physical_counts = || {
            let conn = store.conn.lock().expect("analyzer store mutex poisoned");
            // `blobs` is the intern point and keeps the hex; its children are
            // reached through the id it mints.
            ["blobs", "blob_meta", "code_units"].map(|table| {
                let sql = if table == "blobs" {
                    "SELECT COUNT(*) FROM blobs WHERE blob_oid = ?1 AND lang = 'cpp'".to_string()
                } else {
                    format!(
                        "SELECT COUNT(*) FROM {table}
                         WHERE blob_id = (
                           SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'cpp'
                         )"
                    )
                };
                conn.query_row(&sql, [oid.to_string()], |row| row.get::<_, usize>(0))
                    .unwrap()
            })
        };
        let before = physical_counts();
        assert!(before.into_iter().all(|count| count > 0), "{before:?}");
        assert!(store.contains_parsed_blob(oid, "cpp").unwrap());

        store.ensure_language_epoch_value("cpp", "epoch-b").unwrap();
        assert!(!store.contains_parsed_blob(oid, "cpp").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "cpp".to_string())])
                .unwrap(),
            vec![(oid, "cpp".to_string())]
        );
        assert_eq!(
            before,
            physical_counts(),
            "epoch invalidation should be a constant-time logical cutover; old physical rows belong to deferred GC"
        );
    }
    #[test]
    fn repeated_epoch_string_gets_fresh_generation_without_reviving_a1_rows() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model {}\n");
        let oid = oid_for(file.read_to_string().unwrap().as_bytes());
        let state = parse_state(&JavaAdapter, &file);
        let store = AnalyzerStore::open_ephemeral().unwrap();

        let a1 = store
            .ensure_language_epoch_value("java", "epoch-a")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "java",
                a1,
                &JavaAdapter,
                &state,
            )
            .unwrap();
        let b = store
            .ensure_language_epoch_value("java", "epoch-b")
            .unwrap();
        let a2 = store
            .ensure_language_epoch_value("java", "epoch-a")
            .unwrap();

        assert_ne!(a1, b);
        assert_ne!(a1, a2);
        assert_ne!(b, a2);
        assert!(!store.contains_parsed_blob(oid, "java").unwrap());
        assert!(
            store
                .contains_parsed_blob_at_generation(oid, "java", a1)
                .unwrap_err()
                .is_stale_generation()
        );
    }
    #[test]
    fn stale_prepared_register_and_path_writes_cannot_delete_current_rows() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model {}\n");
        let oid = oid_for(file.read_to_string().unwrap().as_bytes());
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let a = store
            .ensure_language_epoch_value("java", "epoch-a")
            .unwrap();
        let prepared =
            AnalyzerStore::prepare_parsed_blob(oid, "java", a, &JavaAdapter, Arc::clone(&state))
                .unwrap();
        let b = store
            .ensure_language_epoch_value("java", "epoch-b")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "java",
                b,
                &JavaAdapter,
                state.as_ref(),
            )
            .unwrap();

        let (outcomes, stats) =
            store.persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
        assert_eq!(stats.failed_transaction_attempts, 1);
        assert!(outcomes[0].error.as_ref().unwrap().is_stale_generation());
        assert!(
            store
                .register_blobs(&[oid], "java", a)
                .unwrap_err()
                .is_stale_generation()
        );

        let row = PathSymbolRow {
            rel_path: "Model.java".to_string(),
            blob_oid: oid,
            kind: CodeUnitType::Module,
            package_name: String::new(),
            short_name: "Model".to_string(),
            exact_fqn: "Model".to_string(),
            normalized_fqn: "Model".to_string(),
            requires_imports: false,
        };
        store
            .sync_workspace_snapshot(
                "java",
                b,
                &[WorkspaceFileRow {
                    rel_path: row.rel_path.clone(),
                    blob_oid: row.blob_oid,
                }],
                std::slice::from_ref(&row),
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        assert!(
            store
                .sync_workspace_snapshot(
                    "java",
                    a,
                    &[WorkspaceFileRow {
                        rel_path: row.rel_path.clone(),
                        blob_oid: row.blob_oid,
                    }],
                    std::slice::from_ref(&row),
                    &[],
                    &[],
                    &[],
                    &[],
                )
                .unwrap_err()
                .is_stale_generation()
        );
        assert!(store.contains_parsed_blob(oid, "java").unwrap());
        let langs = vec!["java".to_string()];
        let generations = HashMap::from_iter([("java".to_string(), b)]);
        assert_eq!(
            store
                .path_symbol_rows_by_fqn_for_langs(&langs, &generations, "Model", "Model",)
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn hydration_read_snapshot_keeps_meta_and_satellites_on_one_generation() {
        let temp = tempfile::TempDir::new().unwrap();
        let db = temp.path().join("cache.db");
        let file = write_file(temp.path(), "Model.java", "class Alpha {}\n");
        let oid = oid_for(b"stable-oid");
        let state_a = parse_state(&JavaAdapter, &file);
        let writer = AnalyzerStore::open_persistent(&db).unwrap();
        let reader = AnalyzerStore::open_persistent(&db).unwrap();
        let a = writer
            .ensure_language_epoch_value("java", "epoch-a")
            .unwrap();
        writer
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "java",
                a,
                &JavaAdapter,
                &state_a,
            )
            .unwrap();

        let mut reader_conn = reader.read_conn().unwrap();
        let read_tx = reader_conn.transaction().unwrap();
        require_current_generation(&read_tx, "java", a).unwrap();
        let old_meta = read_blob_meta(
            &read_tx,
            &oid.to_string(),
            "java",
            &JavaAdapter,
            &file,
            "class Alpha {}\n",
        )
        .unwrap()
        .unwrap();

        std::fs::write(file.abs_path(), "class Beta {}\n").unwrap();
        let state_b = parse_state(&JavaAdapter, &file);
        let b = writer
            .ensure_language_epoch_value("java", "epoch-b")
            .unwrap();
        writer
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "java",
                b,
                &JavaAdapter,
                &state_b,
            )
            .unwrap();

        let old_units =
            read_unit_rows(&read_tx, &oid.to_string(), "java", &JavaAdapter, &file).unwrap();
        assert_eq!(old_units.len(), old_meta.stored_unit_count);
        assert!(old_units.iter().any(|row| row.unit.short_name() == "Alpha"));
        assert!(!old_units.iter().any(|row| row.unit.short_name() == "Beta"));
        read_tx.commit().unwrap();
        drop(reader_conn);

        let hydrated = reader
            .hydrate_file_state_with_source(oid, "java", b, &JavaAdapter, &file, "class Beta {}\n")
            .unwrap()
            .unwrap();
        assert!(
            hydrated
                .declarations
                .iter()
                .any(|unit| unit.short_name() == "Beta")
        );
        assert!(
            !hydrated
                .declarations
                .iter()
                .any(|unit| unit.short_name() == "Alpha")
        );
    }
    #[test]
    fn stale_generation_reclamation_makes_one_oversize_progress_and_respects_small_budget() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Many.java",
            "class A {} class B {} class C {} class D {}\n",
        );
        let oid = oid_for(file.read_to_string().unwrap().as_bytes());
        let state = parse_state(&JavaAdapter, &file);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let a = store.ensure_language_epoch_value("java", "a").unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "java",
                a,
                &JavaAdapter,
                &state,
            )
            .unwrap();
        store.ensure_language_epoch_value("java", "b").unwrap();
        store
            .conn
            .lock()
            .expect("store mutex")
            .execute(
                "DELETE FROM blob_payload_costs WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java')",
                [oid.to_string()],
            )
            .unwrap();
        let reclaimed = store.reclaim_stale_generations(1).unwrap();
        assert!(reclaimed > 1, "one oversize blob must still make progress");
        let physical: usize = store
            .conn
            .lock()
            .expect("store mutex")
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(physical, 0);
        assert_eq!(store.reclaim_stale_generations(1).unwrap(), 0);

        let one = oid_for(b"one");
        let two = oid_for(b"two");
        let c = store.ensure_language_epoch_value("rust", "c").unwrap();
        store.register_blobs(&[one, two], "rust", c).unwrap();
        store.ensure_language_epoch_value("rust", "d").unwrap();
        assert_eq!(store.reclaim_stale_generations(1).unwrap(), 1);
        let remaining: usize = store
            .conn
            .lock()
            .expect("store mutex")
            .query_row(
                "SELECT COUNT(*) FROM blobs WHERE lang = 'rust'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 1);
    }
    #[test]
    fn prepared_blob_persistence_uses_bounded_transactions() {
        const PREPARED_BLOBS: usize = 257;
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model {}\n");
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store.reset_replacement_cost_lookup_queries_for_test();
        let prepared = (0..PREPARED_BLOBS)
            .map(|index| {
                let oid =
                    Oid::hash_object(ObjectType::Blob, format!("blob-{index}").as_bytes()).unwrap();
                AnalyzerStore::prepare_parsed_blob(
                    oid,
                    "java",
                    GenerationId::BOOTSTRAP,
                    &JavaAdapter,
                    Arc::clone(&state),
                )
                .unwrap()
            })
            .collect();

        let (outcomes, stats) = store.persist_prepared_blobs(
            prepared,
            PersistBatchTargets {
                max_blobs: 64,
                max_rows: usize::MAX,
                max_payload_bytes: usize::MAX,
            },
        );

        assert_eq!(stats.transactions, 5);
        assert_eq!(stats.committed_blobs, PREPARED_BLOBS);
        assert_eq!(stats.failed_transaction_attempts, 0);
        assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));
        assert_eq!(store.parsed_blob_transaction_starts_for_test(), 5);
        assert_eq!(
            store.replacement_cost_lookup_queries_for_test(),
            5,
            "each at-most-64-blob writer transaction must execute one VALUES lookup"
        );
    }
    #[test]
    fn prepared_replacement_cost_is_looked_up_once_per_writer_transaction() {
        const REPLACEMENTS: usize = 8;
        let temp = tempfile::TempDir::new().unwrap();
        let old_file = write_file(temp.path(), "Old.java", "class Old {}\n");
        let replacement_file =
            write_file(temp.path(), "Replacement.java", "class Replacement {}\n");
        let old_state = parse_state(&JavaAdapter, &old_file);
        let replacement_state = Arc::new(parse_state(&JavaAdapter, &replacement_file));
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation_a = store
            .ensure_language_epoch_value("java", "replacement-query-a")
            .unwrap();
        let oids = (0..REPLACEMENTS)
            .map(|index| oid_for(format!("replacement-query-{index}").as_bytes()))
            .collect::<Vec<_>>();
        for oid in &oids {
            store
                .write_parsed_blob_at_generation(
                    &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                    *oid,
                    "java",
                    generation_a,
                    &JavaAdapter,
                    &old_state,
                )
                .unwrap();
        }
        let generation_b = store
            .ensure_language_epoch_value("java", "replacement-query-b")
            .unwrap();
        let prepared = oids
            .iter()
            .copied()
            .map(|oid| {
                AnalyzerStore::prepare_parsed_blob(
                    oid,
                    "java",
                    generation_b,
                    &JavaAdapter,
                    Arc::clone(&replacement_state),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        store.reset_replacement_cost_lookup_queries_for_test();
        store.reset_prepared_generation_lookup_queries_for_test();
        let (outcomes, stats) =
            store.persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION);

        assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));
        assert_eq!(stats.transactions, 1);
        assert_eq!(stats.committed_blobs, REPLACEMENTS);
        let expected = AnalyzerStore::prepare_parsed_blob(
            oids[0],
            "java",
            generation_b,
            &JavaAdapter,
            Arc::clone(&replacement_state),
        )
        .unwrap();
        let conn = store.conn.lock().expect("store mutex");
        let expected_payload_bytes = measured_persisted_payload_bytes(&conn, &expected);
        assert_eq!(
            conn.query_row(
                "SELECT payload_bytes FROM blob_payload_costs
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java')",
                [oids[0].to_string()],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            expected_payload_bytes
        );
        assert_eq!(
            store.replacement_cost_lookup_queries_for_test(),
            1,
            "replacement roots must be fetched once as an ordinal-preserving set"
        );
        assert_eq!(store.replacement_cost_fallback_queries_for_test(), 0);
        assert_eq!(
            store.prepared_generation_lookup_queries_for_test(),
            1,
            "one language generation must be validated once per persistence batch"
        );
    }
    #[test]
    fn unicode_legacy_replacements_use_one_set_lookup_and_reused_fallback() {
        const REPLACEMENTS: usize = 3;
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Unicode.java",
            "package café; class Résumé { String naïve; }\n",
        );
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation_a = store
            .ensure_language_epoch_value("java", "unicode-legacy-a")
            .unwrap();
        let oids = (0..REPLACEMENTS)
            .map(|index| oid_for(format!("unicode-legacy-{index}").as_bytes()))
            .collect::<Vec<_>>();
        for oid in &oids {
            store
                .write_parsed_blob_at_generation(
                    &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                    *oid,
                    "java",
                    generation_a,
                    &JavaAdapter,
                    &state,
                )
                .unwrap();
        }
        let expected = AnalyzerStore::prepare_parsed_blob(
            oids[0],
            "java",
            generation_a,
            &JavaAdapter,
            Arc::clone(&state),
        )
        .unwrap();
        let conn = store.conn.lock().expect("store mutex");
        conn.execute(
            "DELETE FROM blob_payload_costs
             WHERE blob_id IN (SELECT id FROM blobs WHERE lang = 'java')",
            [],
        )
        .unwrap();
        let mut fallback_statement = conn
            .prepare_cached(persisted_blob_mutation_cost_fallback_sql())
            .unwrap();
        assert_eq!(
            persisted_blob_mutation_cost_fallback_statement(
                &mut fallback_statement,
                oids[0].to_string().as_str(),
                "java",
            )
            .unwrap(),
            PersistedMutationCost {
                logical_rows: expected.logical_rows().saturating_sub(1),
                payload_bytes: measured_persisted_payload_bytes(&conn, &expected),
            },
            "SQLite length() must count UTF-8 bytes like Rust String::len"
        );
        drop(fallback_statement);
        drop(conn);

        let generation_b = store
            .ensure_language_epoch_value("java", "unicode-legacy-b")
            .unwrap();
        let prepared = oids
            .iter()
            .map(|oid| {
                AnalyzerStore::prepare_parsed_blob(
                    *oid,
                    "java",
                    generation_b,
                    &JavaAdapter,
                    Arc::clone(&state),
                )
                .unwrap()
            })
            .collect();
        store.reset_replacement_cost_lookup_queries_for_test();
        let (outcomes, stats) =
            store.persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION);

        assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));
        assert_eq!(stats.transactions, 1);
        assert_eq!(stats.committed_blobs, REPLACEMENTS);
        assert_eq!(store.replacement_cost_lookup_queries_for_test(), 1);
        assert_eq!(
            store.replacement_cost_fallback_queries_for_test(),
            REPLACEMENTS
        );
    }
    #[brokk_bifrost_test_macros::hardwon(
        "21e73ad38a68: conflicting prepared generations could mix stale and current facts in one publication"
    )]
    #[test]
    fn conflicting_prepared_generations_isolate_the_stale_root() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model {}\n");
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation_a = store
            .ensure_language_epoch_value("java", "conflicting-generation-a")
            .unwrap();
        let stale_oid = oid_for(b"conflicting stale prepared blob");
        let stale = AnalyzerStore::prepare_parsed_blob(
            stale_oid,
            "java",
            generation_a,
            &JavaAdapter,
            Arc::clone(&state),
        )
        .unwrap();
        let generation_b = store
            .ensure_language_epoch_value("java", "conflicting-generation-b")
            .unwrap();
        let current_oid = oid_for(b"conflicting current prepared blob");
        let current = AnalyzerStore::prepare_parsed_blob(
            current_oid,
            "java",
            generation_b,
            &JavaAdapter,
            state,
        )
        .unwrap();

        store.reset_replacement_cost_lookup_queries_for_test();
        store.reset_prepared_generation_lookup_queries_for_test();
        let (outcomes, stats) = store.persist_prepared_blobs(
            vec![current, stale],
            PersistBatchTargets {
                max_blobs: usize::MAX,
                max_rows: usize::MAX,
                max_payload_bytes: usize::MAX,
            },
        );

        assert_eq!(stats.transactions, 1);
        assert_eq!(stats.committed_blobs, 1);
        assert_eq!(stats.committed_fragments, 1);
        assert_eq!(stats.failed_blobs, 1);
        assert_eq!(stats.failed_fragments, 1);
        assert_eq!(stats.failed_transaction_attempts, 2);
        assert!(outcomes[0].error.is_none());
        assert!(
            outcomes[1]
                .error
                .as_ref()
                .is_some_and(StoreError::is_stale_generation)
        );
        assert_eq!(store.prepared_generation_lookup_queries_for_test(), 2);
        assert_eq!(store.replacement_cost_lookup_queries_for_test(), 1);
        assert!(store.contains_parsed_blob(current_oid, "java").unwrap());
        assert!(!store.contains_parsed_blob(stale_oid, "java").unwrap());
    }
    #[test]
    fn replacement_cost_set_preserves_duplicate_order_and_distinguishes_all_states() {
        let temp = tempfile::TempDir::new().unwrap();
        let old_file = write_file(
            temp.path(),
            "Old.java",
            "class Old { int value; void method(int argument) {} }\n",
        );
        let old_state = Arc::new(parse_state(&JavaAdapter, &old_file));
        let complete_oid = oid_for(b"complete replacement cost");
        let root_only_oid = oid_for(b"root-only replacement cost");
        let missing_oid = oid_for(b"missing replacement cost");
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("java", "mixed-replacement-costs")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                complete_oid,
                "java",
                generation,
                &JavaAdapter,
                &old_state,
            )
            .unwrap();
        store
            .register_blobs(&[root_only_oid], "java", generation)
            .unwrap();
        let prepare = |oid| {
            AnalyzerStore::prepare_parsed_blob(
                oid,
                "java",
                generation,
                &JavaAdapter,
                Arc::clone(&old_state),
            )
            .unwrap()
        };
        let complete_prepared = prepare(complete_oid);
        let conn = store.conn.lock().expect("store mutex");
        let expected_complete = PersistedMutationCost {
            logical_rows: complete_prepared.logical_rows(),
            // Source bytes are part of the transient insertion budget but are not
            // stored in SQLite, so physical replacement cost excludes them.
            payload_bytes: measured_persisted_payload_bytes(&conn, &complete_prepared),
        };
        store.reset_replacement_cost_lookup_queries_for_test();
        let requested = vec![
            prepare(missing_oid),
            complete_prepared,
            prepare(root_only_oid),
            prepare(complete_oid),
        ];
        assert_eq!(
            store.stored_blob_cascade_costs(&conn, &requested).unwrap(),
            vec![
                StoredCascadeCost::Missing,
                StoredCascadeCost::Known(expected_complete),
                StoredCascadeCost::Known(PersistedMutationCost {
                    logical_rows: 1,
                    payload_bytes: 0,
                }),
                StoredCascadeCost::Known(expected_complete),
            ],
            "the ordinal-bearing VALUES relation must preserve order and duplicates"
        );
        assert_eq!(store.replacement_cost_lookup_queries_for_test(), 1);
        assert_eq!(store.replacement_cost_fallback_queries_for_test(), 0);

        let mut physical_cost_statement = conn
            .prepare_cached(persisted_blob_mutation_cost_fallback_sql())
            .unwrap();
        assert_eq!(
            persisted_blob_mutation_cost_fallback_statement(
                &mut physical_cost_statement,
                &complete_oid.to_string(),
                "java",
            )
            .unwrap(),
            expected_complete,
            "physical relations include signature parameters and the payload-cost row"
        );

        conn.execute(
            "UPDATE blobs
             SET cascade_logical_rows = 999, cascade_payload_bytes = 999
             WHERE blob_oid = ?1 AND lang = 'java'",
            [complete_oid.to_string()],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM blob_payload_costs WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java')",
            [complete_oid.to_string()],
        )
        .unwrap();
        store.reset_replacement_cost_lookup_queries_for_test();
        let legacy_request = vec![prepare(complete_oid)];
        assert_eq!(
            store
                .stored_blob_cascade_costs(&conn, &legacy_request)
                .unwrap(),
            vec![StoredCascadeCost::Legacy],
            "non-NULL v5 columns are not trustworthy byte costs and must be ignored"
        );
        let mut fallback_statement = conn
            .prepare_cached(persisted_blob_mutation_cost_fallback_sql())
            .unwrap();
        assert_eq!(
            persisted_blob_mutation_cost_fallback_statement(
                &mut fallback_statement,
                complete_oid.to_string().as_str(),
                "java",
            )
            .unwrap(),
            PersistedMutationCost {
                logical_rows: expected_complete.logical_rows.saturating_sub(1),
                payload_bytes: expected_complete.payload_bytes,
            },
            "a migrated parsed row without payload cost must use the legacy aggregate"
        );
        assert_eq!(store.replacement_cost_lookup_queries_for_test(), 1);
    }
    #[brokk_bifrost_test_macros::hardwon(
        "6098a8148fbc: concurrent cache repairs duplicated persistent writes for the same blob"
    )]
    #[test]
    fn simultaneous_identical_repairs_share_one_persistent_transaction() {
        const PRODUCERS: usize = 50;
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model {}\n");
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let db = temp.path().join("shared-cache.db");
        let stores = (0..PRODUCERS)
            .map(|_| Arc::new(AnalyzerStore::open_persistent(&db).unwrap()))
            .collect::<Vec<_>>();
        let writer_identity = stores[0].conn.identity();
        assert!(
            stores
                .iter()
                .all(|store| store.conn.identity() == writer_identity),
            "every session for the cache must share one writer actor"
        );
        let generation = stores[0]
            .ensure_language_epoch_value("java", "shared-repair-v1")
            .unwrap();
        let oid = oid_for(b"shared repair source");
        let prepared = (0..PRODUCERS)
            .map(|_| {
                AnalyzerStore::prepare_parsed_blob(
                    oid,
                    "java",
                    generation,
                    &JavaAdapter,
                    Arc::clone(&state),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        stores[0]
            .ensure_prepared_resolution_epochs(&prepared)
            .expect("initialize the shared resolution producer epoch");

        let initial_submissions = stores[0].conn.repair_submissions();
        let initial_transactions = stores[0].conn.repair_transactions();
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let blocker_store = Arc::clone(&stores[0]);
        let blocker = std::thread::spawn(move || {
            blocker_store.conn.execute(move |_| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
        });
        entered_rx.recv().unwrap();

        let barrier = Arc::new(std::sync::Barrier::new(PRODUCERS + 1));
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let mut producers = Vec::new();
        for (store, prepared) in stores.iter().cloned().zip(prepared) {
            let barrier = Arc::clone(&barrier);
            let result_tx = result_tx.clone();
            producers.push(std::thread::spawn(move || {
                barrier.wait();
                result_tx
                    .send(store.repair_prepared_blob(prepared))
                    .unwrap();
            }));
        }
        drop(result_tx);
        barrier.wait();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while stores[0].conn.repair_submissions() < initial_submissions + PRODUCERS {
            assert!(
                std::time::Instant::now() < deadline,
                "all repair producers must enqueue behind the blocked writer"
            );
            std::thread::yield_now();
        }
        release_tx.send(()).unwrap();

        for _ in 0..PRODUCERS {
            result_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("repair producer must receive its writer result")
                .unwrap();
        }
        blocker.join().unwrap();
        for producer in producers {
            producer.join().unwrap();
        }
        stores[0].conn.execute(|_| {});
        assert_eq!(
            stores[0].conn.repair_transactions() - initial_transactions,
            1,
            "identical queued repairs must persist one representative"
        );
        assert!(stores[0].contains_parsed_blob(oid, "java").unwrap());
    }
    #[test]
    fn prepared_blob_batches_respect_row_and_payload_caps() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model {}\n");
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let make = |index| {
            AnalyzerStore::prepare_parsed_blob(
                Oid::hash_object(ObjectType::Blob, format!("blob-{index}").as_bytes()).unwrap(),
                "java",
                GenerationId::BOOTSTRAP,
                &JavaAdapter,
                Arc::clone(&state),
            )
            .unwrap()
        };
        let sample = make(99);
        let row_cap = sample.logical_rows().saturating_mul(2);
        let byte_cap = sample.payload_bytes().saturating_mul(2);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let (_, stats) = store.persist_prepared_blobs(
            vec![make(0), make(1), make(2)],
            PersistBatchTargets {
                max_blobs: 64,
                max_rows: row_cap,
                max_payload_bytes: byte_cap,
            },
        );
        assert_eq!(stats.transactions, 2);
        assert!(stats.peak_batch_rows <= row_cap);
        assert!(stats.peak_batch_payload_bytes <= byte_cap);
    }
    #[test]
    fn oversized_singleton_prepared_blob_round_trips_above_grouping_targets() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model { int value; }\n");
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let oid = oid_for(b"oversized singleton");
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let prepared = AnalyzerStore::prepare_parsed_blob(
            oid,
            "java",
            GenerationId::BOOTSTRAP,
            &JavaAdapter,
            Arc::clone(&state),
        )
        .unwrap();
        let expected_rows = prepared.logical_rows();
        let expected_bytes = prepared.payload_bytes();
        store.reset_parsed_blob_transaction_starts_for_test();

        let (outcomes, stats) = store.persist_prepared_blobs(
            vec![prepared],
            PersistBatchTargets {
                max_blobs: 1,
                max_rows: 1,
                max_payload_bytes: 1,
            },
        );

        assert!(outcomes[0].error.is_none());
        assert_eq!(stats.transactions, 1);
        assert_eq!(stats.failed_transaction_attempts, 0);
        assert_eq!(stats.peak_batch_rows, expected_rows);
        assert_eq!(stats.peak_batch_payload_bytes, expected_bytes);
        assert_eq!(store.parsed_blob_transaction_starts_for_test(), 1);
        let hydrated = store
            .hydrate_file_state(oid, "java", &JavaAdapter, &file)
            .unwrap()
            .expect("the complete source must publish");
        assert_file_state_equivalent(&state, &hydrated);
    }
    #[test]
    fn oversized_prepared_replacement_isolated_by_full_mutation_cost() {
        let temp = tempfile::TempDir::new().unwrap();
        let old_file = write_file(
            temp.path(),
            "Old.java",
            "class A {} class B {} class C {} class D {} class E {} class F {}\n",
        );
        let replacement_file = write_file(temp.path(), "Replacement.java", "class Fresh {}\n");
        let peer_file = write_file(temp.path(), "Peer.java", "class Peer {}\n");
        let old_state = parse_state(&JavaAdapter, &old_file);
        let replacement_state = Arc::new(parse_state(&JavaAdapter, &replacement_file));
        let peer_state = Arc::new(parse_state(&JavaAdapter, &peer_file));
        let replaced_oid = oid_for(b"replaced logical identity");
        let peer_oid = oid_for(b"peer logical identity");
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation_a = store
            .ensure_language_epoch_value("java", "replacement-budget-a")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                replaced_oid,
                "java",
                generation_a,
                &JavaAdapter,
                &old_state,
            )
            .unwrap();
        // The legacy cascade_* columns on blobs are not populated or used by
        // publication. Measure the stored relations independently of the
        // writer's manifest-based batch lookup instead.
        let PersistedMutationCost {
            logical_rows: old_rows,
            payload_bytes: old_bytes,
        } = {
            let conn = store.conn.lock().unwrap();
            let mut statement = conn
                .prepare_cached(persisted_blob_mutation_cost_fallback_sql())
                .unwrap();
            persisted_blob_mutation_cost_fallback_statement(
                &mut statement,
                &replaced_oid.to_string(),
                "java",
            )
            .unwrap()
        };
        let generation_b = store
            .ensure_language_epoch_value("java", "replacement-budget-b")
            .unwrap();
        let replacement = AnalyzerStore::prepare_parsed_blob(
            replaced_oid,
            "java",
            generation_b,
            &JavaAdapter,
            Arc::clone(&replacement_state),
        )
        .unwrap();
        let replacement_insert_rows = replacement.logical_rows();
        let replacement_insert_bytes = replacement.payload_bytes();
        let peer = AnalyzerStore::prepare_parsed_blob(
            peer_oid,
            "java",
            generation_b,
            &JavaAdapter,
            peer_state,
        )
        .unwrap();
        let row_cap = replacement_insert_rows.saturating_add(peer.logical_rows());
        let byte_cap = replacement_insert_bytes.saturating_add(peer.payload_bytes());

        let (outcomes, stats) = store.persist_prepared_blobs(
            vec![replacement, peer],
            PersistBatchTargets {
                max_blobs: 8,
                max_rows: row_cap,
                max_payload_bytes: byte_cap,
            },
        );

        let replacement_outcome = outcomes
            .iter()
            .find(|outcome| outcome.prepared.oid() == replaced_oid)
            .expect("replacement outcome");
        assert!(
            replacement_outcome.error.is_none(),
            "one indivisible replacement must publish above grouping targets"
        );
        let peer_outcome = outcomes
            .iter()
            .find(|outcome| outcome.prepared.oid() == peer_oid)
            .expect("peer outcome");
        assert!(
            peer_outcome.error.is_none(),
            "a bounded peer still persists"
        );
        assert_eq!(stats.transactions, 2);
        assert_eq!(
            stats.failed_transaction_attempts, 1,
            "replacement cost must split the initial batch"
        );
        assert_eq!(stats.committed_blobs, 2);
        assert_eq!(stats.failed_blobs, 0);
        assert_eq!(stats.peak_batch_rows, replacement_insert_rows + old_rows);
        assert_eq!(
            stats.peak_batch_payload_bytes,
            replacement_insert_bytes + old_bytes
        );
        assert!(stats.peak_batch_rows > row_cap);
        assert!(store.contains_parsed_blob(replaced_oid, "java").unwrap());
        let stored_generation: i64 = store
            .conn
            .lock()
            .expect("store mutex")
            .query_row(
                "SELECT generation FROM blobs WHERE blob_oid = ?1 AND lang = 'java'",
                [replaced_oid.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_generation, generation_b.0);
        let hydrated = store
            .hydrate_file_state(replaced_oid, "java", &JavaAdapter, &replacement_file)
            .unwrap()
            .expect("replacement must be complete");
        assert_file_state_equivalent(&replacement_state, &hydrated);
    }
    #[test]
    fn failed_prepared_blob_isolated_without_hiding_good_peers() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model {}\n");
        let state = Arc::new(parse_state(&JavaAdapter, &file));
        let prepare = |text: &[u8]| {
            let oid = Oid::hash_object(ObjectType::Blob, text).unwrap();
            let prepared = AnalyzerStore::prepare_parsed_blob(
                oid,
                "java",
                GenerationId::BOOTSTRAP,
                &JavaAdapter,
                Arc::clone(&state),
            )
            .unwrap();
            (oid, prepared)
        };
        let (good_a_oid, good_a) = prepare(b"good-a");
        let (bad_oid, mut bad) = prepare(b"bad");
        bad.inject_invalid_range_for_test();
        let (good_b_oid, good_b) = prepare(b"good-b");
        let store = AnalyzerStore::open_ephemeral().unwrap();

        let (outcomes, stats) = store.persist_prepared_blobs(
            vec![good_a, bad, good_b],
            PersistBatchTargets {
                max_blobs: 64,
                max_rows: usize::MAX,
                max_payload_bytes: usize::MAX,
            },
        );

        assert!(store.contains_parsed_blob(good_a_oid, "java").unwrap());
        assert!(store.contains_parsed_blob(good_b_oid, "java").unwrap());
        assert!(!store.contains_parsed_blob(bad_oid, "java").unwrap());
        assert_eq!(store.content_row_count(bad_oid, "java").unwrap(), 0);
        assert_eq!(stats.committed_blobs, 2);
        assert_eq!(stats.failed_blobs, 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.error.is_some())
                .count(),
            1
        );
    }
    #[test]
    fn writer_is_idempotent_for_same_blob() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "src/demo/Repeat.java",
            "package demo;\nclass Repeat { int value; }\n",
        );
        let oid = oid_for(file.read_to_string().unwrap().as_bytes());
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_ephemeral().unwrap();

        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();
        let first_count = store.content_row_count(oid, "java").unwrap();
        store
            .write_parsed_blob(oid, "java", &adapter, &state)
            .unwrap();
        assert_eq!(store.content_row_count(oid, "java").unwrap(), first_count);
    }
    /// Nothing an import row stores may depend on where the file lives: two
    /// byte-identical files share one blob row. Writing the same source at two
    /// paths must therefore produce identical import rows.
    #[test]
    fn import_rows_are_content_stable_across_paths() {
        let temp = tempfile::TempDir::new().unwrap();
        let source = "package demo\nimport a.{B, C}\nimport d.E as F\nclass Uses\n";
        let first = write_file(temp.path(), "one/Uses.scala", source);
        let second = write_file(temp.path(), "two/other/Uses.scala", source);
        let oid = oid_for(source.as_bytes());

        let dump = |file: &ProjectFile| {
            let state = parse_state(&ScalaAdapter, file);
            let store = AnalyzerStore::open_ephemeral().unwrap();
            store
                .write_parsed_blob(oid, "scala", &ScalaAdapter, &state)
                .unwrap();
            let conn = store.conn.lock().expect("store mutex");
            let mut statement = conn
                .prepare(
                    "SELECT ordinal, statement, is_wildcard, is_global, identifier, alias,
                            path_kind, declaration_start_byte, binder_start, binder_end
                     FROM source_import_statements WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'scala')
                     ORDER BY ordinal",
                )
                .unwrap();
            let rows = statement
                .query_map([oid.to_string()], |row| {
                    Ok(format!(
                        "{:?}",
                        (
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            row.get::<_, Option<String>>(5)?,
                            row.get::<_, Option<String>>(6)?,
                            row.get::<_, Option<i64>>(7)?,
                            row.get::<_, Option<i64>>(8)?,
                            row.get::<_, Option<i64>>(9)?,
                        )
                    ))
                })
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            let mut children = conn
                .prepare(
                    "SELECT 'seg', ordinal, seg_ordinal, segment
                     FROM source_import_path_segments WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'scala')
                     UNION ALL
                     SELECT 'prefix', ordinal, prefix_ordinal, prefix
                     FROM source_import_lexical_prefixes WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'scala')
                     ORDER BY 1, 2, 3",
                )
                .unwrap()
                .query_map([oid.to_string()], |row| {
                    Ok(format!(
                        "{:?}",
                        (
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, String>(3)?,
                        )
                    ))
                })
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            assert!(
                !children.is_empty(),
                "canonical imports must expose their path segments and lexical prefixes"
            );
            children.sort();
            (rows, children)
        };

        assert!(!dump(&first).0.is_empty(), "fixture must persist imports");
        assert_eq!(dump(&first), dump(&second));
    }
    #[brokk_bifrost_test_macros::hardwon(
        "9527ec801458: batched package-fact reads must match per-blob results after startup query batching"
    )]
    #[test]
    fn workspace_package_fact_batch_matches_single_blob_queries() {
        let temp = tempfile::tempdir().unwrap();
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let mut oids = Vec::new();
        for (path, source) in [
            ("src/One.java", "package first.pkg; class One {}\n"),
            ("src/Two.java", "package second.pkg; class Two {}\n"),
        ] {
            let file = write_file(temp.path(), path, source);
            let oid = oid_for(source.as_bytes());
            store
                .write_parsed_blob(oid, "java", &JavaAdapter, &parse_state(&JavaAdapter, &file))
                .unwrap();
            oids.push(oid);
        }
        let generation = store.current_generation("java").unwrap();
        let batched = store
            .workspace_content_package_facts("java", generation, &oids, None)
            .unwrap()
            .facts
            .into_iter()
            .collect::<HashSet<_>>();
        let singles = oids
            .iter()
            .flat_map(|oid| {
                store
                    .workspace_content_package_facts("java", generation, &[*oid], None)
                    .unwrap()
                    .facts
            })
            .collect::<HashSet<_>>();
        assert!(!batched.is_empty(), "fixture must publish package facts");
        assert_eq!(batched, singles);
    }
    /// One short name, more rows than a poll interval, written across many
    /// blobs -- the shape a hot name has on a large workspace (`main` is 22k
    /// rows on the rustc tree).
    fn store_with_repeated_short_name(blobs: usize) -> (tempfile::TempDir, AnalyzerStore) {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "src/demo/Sample.java",
            "package demo; class Sample {}\n",
        );
        let adapter = JavaAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let mut workspace_files = Vec::with_capacity(blobs);
        for index in 0..blobs {
            let oid = oid_for(format!("sample blob {index}").as_bytes());
            store
                .write_parsed_blob(oid, "java", &adapter, &state)
                .unwrap();
            workspace_files.push(WorkspaceFileRow {
                rel_path: format!("src/demo/Sample_{index}.java"),
                blob_oid: oid,
            });
        }
        store
            .sync_workspace_snapshot(
                "java",
                GenerationId::BOOTSTRAP,
                &workspace_files,
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        (temp, store)
    }

    use rusqlite::params;
}
