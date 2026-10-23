#[cfg(test)]
mod python_extraction_tests {
    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;
    use rusqlite::params;

    pub(super) use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    pub(super) use std::sync::Arc;

    pub(super) use brokk_bifrost_core::analyzer::model::CodeUnitType;

    pub(super) use brokk_bifrost_analysis::analyzer::store::GenerationId;

    pub(super) use brokk_bifrost_core::hash::HashMap;

    pub(super) use brokk_bifrost_core::hash::HashSet;

    pub(super) use git2::Oid;

    pub(super) use brokk_bifrost_analysis::analyzer::store::PathSymbolRow;

    pub(super) use brokk_bifrost_analysis::analyzer::store::PersistBatchTargets;

    pub(super) use brokk_bifrost_analysis::analyzer::store::REVERSE_IMPORT_CANDIDATE_BLOBS_SQL;

    pub(super) use brokk_bifrost_analysis::analyzer::store::WorkspaceFileRow;

    pub(super) use brokk_bifrost_analysis::analyzer::store::WorkspaceId;

    pub(super) use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId;

    pub(super) use brokk_bifrost_analysis::analyzer::store::test_support::assert_file_state_equivalent;

    pub(super) use brokk_bifrost_analysis::analyzer::store::epoch;

    pub(super) use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

    pub(super) use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

    pub(super) use brokk_bifrost_analysis::analyzer::store::sync_reverse_reference_lookup_keys;

    use brokk_bifrost_core::test_support::write_file;

    use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

    use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

    use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context;

    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;

    use brokk_bifrost_python_analysis::analyzer::python::PythonAdapter;

    use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;

    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    use brokk_bifrost_analysis::analyzer::store::test_support::assert_prior_parsed_blob_invalidated;

    #[brokk_bifrost_test_macros::hardwon(
        "4b3f6065fca9: batched parsed-blob membership must preserve mixed-language and incomplete-key semantics"
    )]
    #[test]
    fn parsed_blob_keys_batches_mixed_languages_and_incomplete_rows() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let python_file = write_file(root, "pkg/model.py", "class Model:\n    pass\n");
        let java_file = write_file(root, "src/Model.java", "class Model {}\n");
        let python_oid = oid_for(python_file.read_to_string().unwrap().as_bytes());
        let java_oid = oid_for(java_file.read_to_string().unwrap().as_bytes());
        let incomplete_oid = oid_for(b"registered but not parsed");
        let missing_oid = oid_for(b"not registered");
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(
                python_oid,
                "python",
                &PythonAdapter::for_test_file(&python_file),
                &parse_state(&PythonAdapter::for_test_file(&python_file), &python_file),
            )
            .unwrap();
        store
            .write_parsed_blob(
                java_oid,
                "java",
                &JavaAdapter,
                &parse_state(&JavaAdapter, &java_file),
            )
            .unwrap();
        store
            .register_blobs(&[incomplete_oid], "rust", GenerationId::BOOTSTRAP)
            .unwrap();

        let mut entries = vec![
            (python_oid, "python".to_string()),
            (python_oid, "java".to_string()),
            (java_oid, "java".to_string()),
            (incomplete_oid, "rust".to_string()),
            (missing_oid, "python".to_string()),
            (python_oid, "python".to_string()),
        ];
        let bulk_missing = (0..405)
            .map(|index| oid_for(format!("bulk missing {index}").as_bytes()))
            .collect::<Vec<_>>();
        entries.extend(bulk_missing.iter().map(|oid| (*oid, "python".to_string())));
        assert_eq!(
            store.parsed_blob_keys(&entries).unwrap(),
            [
                (python_oid, "python".to_string()),
                (java_oid, "java".to_string()),
            ]
            .into_iter()
            .collect::<HashSet<_>>()
        );
        let missing = store.missing_parsed_blob_keys(&entries).unwrap();
        assert_eq!(missing.len(), 408);
        assert!(missing.contains(&(python_oid, "java".to_string())));
        assert!(missing.contains(&(incomplete_oid, "rust".to_string())));
        assert!(missing.contains(&(missing_oid, "python".to_string())));
        assert!(
            bulk_missing
                .iter()
                .all(|oid| missing.contains(&(*oid, "python".to_string())))
        );
    }
    #[test]
    fn metadata_unit_count_mismatch_is_treated_as_incomplete() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(root, "pkg/corrupt.py", "class Corrupt:\n    pass\n");
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = PythonAdapter::for_test_file(&file);
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "python", &adapter, &state)
            .unwrap();

        {
            let conn = store.conn.lock().unwrap();
            assert!(
                conn.execute(
                    "DELETE FROM code_units WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'python')",
                    [oid.to_string()],
                )
                .is_err()
            );
            // Canonical source links prevent deleting published units. Damage
            // the expected count directly to exercise independent read checks.
            conn.execute(
                "UPDATE blob_meta SET stored_unit_count = stored_unit_count + 1
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'python')",
                [oid.to_string()],
            )
            .unwrap();
        }

        assert!(!store.contains_parsed_blob(oid, "python").unwrap());
        assert!(
            store
                .hydrate_file_state(oid, "python", &adapter, &file)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn unknown_optional_fact_kind_fails_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "pkg/unknown.py", "class Unknown:\n    pass\n");
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(
                oid,
                "python",
                &PythonAdapter::for_test_file(&file),
                &parse_state(&PythonAdapter::for_test_file(&file), &file),
            )
            .unwrap();

        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO blob_optional_fact_manifest(blob_id, fact_kind, row_count)
                 VALUES(
                   (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'python'),
                   99, 1
                 )",
                [oid.to_string()],
            )
            .unwrap();
        }

        assert!(!store.contains_parsed_blob(oid, "python").unwrap());
        let error = store
            .hydrate_file_state(oid, "python", &PythonAdapter::for_test_file(&file), &file)
            .unwrap_err();
        assert!(error.to_string().contains("unknown optional analyzer fact"));
    }
    /// #3451: Python now records callable modifier metadata, and it recorded
    /// none before. A blob persisted under the prior epoch deserializes as
    /// "nobody read the modifiers", which is indistinguishable from a callable
    /// whose adapter honestly never looked, so `receiver_contract_of` reports
    /// no contract and every Python procedure summary stays inert. The salt is
    /// the only thing that retires those rows.
    #[brokk_bifrost_test_macros::hardwon(
        "#3451: persisted Python callables lacked modifier metadata needed for receiver contracts"
    )]
    #[test]
    fn python_callable_modifier_metadata_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "widget.py",
            "class Widget:\n    @staticmethod\n    def build(spec):\n        return spec\n\n    def render(self, target):\n        return target\n",
        );
        let state = Arc::new(parse_state(&PythonAdapter::for_test_file(&file), &file));
        let prior_epoch = epoch::python_epoch_before_callable_modifier_metadata();
        assert_prior_parsed_blob_invalidated(
            &PythonAdapter::for_test_file(&file),
            state.as_ref(),
            &prior_epoch,
        );
    }
    #[test]
    fn parsed_blob_presence_allows_zero_persisted_units() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let file = write_file(root, "pkg/side_effect_only.py", "import os\n");
        let source = file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = PythonAdapter::for_test_file(&file);
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_ephemeral().unwrap();

        store
            .write_parsed_blob(oid, "python", &adapter, &state)
            .unwrap();

        assert!(store.contains_parsed_blob(oid, "python").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "python".to_string())])
                .unwrap(),
            Vec::<(Oid, String)>::new()
        );
        let hydrated = store
            .hydrate_file_state(oid, "python", &adapter, &file)
            .unwrap()
            .unwrap();
        assert_file_state_equivalent(&state, &hydrated);
    }
    #[test]
    fn candidate_and_path_queries_do_not_leak_across_generation_cutover() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "Model.java", "class Model {}\n");
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
            .unwrap();
        let langs = vec!["java".to_string()];
        let a_map = HashMap::from_iter([("java".to_string(), a)]);
        assert!(
            !store
                .declaration_candidate_rows_for_langs(&langs, &a_map)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .path_symbol_rows_by_fqn_for_langs(&langs, &a_map, "Model", "Model")
                .unwrap()
                .len(),
            1
        );

        // Keep both query sources nonempty: exact and normalized lookups must
        // share one cap, including when they admit the same persisted row.
        let normalized_row = PathSymbolRow {
            normalized_fqn: "normalized.Model".to_string(),
            ..row.clone()
        };
        let second_file = write_file(temp.path(), "Other.java", "class Model {}\n");
        assert_eq!(
            oid_for(second_file.read_to_string().unwrap().as_bytes()),
            oid
        );
        let second_row = PathSymbolRow {
            rel_path: "Other.java".to_string(),
            ..normalized_row.clone()
        };
        let snapshot_a = store
            .sync_workspace_snapshot(
                "java",
                a,
                &[
                    WorkspaceFileRow {
                        rel_path: row.rel_path.clone(),
                        blob_oid: oid,
                    },
                    WorkspaceFileRow {
                        rel_path: second_row.rel_path.clone(),
                        blob_oid: oid,
                    },
                ],
                &[normalized_row.clone(), second_row],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        let selected_a = HashMap::from_iter([("java".to_string(), snapshot_a)]);
        let bounded = |limit, continue_query: &mut dyn FnMut() -> bool| {
            store
                .path_symbol_rows_by_fqn_for_langs_limited_at_snapshots(
                    &selected_a,
                    &langs,
                    &a_map,
                    ("Model", "normalized.Model"),
                    limit,
                    continue_query,
                )
                .unwrap()
        };
        let ample = bounded(5, &mut || true);
        assert!(ample.complete);
        assert_eq!(ample.inspected, 4);
        assert_eq!(ample.rows.len(), 4);
        assert!(ample.rows.iter().all(|(lang, item)| lang == "java"
            && matches!(item.rel_path.as_str(), "Model.java" | "Other.java")
            && item.blob_oid == oid));
        for limit in [0, 1, 2, 3, 4] {
            let capped = bounded(limit, &mut || true);
            assert!(!capped.complete, "reaching the cap is not an absence proof");
            assert_eq!(capped.inspected, limit);
            assert_eq!(capped.rows.len(), limit);
        }
        let stopped = bounded(5, &mut || false);
        assert!(!stopped.complete);
        assert!(stopped.rows.is_empty());
        assert_eq!(stopped.inspected, 0);
        let mut polls = 0;
        let interrupted = bounded(5, &mut || {
            polls += 1;
            polls <= 2
        });
        assert!(!interrupted.complete);
        assert_eq!(interrupted.inspected, 1);
        assert_eq!(interrupted.rows.len(), 1);
        assert_eq!(interrupted.rows[0].1.rel_path, "Model.java");
        let missing = store
            .path_symbol_rows_by_fqn_for_langs_limited_at_snapshots(
                &selected_a,
                &langs,
                &a_map,
                ("Missing", "normalized.Missing"),
                3,
                || true,
            )
            .unwrap();
        assert!(missing.complete);
        assert!(missing.rows.is_empty());
        assert_eq!(missing.inspected, 0);

        // These are generic storage rows, not Java/Python resolution. A second
        // language proves the cap is not reset for each language's SQL cursor.
        let python_file = write_file(temp.path(), "other.py", "pass\n");
        let python_adapter = PythonAdapter::for_test_file(&python_file);
        let python_oid = oid_for(python_file.read_to_string().unwrap().as_bytes());
        let python_generation = store.ensure_language_epoch_value("python", "a").unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                python_oid,
                "python",
                python_generation,
                &python_adapter,
                &parse_state(&python_adapter, &python_file),
            )
            .unwrap();
        let python_row = PathSymbolRow {
            rel_path: "other.py".to_string(),
            blob_oid: python_oid,
            ..normalized_row.clone()
        };
        let python_snapshot = store
            .sync_workspace_snapshot(
                "python",
                python_generation,
                &[WorkspaceFileRow {
                    rel_path: python_row.rel_path.clone(),
                    blob_oid: python_oid,
                }],
                &[python_row],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        let mut selected_both = selected_a.clone();
        selected_both.insert("python".to_string(), python_snapshot);
        let both_langs = vec!["java".to_string(), "python".to_string()];
        let both_generations = HashMap::from_iter([
            ("java".to_string(), a),
            ("python".to_string(), python_generation),
        ]);
        let across_languages = |limit| {
            store
                .path_symbol_rows_by_fqn_for_langs_limited_at_snapshots(
                    &selected_both,
                    &both_langs,
                    &both_generations,
                    ("Model", "normalized.Model"),
                    limit,
                    || true,
                )
                .unwrap()
        };
        let capped_languages = across_languages(5);
        assert!(!capped_languages.complete);
        assert_eq!(capped_languages.inspected, 5);
        assert_eq!(
            capped_languages
                .rows
                .iter()
                .map(|(lang, _)| lang.as_str())
                .collect::<Vec<_>>(),
            vec!["java", "java", "java", "java", "python"]
        );
        let all_languages = across_languages(7);
        assert!(all_languages.complete);
        assert_eq!(all_languages.inspected, 6);
        assert_eq!(
            all_languages
                .rows
                .iter()
                .map(|(lang, _)| lang.as_str())
                .collect::<Vec<_>>(),
            vec!["java", "java", "java", "java", "python", "python"]
        );

        let b = store.ensure_language_epoch_value("java", "b").unwrap();
        let b_map = HashMap::from_iter([("java".to_string(), b)]);
        assert!(
            store
                .declaration_candidate_rows_for_langs(&langs, &a_map)
                .unwrap_err()
                .is_stale_generation()
        );
        assert!(
            store
                .declaration_candidate_rows_for_langs(&langs, &b_map)
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .path_symbol_rows_by_fqn_for_langs(&langs, &b_map, "Model", "Model")
                .unwrap()
                .is_empty()
        );

        assert!(
            store
                .path_symbol_rows_by_fqn_for_langs_limited_at_snapshots(
                    &selected_a,
                    &langs,
                    &a_map,
                    ("Model", "normalized.Model"),
                    8,
                    || true,
                )
                .unwrap_err()
                .is_stale_generation()
        );
        let after_cutover = store
            .path_symbol_rows_by_fqn_for_langs_limited_at_snapshots(
                &selected_a,
                &langs,
                &b_map,
                ("Model", "normalized.Model"),
                8,
                || true,
            )
            .unwrap();
        assert!(after_cutover.complete);
        assert!(after_cutover.rows.is_empty());
        assert_eq!(after_cutover.inspected, 0);

        let current_file = write_file(temp.path(), "Model.java", "class Model { int current; }\n");
        let current_oid = oid_for(current_file.read_to_string().unwrap().as_bytes());
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                current_oid,
                "java",
                b,
                &JavaAdapter,
                &parse_state(&JavaAdapter, &current_file),
            )
            .unwrap();
        let current_row = PathSymbolRow {
            blob_oid: current_oid,
            ..normalized_row
        };
        let snapshot_b = store
            .sync_workspace_snapshot(
                "java",
                b,
                &[WorkspaceFileRow {
                    rel_path: current_row.rel_path.clone(),
                    blob_oid: current_oid,
                }],
                &[current_row],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        let selected_b = HashMap::from_iter([("java".to_string(), snapshot_b)]);
        let current = store
            .path_symbol_rows_by_fqn_for_langs_limited_at_snapshots(
                &selected_b,
                &langs,
                &b_map,
                ("Model", "normalized.Model"),
                8,
                || true,
            )
            .unwrap();
        assert!(current.complete);
        assert_eq!(current.inspected, 2);
        assert_eq!(current.rows.len(), 2);
        assert!(
            current
                .rows
                .iter()
                .all(|(_, item)| item.blob_oid == current_oid)
        );
        assert_ne!(current_oid, oid);
        assert!(
            store
                .path_symbol_rows_by_fqn_for_langs_limited_at_snapshots(
                    &selected_b,
                    &langs,
                    &a_map,
                    ("Model", "normalized.Model"),
                    8,
                    || true,
                )
                .unwrap_err()
                .is_stale_generation()
        );
    }
    #[test]
    fn limited_identifier_candidate_seeks_the_identifier_index_with_both_statistics_states() {
        for state in PlannerStatisticsState::BOTH {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(temp.path(), "src/lib.rs", "pub struct Widget;\n");
            let oid = oid_for(file.read_to_string().unwrap().as_bytes());
            let store = AnalyzerStore::open_ephemeral().unwrap();
            store
                .write_parsed_blob(oid, "rust", &RustAdapter, &parse_state(&RustAdapter, &file))
                .unwrap();

            let conn = store.conn.lock().expect("store mutex");
            prepare_pin_context(&conn);
            conn.execute(
                "INSERT INTO temp.declaration_candidate_requests(
                   request_ordinal, lang, identifier, request_limit
                 ) VALUES (0, 'rust', 'Widget', 16)",
                [],
            )
            .unwrap();
            state.install(&conn);
            let plan = explain_pin(&conn, &pinned("limited_identifier_candidate"));

            assert!(
                plan.iter().any(|detail| detail
                    .contains("SEARCH units USING INDEX idx_code_units_lang_identifier_lookup")),
                "limited candidate query must seek the identifier index {state}: {plan:#?}"
            );
            assert!(
                plan.iter().all(|detail| {
                    !detail.contains("SCAN units")
                        && !detail.contains("AUTOMATIC")
                        && !detail.contains("CO-ROUTINE")
                }),
                "limited candidate query must retain indexed execution {state}: {plan:#?}"
            );
        }
    }

    #[test]
    fn round_trips_python_crlf_class_signature() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let python_file = write_file(
            root,
            "pkg/documented.py",
            "# Comment before class\r\nclass DocumentedClass:\r\n    pass\r\n",
        );
        let source = python_file.read_to_string().unwrap();
        let oid = oid_for(source.as_bytes());
        let adapter = PythonAdapter::for_test_file(&python_file);
        let parsed = parse_state(&adapter, &python_file);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "python", &adapter, &parsed)
            .unwrap();

        let hydrated = store
            .hydrate_file_state(oid, "python", &adapter, &python_file)
            .unwrap()
            .unwrap();
        assert_file_state_equivalent(&parsed, &hydrated);
        assert!(
            hydrated
                .signatures
                .values()
                .flatten()
                .any(|signature| signature == "class DocumentedClass:"),
            "expected CRLF class signature to survive store round trip, got {:?}",
            hydrated.signatures
        );
    }
    #[test]
    fn identical_python_blob_hydrates_with_live_path_names() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let content = "class Shared:\n    def run(self):\n        return 1\n";
        let _ = write_file(root, "pkg_a/__init__.py", "");
        let _ = write_file(root, "pkg_b/__init__.py", "");
        let _ = write_file(root, "pkg_b/sub/__init__.py", "");
        let file_a = write_file(root, "pkg_a/mod.py", content);
        let file_b = write_file(root, "pkg_b/sub/mod.py", content);
        let oid = oid_for(content.as_bytes());
        let adapter = PythonAdapter::for_test_file(&file_a);
        let state_a = parse_state(&adapter, &file_a);
        let state_b = parse_state(&adapter, &file_b);
        let store = AnalyzerStore::open_ephemeral().unwrap();

        store
            .write_parsed_blob(oid, "python", &adapter, &state_a)
            .unwrap();
        let first_count = store.content_row_count(oid, "python").unwrap();
        store
            .write_parsed_blob(oid, "python", &adapter, &state_b)
            .unwrap();
        assert_eq!(store.content_row_count(oid, "python").unwrap(), first_count);

        let hydrated_a = store
            .hydrate_file_state(oid, "python", &adapter, &file_a)
            .unwrap()
            .unwrap();
        let hydrated_b = store
            .hydrate_file_state(oid, "python", &adapter, &file_b)
            .unwrap()
            .unwrap();
        assert_file_state_equivalent(&state_a, &hydrated_a);
        assert_file_state_equivalent(&state_b, &hydrated_b);
        assert_eq!(hydrated_a.package_name, "pkg_a.mod");
        assert_eq!(hydrated_b.package_name, "pkg_b.sub.mod");
        assert!(
            hydrated_a
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "pkg_a.mod.Shared")
        );
        assert!(
            hydrated_b
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "pkg_b.sub.mod.Shared")
        );
    }
    #[brokk_bifrost_test_macros::hardwon(
        "85a5d7d8ac62: Java reverse-import candidate reads scanned globally instead of following seed names"
    )]
    #[test]
    fn reverse_reference_candidates_use_name_first_indexes() {
        for state in PlannerStatisticsState::BOTH {
            reverse_reference_candidates_use_name_first_indexes_in(state);
        }
    }
    fn reverse_reference_candidates_use_name_first_indexes_in(state: PlannerStatisticsState) {
        let fixture = crate::inline_project::InlineTestProject::with_language(
            brokk_bifrost_core::analyzer::model::Language::Java,
        )
        .file(
            "src/Canonical.java",
            "import pkg.Target; class Canonical {}\n",
        )
        .file(
            "src/Distractor.java",
            "import noise.Other; class Distractor {}\n",
        )
        .build();
        let canonical_state = parse_state(&JavaAdapter, &fixture.file("src/Canonical.java"));
        let distractor_state = parse_state(&JavaAdapter, &fixture.file("src/Distractor.java"));
        let canonical_oid = oid_for(canonical_state.source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(canonical_oid, "java", &JavaAdapter, &canonical_state)
            .unwrap();
        let generation = store.current_generation("java").unwrap();
        let canonical_distractor_oids: Vec<_> = (0..900)
            .map(|index| oid_for(format!("canonical reverse distractor {index}").as_bytes()))
            .collect();
        let prepared = canonical_distractor_oids
            .iter()
            .map(|oid| {
                AnalyzerStore::prepare_parsed_blob(
                    *oid,
                    "java",
                    generation,
                    &JavaAdapter,
                    Arc::new(distractor_state.clone()),
                )
                .unwrap()
            })
            .collect();
        let (outcomes, stats) =
            store.persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION);
        assert_eq!(stats.committed_blobs, canonical_distractor_oids.len());
        assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));
        let conn = store.conn.lock().expect("store mutex");
        let workspace_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        conn.execute(
            "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
             VALUES(?1, 'java', ?2, 1)",
            params![workspace_id, generation.get()],
        )
        .unwrap();
        let projection_digest = "0".repeat(64);
        let mut expected_paths = std::collections::BTreeSet::new();
        let insert_file = |oid: Oid, path: String| {
            conn.execute(
                "INSERT INTO workspace_file_versions(
                   workspace_id, lang, generation, rel_path, blob_oid,
                   projection_digest, valid_from
                 ) VALUES(?1, 'java', ?2, ?3, ?4, ?5, 1)",
                params![
                    workspace_id,
                    generation.get(),
                    path,
                    oid.to_string(),
                    projection_digest
                ],
            )
            .unwrap();
        };
        insert_file(canonical_oid, "src/Canonical.java".to_owned());
        expected_paths.insert("src/Canonical.java".to_owned());
        for (index, oid) in canonical_distractor_oids.iter().enumerate() {
            insert_file(*oid, format!("src/canonical-distractor-{index}.java"));
        }
        let snapshots = [(
            "java".to_owned(),
            WorkspaceSnapshotId {
                workspace_id: WorkspaceId(workspace_id.to_owned()),
                lang: "java".to_owned(),
                generation,
                revision: 1,
            },
        )]
        .into_iter()
        .collect();
        store
            .select_writer_workspace_snapshots(&conn, &snapshots)
            .unwrap();
        sync_reverse_reference_lookup_keys(
            &conn,
            &["Target".to_string(), "Deserialize".to_string()]
                .into_iter()
                .collect(),
            &["java".to_string()].into_iter().collect(),
            &["Target".to_string()].into_iter().collect(),
        )
        .unwrap();
        let execute_imports = || {
            conn.prepare(REVERSE_IMPORT_CANDIDATE_BLOBS_SQL)
                .unwrap()
                .query_map(["java"], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()
                .unwrap()
        };

        state.install(&conn);
        let imports = explain_pin(&conn, &pinned("reverse_import_candidate_blobs"));
        assert_eq!(execute_imports(), expected_paths);
        {
            let label = state;
            assert!(
                imports.iter().any(|detail| {
                    detail.contains(
                        "SEARCH segments USING COVERING INDEX idx_source_import_segments_by_segment",
                    )
                }),
                "canonical reverse import lookup must seek the source segment ({label}): {imports:#?}"
            );
            assert!(
                imports.iter().all(|detail| {
                    !detail.contains("SCAN segments")
                        && !detail.contains("SCAN source_import_segments")
                        && !detail.contains("SCAN links")
                        && !detail.contains("SCAN imports")
                        && !detail.contains("SCAN source_imports")
                        && !detail.contains("SCAN import_statements")
                        && !detail.contains("SCAN keys")
                        && !detail.contains("SCAN files")
                }),
                "reverse import lookup must not scan persisted candidate tables ({label}): {imports:#?}"
            );
            assert!(
                imports
                    .iter()
                    .any(|detail| { detail.contains("idx_workspace_file_versions_snapshot_blob") }),
                "reverse import lookup must seek snapshot membership by blob ({label}): {imports:#?}"
            );
        }

        let identifiers = explain_pin(&conn, &pinned("reverse_type_candidate_blobs"));
        assert!(
            identifiers.iter().any(|detail| {
                detail.contains(
                    "SEARCH identifiers USING COVERING INDEX idx_reference_identifiers_by_identifier",
                )
            }),
            "reverse type lookup must seek the requested identifier {state}: {identifiers:#?}"
        );
        assert!(
            identifiers
                .iter()
                .all(|detail| !detail.contains("SCAN identifiers")),
            "reverse type lookup must not scan reference_identifiers {state}: {identifiers:#?}"
        );

        let paths = explain_pin(&conn, &pinned("reverse_identifier_candidate_paths"));
        assert!(
            paths.iter().any(|detail| detail.contains(
                "SEARCH identifiers USING COVERING INDEX idx_reference_identifiers_by_identifier"
            )),
            "reverse path lookup must seek the requested identifier {state}: {paths:#?}"
        );
        assert!(
            paths
                .iter()
                .any(|detail| detail.contains("idx_workspace_file_versions_snapshot_blob")),
            "reverse path lookup must seek snapshot membership by blob {state}: {paths:#?}"
        );
        assert!(
            paths.iter().all(|detail| {
                !detail.contains("SCAN identifiers") && !detail.contains("SCAN files")
            }),
            "reverse path lookup must not scan persisted facts {state}: {paths:#?}"
        );
        assert!(
            identifiers
                .iter()
                .any(|detail| { detail.contains("idx_workspace_file_versions_snapshot_blob") }),
            "reverse type lookup must seek snapshot membership by blob {state}: {identifiers:#?}"
        );
    }
}
