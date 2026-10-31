#[cfg(test)]
mod tests {
    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;

    use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;

    use brokk_bifrost_analysis::analyzer::store::test_support::assert_prior_parsed_blob_invalidated;

    pub(super) use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    pub(super) use std::sync::Arc;

    pub(super) use brokk_bifrost_analysis::analyzer::store::GenerationId;

    pub(super) use brokk_bifrost_core::hash::HashMap;

    pub(super) use brokk_bifrost_core::analyzer::model::Language;

    pub(super) use brokk_bifrost_analysis::analyzer::store::MAX_LIMITED_QUERY_ROW_BYTES;

    pub(super) use brokk_bifrost_core::analyzer::model::PackageAnchor;

    pub(super) use brokk_bifrost_core::analyzer::model::ProjectFile;

    pub(super) use brokk_bifrost_analysis::analyzer::store::epoch;

    pub(super) use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

    pub(super) use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

    pub(super) use brokk_bifrost_analysis::analyzer::store::usize_to_i64;

    use brokk_bifrost_core::test_support::write_file;

    #[test]
    fn resource_bound_oversized_current_epoch_import_row_fails_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "main.go",
            "package sample\nimport \"fmt\"\nfunc run() { fmt.Println(\"ok\") }\n",
        );
        let state = parse_state(&GoAdapter, &file);
        assert_eq!(state.imports.len(), 1, "fixture should persist one import");
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("go", "limited-import-row-bytes-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &crate::analyzer::store::test_blob_file(),
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"),
                generation,
                &GoAdapter,
                &state,
            )
            .unwrap();
        let ordinary = store
            .import_infos_for_key_limited(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"),
                generation,
                usize::MAX,
            )
            .unwrap();
        assert!(ordinary.complete);
        assert_eq!(ordinary.rows, state.imports);

        {
            let conn = store.conn.lock().unwrap();
            // Corrupt one canonical row deliberately; ordinary publication
            // cannot mutate sealed import facts.
            conn.execute_batch("DROP TRIGGER source_imports_no_update_after_seal")
                .unwrap();
            assert_eq!(
                conn.execute(
                    // `hex` doubles its argument's length, so this writes a
                    // statement two bytes past the per-row cap.
                    "UPDATE source_imports
                     SET statement = hex(zeroblob(?3))
                     WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)",
                    rusqlite::params![
                        oid.to_string(),
                        "go",
                        usize_to_i64(MAX_LIMITED_QUERY_ROW_BYTES / 2 + 1).unwrap(),
                    ],
                )
                .unwrap(),
                1
            );
        }

        let limited = store
            .import_infos_for_key_limited(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"),
                generation,
                usize::MAX,
            )
            .unwrap();
        assert!(!limited.complete);
        assert!(limited.rows.is_empty());
        assert_eq!(limited.inspected, 1);
    }
    #[test]
    fn resource_bound_inconsistent_current_epoch_import_count_fails_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "main.go",
            "package sample\nimport (\n  \"fmt\"\n  \"os\"\n)\nfunc run() { fmt.Println(os.Args) }\n",
        );
        let state = parse_state(&GoAdapter, &file);
        assert_eq!(state.imports.len(), 2, "fixture should persist two imports");
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("go", "limited-import-count-integrity-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &crate::analyzer::store::test_blob_file(),
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"),
                generation,
                &GoAdapter,
                &state,
            )
            .unwrap();

        {
            let conn = store.conn.lock().unwrap();
            assert_eq!(
                conn.execute(
                    "UPDATE blob_meta
                     SET import_statement_count = 1
                     WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)",
                    rusqlite::params![oid.to_string(), "go"],
                )
                .unwrap(),
                1
            );
        }

        let capped = store
            .import_infos_for_key_limited(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"),
                generation,
                1,
            )
            .unwrap();
        assert!(!capped.complete);
        assert_eq!(capped.rows.len(), 1);
        assert_eq!(capped.inspected, 1);

        let wider = store
            .import_infos_for_key_limited(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"),
                generation,
                3,
            )
            .unwrap();
        assert!(!wider.complete);
        assert_eq!(wider.rows.len(), 2);
        assert_eq!(wider.inspected, 2);
    }
    #[test]
    fn checked_import_facts_require_and_recover_source_publication() {
        let content = "package main\nfunc main() {}\n";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Go)
            .file("main.go", content)
            .build();
        let file = fixture.file("main.go");
        let oid = oid_for(content.as_bytes());
        let adapter = GoAdapter;
        let state = parse_state(&adapter, &file);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generations = HashMap::from_iter([("go".to_string(), GenerationId::BOOTSTRAP)]);
        let entry = [(
            file.clone(),
            brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"),
        )];

        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"),
                &adapter,
                &state,
            )
            .unwrap();
        let complete = store
            .hydrate_canonical_import_facts_by_key(&entry, &generations, &adapter)
            .unwrap();
        assert_eq!(complete.get(&file).unwrap().imports, Vec::new());

        {
            let conn = store.conn.lock().unwrap();
            // Deliberately damage publication witnesses, not their sealed
            // children. The Go family seal otherwise correctly rejects the
            // source-manifest cascade through occurrence-linked type rows.
            conn.execute_batch(
                "DROP TRIGGER source_go_manifests_no_delete_after_seal;
                 DELETE FROM source_go_manifests;
                 DROP TRIGGER source_fact_manifests_no_direct_delete;",
            )
            .unwrap();
            conn.execute(
                "DELETE FROM source_fact_manifests
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'go')",
                [oid.to_string()],
            )
            .unwrap();
        }
        assert!(
            !store
                .hydrate_canonical_import_facts_by_key(&entry, &generations, &adapter)
                .unwrap()
                .contains_key(&file),
            "metadata without the source publication witness is unavailable"
        );

        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"),
                &adapter,
                &state,
            )
            .unwrap();
        let repaired = store
            .hydrate_canonical_import_facts_by_key(&entry, &generations, &adapter)
            .unwrap();
        assert_eq!(repaired.get(&file).unwrap().imports, Vec::new());
    }
    /// #3455: Go now records callable modifier metadata, and it recorded none
    /// before. A blob persisted under the prior epoch deserializes as "nobody
    /// read the modifiers", which is indistinguishable from a callable whose
    /// adapter honestly never looked, so `receiver_contract_of` reports no
    /// contract and every Go procedure summary stays inert. The salt is the
    /// only thing that retires those rows.
    #[test]
    fn go_callable_modifier_metadata_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "client.go",
            "package shop\n\ntype Client struct{}\n\nfunc (c *Client) Send(orderID string) {}\n\nfunc Total(orderID string) int64 { return 0 }\n",
        );
        let state = Arc::new(parse_state(&GoAdapter, &file));
        let prior_epoch = epoch::go_epoch_before_callable_modifier_metadata();
        assert_prior_parsed_blob_invalidated(&GoAdapter, state.as_ref(), &prior_epoch);
    }
    #[test]
    fn go_source_membership_digest_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "client.go", "package shop\n\nfunc Send() {}\n");
        let state = Arc::new(parse_state(&GoAdapter, &file));
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let prior_epoch = epoch::go_epoch_before_source_membership_digest();
        let prior_generation = store
            .ensure_language_epoch_value("go", &prior_epoch)
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &ProjectFile::new(temp.path(), "client.go"),
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"),
                prior_generation,
                &GoAdapter,
                state.as_ref(),
            )
            .unwrap();
        assert!(
            store
                .contains_parsed_blob(&brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"))
                .unwrap()
        );

        let current_generation = store
            .ensure_language_epoch(Language::Go, &tree_sitter_go::LANGUAGE.into())
            .unwrap();

        assert_ne!(current_generation, prior_generation);
        assert!(
            !store
                .contains_parsed_blob(&brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"))
                .unwrap()
        );
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[brokk_bifrost_core::gitblob::BlobKey::unvaried(
                    oid, "go"
                )])
                .unwrap(),
            vec![brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go")]
        );
    }
    #[test]
    fn go_source_owned_package_lookup_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "client.go", "package shop\n\nfunc Send() {}\n");
        let state = Arc::new(parse_state(&GoAdapter, &file));
        let prior_epoch = epoch::go_epoch_before_source_owned_package_lookups();
        assert_prior_parsed_blob_invalidated(&GoAdapter, state.as_ref(), &prior_epoch);
    }
    #[test]
    fn go_argument_independent_call_coverage_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "client.go", "package shop\n\nfunc Send() {}\n");
        let state = Arc::new(parse_state(&GoAdapter, &file));
        let prior_epoch = epoch::go_epoch_before_argument_independent_call_reference_coverage();
        assert_prior_parsed_blob_invalidated(&GoAdapter, state.as_ref(), &prior_epoch);
    }
    /// The anchored encoding changes only Rust rows. Rust blobs cached under
    /// the pre-change salt must be discarded, and a Go blob cached alongside
    /// them must stay warm through that cutover.
    #[test]
    fn rust_anchored_fq_epoch_invalidates_rust_blobs_and_leaves_go_warm() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let rust_file = write_file(
            root,
            "src/service.rs",
            "pub struct Client;\n\nimpl Client {\n    pub fn connect(&self) {}\n}\n",
        );
        let rust_state = Arc::new(parse_state(&RustAdapter, &rust_file));
        let rust_oid = oid_for(rust_state.source.as_bytes());
        let _ = write_file(root, "go.mod", "module example.com/demo\n");
        let go_file = write_file(
            root,
            "internal/service/service.go",
            "package service\ntype Client struct{}\n",
        );
        let go_state = Arc::new(parse_state(&GoAdapter, &go_file));
        let go_oid = oid_for(go_state.source.as_bytes());

        let store = AnalyzerStore::open_ephemeral().unwrap();
        let prior_rust_generation = store
            .ensure_language_epoch_value("rust", &epoch::rust_epoch_before_anchored_fq_encoding())
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &crate::analyzer::store::test_blob_file(),
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(rust_oid, "rust"),
                prior_rust_generation,
                &RustAdapter,
                rust_state.as_ref(),
            )
            .unwrap();
        let go_generation = store
            .ensure_language_epoch(Language::Go, &tree_sitter_go::LANGUAGE.into())
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &crate::analyzer::store::test_blob_file(),
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(go_oid, "go"),
                go_generation,
                &GoAdapter,
                go_state.as_ref(),
            )
            .unwrap();
        assert!(
            store
                .contains_parsed_blob(&brokk_bifrost_core::gitblob::BlobKey::unvaried(
                    rust_oid, "rust"
                ))
                .unwrap()
        );
        assert!(
            store
                .contains_parsed_blob(&brokk_bifrost_core::gitblob::BlobKey::unvaried(
                    go_oid, "go"
                ))
                .unwrap()
        );

        let current_rust_generation = store
            .ensure_language_epoch(Language::Rust, &tree_sitter_rust::LANGUAGE.into())
            .unwrap();

        assert_ne!(current_rust_generation, prior_rust_generation);
        assert!(
            !store
                .contains_parsed_blob(&brokk_bifrost_core::gitblob::BlobKey::unvaried(
                    rust_oid, "rust"
                ))
                .unwrap()
        );
        assert_eq!(
            store
                .ensure_language_epoch(Language::Go, &tree_sitter_go::LANGUAGE.into())
                .unwrap(),
            go_generation,
            "the Rust salt bump must not move Go's epoch"
        );
        assert!(
            store
                .contains_parsed_blob(&brokk_bifrost_core::gitblob::BlobKey::unvaried(
                    go_oid, "go"
                ))
                .unwrap()
        );
    }
    #[test]
    fn identical_go_blob_hydrates_with_live_import_paths() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let _ = write_file(root, "go.mod", "module example.com/demo\n");
        let content = "package service\ntype Client struct{}\n";
        let file_a = write_file(root, "alpha/client.go", content);
        let file_b = write_file(root, "beta/client.go", content);
        let oid = oid_for(content.as_bytes());
        let adapter = GoAdapter;
        let state = parse_state(&adapter, &file_a);
        let store = AnalyzerStore::open_ephemeral().unwrap();

        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"),
                &adapter,
                &state,
            )
            .unwrap();
        let hydrated_a = store
            .hydrate_file_state(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"),
                &adapter,
                &file_a,
            )
            .unwrap()
            .unwrap();
        let hydrated_b = store
            .hydrate_file_state(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"),
                &adapter,
                &file_b,
            )
            .unwrap()
            .unwrap();

        assert_eq!(hydrated_a.content_qualifier, "service");
        assert_eq!(hydrated_b.content_qualifier, "service");
        assert_eq!(hydrated_a.package_name, "example.com/demo/alpha");
        assert_eq!(hydrated_b.package_name, "example.com/demo/beta");
        assert!(
            hydrated_a
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "example.com/demo/alpha.Client")
        );
        assert!(
            hydrated_b
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "example.com/demo/beta.Client")
        );
    }
    #[test]
    fn workspace_package_facts_include_declaration_free_go_files() {
        let temp = tempfile::tempdir().unwrap();
        let _ = write_file(temp.path(), "go.mod", "module example.com/demo\n");
        let source = "package service\n";
        let file = write_file(temp.path(), "service/service.go", source);
        let oid = oid_for(source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "go"),
                &GoAdapter,
                &parse_state(&GoAdapter, &file),
            )
            .unwrap();

        let generation = store.current_generation("go").unwrap();
        let outcome = store
            .workspace_content_package_facts(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(git2::Oid::zero(), "go"),
                generation,
                &[oid],
                Some(PackageAnchor::OwnModule { pop: 0 }),
            )
            .unwrap();

        assert!(outcome.complete);
        let facts = outcome.facts;
        assert_eq!(facts.len(), 1, "one file must publish one package fact");
        assert_eq!(facts[0].blob_oid, oid);
        assert_eq!(facts[0].anchor, Some(PackageAnchor::OwnModule { pop: 0 }));
        assert_eq!(facts[0].content_qualifier, "service");
        assert!(facts[0].package_tail.is_empty());
    }
    #[brokk_bifrost_test_macros::hardwon(
        "43a2c41d9d02: a package read reported complete after a requested blob had no index rows"
    )]
    #[test]
    fn anchored_workspace_package_facts_report_an_unindexed_blob_incomplete() {
        let temp = tempfile::tempdir().unwrap();
        let source = "package service\n";
        let file = write_file(temp.path(), "service/service.go", source);
        let persisted_oid = oid_for(source.as_bytes());
        let missing_oid = oid_for(b"package missing\n");
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(persisted_oid, "go"),
                &GoAdapter,
                &parse_state(&GoAdapter, &file),
            )
            .unwrap();

        let generation = store.current_generation("go").unwrap();
        let outcome = store
            .workspace_content_package_facts(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(git2::Oid::zero(), "go"),
                generation,
                &[persisted_oid, missing_oid],
                Some(PackageAnchor::OwnModule { pop: 0 }),
            )
            .unwrap();

        assert!(!outcome.complete);
        assert_eq!(outcome.facts.len(), 1);
        assert_eq!(outcome.facts[0].blob_oid, persisted_oid);
    }
}
