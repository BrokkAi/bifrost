#[cfg(test)]
mod rust_departing_root_tests {
    use brokk_bifrost_core::analyzer::rust_facts::RustDeclarationKind;
    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;

    use brokk_bifrost_analysis::analyzer::store::test_support::blob_id as rust_blob_id;

    use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

    use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;
    #[test]
    fn rust_native_declaration_sources_publish_exact_ids_and_visibility_facts() {
        const RUST_SOURCE: &str = r#"
mod first { fn repeated() {} }
mod second { fn repeated() {} }
"#;
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", RUST_SOURCE)
            .build();
        let file = fixture.file("src/lib.rs");
        let state = parse_state(&RustAdapter, &file);
        let facts = state
            .source_facts
            .as_ref()
            .expect("Rust publishes canonical source facts");
        assert_eq!(
            facts.declaration_visibilities.as_ref().unwrap().len(),
            4,
            "Rust publishes the structured visibility of both modules and functions"
        );

        let repeated_declarations = facts
            .rust_declaration_properties
            .iter()
            .filter(|property| property.kind == RustDeclarationKind::Function)
            .map(|property| property.declaration)
            .collect::<Vec<_>>();
        assert_eq!(
            repeated_declarations.len(),
            2,
            "same-name module functions retain separate source declaration identities"
        );
        assert_ne!(repeated_declarations[0], repeated_declarations[1]);

        let mut expected_native = facts
            .native_declaration_sources
            .iter()
            .map(|(source_site, declaration)| {
                (i64::from(source_site.get()), i64::from(declaration.get()))
            })
            .collect::<Vec<_>>();
        expected_native.sort_unstable();
        assert_eq!(
            expected_native.len(),
            4,
            "both modules and their same-name functions have native declaration sites"
        );
        assert!(repeated_declarations.iter().all(|declaration| {
            expected_native
                .iter()
                .any(|(_, candidate)| *candidate == i64::from(declaration.get()))
        }));

        let oid = oid_for(RUST_SOURCE.as_bytes());
        let store = AnalyzerStore::open_ephemeral().expect("Rust source publication store");
        store
            .conn
            .execute(|conn| {
                conn.execute_batch(
                    "CREATE TRIGGER test_delete_native_bridge_after_insert
                 AFTER INSERT ON source_native_declaration_bridges
                 BEGIN
                     DELETE FROM source_native_declaration_bridges
                      WHERE blob_id = NEW.blob_id
                        AND source_site = NEW.source_site
                        AND declaration_id = NEW.declaration_id;
                 END;",
                )?;
                Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
            })
            .expect("install native bridge publication fault");
        let error = store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .expect_err("missing native bridge must fail publication");
        assert!(
            error
                .to_string()
                .contains("source native declaration bridge count is inconsistent"),
            "unexpected native bridge count error: {error:?}"
        );
        assert_eq!(
            store
                .content_row_count(oid, "rust")
                .expect("failed Rust publication row count"),
            0,
            "failed native bridge publication leaves no content rows"
        );
        store
            .conn
            .execute(|conn| {
                conn.execute_batch("DROP TRIGGER test_delete_native_bridge_after_insert;")?;
                Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
            })
            .expect("remove native bridge publication fault");
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .expect("publish Rust native declaration bridges");
        let conn = store.read_conn().expect("read Rust source publication");
        let id = rust_blob_id(&conn, oid);

        let common_marker: (Option<i64>, String, bool, bool) = conn
            .query_row(
                "SELECT manifest.native_bridge_count, manifest.publication_state,
                    meta.native_bridges_required, readiness.available
               FROM source_fact_manifests AS manifest
               JOIN blob_meta AS meta ON meta.blob_id = manifest.blob_id
               JOIN source_fact_readiness AS readiness
                 ON readiness.blob_id = manifest.blob_id
              WHERE manifest.blob_id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("Rust common source-facts marker");
        assert_eq!(
            common_marker,
            (
                Some(i64::try_from(expected_native.len()).expect("bridge count fits SQLite")),
                "complete".to_owned(),
                true,
                true
            ),
            "new source publications declare exact bridges, require them, and become ready"
        );

        let actual_native = conn
            .prepare(
                "SELECT source_site, declaration_id
               FROM source_native_declaration_bridges
              WHERE blob_id = ?1
              ORDER BY source_site",
            )
            .expect("prepare Rust native bridge rows")
            .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("read Rust native bridge rows")
            .collect::<rusqlite::Result<Vec<(i64, i64)>>>()
            .expect("collect Rust native bridge rows");
        assert_eq!(actual_native, expected_native);

        let definition_native = conn
            .prepare(
                "SELECT bridge.source_site, bridge.declaration_id
               FROM source_native_declaration_bridges AS bridge
               JOIN resolution_semantic_sites AS site
                 ON site.blob_id = bridge.blob_id
                AND site.source_site = bridge.source_site
              WHERE bridge.blob_id = ?1
                AND site.semantic_role = 'definition'
              ORDER BY bridge.source_site",
            )
            .expect("prepare Rust native definition join")
            .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("read Rust native definition join")
            .collect::<rusqlite::Result<Vec<(i64, i64)>>>()
            .expect("collect Rust native definition join");
        assert_eq!(
            definition_native, expected_native,
            "native bridges join exact producer identities to definition-role sites"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM source_declaration_visibility_manifests
              WHERE blob_id = ?1",
                [id],
                |row| row.get::<_, i64>(0),
            )
            .expect("count Rust visibility family"),
            1,
            "Rust native bridge publication includes its source-owned visibility facts"
        );
    }

    #[test]
    #[hardwon("1051035c2ed9: an empty Rust source family was not published as ready")]
    fn empty_rust_native_declaration_publication_is_ready_with_zero_count() {
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "")
            .build();
        let file = fixture.file("src/lib.rs");
        let state = parse_state(&RustAdapter, &file);
        let facts = state
            .source_facts
            .as_ref()
            .expect("empty Rust source facts");
        assert_eq!(
            facts.declaration_visibilities.as_deref(),
            Some([].as_slice())
        );
        assert!(facts.native_declaration_sources.is_empty());

        let oid = oid_for(b"");
        let store = AnalyzerStore::open_ephemeral().expect("empty Rust source publication store");
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .expect("publish empty Rust native declaration family");
        let conn = store
            .read_conn()
            .expect("read empty Rust source publication");
        let id = rust_blob_id(&conn, oid);
        let common_marker: (Option<i64>, String, bool, bool) = conn
            .query_row(
                "SELECT manifest.native_bridge_count, manifest.publication_state,
                    meta.native_bridges_required, readiness.available
               FROM source_fact_manifests AS manifest
               JOIN blob_meta AS meta ON meta.blob_id = manifest.blob_id
               JOIN source_fact_readiness AS readiness
                 ON readiness.blob_id = manifest.blob_id
              WHERE manifest.blob_id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("empty Rust common source-facts marker");
        assert_eq!(
            common_marker,
            (Some(0), "complete".to_owned(), true, true),
            "empty source publications declare zero bridges, require them, and become ready"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM source_native_declaration_bridges WHERE blob_id = ?1",
                [id],
                |row| row.get::<_, i64>(0),
            )
            .expect("empty Rust native bridge rows"),
            0
        );

        drop(conn);
        let oid_text = oid.to_string();
        store
            .conn
            .execute(move |conn| {
                conn.execute_batch("DROP TRIGGER source_fact_native_bridge_count_is_immutable;")?;
                conn.execute(
                    "UPDATE source_fact_manifests
                    SET native_bridge_count = NULL
                  WHERE blob_id = (SELECT id FROM blobs
                                    WHERE blob_oid = ?1 AND lang = 'rust')",
                    [&oid_text],
                )?;
                Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
            })
            .expect("corrupt empty Rust native bridge count");
        let conn = store
            .read_conn()
            .expect("read corrupted empty Rust source publication");
        assert!(
            !conn
                .query_row(
                    "SELECT available FROM source_fact_readiness
              WHERE blob_id = ?1",
                    [id],
                    |row| row.get::<_, bool>(0),
                )
                .expect("corrupted empty Rust source-fact readiness"),
            "missing zero native bridge count must make readiness unavailable"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM rust_published_fact_blobs
              WHERE blob_oid = ?1 AND lang = 'rust'",
                [oid.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .expect("corrupted empty Rust publication membership"),
            0,
            "unready empty Rust source must be excluded from published facts"
        );
    }
}
