#[cfg(test)]
mod rust_indirect_table_tests {
    use rusqlite::params;

    use brokk_bifrost_core::hash::HashMap;

    use git2::Oid;

    use brokk_bifrost_analysis::analyzer::store::workspace_inputs::WorkspaceConfigurationInput;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceId;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceFileRow;

    #[test]
    fn configuration_and_source_publish_atomically_without_replacing_unchanged_source() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("rust", "shared-input-test")
            .unwrap();
        let workspace = WorkspaceId("a".repeat(64));
        let other_workspace = WorkspaceId("b".repeat(64));
        let source = WorkspaceFileRow {
            rel_path: "src/lib.rs".into(),
            blob_oid: Oid::hash_object(git2::ObjectType::Blob, b"pub fn run() {}").unwrap(),
        };
        let a = WorkspaceConfigurationInput::new(
            "Cargo.toml".into(),
            b"[package]\r\nname = \"a\"\r\n".as_slice().into(),
        );
        let b = WorkspaceConfigurationInput::new(
            "Cargo.toml".into(),
            b"[package]\nname = \"b\"\n".as_slice().into(),
        );
        let publish = |workspace: &WorkspaceId, configuration: &WorkspaceConfigurationInput| {
            store
                .sync_workspace_inputs_for_workspace(
                    workspace,
                    "rust",
                    generation,
                    std::slice::from_ref(&source),
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    std::slice::from_ref(configuration),
                    &[],
                )
                .unwrap()
        };
        let first = publish(&workspace, &a);
        let source_versions = || {
            let conn = store.conn.lock().expect("store mutex");
            conn.prepare(
                "SELECT file_version_id, blob_oid, projection_digest, valid_from, valid_until
                 FROM workspace_file_versions
                 WHERE workspace_id = ?1 AND lang = 'rust' AND generation = ?2
                   AND input_kind = 'source' AND rel_path = 'src/lib.rs'
                 ORDER BY file_version_id",
            )
            .unwrap()
            .query_map(params![workspace.as_str(), generation.0], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            })
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
        };
        let initial_source = source_versions();
        assert_eq!(initial_source.len(), 1);
        assert_eq!(initial_source[0].1, source.blob_oid.to_string());
        assert_eq!(initial_source[0].3, first.revision);
        assert_eq!(initial_source[0].4, None);
        assert_eq!(
            first.revision, 1,
            "source and configuration share initial revision"
        );
        assert_eq!(publish(&workspace, &a), first);
        assert_eq!(source_versions(), initial_source);
        let second = publish(&workspace, &b);
        assert_eq!(second.revision, 2);
        assert_eq!(source_versions(), initial_source);
        let third = publish(&workspace, &a);
        assert_eq!(third.revision, 3);
        assert_eq!(source_versions(), initial_source);
        let independent = publish(&other_workspace, &b);
        assert_eq!(independent.revision, 1);
        let fourth = store
            .replace_path_symbol_unit(
                &workspace,
                &HashMap::from_iter([("rust".to_owned(), third.clone())]),
                &["rust".to_owned()],
                &HashMap::from_iter([("rust".to_owned(), generation)]),
                "src/other.rs",
                Some(("rust", source.blob_oid)),
                None,
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap()
            .remove("rust")
            .unwrap();
        assert_eq!(fourth.revision, 4);
        assert_eq!(source_versions(), initial_source);
        let conn = store.conn.lock().expect("store mutex");
        for (snapshot, configuration) in [
            (&first, &a),
            (&second, &b),
            (&third, &a),
            (&independent, &b),
            (&fourth, &a),
        ] {
            store
                .select_writer_workspace_snapshots(
                    &conn,
                    &HashMap::from_iter([("rust".to_owned(), snapshot.clone())]),
                )
                .unwrap();
            let paths = conn
                .prepare("SELECT rel_path FROM workspace_files ORDER BY rel_path")
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            let expected = if snapshot == &fourth {
                vec!["src/lib.rs", "src/other.rs"]
            } else {
                vec!["src/lib.rs"]
            };
            assert_eq!(paths, expected, "configuration is not a source mount");
            let bytes: Vec<u8> = conn.query_row(
                "SELECT retained.source_bytes FROM workspace_file_versions AS versions
                 JOIN workspace_input_sources AS retained ON retained.content_oid = versions.blob_oid
                 WHERE versions.workspace_id = ?1 AND versions.input_kind = 'configuration'
                   AND versions.valid_from <= ?2
                   AND (versions.valid_until IS NULL OR ?2 < versions.valid_until)",
                params![snapshot.workspace_id.as_str(), snapshot.revision], |row| row.get(0),
            ).unwrap();
            assert_eq!(bytes, configuration.source_bytes());
        }
    }
}
