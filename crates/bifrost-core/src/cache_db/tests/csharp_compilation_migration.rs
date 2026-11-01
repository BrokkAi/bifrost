use super::*;

#[test]
#[hardwon(
    "#8263: migration 0217 failed its foreign-key check on stores holding C# compilation selections"
)]
fn csharp_compilation_rows_are_deleted_before_migration_217_removes_sets() {
    const PRE_MIGRATION_VERSION: i64 = 215;
    let mut conn = create_current_baseline_without_migration();
    for migration in POST_BASELINE_MIGRATIONS
        .iter()
        .filter(|migration| migration.version <= PRE_MIGRATION_VERSION)
    {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn.pragma_update(None, "user_version", PRE_MIGRATION_VERSION)
        .unwrap();
    conn.execute_batch(
        "INSERT INTO workspace_revisions VALUES(printf('%064d', 0), 'csharp', 0, 1);
         INSERT INTO csharp_compilation_sets
             (set_id, workspace_id, lang, generation, derivation_version, input_digest,
              output_digest, membership_complete, gaps)
             VALUES(1, printf('%064d', 0), 'csharp', 0, 1, zeroblob(32), zeroblob(32), 1, jsonb('[]'));
         INSERT INTO csharp_compilation_selections VALUES(printf('%064d', 0), 'csharp', 0, 1, 1);
         INSERT INTO csharp_compilations
             (compilation_id, set_id, references_complete, transitive_flow)
             VALUES(1, 1, 1, 1), (2, 1, 1, 1);
         INSERT INTO csharp_compilation_items
             (compilation_id, ordinal, set_id, kind, rel_path, excluded_trees)
             VALUES(1, 0, 1, 'include', 'a.cs', NULL);
         INSERT INTO csharp_project_references VALUES(1, 2);",
    )
    .unwrap();

    migrate(&mut conn).unwrap();
    validate_foreign_keys(&conn).unwrap();
    for table in [
        "csharp_compilation_sets",
        "csharp_compilation_selections",
        "csharp_compilations",
        "csharp_compilation_items",
        "csharp_project_references",
    ] {
        assert_eq!(
            conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0,
            "migration 217 must clear {table}",
        );
    }
}

#[test]
fn csharp_variant_rows_enforce_their_parent_foreign_keys() {
    let mut conn = Connection::open_in_memory().unwrap();
    configure_connection(&mut conn).unwrap();
    migrate(&mut conn).unwrap();
    assert!(
        conn.execute(
            "INSERT INTO csharp_file_version_decisions(file_version_id,decision_digest,assignment_digest) VALUES(1,zeroblob(32),zeroblob(32))",
            []
        )
        .is_err()
    );
    assert!(
        conn.execute(
            "INSERT INTO csharp_source_condition_symbols VALUES(1,'DEBUG')",
            []
        )
        .is_err()
    );
    conn.execute_batch("INSERT INTO workspace_revisions VALUES(printf('%064d',0),'csharp',1,1);
      INSERT INTO workspace_file_versions(workspace_id,lang,generation,rel_path,blob_oid,projection_digest,valid_from)
      VALUES(printf('%064d',0),'csharp',1,'App.cs',printf('%040d',1),printf('%064d',0),1);
      INSERT INTO blobs(blob_oid,lang,generation) VALUES(printf('%040d',1),'csharp',1);
      INSERT INTO csharp_file_version_decisions(file_version_id,decision_digest,assignment_digest) VALUES(1,zeroblob(32),zeroblob(32));
      INSERT INTO csharp_source_condition_symbols VALUES(1,'DEBUG');").unwrap();
    validate_foreign_keys(&conn).unwrap();
}

#[test]
fn compilation_using_extent_migration_preserves_inputs_and_enforces_lifetimes() {
    let mut conn = create_current_baseline_without_migration();
    for migration in POST_BASELINE_MIGRATIONS.iter().filter(|m| m.version < 226) {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn.pragma_update(None, "user_version", 225).unwrap();
    conn.execute_batch(
        "INSERT INTO workspace_revisions VALUES(printf('%064d',0),'csharp',1,1);
         INSERT INTO workspace_file_versions(file_version_id,workspace_id,lang,generation,
             rel_path,blob_oid,projection_digest,valid_from)
         VALUES(1,printf('%064d',0),'csharp',1,'Global.cs',printf('%040d',1),printf('%064d',0),1);
         INSERT INTO csharp_compilation_sets(set_id,workspace_id,lang,generation,
             derivation_version,input_digest,output_digest,membership_complete,gaps)
         VALUES(1,printf('%064d',0),'csharp',1,4,zeroblob(32),zeroblob(32),1,jsonb('[]'));
         INSERT INTO csharp_compilations(compilation_id,set_id,project_path,references_complete,
             transitive_flow,global_usings_complete,internals_visible_to_complete,global_usings,
             internals_visible_to)
         VALUES(1,1,'App.csproj',1,1,1,1,jsonb('[]'),jsonb('[]'));
         INSERT INTO csharp_compilation_selections VALUES(printf('%064d',0),'csharp',1,1,1);
         INSERT INTO blobs(id,blob_oid,lang) VALUES(1,printf('%040d',1),'csharp');
         INSERT INTO resolution_fragment_interiors(blob_id,lang,semantic_language,producer_epoch,
             interior_digest,expected_semantic_site_count,logical_rows,payload_bytes,publication_state)
         VALUES(1,'csharp','csharp','extent-fixture',zeroblob(32),0,1,0,'building');
         INSERT INTO resolution_root_imports(blob_id,import_site,root_scope,anchor,kind)
         VALUES(1,1,0,'lexical','glob');",
    ).unwrap();
    migrate(&mut conn).unwrap();
    assert!(current_schema_is_valid(&conn).unwrap());
    for table in [
        "workspace_file_versions",
        "csharp_compilations",
        "resolution_root_imports",
    ] {
        assert_eq!(
            conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    let tables = [
        "csharp_compilation_members",
        "csharp_global_using_extent",
        "csharp_compilation_using_coverage",
    ];
    for table in tables {
        assert_eq!(
            conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        let shape: (bool, bool) = conn
            .query_row(
                "SELECT wr,strict FROM pragma_table_list WHERE name=?1",
                [table],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(shape, (true, true), "{table}");
    }
    conn.execute_batch(
        "INSERT INTO csharp_compilation_members VALUES(printf('%064d',0),'csharp',1,1,'Global.cs',1,1,NULL);
         INSERT INTO csharp_global_using_extent VALUES(printf('%064d',0),'csharp',1,1,'Global.cs',1,1,1,NULL);
         INSERT INTO csharp_compilation_using_coverage
         VALUES(printf('%064d',0),'csharp',1,1,1,NULL,1,1,0,1,jsonb('[]'));",
    ).unwrap();
    validate_foreign_keys(&conn).unwrap();
    for invalid in [
        "UPDATE csharp_compilation_members SET valid_until=valid_from",
        "UPDATE csharp_compilation_members SET file_version_id=99",
        "UPDATE csharp_global_using_extent SET import_site=99",
        "UPDATE csharp_global_using_extent SET lang='java'",
        "UPDATE csharp_compilation_using_coverage SET membership_complete=2",
        "UPDATE csharp_compilation_using_coverage SET publications_installed=2",
        "UPDATE csharp_compilation_using_coverage SET reasons=jsonb('{}')",
    ] {
        assert!(conn.execute(invalid, []).is_err(), "{invalid}");
    }
    // Lifecycle parents cascade, independently of the protected content parent.
    for (sql, remaining) in [
        ("DELETE FROM csharp_compilations", [0, 0, 0]),
        ("DELETE FROM workspace_revisions", [0, 0, 0]),
        ("DELETE FROM workspace_file_versions", [0, 1, 1]),
    ] {
        conn.execute_batch("SAVEPOINT lifecycle").unwrap();
        conn.execute(sql, []).unwrap();
        for (table, expected) in tables.into_iter().zip(remaining) {
            assert_eq!(
                conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                expected,
                "{sql}: {table}"
            );
        }
        validate_foreign_keys(&conn).unwrap();
        conn.execute_batch("ROLLBACK TO lifecycle; RELEASE lifecycle")
            .unwrap();
    }
    assert!(conn.execute("DELETE FROM blobs WHERE id=1", []).is_err());
    // Closing an interval still protects its publication for historical readers.
    conn.execute("UPDATE csharp_global_using_extent SET valid_until=2", [])
        .unwrap();
    assert!(conn.execute("DELETE FROM blobs WHERE id=1", []).is_err());
    conn.execute("DELETE FROM csharp_global_using_extent", [])
        .unwrap();
    conn.execute("DELETE FROM blobs WHERE id=1", []).unwrap();
    validate_foreign_keys(&conn).unwrap();
    // Future migrations must delete these children explicitly with FK enforcement off.
    conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
    conn.execute_batch(
        "DELETE FROM csharp_compilation_members;
         DELETE FROM csharp_compilation_using_coverage;
         DELETE FROM csharp_compilation_selections;
         DELETE FROM csharp_compilations;
         DELETE FROM csharp_compilation_sets;
         DELETE FROM workspace_file_versions;
         DELETE FROM workspace_revisions;",
    )
    .unwrap();
    validate_foreign_keys(&conn).unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
}
