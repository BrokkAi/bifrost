use super::*;

#[test]
#[hardwon(
    "#8837: migration must fence legacy empty configuration probes without rewriting history"
)]
fn configuration_presence_upgrade_fences_empty_probe_rows() {
    let mut conn = test_connection_through_262();
    conn.execute_batch("INSERT INTO workspace_revisions VALUES(printf('%064d',0),'csharp',1,1);
        INSERT INTO workspace_file_versions(workspace_id,lang,generation,input_kind,rel_path,blob_oid,valid_from)
        VALUES(printf('%064d',0),'csharp',1,'configuration','Directory.Build.props','e69de29bb2d1d6434b8b29ae775ad8c2e48c5391',1),
              (printf('%064d',0),'csharp',1,'configuration','sub/Directory.Build.props',printf('%040d',1),1);").unwrap();
    migrate(&mut conn).unwrap();
    let rows: Vec<(String, Option<bool>)> = conn
        .prepare("SELECT rel_path,file_present FROM workspace_file_versions ORDER BY rel_path")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(|row| row.unwrap())
        .collect();
    assert_eq!(
        rows,
        vec![
            ("Directory.Build.props".into(), None),
            ("sub/Directory.Build.props".into(), Some(true))
        ]
    );
    validate_foreign_keys(&conn).unwrap();
}

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

#[test]
#[hardwon("#9973: registered reasons violated the csharp_compilations open_reason CHECK")]
fn csharp_open_reasons_upgrade_preserves_rows_and_rejects_unknown_reason() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut conn = Connection::open(file.path()).unwrap();
    configure_connection(&mut conn).unwrap();
    conn.execute_batch(BASELINE_SCHEMA_SQL).unwrap();
    // Stamp the newest migration applied, so `migrate` replays only 0283 and
    // anything registered after it, however many migrations precede 0283.
    let before_open_reasons = POST_BASELINE_MIGRATIONS
        .iter()
        .map(|m| m.version)
        .filter(|version| *version < 283)
        .max()
        .expect("a migration precedes the open-reason migration");
    for migration in POST_BASELINE_MIGRATIONS.iter().filter(|m| m.version < 283) {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn.pragma_update(None, "user_version", before_open_reasons)
        .unwrap();
    conn.execute_batch(
        "INSERT INTO csharp_compilation_sets
         (set_id,workspace_id,lang,generation,derivation_version,input_digest,output_digest,gaps)
         VALUES(1,'workspace','csharp',1,5,zeroblob(32),zeroblob(32),jsonb('[]'));
         INSERT INTO csharp_compilations(compilation_id,set_id,references_complete,transitive_flow,global_usings_complete,internals_visible_to_complete,global_usings,internals_visible_to)
         VALUES(1,1,1,1,1,1,jsonb('[]'),jsonb('[]'));
         INSERT INTO csharp_compilation_symbols VALUES(1,'DEBUG','sdk');",
    )
    .unwrap();
    assert!(
        conn.execute(
            "UPDATE csharp_compilations SET open_reason='target_assignment' WHERE compilation_id=1",
            []
        )
        .is_err()
    );
    migrate(&mut conn).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT open_reason FROM csharp_compilations WHERE compilation_id=1",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "unrestored"
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM csharp_compilation_symbols WHERE compilation_id=1",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    for reason in [
        "unknown_configuration_presence",
        "target_assignment",
        "dynamic_target_property",
        "treat_as_local_property",
    ] {
        conn.execute(
            "UPDATE csharp_compilations SET open_reason=?1 WHERE compilation_id=1",
            [reason],
        )
        .unwrap();
    }
    assert!(
        conn.execute(
            "UPDATE csharp_compilations SET open_reason='unregistered' WHERE compilation_id=1",
            []
        )
        .is_err()
    );
    assert!(
        conn.execute(
            "INSERT INTO csharp_compilation_symbols VALUES(999,'X','sdk')",
            []
        )
        .is_err()
    );
    validate_foreign_keys(&conn).unwrap();
    assert!(current_schema_is_valid(&conn).unwrap());
    drop(conn);
    let reopened = Connection::open(file.path()).unwrap();
    let reason: String = reopened
        .query_row(
            "SELECT open_reason FROM csharp_compilations WHERE compilation_id=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(reason, "treat_as_local_property");
    assert_eq!(
        reopened
            .query_row(
                "SELECT count(*) FROM csharp_compilation_symbols WHERE compilation_id=1",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
}

#[test]
fn structural_role_name_migration_preserves_read_ids_on_upgrade_and_downgrade_replay() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut conn = Connection::open(file.path()).unwrap();
    configure_connection(&mut conn).unwrap();
    conn.execute_batch(BASELINE_SCHEMA_SQL).unwrap();
    // Build the actual predecessor of the read-key table rebuild.
    let previous = POST_BASELINE_MIGRATIONS
        .iter()
        .filter(|migration| migration.version < 285)
        .inspect(|migration| conn.execute_batch(migration.sql).unwrap())
        .map(|migration| migration.version)
        .max()
        .unwrap();
    conn.pragma_update(None, "user_version", previous).unwrap();
    conn.execute_batch(
        "INSERT INTO policy_read_keys(read_id,key_digest,kind,family,languages,name,subject,digest)
         VALUES(17,randomblob(32),'lookup','structural_name_inventory','rust','put',zeroblob(32),zeroblob(32)),
               (29,randomblob(32),'lookup','structural_recovered_inventory','rust',NULL,zeroblob(32),zeroblob(32));",
    ).unwrap();
    let check_rows = |conn: &Connection| {
        let rows: Vec<(i64, String)> = conn
            .prepare("SELECT read_id, family FROM policy_read_keys ORDER BY read_id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(|row| row.unwrap())
            .collect();
        assert_eq!(
            rows,
            [
                (17, "structural_name_inventory".into()),
                (29, "structural_recovered_inventory".into())
            ]
        );
        validate_foreign_keys(conn).unwrap();
        assert!(current_schema_is_valid(conn).unwrap());
    };
    migrate(&mut conn).unwrap();
    check_rows(&conn);
    drop(conn);
    let mut reopened = Connection::open(file.path()).unwrap();
    configure_connection(&mut reopened).unwrap();
    check_rows(&reopened);
    // Re-running 0285's rebuild over its own output must keep populated read
    // rows and their stable read_id values. Later migrations may not be
    // replayable, so replay the rebuild directly instead of lowering
    // user_version past them.
    let rebuild = POST_BASELINE_MIGRATIONS
        .iter()
        .find(|migration| migration.version == 285)
        .expect("structural role-name migration 0285");
    reopened.execute_batch(rebuild.sql).unwrap();
    // Restore the later general-ledger definition before current-schema validation.
    reopened
        .execute_batch(
            POST_BASELINE_MIGRATIONS
                .iter()
                .find(|m| m.version == 299)
                .unwrap()
                .sql,
        )
        .unwrap();
    migrate(&mut reopened).unwrap();
    check_rows(&reopened);
}

#[test]
fn framework_instance_migration_preserves_compilation_ids_and_children() {
    let mut conn = create_current_baseline_without_migration();
    for migration in POST_BASELINE_MIGRATIONS.iter().filter(|m| m.version < 295) {
        conn.execute_batch(migration.sql).unwrap();
        conn.pragma_update(None, "user_version", migration.version)
            .unwrap();
    }
    conn.execute_batch(
        "INSERT INTO csharp_compilation_sets
         (set_id,workspace_id,lang,generation,derivation_version,input_digest,output_digest,gaps)
         VALUES(7,'workspace','csharp',1,16,zeroblob(32),zeroblob(32),jsonb('[]'));
         INSERT INTO csharp_compilations
         (compilation_id,set_id,project_path,target_framework,references_complete,transitive_flow,
          global_usings_complete,internals_visible_to_complete,global_usings,internals_visible_to)
         VALUES(41,7,'app.csproj','net8.0',1,1,1,1,jsonb('[]'),jsonb('[]')),
               (83,7,'lib.csproj','net8.0',1,1,1,1,jsonb('[]'),jsonb('[]'));
         INSERT INTO csharp_compilation_symbols VALUES(41,'DEBUG','sdk'),(83,'TRACE','define_constants');
         INSERT INTO csharp_compilation_items
         (compilation_id,ordinal,set_id,kind,rel_path,excluded_trees)
         VALUES(41,0,7,'include','app.cs',NULL),(83,0,7,'include','lib.cs',NULL);
         INSERT INTO csharp_project_references VALUES(41,83);"
    ).unwrap();
    let snapshot = |conn: &Connection| {
        [
            "csharp_compilations",
            "csharp_compilation_symbols",
            "csharp_compilation_items",
            "csharp_project_references",
        ]
        .map(|table| {
            let mut statement = conn
                .prepare(&format!("SELECT * FROM {table} ORDER BY 1,2"))
                .unwrap();
            let columns = statement
                .column_names()
                .iter()
                .enumerate()
                .filter_map(|(index, name)| (*name != "named_open_symbols").then_some(index))
                .collect::<Vec<_>>();
            statement
                .query_map([], |row| {
                    columns
                        .iter()
                        .copied()
                        .map(|column| row.get::<_, rusqlite::types::Value>(column))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        })
    };
    let before = snapshot(&conn);
    migrate(&mut conn).unwrap();
    assert_eq!(snapshot(&conn), before);
    conn.execute_batch(
        "INSERT INTO csharp_compilations
         (compilation_id,set_id,project_path,target_framework,references_complete,transitive_flow,
          global_usings_complete,internals_visible_to_complete,global_usings,internals_visible_to)
         VALUES(101,7,'app.csproj','net9.0',1,1,1,1,jsonb('[]'),jsonb('[]'));",
    )
    .unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM csharp_compilations WHERE set_id=7 AND project_path='app.csproj'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    validate_foreign_keys(&conn).unwrap();
}

#[test]
#[hardwon(
    "#7314: an already migrated symbol environment must gain named-open storage without losing defined symbols"
)]
fn named_open_migration_preserves_existing_environments() {
    let mut conn = create_current_baseline_without_migration();
    for migration in POST_BASELINE_MIGRATIONS.iter().filter(|m| m.version < 303) {
        conn.execute_batch(migration.sql).unwrap();
        conn.pragma_update(None, "user_version", migration.version)
            .unwrap();
    }
    conn.execute_batch(
        "INSERT INTO csharp_compilation_sets
      (set_id,workspace_id,lang,generation,derivation_version,input_digest,output_digest,gaps)
      VALUES(7,'workspace','csharp',1,17,zeroblob(32),zeroblob(32),jsonb('[]'));
      INSERT INTO csharp_compilations
      (compilation_id,set_id,project_path,target_framework,references_complete,transitive_flow,
       global_usings_complete,internals_visible_to_complete,global_usings,internals_visible_to,
       symbols_closed,open_reason,symbol_set_digest)
      VALUES(41,7,'app.csproj','net8.0',1,1,1,1,jsonb('[]'),jsonb('[]'),1,NULL,zeroblob(32));
      INSERT INTO csharp_compilation_symbols VALUES(41,'DEBUG','sdk');",
    )
    .unwrap();
    migrate(&mut conn).unwrap();
    let row = conn
        .query_row(
            "SELECT c.project_path,c.symbols_closed,c.open_reason,
      json(c.named_open_symbols),s.symbol,s.source,length(c.symbol_set_digest)
      FROM csharp_compilations c JOIN csharp_compilation_symbols s USING(compilation_id)
      WHERE c.compilation_id=41",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, bool>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        row,
        (
            "app.csproj".into(),
            true,
            None,
            "[]".into(),
            "DEBUG".into(),
            "sdk".into(),
            32
        )
    );
    conn.execute("UPDATE csharp_compilations SET named_open_symbols=jsonb('[\"RELEASE\"]') WHERE compilation_id=41",[]).unwrap();
    assert_eq!(conn.query_row("SELECT json_extract(named_open_symbols,'$[0]') FROM csharp_compilations WHERE compilation_id=41",[],|row|row.get::<_,String>(0)).unwrap(),"RELEASE");
    assert!(current_schema_shape_is_valid(&conn).unwrap());
}
