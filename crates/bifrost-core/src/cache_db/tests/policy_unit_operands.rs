//! #11552: rebuilding the policy-unit parent must preserve all dependent rows.
use super::*;
use rusqlite::types::Value;

fn rows(conn: &Connection, sql: &str) -> Vec<Vec<Value>> {
    let mut statement = conn.prepare(sql).unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            (0..columns).map(|column| row.get(column)).collect()
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn operand_upgrade_from_0338_preserves_units_and_every_child() {
    let mut conn = create_current_baseline_without_migration();
    for migration in POST_BASELINE_MIGRATIONS
        .iter()
        .filter(|migration| migration.version <= 338)
    {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn.pragma_update(None, "user_version", 338).unwrap();
    for (id, kind, product) in [
        (1, "prefix", "prefix"),
        (2, "selector", "selector"),
        (3, "whole", "rows"),
        (4, "root", "root"),
    ] {
        conn.execute(
            "INSERT INTO policy_units(unit_id,policy_semantic_hash,family,partition_kind,seed_rel_path,seed_blob_oid,configuration_fingerprint,active_model_set_hash,engine_epoch,completion,budget_mode,product_kind,product,read_set_digest,published_at,prefix_cut_digest,prefix_input_digest,selector_digest,root_locator,root_compilation)
             VALUES(?1,hex(zeroblob(32)),'match',?2,?3,?4,hex(zeroblob(32)),hex(zeroblob(32)),hex(zeroblob(32)),'complete','exhaustive',?5,jsonb('{\"retained\":true}'),zeroblob(32),17,?6,?6,?7,?8,?8)",
            rusqlite::params![id, kind, if kind == "whole" { "" } else { "src/root.rs" },
                if kind == "whole" { "" } else { "1111111111111111111111111111111111111111" }, product,
                if kind == "prefix" { "0".repeat(64) } else { String::new() },
                if kind == "selector" { "0".repeat(64) } else { String::new() },
                if kind == "root" { "0".repeat(64) } else { String::new() }],
        ).unwrap();
    }
    conn.execute_batch(
        "INSERT INTO policy_read_keys(key_digest,kind,languages,rel_path,blob_oid) VALUES(zeroblob(32),'file','rust','src/root.rs','1111111111111111111111111111111111111111');
         INSERT INTO policy_unit_reads(unit_id,read_id) VALUES(1,1),(2,1),(3,1),(4,1);
         INSERT INTO policy_unit_snapshots(unit_id,content_identity,attestation) VALUES(1,zeroblob(32),1),(2,zeroblob(32),1),(3,zeroblob(32),1),(4,zeroblob(32),1);
         INSERT INTO policy_evaluations(base_tree_oid,policy_set_digest,options_digest,configuration_fingerprint,active_model_set_hash,engine_epoch,resolved_commit,published_at,effective_grant,census_files,census_bytes,evidence_complete)
         VALUES('3333333333333333333333333333333333333333',hex(zeroblob(32)),hex(zeroblob(32)),hex(zeroblob(32)),hex(zeroblob(32)),hex(zeroblob(32)),'4444444444444444444444444444444444444444',1,'{\"files\":7}',3,4,1);
         INSERT INTO policy_evaluation_policies(evaluation_id,policy_id,source_hash,semantic_hash,completion,completion_detail,qualified,qualification_detail,diagnostics,effective_grant,census_files,census_bytes)
         VALUES(1,'test',hex(zeroblob(32)),hex(zeroblob(32)),'complete','\"complete\"',1,'','[]','{\"files\":5}',2,9);
         INSERT INTO policy_evaluation_units(evaluation_id,policy_id,unit_id) VALUES(1,'test',1),(1,'test',2),(1,'test',3),(1,'test',4);"
    ).unwrap();
    let columns = conn
        .prepare("PRAGMA table_info(policy_units)")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
        .join(",");
    let unit_query = format!("SELECT {columns} FROM policy_units ORDER BY unit_id");
    let before = rows(&conn, &unit_query);
    let children = [
        "policy_evaluation_units",
        "policy_unit_reads",
        "policy_unit_snapshots",
    ];
    // Pin the complete referencing vocabulary: a new child cannot silently
    // escape the upgrade fixture's preservation check.
    let tables = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let referencing: Vec<_> = tables
        .into_iter()
        .filter(|table| {
            conn.prepare(&format!("PRAGMA foreign_key_list(\"{table}\")"))
                .unwrap()
                .query_map([], |row| row.get::<_, String>(2))
                .unwrap()
                .any(|parent| parent.unwrap() == "policy_units")
        })
        .collect();
    assert_eq!(referencing, children);
    let queries: Vec<_> = children
        .iter()
        .map(|child| format!("SELECT * FROM {child} ORDER BY 1,2"))
        .collect();
    let dependents: Vec<_> = queries.iter().map(|query| rows(&conn, query)).collect();
    assert!(dependents.iter().all(|child| child.len() == 4));
    migrate(&mut conn).unwrap();
    assert_eq!(
        cache_migration_version(&conn).unwrap(),
        CURRENT_MIGRATION_VERSION
    );
    verify_upgraded_store(&conn, Path::new("operand-0338-upgrade")).unwrap();
    assert_eq!(
        rows(&conn, &unit_query),
        before,
        "all preexisting keys and products stay byte-identical"
    );
    for (query, before) in queries.iter().zip(dependents) {
        assert_eq!(rows(&conn, query), before, "child rows survive: {query}");
    }
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM policy_units WHERE operand_question_digest <> ''",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert!(
        conn.execute(
            "UPDATE policy_units SET operand_question_digest = ?1",
            ["1".repeat(64)]
        )
        .is_err(),
        "only Operand rows may carry a question"
    );
    for question in ["1".repeat(64), "2".repeat(64)] {
        conn.execute("INSERT INTO policy_units(policy_semantic_hash,family,partition_kind,seed_rel_path,seed_blob_oid,configuration_fingerprint,active_model_set_hash,engine_epoch,completion,budget_mode,product_kind,product,read_set_digest,published_at,operand_question_digest)
            SELECT policy_semantic_hash,family,'operand','','',configuration_fingerprint,active_model_set_hash,engine_epoch,completion,budget_mode,'prefix',product,read_set_digest,published_at,?1 FROM policy_units WHERE unit_id = 3", [&question]).unwrap();
    }
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM policy_units WHERE partition_kind = 'operand'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    assert!(
        conn.execute(
            "UPDATE policy_units SET operand_question_digest = '' WHERE partition_kind = 'operand'",
            []
        )
        .is_err(),
        "every Operand must carry its question"
    );
    conn.execute(
        "UPDATE policy_units SET product_kind = 'rows' WHERE partition_kind = 'prefix'",
        [],
    )
    .expect("output-bound continuation prefixes retain final rows");
    assert!(
        conn.execute(
            "UPDATE policy_units SET product_kind = 'rows' WHERE partition_kind = 'operand'",
            []
        )
        .is_err(),
        "operand units must retain typed Prefix payloads"
    );
    assert!(
        conn.execute(
            "UPDATE policy_units SET product_kind = 'prefix' WHERE partition_kind = 'whole'",
            []
        )
        .is_err(),
        "typed Prefix payloads require Prefix or Operand keys"
    );
    validate_foreign_keys(&conn).unwrap();
}
