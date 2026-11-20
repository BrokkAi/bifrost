use super::*;
use brokk_bifrost_test_macros::hardwon;

#[test]
#[hardwon(
    "#2622: Rust glob-route migration round trip; #4488: later migrations moved the fixture floor"
)]
fn crate_rows_migrate_and_round_trip_glob_routes() {
    // Migration 155 derives member rows from the legacy source rows. Keep this
    // fixture before that migration when later schema versions are added.
    const PRE_MEMBER_SCHEMA_VERSION: i64 = 154;
    let mut conn = create_current_baseline_without_migration();
    for migration in POST_BASELINE_MIGRATIONS
        .iter()
        .filter(|migration| migration.version <= PRE_MEMBER_SCHEMA_VERSION)
    {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn.pragma_update(None, "user_version", PRE_MEMBER_SCHEMA_VERSION)
        .unwrap();
    conn.execute(
        "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'rust', 0)",
        ["a".repeat(40)],
    )
    .unwrap();
    conn.execute_batch(
        "INSERT INTO rust_crate_topologies(topology_digest, crate_key, producer_epoch,
             target_kind, crate_name, edition, prelude, cfg_atoms, inventory_complete, publication_state)
         VALUES(zeroblob(32), zeroblob(32), 'crate-rows-test', 'lib', 'sample', '2021', 'std',
                jsonb('[\"test\"]'), 1, 'building');
         INSERT INTO rust_crate_containers VALUES(1, 'crate', 'module', 'root');
         INSERT INTO rust_crate_container_sources
         SELECT 1, 'crate', id, 0, 'src/lib.rs', 'declared', NULL, NULL FROM blobs;",
    )
    .unwrap();
    migrate(&mut conn).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM rust_crate_container_sources",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        1,
        "migration 155 preserves the existing source path",
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM rust_crate_container_members",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        1,
        "migration 155 creates the source's semantic member identity",
    );
    conn.execute_batch(
        "INSERT INTO rust_crate_container_sources SELECT 1, 'crate', id, 0, 'src/alias.rs', 'include', NULL, NULL FROM blobs;
         INSERT INTO rust_crate_glob_reexport_routes
         VALUES(1, 'crate', zeroblob(32), 'crate::a', 'public', NULL);
         INSERT INTO rust_crate_reexport_routes
         VALUES(1, 'crate', 'Y', zeroblob(32), 'crate::a', 'X', 'public', NULL);
         INSERT INTO rust_crate_gaps VALUES(1, 'unresolved_import', 'crate::missing',
                                          jsonb('{\"reason\":\"missing\"}'));
         UPDATE rust_crate_topologies SET export_surface_digest = zeroblob(32),
                publication_state = 'complete' WHERE topology_id = 1;",
    )
    .unwrap();
    assert!(
        conn.execute(
            "INSERT INTO rust_crate_glob_reexport_routes
         VALUES(1, 'crate', zeroblob(32), 'crate::a', 'public', NULL)",
            [],
        )
        .is_err(),
        "duplicate glob routes must be rejected"
    );
    assert!(
        conn.execute(
            "INSERT INTO rust_crate_reexport_routes
         VALUES(1, 'crate', 'Y', zeroblob(32), 'crate::a', 'X', 'public', NULL)",
            [],
        )
        .is_err(),
        "duplicate named routes must be rejected"
    );
    assert!(
        conn.execute(
            "UPDATE rust_crate_topologies SET export_surface_digest = NULL",
            [],
        )
        .is_err(),
        "complete topology requires a surface digest"
    );
    assert_eq!(
        conn.query_row(
            "SELECT json(cfg_atoms) FROM rust_crate_topologies",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap(),
        "[\"test\"]"
    );
    migrate(&mut conn).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM rust_crate_container_sources",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        2,
        "one member can retain two source paths",
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM rust_crate_container_members",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        1,
        "the two paths share one semantic member identity",
    );
    assert_eq!(
        conn.query_row(
            "SELECT (SELECT count(*) FROM rust_crate_reexport_routes) + (SELECT count(*) FROM rust_crate_glob_reexport_routes)",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        2
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM blobs", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(current_schema_is_valid(&conn).unwrap());
    validate_foreign_keys(&conn).unwrap();
}

#[test]
fn rust_impl_scope_and_include_invocation_migration_preserves_unknowns() {
    let scope_migration = POST_BASELINE_MIGRATIONS
        .iter()
        .find(|migration| migration.version == 500)
        .expect("impl scope migration is registered");
    let mut conn = create_current_baseline_without_migration();
    conn.pragma_update(None, "foreign_keys", false).unwrap();
    for migration in POST_BASELINE_MIGRATIONS
        .iter()
        .filter(|migration| migration.version < scope_migration.version)
    {
        conn.execute_batch(migration.sql).unwrap();
    }
    conn.execute(
        "INSERT INTO blobs(blob_oid,lang,generation) VALUES(?1,'rust',0)",
        ["1".repeat(40)],
    )
    .unwrap();
    let blob = conn.last_insert_rowid();
    conn.execute("INSERT INTO resolution_fragment_interiors(blob_id,lang,semantic_language,producer_epoch,interior_digest,expected_semantic_site_count,logical_rows,payload_bytes,publication_state) VALUES(?1,'rust','rust','test',zeroblob(32),0,1,0,'building')", [blob]).unwrap();
    conn.execute("INSERT INTO rust_include_edges(blob_id,lang,ordinal,relative_path,file_name,include_start) VALUES(?1,'rust',0,'part.rs','part.rs',0)", [blob]).unwrap();
    conn.execute_batch(scope_migration.sql).unwrap();
    conn.pragma_update(None, "foreign_keys", true).unwrap();
    conn.execute("INSERT INTO resolution_rust_impl_declarations(blob_id,declaration,enclosing_scope) VALUES(?1,1,NULL),(?1,2,0)", [blob]).unwrap();
    let scopes = conn
        .prepare(
            "SELECT enclosing_scope FROM resolution_rust_impl_declarations ORDER BY declaration",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, Option<u32>>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(scopes, [None, Some(0)]);
    let invocation: Option<u32> = conn
        .query_row(
            "SELECT invocation_occurrence_id FROM rust_include_edges",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        invocation, None,
        "old include rows retain unknown invocation identity"
    );
    validate_foreign_keys(&conn).unwrap();
    conn.execute(
        "DELETE FROM resolution_fragment_interiors WHERE blob_id=?1",
        [blob],
    )
    .unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM resolution_rust_impl_declarations",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );

    // Assert migration 500's data effects above, then check the whole chain.
    conn.pragma_update(None, "user_version", scope_migration.version)
        .unwrap();
    migrate(&mut conn).unwrap();
    assert_eq!(
        schema_object_definitions_sha256(&conn).unwrap(),
        CURRENT_SCHEMA_OBJECTS_SHA256
    );
}
