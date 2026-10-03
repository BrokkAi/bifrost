use super::*;

#[test]
fn crate_rows_migrate_and_round_trip_glob_routes() {
    let mut conn = create_current_baseline_without_migration();
    conn.pragma_update(None, "user_version", BASELINE_MIGRATION_VERSION)
        .unwrap();
    conn.execute(
        "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'rust', 0)",
        ["a".repeat(40)],
    )
    .unwrap();
    migrate(&mut conn).unwrap();
    conn.execute_batch(
        "INSERT INTO rust_crate_topologies(topology_digest, crate_key, producer_epoch,
             target_kind, crate_name, edition, prelude, cfg_atoms, inventory_complete, publication_state)
         VALUES(zeroblob(32), zeroblob(32), 'crate-rows-test', 'lib', 'sample', '2021', 'std',
                jsonb('[\"test\"]'), 1, 'building');
         INSERT INTO rust_crate_containers VALUES(1, 'crate', 'module', 'root');
         INSERT INTO rust_crate_container_sources SELECT 1, 'crate', id, 0, 'src/lib.rs', 'declared', NULL, NULL FROM blobs;
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
