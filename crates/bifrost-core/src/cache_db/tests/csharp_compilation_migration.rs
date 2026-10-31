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
