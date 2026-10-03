use super::*;

const OWNER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OID: &str = "2222222222222222222222222222222222222222";

fn root(conn: &Connection, revision: i64) {
    let tx = conn.unchecked_transaction().unwrap();
    tx.execute(
        "INSERT OR IGNORE INTO workspace_revisions VALUES(?1,'java',1,?2)",
        rusqlite::params![OWNER, revision],
    )
    .unwrap();
    tx.execute(
        "INSERT INTO workspace_resolution_content_roots
        SELECT ?1,'java',1,?2,blob.id FROM blobs AS blob
        JOIN analysis_epochs AS epoch ON epoch.lang=blob.lang AND epoch.generation=blob.generation
        WHERE blob.blob_oid=?3 AND blob.lang='java' AND blob.generation=1
        ON CONFLICT DO NOTHING",
        rusqlite::params![OWNER, revision, OID],
    )
    .unwrap();
    tx.commit().unwrap();
}

#[test]
fn real_collector_preserves_roots_published_after_candidate_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = temp.path().canonicalize().unwrap();
    let repo = gitblob::test_repo::init_repo(&workspace);
    let db = gitblob::cache_db_path(&workspace);
    let conn = cache_db::open_unified_connection(&db).unwrap();
    conn.execute_batch("INSERT INTO analysis_epochs VALUES('java','active',1)")
        .unwrap();
    conn.execute(
        "INSERT INTO blobs(blob_oid,lang,generation) VALUES(?1,'java',1)",
        [OID],
    )
    .unwrap();
    assert_eq!(
        force_gc(&db, &repo, &workspace).unwrap().analyzer_dropped,
        1
    );
    conn.execute(
        "INSERT INTO blobs(blob_oid,lang,generation) VALUES(?1,'java',1)",
        [OID],
    )
    .unwrap();
    let other_db = db.clone();
    let _hook = after_resolution_candidate_snapshot_for_test(move || {
        let writer = cache_db::open_unified_connection(&other_db).unwrap();
        root(&writer, 1);
        root(&writer, 1);
    });
    assert_eq!(
        force_gc(&db, &repo, &workspace).unwrap().analyzer_dropped,
        0,
        "the real deletion transaction rechecks a root committed after its candidate snapshot"
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM workspace_resolution_content_roots",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    root(&conn, 2);
    conn.execute("INSERT INTO workspace_heads VALUES(?1,'java',1,2)", [OWNER])
        .unwrap();
    conn.execute("DELETE FROM workspace_revisions WHERE revision=1", [])
        .unwrap();
    assert_eq!(
        force_gc(&db, &repo, &workspace).unwrap().analyzer_dropped,
        0
    );
    conn.execute("DELETE FROM workspace_heads", []).unwrap();
    conn.execute("DELETE FROM workspace_revisions", []).unwrap();
    assert_eq!(
        force_gc(&db, &repo, &workspace).unwrap().analyzer_dropped,
        1
    );
}

#[test]
fn real_collector_root_seeks_have_constant_vm_work_across_history_sizes() {
    for state in PlannerStatisticsState::BOTH {
        let mut previous_vm = None;
        for count in [16, 256, 4096] {
            let mut conn = Connection::open_in_memory().unwrap();
            cache_db::configure_connection(&mut conn).unwrap();
            cache_db::migrate(&mut conn).unwrap();
            conn.execute_batch("INSERT INTO analysis_epochs VALUES('java','active',1)")
                .unwrap();
            conn.execute(
                "INSERT INTO blobs(blob_oid,lang,generation) VALUES(?1,'java',1)",
                [OID],
            )
            .unwrap();
            root(&conn, 1);
            for index in 1..=count {
                let oid = format!("{index:040x}");
                conn.execute(
                    "INSERT INTO blobs(blob_oid,lang,generation) VALUES(?1,'java',1)",
                    [&oid],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO workspace_resolution_content_roots
                    SELECT ?1,'java',1,1,id FROM blobs WHERE blob_oid=?2 AND lang='java'",
                    rusqlite::params![OWNER, oid],
                )
                .unwrap();
            }
            state.install(&conn);
            let plan = conn
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN {DELETE_ANALYZER_CANDIDATE_SQL}"
                ))
                .unwrap()
                .query_map(rusqlite::params![OID, "java", 1], |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                plan.iter().any(|detail| detail.contains(
                    "SEARCH roots USING COVERING INDEX workspace_resolution_content_roots_blob"
                )),
                "state={state:?}, roots={count}, plan={plan:?}"
            );
            let mut delete = conn.prepare(DELETE_ANALYZER_CANDIDATE_SQL).unwrap();
            assert_eq!(
                delete.execute(rusqlite::params![OID, "java", 1]).unwrap(),
                0
            );
            let vm = delete.get_status(rusqlite::StatementStatus::VmStep);
            eprintln!(
                "resolution root collector: state={state:?}, roots={count}, bindings=({OID},java,1), vm={vm}, plan={plan:?}"
            );
            if let Some(previous) = previous_vm {
                assert_eq!(vm, previous, "state={state:?}, roots={count}");
            }
            previous_vm = Some(vm);
        }
    }
}
