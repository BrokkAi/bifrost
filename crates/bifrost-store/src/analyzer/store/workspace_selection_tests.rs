//! External-writer regressions for connection-local materialized selections.

use super::*;
use brokk_bifrost_core::cache_db::sql_profile::{ListenerEvent, attach_listener};
use brokk_bifrost_test_macros::hardwon;
use std::sync::{Arc, Mutex};

fn selected_rows(conn: &Connection) -> Vec<String> {
    let mut rows = Vec::new();
    for sql in [
        "SELECT json_array(hex(unit_key),valid_from,summary_id,manifest_file_version_id,topology_id)
         FROM temp.selected_rust_unit_summaries ORDER BY workspace_id,unit_key,summary_id",
        "SELECT json_array(hex(root_unit_key),hex(unit_key),summary_id,topology_id)
         FROM temp.selected_rust_unit_closure ORDER BY workspace_id,root_unit_key,unit_key,summary_id",
    ] {
        rows.extend(
            conn.prepare(sql)
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap(),
        );
    }
    rows
}

#[expect(
    clippy::disallowed_methods,
    reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
)]
fn check_fresh(store: &AnalyzerStore, snapshots: &WorkspaceSnapshots) -> Vec<String> {
    let reused = store.read_conn_for_workspace(snapshots).unwrap();
    let actual = selected_rows(&reused);
    let fresh =
        crate::cache_db::open_readonly_temp_connection(store.db_path.as_ref().unwrap()).unwrap();
    ensure_revisioned_workspace_views(&fresh).unwrap();
    for snapshot in snapshots.values() {
        fresh
            .execute(
                "INSERT INTO temp.selected_workspace_revisions VALUES(?1,?2,?3,?4)",
                params![
                    snapshot.workspace_id.as_str(),
                    snapshot.lang,
                    snapshot.generation.0,
                    snapshot.revision
                ],
            )
            .unwrap();
    }
    fill_selected_rust_units(&fresh).unwrap();
    assert_eq!(actual, selected_rows(&fresh));
    actual
}

fn selection_fixture() -> (tempfile::TempDir, AnalyzerStore, Connection, String, String) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("cache.db");
    let store = AnalyzerStore::open_persistent(&path).unwrap();
    // No AnalyzerStore writer helper or authorizer: this is an independent
    // older writer, whose raw SQL must be covered by the persisted schema.
    let writer = crate::cache_db::open_unified_connection(&path).unwrap();
    let workspace = "a".repeat(64);
    let other = "b".repeat(64);
    writer
        .execute(
            "INSERT INTO resolution_producer_epochs VALUES('rust','fixture')
                    ON CONFLICT(lang) DO UPDATE SET producer_epoch=excluded.producer_epoch",
            [],
        )
        .unwrap();
    for id in [&workspace, &other] {
        for revision in [1, 3] {
            writer
                .execute(
                    "INSERT INTO workspace_revisions VALUES(?1,'rust',0,?2)",
                    params![id, revision],
                )
                .unwrap();
        }
    }
    for id in [1_i64, 2] {
        let digest = [id as u8; 32];
        writer.execute("INSERT INTO rust_crate_topologies(topology_id,topology_digest,crate_key,producer_epoch,target_kind,crate_name,edition,prelude,cfg_atoms,inventory_complete,export_surface_digest,publication_state)
            VALUES(?1,?2,?2,'fixture','lib','fixture','2021','std',jsonb('[]'),1,?2,'complete')", params![id,digest]).unwrap();
        writer.execute("INSERT INTO resolution_unit_summaries(summary_id,lang,unit_kind,unit_key,summary_digest,producer_epoch,derivation_identity,complete,output_digest,publication_state)
            VALUES(?1,'rust','rust_crate',?2,?2,'fixture',?3,1,?2,'complete')", params![id,digest,rust_unit_summaries::rust_unit_summary_derivation_identity()]).unwrap();
        writer.execute("INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id)
            VALUES(?1,'rust',0,?2,1,?3)", params![workspace,digest,id]).unwrap();
        writer.execute("INSERT INTO rust_resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id,topology_id)
            VALUES(?1,'rust',0,?2,1,?3,?3)", params![workspace,digest,id]).unwrap();
        writer.execute("INSERT INTO rust_resolution_unit_summary_contexts(summary_id,target_kind,crate_name,edition,prelude,cfg_atoms,inventory_complete,development_capable)
            VALUES(?1,'lib','fixture','2021','std',jsonb('[]'),1,0)", [id]).unwrap();
    }
    (temp, store, writer, workspace, other)
}

#[test]
#[hardwon(
    "#13416: unrelated commits rebuilt selections while external selection mutations needed freshness"
)]
#[expect(
    clippy::disallowed_methods,
    reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
)]
fn workspace_selection_external_mutation_matrix() {
    let (_temp, store, writer, workspace, other) = selection_fixture();
    let snapshots = |revision| {
        WorkspaceSnapshots::from_iter([(
            "rust".into(),
            WorkspaceSnapshotId {
                workspace_id: WorkspaceId(workspace.clone()),
                lang: "rust".into(),
                generation: GenerationId::BOOTSTRAP,
                revision,
            },
        )])
    };
    let selection = snapshots(3);
    let initial = check_fresh(&store, &selection);
    assert_eq!(
        initial.len(),
        4,
        "two summary rows and their reflexive closure"
    );
    let mutate = |sql: &str, changes: bool| {
        let before = workspace_selection_stamp(&writer, &selection).unwrap();
        let counts = store.workspace_selection_counts_for_test();
        writer.execute_batch(sql).unwrap();
        let after = workspace_selection_stamp(&writer, &selection).unwrap();
        assert_eq!(before != after, changes, "{sql}");
        let result = check_fresh(&store, &selection);
        assert_eq!(
            store.workspace_selection_counts_for_test().1,
            counts.1 + usize::from(changes),
            "{sql}"
        );
        result
    };
    // All six input families change through independent raw SQL.
    mutate(
        "UPDATE resolution_unit_summaries SET producer_epoch='other' WHERE summary_id=1",
        true,
    );
    assert_eq!(
        mutate(
            "UPDATE resolution_unit_summaries SET producer_epoch='fixture' WHERE summary_id=1",
            true
        ),
        initial
    );
    let dependency = format!(
        "INSERT INTO resolution_unit_summary_dependencies VALUES(1,0,x'{}',zeroblob(32),'workspace',NULL)",
        "02".repeat(32)
    );
    assert_eq!(
        mutate(&dependency, true).len(),
        5,
        "the added edge must extend closure"
    );
    // Same-ID repair changes the dependency relation without changing versions.
    mutate(
        "UPDATE resolution_unit_summary_dependencies SET boundary='external' WHERE summary_id=1",
        true,
    );
    mutate(
        "UPDATE resolution_unit_summary_dependencies SET boundary='workspace' WHERE summary_id=1",
        true,
    );
    mutate(
        "DELETE FROM resolution_unit_summary_dependencies WHERE summary_id=1",
        true,
    );
    mutate(
        "DELETE FROM rust_resolution_unit_summary_contexts WHERE summary_id=1",
        true,
    );
    mutate(
        "INSERT INTO rust_resolution_unit_summary_contexts(summary_id,target_kind,crate_name,edition,prelude,cfg_atoms,inventory_complete,development_capable) VALUES(1,'lib','fixture','2021','std',jsonb('[]'),1,0)",
        true,
    );
    mutate(
        "UPDATE rust_resolution_unit_summary_versions SET topology_id=2 WHERE summary_id=1",
        true,
    );
    mutate(
        "UPDATE rust_resolution_unit_summary_versions SET topology_id=1 WHERE summary_id=1",
        true,
    );
    mutate(
        "UPDATE resolution_producer_epochs SET producer_epoch='other' WHERE lang='rust'",
        true,
    );
    mutate(
        "UPDATE resolution_producer_epochs SET producer_epoch='fixture' WHERE lang='rust'",
        true,
    );
    mutate(
        "UPDATE resolution_unit_summary_versions SET valid_until=2 WHERE summary_id=1",
        true,
    );
    // R=1 remains inside both intervals: closing at R=2 must not invalidate it.
    let old = snapshots(1);
    check_fresh(&store, &old);
    let old_stamp = workspace_selection_stamp(&writer, &old).unwrap();
    writer
        .execute(
            "UPDATE resolution_unit_summary_versions SET valid_until=NULL WHERE summary_id=1",
            [],
        )
        .unwrap();
    assert_eq!(old_stamp, workspace_selection_stamp(&writer, &old).unwrap());
    check_fresh(&store, &old);
    check_fresh(&store, &selection);
    mutate(
        "DELETE FROM resolution_unit_summary_versions WHERE summary_id=2",
        true,
    );
    assert_eq!(
        writer
            .query_row(
                "SELECT count(*) FROM rust_resolution_unit_summary_versions WHERE summary_id=2",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0,
        "version removal cascades to Rust linkage"
    );
    mutate(
        "INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id) SELECT workspace_id,lang,generation,x'0202020202020202020202020202020202020202020202020202020202020202',1,2 FROM workspace_revisions WHERE revision=1 AND workspace_id='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
        true,
    );
    mutate(
        "INSERT INTO rust_resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id,topology_id) SELECT workspace_id,lang,generation,unit_key,valid_from,summary_id,2 FROM resolution_unit_summary_versions WHERE summary_id=2",
        true,
    );
    // Raw older writers need not enable recursive DELETE triggers. REPLACE
    // must still invalidate the OLD interval and producer epoch, not just NEW.
    writer
        .pragma_update(None, "recursive_triggers", false)
        .unwrap();
    mutate(
        "INSERT OR REPLACE INTO resolution_producer_epochs VALUES('rust','replacement')",
        true,
    );
    mutate(
        "INSERT OR REPLACE INTO resolution_producer_epochs VALUES('rust','fixture')",
        true,
    );
    mutate(
        "INSERT OR REPLACE INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,valid_until,summary_id) SELECT workspace_id,lang,generation,unit_key,valid_from,2,summary_id FROM resolution_unit_summary_versions WHERE summary_id=1 AND valid_from=1 AND workspace_id='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
        true,
    );
    mutate(
        "UPDATE resolution_unit_summary_versions SET valid_until=NULL WHERE summary_id=1 AND valid_from=1",
        true,
    );
    mutate(
        "INSERT INTO rust_resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id,topology_id) SELECT workspace_id,lang,generation,unit_key,valid_from,summary_id,1 FROM resolution_unit_summary_versions WHERE summary_id=1 AND valid_from=1",
        true,
    );
    writer
        .pragma_update(None, "recursive_triggers", true)
        .unwrap();
    // A repair can replace children while retaining the header and version IDs.
    mutate(
        &format!(
            "BEGIN; UPDATE resolution_unit_summaries SET publication_state='building',output_digest=NULL WHERE summary_id=1; DELETE FROM resolution_unit_summary_dependencies WHERE summary_id=1; {dependency}; UPDATE resolution_unit_summaries SET publication_state='complete',output_digest=zeroblob(32) WHERE summary_id=1; COMMIT;"
        ),
        true,
    );
    mutate(
        "BEGIN; UPDATE resolution_unit_summaries SET producer_epoch='rolled-back' WHERE summary_id=1; ROLLBACK;",
        false,
    );
    mutate(
        "UPDATE resolution_unit_summaries SET producer_epoch=producer_epoch",
        false,
    );
    mutate(
        "UPDATE rust_resolution_unit_summary_contexts SET crate_name='live-attribute'",
        false,
    );
    mutate("CREATE TABLE unrelated(value INTEGER);", true); // A schema change still refreshes.
    mutate("INSERT INTO unrelated VALUES(1)", false);
    mutate(
        &format!(
            "INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id) VALUES('{other}','rust',0,zeroblob(32),1,1)"
        ),
        false,
    );
    // More recent versions are irrelevant to both selected historical revisions.
    mutate(
        &format!(
            "INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id) VALUES('{workspace}','rust',0,zeroblob(32),4,1)"
        ),
        false,
    );

    let mut reader = store.read_conn_for_workspace(&selection).unwrap();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let captured = Arc::clone(&seen);
    let _listener = attach_listener(
        &reader,
        Arc::new(move |event| {
            if let ListenerEvent::Statement { sql: Some(sql), .. } = event {
                captured.lock().unwrap().push(sql.to_owned());
            }
        }),
    );
    store
        .select_workspace_snapshots(&mut reader, &selection)
        .unwrap();
    assert_eq!(
        seen.lock().unwrap().len(),
        3,
        "stable checkout is one indexed epoch SELECT and two schema PRAGMAs"
    );
    let first = std::mem::take(&mut *seen.lock().unwrap());
    writer
        .execute("INSERT INTO unrelated VALUES(2)", [])
        .unwrap();
    store
        .select_workspace_snapshots(&mut reader, &selection)
        .unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        first,
        "an unrelated external commit preserves exact stable-checkout SQL work"
    );
}

#[test]
#[hardwon(
    "#13857: non-Rust reader checkouts did redundant Rust work and could retain untracked Rust selection rows"
)]
#[expect(
    clippy::disallowed_methods,
    reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
)]
fn workspace_selection_without_rust_snapshot_does_no_rust_work() {
    let (_temp, store, writer, workspace, _other) = selection_fixture();
    let snapshot = |lang: &str| {
        (
            lang.to_owned(),
            WorkspaceSnapshotId {
                workspace_id: WorkspaceId(workspace.clone()),
                lang: lang.into(),
                generation: GenerationId::BOOTSTRAP,
                revision: 3,
            },
        )
    };
    let empty = WorkspaceSnapshots::default();
    let java = WorkspaceSnapshots::from_iter([snapshot("java")]);
    let rust = WorkspaceSnapshots::from_iter([snapshot("rust")]);
    let mut reader = store.read_conn_for_workspace(&java).unwrap();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let captured = Arc::clone(&seen);
    let _listener = attach_listener(
        &reader,
        Arc::new(move |event| {
            if let ListenerEvent::Statement { sql: Some(sql), .. } = event {
                captured.lock().unwrap().push(sql.to_owned());
            }
        }),
    );
    let rust_work = |seen: &Mutex<Vec<String>>| {
        std::mem::take(&mut *seen.lock().unwrap())
            .into_iter()
            .filter(|sql| {
                sql.contains("workspace_selection_epochs")
                    || sql.contains("schema_version")
                    || sql.contains("selected_rust_unit")
            })
            .collect::<Vec<_>>()
    };
    // Warm up, then alternate: no Rust statement of any kind may run.
    store
        .select_workspace_snapshots(&mut reader, &empty)
        .unwrap();
    store
        .select_workspace_snapshots(&mut reader, &java)
        .unwrap();
    seen.lock().unwrap().clear();
    for _ in 0..3 {
        for selection in [&empty, &java, &java, &empty] {
            store
                .select_workspace_snapshots(&mut reader, selection)
                .unwrap();
        }
    }
    assert_eq!(rust_work(&seen), Vec::<String>::new());
    // A Rust selection materializes, and a later move of its epoch rebuilds it.
    store
        .select_workspace_snapshots(&mut reader, &rust)
        .unwrap();
    assert_eq!(selected_rows(&reader).len(), 4);
    seen.lock().unwrap().clear();
    writer
        .execute(
            "UPDATE resolution_unit_summaries SET producer_epoch='other' WHERE summary_id=1",
            [],
        )
        .unwrap();
    let writes = store.workspace_selection_counts_for_test().1;
    store
        .select_workspace_snapshots(&mut reader, &rust)
        .unwrap();
    assert_eq!(store.workspace_selection_counts_for_test().1, writes + 1);
    // Leaving Rust clears the Rust rows, not just the request.
    store
        .select_workspace_snapshots(&mut reader, &java)
        .unwrap();
    assert_eq!(selected_rows(&reader), Vec::<String>::new());
    drop(reader);

    // A resolution selection fills the Rust rows of a pooled reader whose memo
    // says "Java, no Rust". It must not leave that memo behind: the next
    // non-Rust selection has to clear the rows the memo knows nothing about.
    // A fresh store whose Rust producer epoch is the one a selection requires.
    let (_temp, store, writer, workspace, _other) = selection_fixture();
    let bundle_epoch = resolution::resolution_bundle_epoch(Language::Rust);
    writer
        .execute(
            "UPDATE resolution_producer_epochs SET producer_epoch=?1 WHERE lang='rust'",
            [bundle_epoch],
        )
        .unwrap();
    writer
        .execute(
            "UPDATE resolution_unit_summaries SET producer_epoch=?1",
            [bundle_epoch],
        )
        .unwrap();
    let snapshot = |lang: &str, revision: i64| {
        (
            lang.to_owned(),
            WorkspaceSnapshotId {
                workspace_id: WorkspaceId(workspace.clone()),
                lang: lang.into(),
                generation: GenerationId::BOOTSTRAP,
                revision,
            },
        )
    };
    let java = WorkspaceSnapshots::from_iter([snapshot("java", 3)]);
    let rust = WorkspaceSnapshots::from_iter([snapshot("rust", 3)]);
    let java_old = WorkspaceSnapshots::from_iter([snapshot("java", 1)]);
    let mut reader = store.active_read_conn().unwrap();
    store
        .select_workspace_snapshots(&mut reader, &java)
        .unwrap();
    let serial = reader.pooled_reader_serial_for_test();
    drop(reader);
    let cancellation = CancellationToken::new();
    let resolution_selection::SelectedResolutionMountInventoryOutcome::Ready(inventory) = store
        .open_selected_resolution_mount_inventory(
            &WorkspaceId(workspace.clone()),
            &rust,
            &[resolution_selection::SelectedResolutionLanguage::new(
                "rust",
                Language::Rust,
            )],
            &[],
            &cancellation,
        )
        .unwrap()
    else {
        panic!("the Rust fixture selection must open an inventory");
    };
    // Finishing a current selection authorizes retaining the reader with its
    // TEMP rows, as a resolution operation does.
    assert!(matches!(
        inventory.revalidate(&cancellation).unwrap(),
        resolution_selection::SelectedResolutionRevalidationOutcome::Current
    ));
    assert_eq!(
        selected_rows(inventory.connection()).len(),
        4,
        "the resolution inventory materialized its Rust rows"
    );
    drop(inventory);
    let mut reader = store.active_read_conn().unwrap();
    assert_eq!(
        reader.pooled_reader_serial_for_test(),
        serial,
        "the resolution reader is the one that was pooled"
    );
    assert_eq!(
        selected_rows(&reader).len(),
        4,
        "its Rust rows were retained"
    );
    store
        .select_workspace_snapshots(&mut reader, &java_old)
        .unwrap();
    assert_eq!(selected_rows(&reader), Vec::<String>::new());
}

// Each case gets a new store so an earlier replacement cannot hide a missed
// invalidation. The raw writer deliberately keeps recursive DELETE triggers off.
fn check_replacement(sql: &str) {
    let (_temp, store, writer, workspace, _other) = selection_fixture();
    writer
        .pragma_update(None, "recursive_triggers", false)
        .unwrap();
    let selection = WorkspaceSnapshots::from_iter([(
        "rust".into(),
        WorkspaceSnapshotId {
            workspace_id: WorkspaceId(workspace),
            lang: "rust".into(),
            generation: GenerationId::BOOTSTRAP,
            revision: 3,
        },
    )]);
    // A real workspace edge makes loss of that edge observable in the closure.
    writer.execute("INSERT INTO resolution_unit_summary_dependencies VALUES(1,0,?1,zeroblob(32),'workspace',NULL)", [[2_u8;32]]).unwrap();
    assert_eq!(check_fresh(&store, &selection).len(), 5);
    let before = workspace_selection_stamp(&writer, &selection).unwrap();
    writer.execute_batch(sql).unwrap();
    let after = workspace_selection_stamp(&writer, &selection).unwrap();
    assert_ne!(
        before, after,
        "replacement must invalidate the displaced row: {sql}"
    );
    check_fresh(&store, &selection);
}

macro_rules! replacement_test {
    ($name:ident, $sql:expr) => {
        #[test]
        #[hardwon("#13416: REPLACE with recursive triggers off must invalidate every displaced selection input")]
        fn $name() { check_replacement($sql); }
    };
}

replacement_test!(
    workspace_selection_replace_dependency_primary_key,
    "INSERT OR REPLACE INTO resolution_unit_summary_dependencies VALUES(1,0,zeroblob(32),zeroblob(32),'external',NULL)"
);
replacement_test!(
    workspace_selection_replace_dependency_unique_key,
    "INSERT OR REPLACE INTO resolution_unit_summary_dependencies SELECT summary_id,1,dependency_unit_key,consumed_output_digest,'standard',NULL FROM resolution_unit_summary_dependencies WHERE summary_id=1"
);
replacement_test!(
    workspace_selection_replace_rust_linkage,
    "INSERT OR REPLACE INTO rust_resolution_unit_summary_versions SELECT workspace_id,lang,generation,unit_key,profile_digest,valid_from,2,manifest_file_version_id,topology_id FROM rust_resolution_unit_summary_versions WHERE summary_id=1"
);
replacement_test!(
    workspace_selection_replace_generic_version_primary_key,
    "INSERT OR REPLACE INTO resolution_unit_summary_versions SELECT workspace_id,lang,generation,unit_key,profile_digest,valid_from,2,summary_id FROM resolution_unit_summary_versions WHERE summary_id=1"
);
replacement_test!(
    workspace_selection_replace_generic_version_open_unique_key,
    "INSERT OR REPLACE INTO resolution_unit_summary_versions SELECT workspace_id,lang,generation,unit_key,profile_digest,4,NULL,summary_id FROM resolution_unit_summary_versions WHERE summary_id=1"
);
replacement_test!(
    workspace_selection_replace_producer,
    "INSERT OR REPLACE INTO resolution_producer_epochs VALUES('rust','replacement')"
);
replacement_test!(
    workspace_selection_replace_context,
    "INSERT OR REPLACE INTO rust_resolution_unit_summary_contexts(summary_id,target_kind,crate_name,edition,prelude,cfg_atoms,inventory_complete,development_capable) VALUES(1,'lib','replacement','2021','std',jsonb('[]'),1,0)"
);
replacement_test!(
    workspace_selection_replace_header_primary_key,
    "INSERT OR REPLACE INTO resolution_unit_summaries(summary_id,lang,unit_kind,unit_key,summary_digest,producer_epoch,derivation_identity,complete,output_digest,publication_state) SELECT summary_id,'python',unit_kind,unit_key,summary_digest,producer_epoch,derivation_identity,complete,output_digest,publication_state FROM resolution_unit_summaries WHERE summary_id=1"
);
// Disable FK enforcement only for this legacy-writer case: otherwise changing
// the header ID would be rejected by the non-cascading generic-version FK.
replacement_test!(
    workspace_selection_replace_header_unique_key,
    "PRAGMA foreign_keys=OFF; INSERT OR REPLACE INTO resolution_unit_summaries(summary_id,lang,unit_kind,unit_key,summary_digest,producer_epoch,derivation_identity,complete,output_digest,publication_state) SELECT 3,'python',unit_kind,unit_key,summary_digest,producer_epoch,derivation_identity,complete,output_digest,publication_state FROM resolution_unit_summaries WHERE summary_id=1"
);

replacement_test!(
    workspace_selection_update_replace_dependency_primary_key,
    "INSERT INTO resolution_unit_summary_dependencies VALUES(1,1,zeroblob(32),zeroblob(32),'external',NULL); UPDATE OR REPLACE resolution_unit_summary_dependencies SET dependency_ordinal=0 WHERE summary_id=1 AND dependency_ordinal=1"
);
replacement_test!(
    workspace_selection_update_replace_dependency_unique_key,
    "INSERT INTO resolution_unit_summary_dependencies VALUES(1,1,zeroblob(32),zeroblob(32),'external',NULL); UPDATE OR REPLACE resolution_unit_summary_dependencies SET dependency_unit_key=(SELECT dependency_unit_key FROM resolution_unit_summary_dependencies WHERE summary_id=1 AND dependency_ordinal=0) WHERE summary_id=1 AND dependency_ordinal=1"
);
replacement_test!(
    workspace_selection_update_replace_rust_linkage,
    "INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,valid_until,summary_id) SELECT workspace_id,lang,generation,unit_key,4,5,2 FROM resolution_unit_summary_versions WHERE summary_id=1; INSERT INTO rust_resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id,topology_id) SELECT workspace_id,lang,generation,unit_key,valid_from,summary_id,2 FROM resolution_unit_summary_versions WHERE valid_from=4; UPDATE OR REPLACE rust_resolution_unit_summary_versions SET valid_from=1 WHERE valid_from=4"
);
// Disabling FKs isolates the generic input trigger from cascading Rust-linkage
// deletion, which can independently invalidate the same selected revision.
replacement_test!(
    workspace_selection_update_replace_generic_version_primary_key,
    "PRAGMA foreign_keys=OFF; INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,valid_until,summary_id) SELECT workspace_id,lang,generation,unit_key,4,5,summary_id FROM resolution_unit_summary_versions WHERE summary_id=1; UPDATE OR REPLACE resolution_unit_summary_versions SET valid_from=1,valid_until=2 WHERE valid_from=4"
);
replacement_test!(
    workspace_selection_update_replace_generic_version_open_unique_key,
    "PRAGMA foreign_keys=OFF; INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,valid_until,summary_id) SELECT workspace_id,lang,generation,unit_key,4,5,summary_id FROM resolution_unit_summary_versions WHERE summary_id=1; UPDATE OR REPLACE resolution_unit_summary_versions SET valid_until=NULL WHERE valid_from=4"
);
replacement_test!(
    workspace_selection_update_replace_producer,
    "INSERT INTO resolution_producer_epochs VALUES('python','unselected'); UPDATE OR REPLACE resolution_producer_epochs SET lang='rust' WHERE lang='python'"
);
replacement_test!(
    workspace_selection_update_replace_context,
    "INSERT INTO resolution_unit_summaries(summary_id,lang,unit_kind,unit_key,summary_digest,producer_epoch,derivation_identity,complete,output_digest,publication_state) SELECT 3,lang,unit_kind,unit_key,zeroblob(32),producer_epoch,derivation_identity,complete,output_digest,publication_state FROM resolution_unit_summaries WHERE summary_id=1; INSERT INTO rust_resolution_unit_summary_contexts(summary_id,target_kind,crate_name,edition,prelude,cfg_atoms,inventory_complete,development_capable) VALUES(3,'lib','unselected','2021','std',jsonb('[]'),1,0); UPDATE OR REPLACE rust_resolution_unit_summary_contexts SET summary_id=1 WHERE summary_id=3"
);
// As in the INSERT case, the non-cascading generic-version FK would reject a
// header ID displacement unless this legacy writer disabled FK enforcement.
replacement_test!(
    workspace_selection_update_replace_header_primary_key,
    "PRAGMA foreign_keys=OFF; INSERT INTO resolution_unit_summaries(summary_id,lang,unit_kind,unit_key,summary_digest,producer_epoch,derivation_identity,complete,output_digest,publication_state) SELECT 3,'python',unit_kind,unit_key,zeroblob(32),producer_epoch,derivation_identity,complete,output_digest,publication_state FROM resolution_unit_summaries WHERE summary_id=1; UPDATE OR REPLACE resolution_unit_summaries SET summary_id=1 WHERE summary_id=3"
);
replacement_test!(
    workspace_selection_update_replace_header_unique_key,
    "PRAGMA foreign_keys=OFF; INSERT INTO resolution_unit_summaries(summary_id,lang,unit_kind,unit_key,summary_digest,producer_epoch,derivation_identity,complete,output_digest,publication_state) SELECT 3,'python',unit_kind,unit_key,zeroblob(32),producer_epoch,derivation_identity,complete,output_digest,publication_state FROM resolution_unit_summaries WHERE summary_id=1; UPDATE OR REPLACE resolution_unit_summaries SET summary_digest=(SELECT summary_digest FROM resolution_unit_summaries WHERE summary_id=1) WHERE summary_id=3"
);
