//! Thread-bound read-only borrowing of a selected operation's writer reader.
//! Nested workspace reads use exactly the selection installed on that connection.
//! Scope exit aborts if a nested guard remains: its raw connection pointer must
//! never be used after the selected reader is released.
use super::Connection;
use std::cell::RefCell;
use std::collections::HashMap;

struct Lend {
    connection: *const Connection,
    guards: usize,
}

thread_local! {
    static LENDS: RefCell<HashMap<usize, Lend>> = RefCell::new(HashMap::new());
}

pub(super) struct Scope {
    writer: usize,
}

impl Scope {
    pub(super) fn new(writer: usize, connection: &Connection) -> Self {
        // Check before insertion, and assert after the RefCell borrow ends: a
        // caught reentrant panic must leave the outer lend and guard check intact.
        let occupied = LENDS.with(|lends| lends.borrow().contains_key(&writer));
        assert!(!occupied, "nested selected-operation lend on one writer");
        LENDS.with(|lends| {
            let previous = lends.borrow_mut().insert(
                writer,
                Lend {
                    connection: connection as *const Connection,
                    guards: 0,
                },
            );
            debug_assert!(previous.is_none());
        });
        Self { writer }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let lend = LENDS.with(|lends| lends.borrow_mut().remove(&self.writer));
        // Nothing that can panic runs before this check.
        if let Some(lend) = &lend
            && lend.guards != 0
        {
            // An escaped nested guard is the only cause of an abort here. No
            // diagnostic I/O runs first: a write to stderr can panic (closed)
            // or block (full pipe, held lock) before the abort is reached.
            std::process::abort();
        }
        assert!(
            lend.is_some() || std::thread::panicking(),
            "selected-operation lend registered"
        );
    }
}

pub(super) fn active(writer: usize) -> bool {
    LENDS.with(|lends| lends.borrow().contains_key(&writer))
}

pub(super) fn borrow(writer: usize) -> Option<*const Connection> {
    LENDS.with(|lends| {
        lends.borrow_mut().get_mut(&writer).map(|lend| {
            lend.guards += 1;
            lend.connection
        })
    })
}

pub(super) fn release(writer: usize) {
    LENDS.with(|lends| {
        let mut lends = lends.borrow_mut();
        let lend = lends
            .get_mut(&writer)
            .expect("nested reader lend registered");
        assert!(lend.guards > 0);
        lend.guards -= 1;
    });
}

#[cfg(test)]
mod tests {
    use super::super::{AnalyzerStore, StoreErrorKind, WorkspaceSnapshots};
    use brokk_bifrost_test_macros::hardwon;
    use std::time::Duration;

    #[test]
    fn nested_reads_share_selected_transaction() {
        let store = AnalyzerStore::open_in_memory_single_connection().unwrap();
        let mut reader = store.read_conn().unwrap();
        let tx = reader
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .unwrap();
        store.lend_selected_reader(&tx, || {
            for nested in [
                store.read_conn().unwrap(),
                store.checkout_read_conn().unwrap(),
            ] {
                let value: i64 = nested.query_row("SELECT 42", [], |row| row.get(0)).unwrap();
                assert_eq!(value, 42);
            }
        });
        tx.commit().unwrap();
    }

    #[test]
    #[hardwon(
        "#9962: a caught reentrant lend panic must preserve the outer guard check and permit a later lend"
    )]
    fn caught_reentrant_lend_keeps_the_scope_usable() {
        let store = AnalyzerStore::open_in_memory_single_connection().unwrap();
        let mut reader = store.read_conn().unwrap();
        let tx = reader
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .unwrap();
        store.lend_selected_reader(&tx, || {
            let reentrant = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                store.lend_selected_reader(&tx, || ())
            }));
            assert!(reentrant.is_err());
            let nested = store.read_conn().unwrap();
            let value: i64 = nested.query_row("SELECT 42", [], |row| row.get(0)).unwrap();
            assert_eq!(value, 42);
        });
        // The outer scope exited through its guard check and released the
        // writer, so a later lend registers again.
        store.lend_selected_reader(&tx, || {
            assert!(store.read_conn().is_ok());
        });
        tx.commit().unwrap();
    }

    #[test]
    #[hardwon("#9962: Python selected admission opened a nested transaction on a lent reader")]
    fn python_selected_reads_share_selected_transaction() {
        use super::super::WorkspaceId;
        use super::super::python_runtime::test_support::empty_python_snapshot;
        use brokk_bifrost_core::CancellationToken;

        let store = AnalyzerStore::open_in_memory_single_connection().unwrap();
        let workspace_id = WorkspaceId("a".repeat(64));
        let snapshot = empty_python_snapshot(&store, &workspace_id, "nested-python");
        let publication = store
            .publish_python_runtime_providers(
                &snapshot,
                None,
                [0x33; 32],
                Vec::new(),
                &CancellationToken::default(),
            )
            .unwrap();
        let mut snapshots = WorkspaceSnapshots::default();
        snapshots.insert("python".into(), snapshot.clone());
        let mut generations = crate::hash::HashMap::default();
        generations.insert("python".into(), snapshot.generation);
        let mut reader = store.read_conn().unwrap();
        store
            .select_workspace_snapshots(&mut reader, &snapshots)
            .unwrap();
        let tx = reader
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .unwrap();
        store.lend_selected_reader(&tx, || {
            store
                .path_symbol_rows_by_fqn_for_langs_limited_at_snapshots(
                    &snapshots,
                    &["python".into()],
                    &generations,
                    ("pkg.mod", "pkg.mod"),
                    10,
                    || true,
                )
                .unwrap();
            store
                .with_python_runtime_acquisition(
                    publication.acquisition_id,
                    &publication.snapshot,
                    |_| Ok(()),
                )
                .unwrap();
            store
                .declaration_candidate_rows_by_identifier_for_langs_limited(
                    &["python".into()],
                    &generations,
                    "missing",
                    10,
                )
                .unwrap();
        });
        tx.commit().unwrap();
    }

    #[test]
    fn nested_transaction_commit_preserves_selected_transaction() {
        let store = AnalyzerStore::open_in_memory_single_connection().unwrap();
        let mut reader = store.read_conn().unwrap();
        let outer = reader.transaction().unwrap();
        store.lend_selected_reader(&outer, || {
            let mut nested = store.read_conn().unwrap();
            let tx = nested.transaction().unwrap();
            assert_eq!(
                tx.query_row("SELECT 42", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                42
            );
            tx.commit().unwrap();
        });
        assert!(!outer.is_autocommit());
        outer.commit().unwrap();
    }

    #[test]
    #[should_panic(expected = "nested transactional read under a selected-operation lend")]
    fn nested_mutable_reader_panics() {
        let store = AnalyzerStore::open_in_memory_single_connection().unwrap();
        let reader = store.read_conn().unwrap();
        store.lend_selected_reader(&reader, || {
            let mut nested = store.checkout_read_conn().unwrap();
            let _ = &mut *nested;
        });
    }

    #[test]
    #[hardwon("#9962: a subset request admitted extra installed languages under the lend")]
    fn nested_workspace_selection_checks_installed_rows() {
        use super::super::{GenerationId, WorkspaceId, WorkspaceSnapshotId};

        let store = AnalyzerStore::open_in_memory_single_connection().unwrap();
        let snapshot = |lang: &str, revision| WorkspaceSnapshotId {
            workspace_id: WorkspaceId("a".repeat(64)),
            lang: lang.into(),
            generation: GenerationId(1),
            revision,
        };
        let csharp = snapshot("csharp", 1);
        let python = snapshot("python", 2);
        let mut selection = WorkspaceSnapshots::default();
        selection.insert("csharp".into(), csharp.clone());
        selection.insert("python".into(), python);
        let mut reader = store.read_conn().unwrap();
        store
            .select_workspace_snapshots(&mut reader, &selection)
            .unwrap();
        let tx = reader.transaction().unwrap();
        store.lend_selected_reader(&tx, || {
            let mut request = WorkspaceSnapshots::default();
            request.insert("csharp".into(), csharp.clone());
            assert_eq!(
                store
                    .read_conn_for_workspace(&request)
                    .err()
                    .unwrap()
                    .kind(),
                StoreErrorKind::SelectedLendSnapshotMismatch
            );
            assert!(store.read_conn_for_workspace(&selection).is_ok());
            request.insert("go".into(), snapshot("go", 1));
            assert_eq!(
                store
                    .read_conn_for_workspace(&request)
                    .err()
                    .unwrap()
                    .kind(),
                StoreErrorKind::SelectedLendSnapshotMismatch
            );
            request.remove("go");
            request.insert("csharp".into(), snapshot("csharp", 3));
            assert_eq!(
                store
                    .read_conn_for_workspace(&request)
                    .err()
                    .unwrap()
                    .kind(),
                StoreErrorKind::SelectedLendSnapshotMismatch
            );
        });
        tx.commit().unwrap();
    }

    #[test]
    fn nested_workspace_without_temp_table_is_typed() {
        use super::super::{GenerationId, WorkspaceId, WorkspaceSnapshotId};
        let store = AnalyzerStore::open_in_memory_single_connection().unwrap();
        let mut reader = store.read_conn().unwrap();
        reader
            .execute_batch("DROP TABLE temp.selected_workspace_revisions")
            .unwrap();
        let tx = reader.transaction().unwrap();
        store.lend_selected_reader(&tx, || {
            let mut request = WorkspaceSnapshots::default();
            request.insert(
                "csharp".into(),
                WorkspaceSnapshotId {
                    workspace_id: WorkspaceId("a".repeat(64)),
                    lang: "csharp".into(),
                    generation: GenerationId(1),
                    revision: 1,
                },
            );
            assert_eq!(
                store
                    .read_conn_for_workspace(&request)
                    .err()
                    .unwrap()
                    .kind(),
                StoreErrorKind::SelectedLendSnapshotMismatch
            );
        });
        tx.commit().unwrap();
    }

    #[test]
    #[hardwon(
        "#9962: an independent thread must wait for the selected reader instead of receiving a timing-dependent error"
    )]
    fn cross_thread_checkout_waits_for_reader() {
        let store = std::sync::Arc::new(AnalyzerStore::open_in_memory_single_connection().unwrap());
        let mut reader = store.read_conn().unwrap();
        let tx = reader.transaction().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let other_store = std::sync::Arc::clone(&store);
        let handle = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let value = other_store.read_conn().and_then(|conn| {
                conn.query_row("SELECT 42", [], |row| row.get::<_, i64>(0))
                    .map_err(Into::into)
            });
            done_tx.send(value).unwrap();
        });
        store.lend_selected_reader(&tx, || {
            started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
        });
        tx.commit().unwrap();
        assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
        drop(reader);
        assert_eq!(
            done_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap(),
            42
        );
        handle.join().unwrap();
    }

    #[test]
    fn multi_connection_lend_keeps_pool() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let reader = store.read_conn().unwrap();
        store.lend_selected_reader(&reader, || {
            assert!(store.checkout_read_conn().unwrap().is_pooled());
        });
    }

    #[test]
    #[hardwon(
        "#9962: escaped nested reader could outlive a selected connection after a caught panic"
    )]
    fn outstanding_guard_aborts_at_scope_exit() {
        let marker = std::env::temp_dir().join(format!(
            "bifrost-nested-lend-after-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("analyzer::store::nested_lend::tests::outstanding_guard_abort_child")
            .arg("--nocapture")
            .env("BIFROST_NESTED_LEND_ABORT_CHILD", &marker)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "child unexpectedly succeeded: {output:?}"
        );
        assert!(!marker.exists(), "code after the lend ran");
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(output.status.signal(), Some(6));
        }
    }

    #[test]
    fn outstanding_guard_abort_child() {
        let Ok(marker) = std::env::var("BIFROST_NESTED_LEND_ABORT_CHILD") else {
            return;
        };
        let store = AnalyzerStore::open_in_memory_single_connection().unwrap();
        let reader = store.read_conn().unwrap();
        let _escaped = store.lend_selected_reader(&reader, || store.checkout_read_conn().unwrap());
        std::fs::write(marker, b"after lend").unwrap();
    }
}
