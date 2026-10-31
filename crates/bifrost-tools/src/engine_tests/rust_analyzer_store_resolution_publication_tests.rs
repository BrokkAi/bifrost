#[cfg(test)]
mod rust_departing_root_tests {
    use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;

    use rusqlite::params;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use std::sync::Arc;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::store::GenerationId;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::store::PreparedParsedBlob;

    use brokk_bifrost_analysis::analyzer::store::StoredCascadeCost;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceId;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::measured_resolution_payload;

    use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid;

    use brokk_bifrost_analysis::analyzer::store::js_ts_resolution_producer_support::parsed_fixture_state;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::persist_one;

    use brokk_bifrost_analysis::analyzer::store::persisted_blob_mutation_cost_fallback_sql;

    use brokk_bifrost_analysis::analyzer::store::persisted_blob_mutation_cost_fallback_statement;

    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    use brokk_bifrost_analysis::analyzer::store::rust_projection_cascade_payload_bytes_sql;

    use brokk_bifrost_analysis::analyzer::store::rust_projection_cascade_rows_sql;

    use brokk_bifrost_analysis::analyzer::store::stale_generation_blob_costs_sql;

    use brokk_bifrost_analysis::analyzer::store::stored_blob_cascade_costs_sql;

    use brokk_bifrost_analysis::analyzer::store::resolution_publication::PublishedResolutionContent;

    use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionContentInput;

    use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionContentPublicationOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionStale;
    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::selected_publication::rust_root_test_support::counted_logical_store_rows as counted_logical_store_rows;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::selected_publication::rust_root_test_support::owner as owner;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::selected_publication::rust_root_test_support::ready as ready;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::selected_publication::rust_root_test_support::roots as roots;

    const SOURCE: &str = "pub fn target() {}\npub fn caller() { target(); }\n";

    const HOST: &str = "src/lib.rs";

    fn prepared(snapshot: &WorkspaceSnapshotId) -> PreparedParsedBlob {
        let state = parsed_fixture_state(&RustAdapter, HOST, SOURCE);
        AnalyzerStore::prepare_parsed_blob(
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid(SOURCE.as_bytes()), "rust"),
            snapshot.generation,
            &RustAdapter,
            state,
        )
        .unwrap()
    }

    fn publish(
        store: &AnalyzerStore,
        snapshot: &WorkspaceSnapshotId,
    ) -> PublishedResolutionContent {
        ready(
            store
                .publish_selected_parsed_content(
                    snapshot,
                    HOST,
                    prepared(snapshot),
                    &CancellationToken::default(),
                )
                .unwrap(),
        )
    }

    #[test]
    fn selected_publication_new_cached_and_cancelled_retry_are_atomic() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let snapshot = owner(&store, 'a');
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        assert!(matches!(
            store
                .publish_selected_parsed_content(&snapshot, HOST, prepared(&snapshot), &cancelled)
                .unwrap(),
            ResolutionContentPublicationOutcome::Cancelled
        ));
        assert!(roots(&store).is_empty());
        assert_eq!(
            store.conn.execute(|conn| conn
                .query_row("SELECT count(*) FROM blobs", [], |row| row.get::<_, i64>(0))
                .unwrap()),
            0
        );
        let published = publish(&store, &snapshot);
        let (witness, membership) = published.into_parts();
        assert_eq!(witness.owner(), &snapshot);
        assert!(!membership.is_empty());
        let before = store.conn.execute(|conn| conn.total_changes());
        let cached = ready(
            store
                .admit_cached_selected_content(
                    &snapshot,
                    HOST,
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                        witness.blob_oid(),
                        snapshot.lang.as_str(),
                    ),
                    witness.input(),
                    &CancellationToken::default(),
                )
                .unwrap(),
        );
        let (cached_witness, cached_membership) = cached.into_parts();
        assert_eq!(cached_witness, witness);
        assert_eq!(cached_membership, membership);
        assert_eq!(
            store.conn.execute(|conn| conn.total_changes()),
            before,
            "repeated exact cached rooting does not modify any row"
        );
    }

    #[test]
    fn selected_publication_retired_owner_and_failed_write_leave_no_content() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let snapshot = owner(&store, 'b');
        let mut broken = prepared(&snapshot);
        broken.inject_invalid_range_for_test();
        assert!(
            store
                .publish_selected_parsed_content(
                    &snapshot,
                    HOST,
                    broken,
                    &CancellationToken::default()
                )
                .is_err()
        );
        assert!(roots(&store).is_empty());
        assert_eq!(
            store.conn.execute(|conn| conn
                .query_row("SELECT count(*) FROM blobs", [], |row| row.get::<_, i64>(0))
                .unwrap()),
            0
        );
        store
            .conn
            .execute(|conn| conn.execute("DELETE FROM workspace_revisions", []))
            .unwrap();
        assert!(matches!(
            store
                .publish_selected_parsed_content(
                    &snapshot,
                    HOST,
                    prepared(&snapshot),
                    &CancellationToken::default()
                )
                .unwrap(),
            ResolutionContentPublicationOutcome::Stale(
                SelectedResolutionStale::WorkspaceRevision { .. }
            )
        ));
        assert!(roots(&store).is_empty());
    }

    #[test]
    fn ordinary_repair_preserves_every_captured_revision_owner() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let first = owner(&store, 'c');
        let second = owner(&store, 'd');
        let witness = publish(&store, &first).into_parts().0;
        ready(
            store
                .admit_cached_selected_content(
                    &second,
                    HOST,
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                        witness.blob_oid(),
                        second.lang.as_str(),
                    ),
                    witness.input(),
                    &CancellationToken::default(),
                )
                .unwrap(),
        );
        let mut later = first.clone();
        later.revision = 2;
        let later_writer = later.clone();
        store
            .conn
            .execute(move |conn| {
                conn.execute(
                    "INSERT INTO workspace_revisions VALUES(?1,?2,?3,?4)",
                    params![
                        later_writer.workspace_id.as_str(),
                        later_writer.lang,
                        later_writer.generation.0,
                        later_writer.revision
                    ],
                )
            })
            .unwrap();
        ready(
            store
                .admit_cached_selected_content(
                    &later,
                    HOST,
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                        witness.blob_oid(),
                        later.lang.as_str(),
                    ),
                    witness.input(),
                    &CancellationToken::default(),
                )
                .unwrap(),
        );
        let before = roots(&store);
        assert_eq!(before.len(), 3);
        store.repair_prepared_blob(prepared(&first)).unwrap();
        assert_eq!(
            roots(&store),
            before,
            "ordinary DELETE/reinsert preserves all valid revision owners"
        );
        assert_eq!(store.gc_with(|_| false).unwrap(), 0);
        store
            .conn
            .execute(|conn| conn.execute("DELETE FROM workspace_revisions WHERE revision=1", []))
            .unwrap();
        assert_eq!(
            roots(&store),
            vec![(later.workspace_id.as_str().to_owned(), 2)]
        );
        assert_eq!(store.gc_with(|_| false).unwrap(), 0);
        store
            .conn
            .execute(|conn| conn.execute("DELETE FROM workspace_revisions", []))
            .unwrap();
        assert_eq!(store.gc_with(|_| false).unwrap(), 1);
    }

    #[test]
    fn physical_roots_do_not_override_stale_generation_or_producer() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let snapshot = owner(&store, 'e');
        let witness = publish(&store, &snapshot).into_parts().0;
        store
            .conn
            .execute(|conn| {
                conn.execute(
        "UPDATE resolution_producer_epochs SET producer_epoch='next-producer' WHERE lang='rust'", []
    )
            })
            .unwrap();
        assert!(!roots(&store).is_empty());
        assert!(matches!(
            store
                .admit_cached_selected_content(
                    &snapshot,
                    HOST,
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                        witness.blob_oid(),
                        snapshot.lang.as_str()
                    ),
                    witness.input(),
                    &CancellationToken::default()
                )
                .unwrap(),
            ResolutionContentPublicationOutcome::Stale(
                SelectedResolutionStale::ProducerEpoch { .. }
            )
        ));
        store
            .ensure_language_epoch_value("rust", "publication-test-v2")
            .unwrap();
        assert!(matches!(
            store
                .admit_cached_selected_content(
                    &snapshot,
                    HOST,
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                        witness.blob_oid(),
                        snapshot.lang.as_str()
                    ),
                    witness.input(),
                    &CancellationToken::default()
                )
                .unwrap(),
            ResolutionContentPublicationOutcome::Stale(
                SelectedResolutionStale::AnalysisGeneration { .. }
            )
        ));
        store.reclaim_stale_generations(1).unwrap();
        assert!(
            roots(&store).is_empty(),
            "stale cleanup cascades physical roots"
        );
    }

    #[test]
    fn cached_parsed_content_checks_selected_semantic_language() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let snapshot = owner(&store, 'f');
        let witness = publish(&store, &snapshot).into_parts().0;
        let wrong = ResolutionContentInput::Parsed {
            key: brokk_bifrost_core::gitblob::BlobKey::unvaried(witness.blob_oid(), "rust"),
            semantic_language: Language::Java,
        };
        assert!(matches!(
            store
                .admit_cached_selected_content(
                    &snapshot,
                    HOST,
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                        witness.blob_oid(),
                        snapshot.lang.as_str()
                    ),
                    &wrong,
                    &CancellationToken::default()
                )
                .unwrap(),
            ResolutionContentPublicationOutcome::Stale(
                SelectedResolutionStale::ProducerEpoch { .. }
            )
        ));
    }

    #[test]
    #[hardwon("3da13ca2218b: cancellation after publication writes left partial content")]
    fn selected_publication_cancellation_after_writes_rolls_back_and_retries() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let snapshot = owner(&store, '1');
        let before = store.conn.execute(|conn| conn.total_changes());
        let cancelled = CancellationToken::cancel_after_checks_for_test(8);
        assert!(matches!(
            store
                .publish_selected_parsed_content(&snapshot, HOST, prepared(&snapshot), &cancelled)
                .unwrap(),
            ResolutionContentPublicationOutcome::Cancelled
        ));
        assert!(
            store.conn.execute(|conn| conn.total_changes()) > before,
            "cancellation happened after real transactional writes"
        );
        assert!(roots(&store).is_empty());
        assert_eq!(
            store.conn.execute(|conn| conn
                .query_row("SELECT count(*) FROM blobs", [], |row| row.get::<_, i64>(0))
                .unwrap()),
            0
        );
        let witness = publish(&store, &snapshot).into_parts().0;
        store
            .conn
            .execute(|conn| conn.execute("DELETE FROM workspace_resolution_content_roots", []))
            .unwrap();
        let before = store.conn.execute(|conn| conn.total_changes());
        let cancelled = CancellationToken::cancel_after_checks_for_test(2);
        assert!(matches!(
            store
                .admit_cached_selected_content(
                    &snapshot,
                    HOST,
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                        witness.blob_oid(),
                        snapshot.lang.as_str()
                    ),
                    witness.input(),
                    &cancelled
                )
                .unwrap(),
            ResolutionContentPublicationOutcome::Cancelled
        ));
        assert!(
            store.conn.execute(|conn| conn.total_changes()) > before,
            "cached admission rooted before cancellation interrupted membership receipt"
        );
        assert!(
            roots(&store).is_empty(),
            "cancelled receipt rolls back its root insertion"
        );
        ready(
            store
                .admit_cached_selected_content(
                    &snapshot,
                    HOST,
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                        witness.blob_oid(),
                        snapshot.lang.as_str(),
                    ),
                    witness.input(),
                    &CancellationToken::default(),
                )
                .unwrap(),
        );
        assert_eq!(roots(&store).len(), 1);
    }

    #[test]
    #[hardwon(
        "3da13ca2218b: legacy replacement and restored roots escaped complete row accounting"
    )]
    fn parsed_legacy_replacement_and_restored_roots_are_fully_charged() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let snapshot = owner(&store, '2');
        publish(&store, &snapshot);
        let repair = prepared(&snapshot);
        let new_rows = repair.mutation_logical_rows();
        let new_bytes = repair.mutation_payload_bytes();
        let costs = store
            .stored_blob_cascade_costs(&store.read_conn().unwrap(), &[repair])
            .unwrap();
        let StoredCascadeCost::Known(replaced) = costs[0] else {
            panic!("complete fast replacement cost")
        };
        let deleted_rows = store.conn.execute(|conn| {
        let tables = conn
            .prepare(
                "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let (arena, occurrences): (String, usize) = conn.query_row(
            "SELECT json(spans),json_array_length(spans) FROM source_occurrence_arenas JOIN blobs ON blobs.id=blob_id WHERE blob_oid=?1 AND lang='rust'",
            [oid(SOURCE.as_bytes()).to_string()], |row| Ok((row.get(0)?,row.get(1)?)),
        ).unwrap();
        eprintln!("RP replacement source occurrence arena: occurrences={occurrences}, spans={arena}");
        assert_eq!(occurrences,11,"independent packed occurrence proof: {arena}");
        let identifiers = conn.prepare("SELECT identifier FROM rust_identifier_occurrences WHERE blob_id=(SELECT id FROM blobs WHERE blob_oid=?1 AND lang='rust') ORDER BY identifier").unwrap().query_map([oid(SOURCE.as_bytes()).to_string()],|row|row.get::<_,String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        eprintln!("RP replacement projected identifiers: {identifiers:?}");
        assert_eq!(identifiers,vec!["caller","target"],"the omitted projections explain the remaining two logical rows");
        let tx = conn.unchecked_transaction().unwrap();
        let count_rows = || counted_logical_store_rows(&tx, &tables);
        let before = count_rows();
        tx.execute(
            "DELETE FROM blobs WHERE blob_oid=?1 AND lang='rust'",
            [oid(SOURCE.as_bytes()).to_string()],
        )
        .unwrap();
        let deleted = before - count_rows();
        tx.rollback().unwrap();
        deleted
    });
        assert_eq!(
            replaced.logical_rows, deleted_rows,
            "replacement rows equal independently counted whole-store cascade deletions"
        );
        let raw_oid = oid(SOURCE.as_bytes()).to_string();
        let fallback = store.conn.execute(move |conn| {
            conn.execute("DELETE FROM blob_payload_costs", []).unwrap();
            let mut statement = conn
                .prepare_cached(persisted_blob_mutation_cost_fallback_sql())
                .unwrap();
            persisted_blob_mutation_cost_fallback_statement(
                &mut statement,
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                    git2::Oid::from_str(&raw_oid).unwrap(),
                    "rust",
                ),
            )
            .unwrap()
        });
        assert_eq!(
            fallback.logical_rows + 1,
            replaced.logical_rows,
            "legacy fallback differs only by the deleted payload-cost row"
        );
        assert_eq!(fallback.payload_bytes, replaced.payload_bytes);
        let stats = persist_one(&store, prepared(&snapshot));
        assert_eq!(
            stats.logical_rows,
            new_rows + fallback.logical_rows + 1,
            "repair charges both root deletion and root restoration"
        );
        assert_eq!(
            stats.payload_bytes,
            new_bytes + fallback.payload_bytes + 64 + "rust".len()
        );
        assert_eq!(roots(&store).len(), 1);
    }

    #[test]
    #[hardwon("3da13ca2218b: prewrite accounting miscounted shared ids and multibyte payloads")]
    fn large_shared_ids_and_multibyte_payloads_fit_prewrite_estimates() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let snapshot = owner(&store, '3');
        store
            .conn
            .execute(|conn| {
                conn.execute(
                    "INSERT INTO resolution_identities(id,identity_digest) VALUES(2000000000,?1)",
                    [[0x9a; 32].as_slice()],
                )
            })
            .unwrap();
        let source = "pub fn caf\u{e9}() {}\npub fn entr\u{e9}e() { caf\u{e9}(); let na\u{ef}ve = 1; let _ = na\u{ef}ve; }\n";
        let state = parsed_fixture_state(&RustAdapter, HOST, source);
        let oid = oid(source.as_bytes());
        let prepared = AnalyzerStore::prepare_parsed_blob(
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "rust"),
            snapshot.generation,
            &RustAdapter,
            state,
        )
        .unwrap();
        let estimate = prepared.resolution.payload_bytes() + "rust".len();
        let content = ready(
            store
                .publish_selected_parsed_content(
                    &snapshot,
                    HOST,
                    prepared,
                    &CancellationToken::default(),
                )
                .unwrap(),
        );
        let (witness, membership) = content.into_parts();
        assert!(membership.iter().all(|(_, id)| id.get() >= 2000000000));
        assert_eq!(
            witness.payload_bytes() as usize,
            measured_resolution_payload(&store, oid, "rust")
        );
        assert!(
            estimate >= witness.payload_bytes() as usize,
            "prewrite estimate {estimate} covers exact committed bytes {}",
            witness.payload_bytes()
        );
    }

    #[test]
    #[hardwon("3da13ca2218b: a collector snapshot deleted a blob admitted concurrently")]
    fn collector_snapshot_cannot_delete_an_externally_admitted_cached_blob() {
        use std::io::{BufRead, Write};
        const READY: &str = "RP_CACHED_ADMISSION_COMMITTED";
        struct PendingPublisher {
            child: Option<std::process::Child>,
            ready_output: String,
        }
        impl PendingPublisher {
            fn await_admission(&mut self) {
                let mut output =
                    std::io::BufReader::new(self.child.as_mut().unwrap().stdout.as_mut().unwrap());
                loop {
                    let mut line = String::new();
                    assert_ne!(
                        output.read_line(&mut line).unwrap(),
                        0,
                        "publisher ended before admission: {}",
                        self.ready_output
                    );
                    self.ready_output.push_str(&line);
                    if line.trim_end() == READY {
                        break;
                    }
                }
                // Child emits no more stdout until stdin releases its store, so
                // dropping this temporary reader cannot discard later diagnostics.
            }
            fn finish(&mut self) -> std::io::Result<std::process::Output> {
                let mut child = self.child.take().unwrap();
                if let Some(mut input) = child.stdin.take()
                    && let Err(error) = input.write_all(&[1])
                {
                    eprintln!("publisher release failed (still reaping child): {error}");
                }
                let mut output = child.wait_with_output()?;
                let mut stdout = self.ready_output.as_bytes().to_vec();
                stdout.append(&mut output.stdout);
                output.stdout = stdout;
                Ok(output)
            }
        }
        impl Drop for PendingPublisher {
            fn drop(&mut self) {
                if self.child.is_some() {
                    match self.finish() {
                        Ok(output) => {
                            eprintln!("publisher reaped during fixture cleanup: {output:?}")
                        }
                        Err(error) => eprintln!("publisher cleanup failed: {error}"),
                    }
                }
            }
        }
        const CHILD_DB: &str = "BIFROST_RP_CACHED_PUBLISHER_CHILD_DB";
        if let Some(db_path) = std::env::var_os(CHILD_DB) {
            let captured =
                |name| std::env::var(name).expect("child receives captured publication input");
            let publisher = AnalyzerStore::open_persistent(std::path::Path::new(&db_path)).unwrap();
            let snapshot = WorkspaceSnapshotId {
                workspace_id: WorkspaceId(captured("BIFROST_RP_CHILD_WORKSPACE")),
                lang: captured("BIFROST_RP_CHILD_LANGUAGE"),
                generation: GenerationId::from_persisted(
                    captured("BIFROST_RP_CHILD_GENERATION").parse().unwrap(),
                ),
                revision: captured("BIFROST_RP_CHILD_REVISION").parse().unwrap(),
            };
            let blob_oid = git2::Oid::from_str(&captured("BIFROST_RP_CHILD_OID")).unwrap();
            assert_eq!(captured("BIFROST_RP_CHILD_SEMANTIC_LANGUAGE"), "rust");
            let input = ResolutionContentInput::Parsed {
                key: brokk_bifrost_core::gitblob::BlobKey::unvaried(blob_oid, "rust"),
                semantic_language: Language::Rust,
            };
            ready(
                publisher
                    .admit_cached_selected_content(
                        &snapshot,
                        &captured("BIFROST_RP_CHILD_HOST"),
                        &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                            blob_oid,
                            snapshot.lang.as_str(),
                        ),
                        &input,
                        &CancellationToken::default(),
                    )
                    .unwrap(),
            );
            println!("\n{READY}");
            std::io::stdout().flush().unwrap();
            let mut release = [0];
            std::io::Read::read_exact(&mut std::io::stdin(), &mut release).unwrap();
            assert_eq!(release, [1]);
            return;
        }
        // Separate processes are necessary: same-path stores share a writer queue.
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("publication-race.db");
        let collector = AnalyzerStore::open_persistent(&path).unwrap();
        let publisher = Arc::new(AnalyzerStore::open_persistent(&path).unwrap());
        let snapshot = owner(&publisher, '4');
        let witness = publish(&publisher, &snapshot).into_parts().0;
        publisher
            .conn
            .execute(|conn| conn.execute("DELETE FROM workspace_resolution_content_roots", []))
            .unwrap();
        // Keep this test focused on StoreError's primary and extended SQLite codes.
        // Production writable connections now default to IMMEDIATE; explicitly
        // restore DEFERRED only here to construct the stale-snapshot failure.
        collector.conn.execute(|conn| {
            conn.set_transaction_behavior(rusqlite::TransactionBehavior::Deferred);
        });
        let pending = Arc::new(std::sync::Mutex::new(None::<PendingPublisher>));
        let callback_pending = Arc::clone(&pending);
        let result = collector.gc_with(move |candidate| {
        assert_eq!(candidate, witness.blob_oid().to_string());
        assert_eq!(witness.input(), &ResolutionContentInput::Parsed {
            key: brokk_bifrost_core::gitblob::BlobKey::unvaried(witness.blob_oid(), "rust"), semantic_language: Language::Rust,
        });
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "engine_tests::rust_analyzer_store_resolution_publication_tests::rust_departing_root_tests::collector_snapshot_cannot_delete_an_externally_admitted_cached_blob", "--nocapture"])
            .env(CHILD_DB, &path)
            .env("BIFROST_RP_CHILD_WORKSPACE", snapshot.workspace_id.as_str())
            .env("BIFROST_RP_CHILD_LANGUAGE", &snapshot.lang)
            .env("BIFROST_RP_CHILD_GENERATION", snapshot.generation.get().to_string())
            .env("BIFROST_RP_CHILD_REVISION", snapshot.revision.to_string())
            .env("BIFROST_RP_CHILD_OID", witness.blob_oid().to_string())
            .env("BIFROST_RP_CHILD_HOST", HOST)
            .env("BIFROST_RP_CHILD_SEMANTIC_LANGUAGE", "rust")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn().unwrap();
        let mut pending = callback_pending.lock().unwrap();
        *pending = Some(PendingPublisher { child: Some(child), ready_output: String::new() });
        pending.as_mut().unwrap().await_admission();
        false
    });
        // gc_with has now committed or unwound its transaction. Normal child
        // writer close/checkpoint is safe only after this snapshot is released.
        let output = pending.lock().unwrap().as_mut().unwrap().finish().unwrap();
        assert!(
            output.status.success(),
            "external publisher failed: {output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "external publisher test did not execute: {output:?}"
        );
        let error = result.expect_err("SQLite rejects upgrading the obsolete read snapshot");
        assert_eq!(
            error.to_string(),
            format!(
                "analyzer store SQLite error: database is locked (code: DatabaseBusy, extended code: {})",
                rusqlite::ffi::SQLITE_BUSY_SNAPSHOT
            )
        );
        assert_eq!(roots(&publisher).len(), 1);
        assert_eq!(collector.gc_with(|_| false).unwrap(), 0);
    }

    #[test]
    #[hardwon("3da13ca2218b: core collection dropped roots published after its snapshot")]
    fn actual_cached_publisher_roots_survive_real_core_post_snapshot_collection() {
        use brokk_bifrost_core::{cache_gc, gitblob};
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().canonicalize().unwrap();
        let repo = gitblob::test_repo::init_repo(&workspace);
        let db = gitblob::cache_db_path(&workspace);
        let store = Arc::new(AnalyzerStore::open_persistent(&db).unwrap());
        let snapshot = owner(&store, '5');
        let witness = publish(&store, &snapshot).into_parts().0;
        store
            .conn
            .execute(|conn| conn.execute("DELETE FROM workspace_resolution_content_roots", []))
            .unwrap();
        let publisher = Arc::clone(&store);
        let _hook = cache_gc::after_resolution_candidate_snapshot_for_test(move || {
            ready(
                publisher
                    .admit_cached_selected_content(
                        &snapshot,
                        HOST,
                        &brokk_bifrost_core::gitblob::BlobKey::unvaried(
                            witness.blob_oid(),
                            snapshot.lang.as_str(),
                        ),
                        witness.input(),
                        &CancellationToken::default(),
                    )
                    .unwrap(),
            );
        });
        assert_eq!(
            cache_gc::force_gc(&db, &repo, &workspace)
                .unwrap()
                .analyzer_dropped,
            0
        );
        assert_eq!(roots(&store).len(), 1);
        assert_eq!(
            cache_gc::force_gc(&db, &repo, &workspace)
                .unwrap()
                .analyzer_dropped,
            0
        );
    }

    #[test]
    #[hardwon("7733e6d12b42: node payload schema validation must charge newly stored fields")]
    fn node_payload_schema_checks_null_shapes_membership_and_exact_key_reads() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let snapshot = owner(&store, '9');
        let witness = publish(&store, &snapshot).into_parts().0;
        let blob_id = witness.blob_id();
        store.conn.execute(move |conn| {
        conn.execute("INSERT INTO resolution_identities(identity_digest) VALUES(?1)", [[0xee_u8;32].as_slice()]).unwrap();
        let foreign_shared = conn.last_insert_rowid();
        let query = brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned("resolution_node_catalog_payload_by_key");
        let read = |conn: &rusqlite::Connection, key: i64| conn.query_row(&query.sql, params![blob_id,key], |row| {
            Ok((row.get::<_,Option<i64>>(0)?,row.get::<_,Option<i64>>(1)?,row.get::<_,Option<i64>>(2)?,
                row.get::<_,Option<i64>>(3)?,row.get::<_,Option<i64>>(4)?))
        }).unwrap();
        // Exhaust every absent/present payload combination, including NULL kind.
        // A schema-only Root row tests the representation without weakening the
        // producer's separate content-owned universal-root prohibition.
        for kind in std::iter::once(None).chain((0..10).map(Some)) {
            for mask in 0..16 {
                let local = (mask & 1 != 0).then_some(0_i64);
                let shared = (mask & 2 != 0).then_some(foreign_shared);
                let target = (mask & 4 != 0).then_some(0_i64);
                let boundary = (mask & 8 != 0).then_some(0_i64);
                let expected = match kind {
                    Some(2..=5 | 8 | 9) => local.is_some() != shared.is_some() && target.is_none() && boundary.is_none(),
                    Some(7) => local.is_none() && shared.is_none() && target.is_some() != boundary.is_some(),
                    _ => mask == 0,
                };
                let tx = conn.unchecked_transaction().unwrap();
                let result = tx.execute(
                    "INSERT INTO resolution_node_catalog(blob_id,local_key,identity_digest,kind,semantic_local_key,semantic_shared_identity,target_local_key,target_boundary_key) VALUES(?1,1000000,?2,?3,?4,?5,?6,?7)",
                    params![blob_id,[0xfa_u8;32].as_slice(),kind,local,shared,target,boundary],
                );
                assert_eq!(result.is_ok(),expected,"kind={kind:?} mask={mask}: {result:?}");
                if expected {
                    assert_eq!(read(&tx,1_000_000),(kind,local,shared,target,boundary));
                    assert!(tx.execute(
                        "INSERT INTO resolution_node_catalog(blob_id,local_key,identity_digest,kind) VALUES(?1,1000000,?2,1)",
                        params![blob_id,[0xfb_u8;32].as_slice()],
                    ).is_err(),"one node coordinate cannot acquire conflicting declared payload");
                }
                tx.rollback().unwrap();
            }
        }
        let reference: i64 = conn.query_row("SELECT local_key FROM resolution_node_catalog WHERE blob_id=?1 AND kind=8 LIMIT 1",[blob_id],|row|row.get(0)).unwrap();
        let other_semantic: i64 = conn.query_row("SELECT local_key FROM resolution_semantic_catalog WHERE blob_id=?1 AND shared_identity IS NULL AND local_key<>?2 LIMIT 1",params![blob_id,reference],|row|row.get(0)).unwrap();
        for (kind,local,shared,target,boundary) in [
            (2,Some(1_000_000),None,None,None::<i64>),
            (2,None,Some(foreign_shared),None,None),
            (7,None,None,Some(1_000_000),None),
            (8,Some(other_semantic),None,None,None),
            (9,Some(reference),None,None,None),
        ] {
            let tx=conn.unchecked_transaction().unwrap();
            tx.execute("UPDATE resolution_fragment_interiors SET publication_state='building' WHERE blob_id=?1",[blob_id]).unwrap();
            tx.execute("UPDATE resolution_node_catalog SET kind=?3,semantic_local_key=?4,semantic_shared_identity=?5,target_local_key=?6,target_boundary_key=?7 WHERE blob_id=?1 AND local_key=?2",
                params![blob_id,reference,kind,local,shared,target,boundary]).unwrap();
            let error=tx.execute("UPDATE resolution_fragment_interiors SET publication_state='complete' WHERE blob_id=?1",[blob_id]).unwrap_err();
            assert!(error.to_string().contains("resolution node payload is inconsistent"),"{error}");
            tx.rollback().unwrap();
        }
        for statistics in brokk_bifrost_core::cache_gc::PlannerStatisticsState::BOTH {
            statistics.install(conn);
            let plans=conn.prepare(&format!("EXPLAIN QUERY PLAN {}",query.sql)).unwrap()
                .query_map(params![blob_id,reference],|row|row.get::<_,String>(3)).unwrap()
                .collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert!(plans.iter().any(|line|line.contains("SEARCH resolution_node_catalog USING PRIMARY KEY")),"{statistics:?}: {plans:?}");
            assert!(!plans.iter().any(|line|line.contains("SCAN")||line.contains("AUTOMATIC")||line.contains("TEMP B-TREE")),"{statistics:?}: {plans:?}");
            assert_eq!(read(conn,reference),(Some(8),Some(reference),None,None,None));
        }
    });
        assert_eq!(
            witness.payload_bytes() as usize,
            measured_resolution_payload(&store, witness.blob_oid(), "rust"),
            "sealed payload counts actual stored bytes after new INTEGER node fields"
        );
    }

    #[test]
    fn typed_owner_indexes_preserve_uniqueness_provenance_and_bounded_seeks() {
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        use rusqlite::StatementStatus;
        let mut baseline_seek_steps = None;
        for unrelated in [16_usize, 512, 4096] {
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let snapshot = owner(&store, '7');
            let blob_id = publish(&store, &snapshot).witness().blob_id();
            let measured_seek_steps = store.conn.execute(move |conn| {
            // Relational access fixture only: this transaction is rolled back,
            // and no modified building fragment is admitted as complete.
            let tx=conn.unchecked_transaction().unwrap();
            tx.execute("UPDATE resolution_fragment_interiors SET publication_state='building' WHERE blob_id=?1",[blob_id]).unwrap();
            let before_write=tx.total_changes();
            let mut transfers=tx.prepare("INSERT INTO resolution_type_transfers VALUES(?1,?2,?3,?4,0,0,0,0,NULL)").unwrap();
            let mut calls=tx.prepare("INSERT INTO resolution_call_obligations VALUES(?1,?2,?3,NULL,?4,0,0,jsonb('[]'),jsonb('[[],[],null,null]'),jsonb('[]'),NULL)").unwrap();
            let mut gaps=tx.prepare("INSERT INTO resolution_definition_property_gaps VALUES(?1,?2,?3,3,?4,777777,?5)").unwrap();
            for index in 0..unrelated {
                let key=1_000_000+i64::try_from(index).unwrap();
                transfers.execute(params![blob_id,key,key,key+1]).unwrap();
                calls.execute(params![blob_id,key,key,key+1]).unwrap();
                gaps.execute(params![blob_id,key,0,key+1,key]).unwrap();
            }
            for seq in 0..4 {
                gaps.execute(params![blob_id,888888,seq,888890+seq,77]).unwrap();
            }
            let write_steps=transfers.get_status(StatementStatus::VmStep)+calls.get_status(StatementStatus::VmStep)+gaps.get_status(StatementStatus::VmStep);
            drop((transfers,calls,gaps));
            assert_eq!(tx.total_changes()-before_write,(unrelated*3+4) as u64);
            assert!(tx.execute("INSERT INTO resolution_type_transfers VALUES(?1,9999999,1000000,9999999,0,0,0,0,NULL)",[blob_id]).is_err(),
                "same rule with a different source violates constructor uniqueness");
            assert!(tx.execute("INSERT INTO resolution_call_obligations VALUES(?1,9999999,1000000,NULL,9999999,0,0,jsonb('[]'),jsonb('[]'),NULL)",[blob_id]).is_err(),
                "same call with a different callee violates constructor uniqueness");
            let shapes=[
                ("resolution_type_transfer_owner_by_rule","resolution_type_transfers_rule",vec![blob_id,1_000_000],vec![vec![1_000_000,1_000_001]]),
                ("resolution_call_obligation_owner_by_call","resolution_call_obligations_call",vec![blob_id,1_000_000],vec![vec![1_000_000]]),
                ("resolution_property_gap_owner_by_provenance","resolution_definition_property_gaps_provenance",vec![blob_id,777777,77,3],vec![vec![888888];4]),
            ];
            let mut all_seek_steps = Vec::new();
            for statistics in PlannerStatisticsState::BOTH {
                statistics.install(&tx);
                let reason_query = brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned("resolution_definition_property_gaps_by_reason");
                let requested = serde_json::to_string(&[777777_i64, 9999999]).unwrap();
                let rows = tx.prepare(&reason_query.sql).unwrap()
                    .query_map(params![blob_id, requested], |row| Ok((row.get::<_,i64>(0)?, row.get::<_,i64>(3)?)))
                    .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
                assert_eq!(rows.len(), unrelated + 4, "{statistics:?}: {rows:?}");
                assert!(rows.iter().all(|(_, reason)| *reason == 777777), "{rows:?}");
                assert_eq!(rows.iter().filter(|(owner, _)| *owner == 888888).count(), 4, "{rows:?}");
                let plan = tx.prepare(&format!("EXPLAIN QUERY PLAN {}", reason_query.sql)).unwrap()
                    .query_map(params![blob_id, requested], |row| row.get::<_,String>(3))
                    .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
                assert!(plan.iter().any(|step| step.contains("SEARCH resolution_definition_property_gaps USING INDEX resolution_definition_property_gaps_provenance")), "{statistics:?}: {plan:?}");
                assert!(!plan.iter().any(|step| step.contains("SCAN resolution_definition_property_gaps") || step.contains("AUTOMATIC") || step.contains("TEMP B-TREE")), "{statistics:?}: {plan:?}");
                let mut seek_costs=Vec::new();
                for (name,index,hit,expected) in &shapes {
                    let query=brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned(name);
                    let mut miss=hit.clone();
                    let missing_position=if hit.len()==4 {2}else{1};
                    miss[missing_position]=9_000_000;
                    for (bindings,wanted) in [(hit.clone(),expected.clone()),(miss,Vec::new())] {
                        let mut statement=tx.prepare(&query.sql).unwrap();
                        let columns=statement.column_count();
                        let rows=statement.query_map(rusqlite::params_from_iter(bindings.iter()),|row| {
                            (0..columns).map(|column|row.get::<_,i64>(column)).collect::<rusqlite::Result<Vec<_>>>()
                        }).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
                        assert_eq!(rows,wanted,"{name} {statistics:?} {bindings:?}");
                        let steps=statement.get_status(StatementStatus::VmStep);
                        let plans=tx.prepare(&format!("EXPLAIN QUERY PLAN {}",query.sql)).unwrap()
                            .query_map(rusqlite::params_from_iter(bindings.iter()),|row|row.get::<_,String>(3)).unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>().unwrap();
                        assert!(plans.iter().any(|line|line.contains("SEARCH")&&line.contains(*index)),"{name} {statistics:?}: {plans:?}");
                        assert!(!plans.iter().any(|line|line.contains("SCAN")||line.contains("AUTOMATIC")||line.contains("TEMP B-TREE")),"{name} {statistics:?}: {plans:?}");
                        all_seek_steps.push(steps);
                        seek_costs.push((name,bindings,steps,plans));
                    }
                }
                tx.execute_batch("SAVEPOINT measure_parent_delete").unwrap();
                let before_delete=tx.total_changes();
                let mut delete=tx.prepare("DELETE FROM blobs WHERE id=?1").unwrap();
                assert_eq!(delete.execute([blob_id]).unwrap(),1);
                let delete_steps=delete.get_status(StatementStatus::VmStep);
                drop(delete);
                let deleted_changes=tx.total_changes()-before_delete;
                assert_eq!(tx.query_row("SELECT (SELECT count(*) FROM resolution_type_transfers WHERE blob_id=?1)+(SELECT count(*) FROM resolution_call_obligations WHERE blob_id=?1)+(SELECT count(*) FROM resolution_definition_property_gaps WHERE blob_id=?1)",[blob_id],|row|row.get::<_,usize>(0)).unwrap(),0);
                tx.execute_batch("ROLLBACK TO measure_parent_delete; RELEASE measure_parent_delete").unwrap();
                let payload: usize=tx.query_row("SELECT coalesce(sum(length(argument_slots)+length(eligible_rules)+coalesce(length(completion),0)),0) FROM resolution_call_obligations WHERE blob_id=?1",[blob_id],|row|row.get(0)).unwrap();
                eprintln!("RP typed indexes unrelated={unrelated} statistics={statistics:?} inserted_rows={} write_vm={write_steps} parent_delete_changes={deleted_changes} parent_delete_vm={delete_steps} call_payload_bytes={payload} seeks={seek_costs:?}",unrelated*3+4);
            }
            tx.rollback().unwrap();
            all_seek_steps
        });
            if let Some(baseline) = &baseline_seek_steps {
                assert_eq!(
                    &measured_seek_steps, baseline,
                    "fixed hit/miss cardinalities must not acquire work with {unrelated} unrelated rows"
                );
            } else {
                baseline_seek_steps = Some(measured_seek_steps);
            }
        }
    }

    #[test]
    fn rust_projection_costs_cover_all_written_families_and_actual_deletion() {
        const SOURCE: &str = concat!(
            "#[macro_use]\nextern crate facade;\n",
            "pub use alpha::Exported;\npub use beta::Renamed as Alias;\npub use gamma::*;\n",
            "use delta::Private;\n",
            "#[macro_export]\nmacro_rules! replay { ($($item:item)*) => { $($item)* }; }\n",
            "pub fn target() {}\ninclude!(\"generated/table.rs\");\n",
        );
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let snapshot = owner(&store, 'a');
        let parsed = AnalyzerStore::prepare_parsed_blob(
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid(SOURCE.as_bytes()), "rust"),
            snapshot.generation,
            &RustAdapter,
            parsed_fixture_state(&RustAdapter, HOST, SOURCE),
        )
        .unwrap();
        let expected_projection_rows = parsed.rust_facts.logical_rows();
        let expected_projection_bytes = parsed.rust_facts.string_bytes();
        let witness = ready(
            store
                .publish_selected_parsed_content(
                    &snapshot,
                    HOST,
                    parsed,
                    &CancellationToken::default(),
                )
                .unwrap(),
        )
        .into_parts()
        .0;
        let blob_id = witness.blob_id();
        let raw_oid = witness.blob_oid().to_string();
        store.conn.execute(move |conn| {
        // Discover actual stored scalar types instead of copying production byte expressions.
        let mut projection_rows=0;
        let mut projection_bytes=0;
        for table in ["rust_exports","rust_import_targets","rust_identifier_occurrences","source_rust_item_macros","rust_include_edges","rust_include_host_bindings"] {
            let mut statement=conn.prepare(&format!("SELECT * FROM {table} WHERE blob_id=?1")).unwrap();
            let columns=statement.column_names().iter().map(|name|name.to_string()).collect::<Vec<_>>();
            let mut rows=statement.query([blob_id]).unwrap();
            let mut count=0;
            let mut bytes=0;
            while let Some(row)=rows.next().unwrap() {
                count+=1;
                for (column,name) in columns.iter().enumerate() {
                    if name=="lang" {continue;}
                    match row.get_ref(column).unwrap() {
                        rusqlite::types::ValueRef::Text(value)|rusqlite::types::ValueRef::Blob(value)=>bytes+=value.len(),
                        _=>{}
                    }
                }
            }
            assert!(count>0,"actual parsed fixture must publish {table}");
            eprintln!("RP Rust projection table={table} rows={count} stored_payload_bytes={bytes}");
            projection_rows+=count;
            projection_bytes+=bytes;
        }
        assert_eq!(projection_rows,expected_projection_rows);
        assert_eq!(projection_bytes,expected_projection_bytes);
        let fast: (usize,usize)=conn.query_row(&stored_blob_cascade_costs_sql(1),params![raw_oid,"rust",brokk_bifrost_core::gitblob::ParseVariant::Empty],|row|Ok((row.get(3)?,row.get(4)?))).unwrap();
        let fallback=persisted_blob_mutation_cost_fallback_statement(&mut conn.prepare_cached(persisted_blob_mutation_cost_fallback_sql()).unwrap(),&brokk_bifrost_core::gitblob::BlobKey::unvaried(git2::Oid::from_str(&raw_oid).unwrap(), "rust")).unwrap();
        assert_eq!(fast,(fallback.logical_rows,fallback.payload_bytes));
        let measured: (usize,usize)=conn.query_row(&format!("SELECT {}, {}",rust_projection_cascade_rows_sql(&blob_id.to_string()),rust_projection_cascade_payload_bytes_sql(&blob_id.to_string())),[],|row|Ok((row.get(0)?,row.get(1)?))).unwrap();
        assert_eq!(measured,(projection_rows,projection_bytes));
        let tables=conn.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").unwrap()
            .query_map([],|row|row.get::<_,String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let tx=conn.unchecked_transaction().unwrap();
        tx.execute("UPDATE analysis_epochs SET generation=generation+1 WHERE lang='rust'",[]).unwrap();
        let fq_segments: usize=tx.query_row("SELECT count(*) FROM code_unit_fq_segments WHERE blob_id=?1",[blob_id],|row|row.get(0)).unwrap();
        eprintln!("RP Rust projection previously omitted FQ segments={fq_segments}");
        assert_eq!(fq_segments,2,"the actual stored family explains stale460 versus deletion462");
        let stale: usize=tx.query_row(stale_generation_blob_costs_sql(),[],|row|row.get(3)).unwrap();
        let before=counted_logical_store_rows(&tx,&tables);
        tx.execute("DELETE FROM blobs WHERE id=?1",[blob_id]).unwrap();
        let deleted=before-counted_logical_store_rows(&tx,&tables);
        assert_eq!(fast.0,deleted,"replacement row estimate equals independent actual deletion");
        assert_eq!(stale,deleted,"stale row estimate equals independent actual deletion");
        eprintln!("RP Rust projection whole deletion rows={deleted} fallback_payload_bytes={} projection_rows={projection_rows} projection_bytes={projection_bytes}",fallback.payload_bytes);
        tx.rollback().unwrap();
    });
    }
}
