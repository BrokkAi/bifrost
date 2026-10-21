#[cfg(test)]
mod rust_departing_tests_tests {
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::store::gc::AnalyzerGcCoordinator;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_analysis::analyzer::store::gc::WorkerHold;

    use brokk_bifrost_analysis::analyzer::store::gc::run_gc;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_core::gitblob::test_repo::commit_all;

    use brokk_bifrost_core::gitblob::test_repo::init_repo;
    /// Issue #3170: a store created moments ago is not overdue for collection.
    ///
    /// Collection is due when the store has grown and the time cadence has
    /// elapsed since the last one. A store whose `cache_state` row was written
    /// with `last_gc_at = 0` reads as overdue by the whole epoch, so the first
    /// build that persisted a blob scheduled a full sweep of a store it had
    /// just written -- and that sweep held the analyzer-cache build lock in
    /// front of the session's first diff-derived request.
    ///
    /// The tuning guard pins the production cadence rather than changing it:
    /// the default interval is the subject here.
    #[test]
    #[hardwon("#3170: a newly created store was immediately treated as due for collection")]
    fn a_fresh_store_is_not_born_due_for_collection() {
        let _tuning = brokk_bifrost_core::cache_gc::set_tuning_for_test(
            brokk_bifrost_core::cache_gc::GC_AUTO_BLOB_THRESHOLD,
            brokk_bifrost_core::cache_gc::GC_MIN_INTERVAL_SECS,
        );
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join(".gitignore"), ".bifrost/cache/\n").unwrap();
        std::fs::write(root.join("app.rs"), "pub fn widget() -> u32 { 1 }\n").unwrap();
        let repository = init_repo(&root);
        commit_all(&repository, "first content");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
            project,
            AnalyzerConfig::default(),
        )
        .expect("persisted analyzer should build");
        let db_path = workspace
            .persisted_store_path()
            .expect("a persisted build reports its store path");
        drop(workspace);

        let store = AnalyzerStore::open_persistent(&db_path).expect("open the built store");
        let outcome = run_gc(&store, &repository, &root).expect("scheduled collection");

        assert!(
            !outcome.ran,
            "a store created by this build must not already be due: {outcome:?}"
        );
        assert!(
            outcome.total_blobs_after > 0,
            "the build must persist blobs, or the scheduling condition is vacuous"
        );
        let (last_gc_at, blobs_at_last_gc) =
            brokk_bifrost_core::cache_gc::gc_accounting_for_test(&db_path)
                .expect("cache_state accounting");
        assert_eq!(
            blobs_at_last_gc, 0,
            "no collection ran, so the recorded blob count must still be the store's initial one"
        );
        assert!(
            last_gc_at > 0,
            "a created store starts its collection cadence at its creation time"
        );
    }

    /// Issue #3349: a collection scheduled by a build whose final owner goes
    /// away immediately afterwards still runs, and that owner's drop waits for
    /// it.
    ///
    /// This is what `SearchToolsService::close` does to a watched persisted
    /// session that is closed right after construction: the build has already
    /// scheduled a collection, and the close drops the last store context.
    /// The worker used to consult a weak reference to the coordinator before
    /// touching anything, so when the final drop began before the worker
    /// thread had run its first instruction the collection was cancelled and
    /// `cache_state` never advanced -- an outcome of thread scheduling, which
    /// is why the MCP regression flaked. The hold reproduces that ordering
    /// exactly: the worker is parked before it does anything until the final
    /// drop is already waiting for it.
    #[test]
    #[hardwon("#3349: dropping the last coordinator cancelled a scheduled collection")]
    fn a_collection_scheduled_before_the_final_drop_still_runs_and_the_drop_waits() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join(".gitignore"), ".bifrost/cache/\n").unwrap();
        std::fs::write(root.join("app.rs"), "pub fn widget() -> u32 { 1 }\n").unwrap();
        let repository = init_repo(&root);
        commit_all(&repository, "first content");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
            project,
            AnalyzerConfig::default(),
        )
        .expect("persisted analyzer should build");
        let db_path = workspace
            .persisted_store_path()
            .expect("a persisted build reports its store path");
        drop(workspace);
        // The MCP regression's setup: a store that holds blobs and is due.
        brokk_bifrost_core::cache_gc::set_accounting_for_test(&db_path, 0, 0)
            .expect("make collection due");
        let store =
            Arc::new(AnalyzerStore::open_persistent(&db_path).expect("open the built store"));

        let hold = Arc::new(WorkerHold::default());
        let coordinator = Arc::new(AnalyzerGcCoordinator::holding_workers_for_test(Arc::clone(
            &hold,
        )));
        coordinator.schedule(&root, Arc::clone(&store));
        let final_drop = std::thread::spawn(move || drop(coordinator));
        hold.wait_until_parked();

        // The worker has done nothing yet, and the final owner cannot finish
        // dropping while the worker is parked: the drop is waiting for it.
        assert_eq!(
            brokk_bifrost_core::cache_gc::gc_accounting_for_test(&db_path)
                .expect("cache_state accounting"),
            (0, 0)
        );
        assert!(
            !final_drop.is_finished(),
            "the final drop must join the scheduled collection, not return around it"
        );

        hold.release();
        final_drop
            .join()
            .expect("the final drop must not panic while joining the collection");
        let (last_gc_at, blobs_at_last_gc) =
            brokk_bifrost_core::cache_gc::gc_accounting_for_test(&db_path)
                .expect("cache_state accounting");
        assert!(
            last_gc_at > 0,
            "the collection scheduled before the final drop must have run"
        );
        assert!(
            blobs_at_last_gc > 0,
            "the collection must have accounted for the store's blobs"
        );
    }
}
