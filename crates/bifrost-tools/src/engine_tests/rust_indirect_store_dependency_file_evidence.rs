#[cfg(test)]
mod rust_indirect_table_tests {

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshots;

    use brokk_bifrost_analysis::analyzer::store::workspace_inputs::WorkspaceConfigurationInput;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceId;

    #[test]
    fn selected_dependency_rows_are_indexed_and_revisions_keep_old_evidence() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("rust", "static-evidence-pin")
            .unwrap();
        let workspace = WorkspaceId("a".repeat(64));
        let manifest = WorkspaceConfigurationInput::new(
            "Cargo.toml".into(),
            b"[package]\nname='demo'\nversion='0.1.0'\n[dependencies]\nwidget='1'\n"
                .as_slice()
                .into(),
        );
        let lock = |version: &str| {
            WorkspaceConfigurationInput::new("Cargo.lock".into(),format!("version=3\n[[package]]\nname='demo'\nversion='0.1.0'\ndependencies=['widget']\n[[package]]\nname='widget'\nversion='{version}'\nsource='registry+https://github.com/rust-lang/crates.io-index'\n").into_bytes().into_boxed_slice())
        };
        let publish = |lock| {
            store
                .sync_workspace_inputs_for_workspace(
                    &workspace,
                    "rust",
                    generation,
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[manifest.clone(), lock],
                    &[],
                    &[],
                )
                .unwrap()
        };
        let first = publish(lock("1.0.0"));
        let second = publish(lock("1.1.0"));
        let read = |snapshot| {
            store
                .dependency_file_evidence(&WorkspaceSnapshots::from_iter([(
                    "rust".into(),
                    snapshot,
                )]))
                .unwrap()
        };
        let first_selection = WorkspaceSnapshots::from_iter([("rust".into(), first.clone())]);
        let old_locations = store.dependency_file_locations(&first_selection).unwrap();
        let before = read(first.clone());
        let after = read(second);
        assert_eq!(old_locations.len(), before.rows.len());
        let old_locked = before
            .rows
            .iter()
            .find(|r| r.exact_version.as_deref() == Some("1.0.0"))
            .unwrap();
        let old_location = old_locations
            .iter()
            .find(|(id, _)| id == &old_locked.id())
            .unwrap()
            .1;
        let lock_text = String::from_utf8(lock("1.0.0").source_bytes().to_vec()).unwrap();
        assert_eq!(
            old_location.slice_sha256,
            brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(
                lock_text[old_locked.byte_range.clone()].as_bytes()
            )
        );
        assert!(old_location.start_line > 1);
        assert_eq!(
            old_locations,
            store.dependency_file_locations(&first_selection).unwrap()
        );
        assert!(
            before
                .rows
                .iter()
                .any(|r| r.exact_version.as_deref() == Some("1.0.0"))
        );
        assert!(
            after
                .rows
                .iter()
                .any(|r| r.exact_version.as_deref() == Some("1.1.0"))
        );
        assert_eq!(before, read(first));
        let conn = store.conn.lock().unwrap();
        let query =
            brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned(
                "selected_dependency_file_evidence",
            );
        for state in brokk_bifrost_core::cache_gc::PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin(&conn, &query);
            assert!(
                plan.iter()
                    .any(|line| line.contains("SEARCH dependency_file_evidence USING PRIMARY KEY")),
                "{state:?}: {plan:?}"
            );
            assert!(
                !plan
                    .iter()
                    .any(|line| line.contains("SCAN dependency_file_evidence")
                        || line.contains("AUTOMATIC")
                        || line.contains("TEMP B-TREE")),
                "{state:?}: {plan:?}"
            );
        }
    }
}
