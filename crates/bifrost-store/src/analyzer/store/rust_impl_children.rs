//! Point reads of resolver-placed Rust impl members, shared by both child APIs.
use super::*;

#[doc(hidden)]
pub fn sql() -> &'static str {
    static SQL: LazyLock<String> = LazyLock::new(|| {
        include_str!("rust_impl_children.sql")
            .replace(
                "{projection}",
                &format!("keys.blob_oid, {}", candidate_unit_projection_sql("child")),
            )
            .replace("{complete}", PARSED_BLOB_COMPLETE_CONDITION)
    });
    &SQL
}

impl AnalyzerStore {
    fn rust_impl_children_read_conn(
        &self,
        snapshots: &WorkspaceSnapshots,
    ) -> Result<ReaderGuard<'_>> {
        use super::resolution_selection::{
            RetainedResolutionSelectionKey, SelectedResolutionLanguage,
        };

        let snapshot = snapshots
            .get("rust")
            .expect("Rust children have a snapshot");
        let key = RetainedResolutionSelectionKey {
            workspace_id: snapshot.workspace_id.as_str().to_owned(),
            snapshots: snapshots.clone(),
            languages: vec![SelectedResolutionLanguage::new("rust", Language::Rust)],
            overlay_masks: Vec::new(),
            content_mounts: Vec::new(),
        };
        let mut conn = self.active_read_conn_for_resolution(&key)?;
        // Membership access paths are pinned with QPSG on. Retain that policy
        // across resolution checkouts, rather than expiring plans on each call.
        conn.retain_resolution_query_plans()?;
        self.select_workspace_snapshots(&mut conn, snapshots)?;
        Ok(conn)
    }

    /// The result is scoped to one owner query; no workspace member map is kept.
    #[doc(hidden)]
    pub fn rust_impl_children<A: StoreLanguageAdapter>(
        &self,
        oid: Oid,
        generation: GenerationId,
        snapshots: &WorkspaceSnapshots,
        adapter: &A,
        owner: &CodeUnit,
        limit: usize,
    ) -> Result<Vec<HydratedMountedCandidatePrimaryRangeRow>> {
        let Some(fq) = prepare_unit_fq(adapter, owner, "")? else {
            return Ok(Vec::new());
        };
        let mut conn = self.rust_impl_children_read_conn(snapshots)?;
        let tx = conn.transaction()?;
        require_current_generation(&tx, "rust", generation)?;
        let mut statement = tx.prepare_cached(sql())?;
        let rows = statement
            .query_map(
                params![
                    oid.to_string(),
                    crate::path_utils::rel_path_string(owner.source()),
                    code_unit_kind_to_i64(owner.kind()),
                    owner.signature(),
                    bool_to_i64(owner.is_synthetic()),
                    fq.anchor_kind,
                    fq.anchor_pop,
                    fq.package_tail_segments,
                    fq.exact_tail,
                    rust_crates::derivation_version(),
                    i64::try_from(limit).unwrap_or(i64::MAX),
                ],
                |row| {
                    Ok(MountedCandidatePrimaryRangeRow {
                        candidate: candidate_row_from_row(row)?,
                        rel_path: row.get(20)?,
                        primary_range: primary_range_from_row(row, 21)?,
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        let rows =
            hydrate_candidate_rows(&tx, rows, None)?.expect("uncancelled impl children hydrate");
        tx.commit()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use brokk_bifrost_test_macros::hardwon;
    use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_QPSG;

    #[test]
    #[hardwon(
        "#6394: cross-file child reads require subject seeks and selected complete topologies"
    )]
    fn impl_child_plans_seek_both_subject_indexes_and_bind_topology() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        store
            .select_writer_workspace_snapshots(&conn, &HashMap::default())
            .unwrap();
        conn.set_db_config(SQLITE_DBCONFIG_ENABLE_QPSG, true)
            .unwrap();
        let query = super::super::planner_statistics::pinned_plans::pinned_queries()
            .into_iter()
            .find(|query| query.name == "rust_impl_children")
            .unwrap();
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            assert!(conn.db_config(SQLITE_DBCONFIG_ENABLE_QPSG).unwrap());
            let plan = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {}", query.sql))
                .unwrap()
                .query_map(
                    rusqlite::params_from_iter(vec![rusqlite::types::Value::Null; 11]),
                    |row| row.get::<_, String>(3),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            for expected in [
                "rust_crate_trait_impls_subject",
                "rust_crate_inherent_impls_subject",
                "rust_crate_versions_topology",
                "SEARCH topology USING INTEGER PRIMARY KEY",
                "SEARCH reconciliation USING PRIMARY KEY",
            ] {
                assert!(
                    plan.iter().any(|step| step.contains(expected)),
                    "{state:?}: missing {expected}: {plan:?}"
                );
            }
            assert!(
                !plan.iter().any(|step| step.contains("AUTOMATIC")),
                "{state:?}: {plan:?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#6457: direct_children re-prepared its membership query on every call (7 us -> 6.7 ms warm)"
    )]
    fn impl_children_retain_plans_on_the_same_resolution_reader() {
        use rusqlite::{StatementStatus, types::Value};

        let temp = tempfile::tempdir().unwrap();
        let store = AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap();
        for state in PlannerStatisticsState::BOTH {
            store.conn.execute(move |conn| state.install(conn));
            store.recycle_readers_for_new_statistics();
            let snapshots = WorkspaceSnapshots::from_iter([(
                "rust".to_owned(),
                WorkspaceSnapshotId {
                    workspace_id: WorkspaceId("children-plan-test".to_owned()),
                    lang: "rust".to_owned(),
                    generation: GenerationId(0),
                    revision: 0,
                },
            )]);
            let mut reader_id = None;
            for (run, subject) in ["First", "Second", "First", "Second"]
                .into_iter()
                .enumerate()
            {
                let conn = store.rust_impl_children_read_conn(&snapshots).unwrap();
                assert!(conn.db_config(SQLITE_DBCONFIG_ENABLE_QPSG).unwrap());
                // The SQLite connection survives moving its Rust pool guard.
                let id = unsafe { conn.handle() };
                if let Some(previous) = reader_id {
                    assert_eq!(previous, id, "{state:?}: the same pooled reader is reused");
                }
                reader_id = Some(id);
                let mut statement = conn.prepare_cached(sql()).unwrap();
                let mut parameters = vec![Value::Null; 11];
                parameters[1] = Value::Text(format!("src/{subject}.rs"));
                parameters[8] = Value::Text(subject.to_owned());
                parameters[10] = Value::Integer(i64::MAX);
                let mut rows = statement
                    .query(rusqlite::params_from_iter(parameters))
                    .unwrap();
                assert!(rows.next().unwrap().is_none());
                drop(rows);
                assert_eq!(
                    statement.get_status(StatementStatus::Run),
                    i32::try_from(run + 1).unwrap()
                );
                assert_eq!(
                    statement.get_status(StatementStatus::RePrepare),
                    0,
                    "{state:?}: {subject}"
                );
            }
        }
    }
}
