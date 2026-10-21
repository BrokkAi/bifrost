#[cfg(test)]
use self::rust_root_test_support::*;
use super::*;

// Packed source spans retain one logical occurrence per readable JSON element.
// Other counted families use their actual stored rows.

#[cfg(test)]
#[test]
fn callable_parameter_ownership_is_exact_indexed_and_cascades_with_linear_work() {
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use rusqlite::StatementStatus;
    let mut samples = Vec::new();
    for (signature_count, parameter_count) in [(8, 2), (64, 8)] {
        // Rust deliberately retains an empty callable-parameter inventory with
        // UnsupportedCallApplicability. Java supplies exact structured parameters.
        let methods = (0..signature_count)
            .map(|signature| {
                let parameters = (0..parameter_count)
                    .map(|parameter| format!("int p{parameter}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("public void f{signature}({parameters}) {{}}\n")
            })
            .collect::<String>();
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let source = format!("class Owner {{\n{methods}}}\n");
        let generation = store
            .ensure_language_epoch_value("java", "publication-test-v1")
            .unwrap();
        store
            .ensure_resolution_producer_epoch("java", Language::Java)
            .unwrap();
        let snapshot = WorkspaceSnapshotId {
            workspace_id: WorkspaceId("8".repeat(64)),
            lang: "java".to_owned(),
            generation,
            revision: 1,
        };
        let captured = snapshot.clone();
        store.conn.execute(move |conn| conn.execute(
            "INSERT INTO workspace_revisions(workspace_id,lang,generation,revision) VALUES(?1,?2,?3,?4)",
            params![captured.workspace_id.as_str(),captured.lang,captured.generation.0,captured.revision],
        )).unwrap();
        let state = parsed_fixture_state(&JavaAdapter, "Owner.java", &source);
        let parsed = AnalyzerStore::prepare_parsed_blob(
            oid(source.as_bytes()),
            "java",
            snapshot.generation,
            &JavaAdapter,
            state,
        )
        .unwrap();
        let witness = ready(
            store
                .publish_selected_parsed_content(
                    &snapshot,
                    "Owner.java",
                    parsed,
                    &CancellationToken::default(),
                )
                .unwrap(),
        )
        .into_parts()
        .0;
        let blob_id = witness.blob_id();
        let raw_oid = witness.blob_oid().to_string();
        let measurements = store.conn.execute(move |conn| {
            let expected = conn.prepare(
                "SELECT json_extract(parameter.value,'$[0]'), signature.definition
                 FROM resolution_callable_signatures AS signature, json_each(signature.body,'$[1]') AS parameter
                 WHERE signature.blob_id=?1 ORDER BY 1",
            ).unwrap().query_map([blob_id], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
                .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(expected.len(), signature_count * parameter_count);
            let manifest_count: usize = conn.query_row(
                "SELECT expected_callable_parameter_owner_count FROM resolution_fragment_interiors WHERE blob_id=?1",
                [blob_id], |row| row.get(0),
            ).unwrap();
            assert_eq!(manifest_count, expected.len());
            let pin = super::super::planner_statistics::pinned_plans::pinned("resolution_callable_parameter_owner_by_definition");
            let mut keyed = conn.prepare(&pin.sql).unwrap();
            for &(parameter, signature) in &expected {
                let actual: i64 = keyed.query_row(params![blob_id,parameter], |row| row.get(0)).unwrap();
                assert_eq!(actual, signature, "owner query agrees with independently decoded signature body");
            }
            drop(keyed);
            let (parameter, signature) = expected[0];
            let other_signature = expected.iter().find(|(_, owner)| *owner != signature).unwrap().1;
            assert!(conn.execute(
                "INSERT INTO resolution_callable_parameter_owners VALUES(?1,?2,?3)",
                params![blob_id, parameter, other_signature],
            ).is_err(), "a parameter cannot acquire a second signature owner");
            for damage in ["missing", "wrong-owner", "extra"] {
                let tx = conn.unchecked_transaction().unwrap();
                tx.execute("UPDATE resolution_fragment_interiors SET publication_state='building' WHERE blob_id=?1", [blob_id]).unwrap();
                match damage {
                    "missing" => { tx.execute("DELETE FROM resolution_callable_parameter_owners WHERE blob_id=?1 AND parameter_definition=?2", params![blob_id,parameter]).unwrap(); }
                    "wrong-owner" => { tx.execute("UPDATE resolution_callable_parameter_owners SET signature_definition=?3 WHERE blob_id=?1 AND parameter_definition=?2", params![blob_id,parameter,other_signature]).unwrap(); }
                    "extra" => { tx.execute("INSERT INTO resolution_callable_parameter_owners VALUES(?1,9223372036854775807,?2)", params![blob_id,signature]).unwrap(); }
                    _ => unreachable!(),
                }
                // Even a matching forged count cannot replace exact body correspondence.
                tx.execute("UPDATE resolution_fragment_interiors SET expected_callable_parameter_owner_count=(SELECT count(*) FROM resolution_callable_parameter_owners WHERE blob_id=?1) WHERE blob_id=?1", [blob_id]).unwrap();
                let error = tx.execute("UPDATE resolution_fragment_interiors SET publication_state='complete' WHERE blob_id=?1", [blob_id]).unwrap_err();
                assert!(error.to_string().contains("resolution callable parameter ownership is inconsistent"), "{damage}: {error}");
                tx.rollback().unwrap();
            }
            let tables = conn.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")
                .unwrap().query_map([], |row| row.get::<_, String>(0)).unwrap()
                .collect::<rusqlite::Result<Vec<_>>>().unwrap();
            let cost = persisted_blob_mutation_cost_fallback_statement(
                &mut conn.prepare_cached(persisted_blob_mutation_cost_fallback_sql()).unwrap(), &raw_oid, "java",
            ).unwrap();
            let mut measurements = Vec::new();
            for statistics in PlannerStatisticsState::BOTH {
                statistics.install(conn);
                let plans = conn.prepare(&format!("EXPLAIN QUERY PLAN {}", pin.sql)).unwrap()
                    .query_map(params![blob_id,parameter], |row| row.get::<_, String>(3)).unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>().unwrap();
                assert!(plans.iter().any(|line| line.contains("SEARCH resolution_callable_parameter_owners USING PRIMARY KEY")), "{statistics:?}: {plans:?}");
                assert!(!plans.iter().any(|line| line.contains("SCAN") || line.contains("AUTOMATIC") || line.contains("TEMP B-TREE")), "{statistics:?}: {plans:?}");
                let tx = conn.unchecked_transaction().unwrap();
                let count_rows = || counted_logical_store_rows(&tx, &tables);
                let before = count_rows();
                let mut delete = tx.prepare("DELETE FROM blobs WHERE id=?1").unwrap();
                assert_eq!(delete.execute([blob_id]).unwrap(), 1);
                let steps = delete.get_status(StatementStatus::VmStep) as usize;
                drop(delete);
                let deleted_rows = before - count_rows();
                let remaining: usize = tx.query_row("SELECT count(*) FROM resolution_callable_parameter_owners WHERE blob_id=?1", [blob_id], |row| row.get(0)).unwrap();
                assert_eq!(remaining, 0);
                assert_eq!(deleted_rows, cost.logical_rows, "{statistics:?}: exact whole-store deletion cost includes owner rows");
                tx.rollback().unwrap();
                eprintln!("RP callable owner cascade signatures={signature_count} parameters={parameter_count} statistics={statistics:?} rows={deleted_rows} vm_steps={steps} payload_bytes={} plans={plans:?}", cost.payload_bytes);
                measurements.push((statistics, deleted_rows, steps));
            }
            measurements
        });
        samples.push(measurements);
    }
    for (small, large) in samples[0].iter().zip(&samples[1]) {
        assert_eq!(small.0, large.0);
        assert!(
            large.2 * small.1 <= small.2 * large.1 * 2,
            "whole-fragment cascade work scales with deleted rows, not signatures times parameters: {samples:?}"
        );
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod rust_root_test_support {
    use super::*;

    use crate::analyzer::store::resolution_publication::PublishedResolutionContent;
    use crate::analyzer::store::resolution_publication::ResolutionContentPublicationOutcome;
    #[doc(hidden)]
    pub fn owner(store: &AnalyzerStore, name: char) -> WorkspaceSnapshotId {
        let generation = store
            .ensure_language_epoch_value("rust", "publication-test-v1")
            .unwrap();
        store
            .ensure_resolution_producer_epoch("rust", Language::Rust)
            .unwrap();
        let snapshot = WorkspaceSnapshotId {
            workspace_id: WorkspaceId(name.to_string().repeat(64)),
            lang: "rust".to_owned(),
            generation,
            revision: 1,
        };
        let captured = snapshot.clone();
        store.conn.execute(move |conn| conn.execute(
        "INSERT INTO workspace_revisions(workspace_id,lang,generation,revision) VALUES(?1,?2,?3,?4)",
        params![captured.workspace_id.as_str(),captured.lang,captured.generation.0,captured.revision],
    )).unwrap();
        snapshot
    }
    #[doc(hidden)]
    pub fn ready(outcome: ResolutionContentPublicationOutcome) -> PublishedResolutionContent {
        match outcome {
            ResolutionContentPublicationOutcome::Ready(content) => *content,
            outcome => panic!("expected committed content, got {outcome:?}"),
        }
    }
    #[doc(hidden)]
    pub fn roots(store: &AnalyzerStore) -> Vec<(String, i64)> {
        store.conn.execute(|conn| conn.prepare(
        "SELECT workspace_id,revision FROM workspace_resolution_content_roots ORDER BY workspace_id,revision"
    ).unwrap().query_map([], |row| Ok((row.get(0)?,row.get(1)?))).unwrap()
        .collect::<rusqlite::Result<Vec<_>>>().unwrap())
    }
    #[doc(hidden)]
    pub fn counted_logical_store_rows(conn: &rusqlite::Connection, tables: &[String]) -> usize {
        tables
            .iter()
            .map(|table| {
                let table = table.replace('"', "\"\"");
                let sql = if table == "source_occurrence_arenas" {
                    "SELECT coalesce(sum(json_array_length(spans)),0) FROM source_occurrence_arenas"
                        .to_owned()
                } else {
                    format!("SELECT count(*) FROM \"{table}\"")
                };
                conn.query_row(&sql, [], |row| row.get::<_, usize>(0))
                    .unwrap()
            })
            .sum()
    }
}
