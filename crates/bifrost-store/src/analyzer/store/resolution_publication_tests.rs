use super::*;

// Packed source spans retain one logical occurrence per readable JSON element.
// Other counted families use their actual stored rows.

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
