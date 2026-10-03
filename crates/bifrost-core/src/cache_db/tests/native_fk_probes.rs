//! Native replacement must not scan a blob's children for each parent row.

use super::*;
use std::collections::BTreeMap;

fn string_column(conn: &Connection, sql: &str, parameter: &str) -> Vec<String> {
    conn.prepare(sql)
        .unwrap()
        .query_map([parameter], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn native_foreign_keys_have_selective_or_unique_bounded_child_probes() {
    let conn = open_in_memory_cache();
    let blob = insert_json_evidence_interior(&conn, "fk-plan", 128);
    seal_resolution_interior(&conn, blob).unwrap();
    let source = insert_nested_source_fixture(&conn, 128);
    conn.execute(
        "UPDATE source_fact_manifests SET publication_state = 'complete' WHERE blob_id = ?1",
        [source],
    )
    .unwrap();
    let tables = string_column(
        &conn,
        "SELECT name FROM sqlite_schema WHERE type = 'table'
         AND (name LIKE 'resolution_%' OR name LIKE 'source_%') AND ?1 = ''",
        "",
    );
    for state in PlannerStatisticsState::BOTH {
        state.install(&conn);
        for table in &tables {
            let mut keys = vec![string_column(
                &conn,
                "SELECT name FROM pragma_table_info(?1) WHERE pk > 0 ORDER BY pk",
                table,
            )];
            for index in string_column(
                &conn,
                // A unique expression index does not prove that any subset
                // of its ordinary columns is unique. Exclude the whole key.
                "SELECT indexes.name FROM pragma_index_list(?1) AS indexes
                 WHERE indexes.\"unique\" = 1 AND indexes.partial = 0
                   AND NOT EXISTS (
                     SELECT 1 FROM pragma_index_info(indexes.name) AS columns
                     WHERE columns.name IS NULL
                   )",
                table,
            ) {
                keys.push(string_column(
                    &conn,
                    "SELECT name FROM pragma_index_info(?1) ORDER BY seqno",
                    &index,
                ));
            }
            let mut foreign_keys = BTreeMap::<i64, Vec<String>>::new();
            let mut blob_parents = BTreeMap::<i64, (String, String)>::new();
            let mut statement = conn
                .prepare(
                    "SELECT id, \"from\", \"table\", \"to\"
                     FROM pragma_foreign_key_list(?1) ORDER BY id, seq",
                )
                .unwrap();
            for row in statement
                .query_map([table], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .unwrap()
            {
                let (id, column, parent, target) = row.unwrap();
                if column == "blob_id" {
                    blob_parents.insert(id, (parent, target));
                }
                foreign_keys.entry(id).or_default().push(column);
            }
            for (id, columns) in &foreign_keys {
                if columns.len() < 2 || !columns.iter().any(|column| column == "blob_id") {
                    continue;
                }
                if keys
                    .iter()
                    .any(|key| !key.is_empty() && key.iter().all(|column| columns.contains(column)))
                {
                    continue;
                }
                // A singleton parent primary key permits only one parent
                // per child blob. A keyed visit to all of that blob's rows
                // is linear, not a repeated semantic-parent scan. Still
                // require the child blob lookup below; never exempt a
                // composite semantic parent whose blob can have many rows.
                let (parent, target) = &blob_parents[id];
                let parent_key = string_column(
                    &conn,
                    "SELECT name FROM pragma_table_info(?1) WHERE pk > 0 ORDER BY pk",
                    parent,
                );
                let parent_bounded = parent_key.len() == 1 && parent_key[0] == *target;
                let predicates = columns
                    .iter()
                    .enumerate()
                    .map(|(index, column)| format!("\"{column}\" = ?{}", index + 1))
                    .collect::<Vec<_>>()
                    .join(" AND ");
                let sql =
                    format!("EXPLAIN QUERY PLAN SELECT 1 FROM \"{table}\" WHERE {predicates}");
                let probe_blob = if table.starts_with("source_") {
                    source
                } else {
                    blob
                };
                let values = columns.iter().map(|column| match column.as_str() {
                    "blob_id" => rusqlite::types::Value::Integer(probe_blob),
                    "lang" => rusqlite::types::Value::Text("rust".into()),
                    _ => rusqlite::types::Value::Integer(42),
                });
                let plan = conn
                    .prepare(&sql)
                    .unwrap()
                    .query_map(rusqlite::params_from_iter(values), |row| {
                        row.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap()
                    .join("; ");
                assert!(
                    columns
                        .iter()
                        .filter(|column| !parent_bounded || column.as_str() == "blob_id")
                        .all(|column| plan.contains(&format!("{column}=?"))),
                    "unbounded FK probe {table} {columns:?} {state}: {plan}"
                );
                assert!(!plan.contains("AUTOMATIC"), "{table} {columns:?}: {plan}");
            }
        }
    }
}

fn delete_vm_steps(conn: &Connection, blob: i64) -> i32 {
    conn.execute_batch("SAVEPOINT measure_delete").unwrap();
    let oid: String = conn
        .query_row("SELECT blob_oid FROM blobs WHERE id = ?1", [blob], |row| {
            row.get(0)
        })
        .unwrap();
    let mut statement = conn
        .prepare("DELETE FROM blobs WHERE blob_oid = ?1 AND lang = ?2")
        .unwrap();
    let lang: String = conn
        .query_row("SELECT lang FROM blobs WHERE id = ?1", [blob], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(statement.execute(params![oid, lang]).unwrap(), 1);
    let steps = statement.get_status(rusqlite::StatementStatus::VmStep);
    validate_foreign_keys(conn).unwrap();
    conn.execute_batch("ROLLBACK TO measure_delete; RELEASE measure_delete")
        .unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM blobs WHERE id = ?1", [blob], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    steps
}

#[test]
fn native_and_source_blob_deletion_scales_subquadratically_and_rolls_back() {
    let conn = open_in_memory_cache();
    let native = [64, 128, 256].map(|count| {
        let blob = insert_json_evidence_interior(&conn, &format!("delete-{count}"), count);
        seal_resolution_interior(&conn, blob).unwrap();
        blob
    });
    let sources = [64, 128, 256].map(|count| {
        let blob = insert_nested_source_fixture(&conn, count);
        conn.execute(
            "UPDATE source_fact_manifests SET publication_state = 'complete' WHERE blob_id = ?1",
            [blob],
        )
        .unwrap();
        blob
    });
    for phase in ["before statistics", "after statistics"] {
        for blobs in [native, sources] {
            let work = blobs.map(|blob| delete_vm_steps(&conn, blob));
            for pair in work.windows(2) {
                assert!(
                    pair[1] < pair[0] * 5 / 2,
                    "DELETE must not rescan children per parent {phase}: {work:?}"
                );
            }
        }
        conn.execute_batch("ANALYZE").unwrap();
    }
}
