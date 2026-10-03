//! Schema 62 canonical import path-availability laws.

use super::*;
use rusqlite::params;

fn connection_through(_version: i64) -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    configure_connection(&mut conn).unwrap();
    migrate(&mut conn).unwrap();
    conn
}

fn insert_import_fixture(
    conn: &Connection,
    seed: &str,
    has_structured_path: Option<i64>,
    path_kind: Option<&str>,
    segment: Option<&str>,
) -> i64 {
    conn.execute(
        "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'python', 0)",
        [seeded_oid(seed)],
    )
    .unwrap();
    let blob_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO blob_meta(
           blob_id, lang, contains_tests, content_package,
           stored_unit_count, range_count, signature_count,
           signature_metadata_count, supertype_count, child_count,
           import_statement_count, type_identifier_count, is_complete
         ) VALUES(?1, 'python', 0, '', 0, 0, 0, 0, 0, 0, 1, 0, 1)",
        [blob_id],
    )
    .unwrap();

    let statement = "import";
    let segment_count = i64::from(segment.is_some());
    let logical_rows = 1 + 1 + 1 + segment_count;
    // The arena holds a one-byte provenance code, so no occurrence text counts.
    let payload_bytes = statement.len() as i64
        + path_kind.map_or(0, |kind| kind.len() as i64)
        + segment.map_or(0, |value| value.len() as i64);
    conn.execute(
        "INSERT INTO source_fact_manifests(
           blob_id, facts_version, source_bytes, occurrence_count,
           declaration_count, declaration_unit_count, node_count,
           role_count, occurrence_role_count, import_count,
           import_segment_count, import_scope_count, import_prefix_count,
           logical_rows, payload_bytes, publication_state)
         VALUES(?1, 1, 8, 1, 0, 0, 0, 0, 0, 1, ?2, 0, 0, ?3, ?4, 'building')",
        params![blob_id, segment_count, logical_rows, payload_bytes],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_occurrence_arenas(blob_id, spans)\n             VALUES(?1, jsonb('[[0,8,1,1,0]]'))",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_imports(
               blob_id, import_id, statement, is_wildcard, is_global,
               identifier, alias, path_kind, declaration_occurrence_id,
               target_occurrence_id, alias_occurrence_id,
               declaration_start_byte, declaration_end_byte,
               target_start_byte, target_end_byte,
               alias_start_byte, alias_end_byte)
             SELECT ?1, 0, ?2, 0, 0, NULL, NULL, ?3, 0, NULL, NULL, json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]'), NULL, NULL, NULL, NULL FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        params![blob_id, statement, path_kind],
    )
    .unwrap();
    if let Some(has_structured_path) = has_structured_path {
        conn.execute(
            "UPDATE source_imports
                SET has_structured_path = ?2
              WHERE blob_id = ?1 AND import_id = 0",
            params![blob_id, has_structured_path],
        )
        .unwrap();
    }
    if let Some(segment) = segment {
        conn.execute(
            "INSERT INTO source_import_segments(blob_id, import_id, ordinal, segment)
             VALUES(?1, 0, 0, ?2)",
            params![blob_id, segment],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO import_statements(blob_id, lang, ordinal, source_import_id, statement, is_wildcard, is_global, identifier, alias, path_kind, declaration_start_byte, binder_start, binder_end, declaration_occurrence_id, binder_occurrence_id, occurrence_declaration_start_byte, occurrence_declaration_end_byte, occurrence_binder_start_byte, occurrence_binder_end_byte)
         VALUES(?1, 'python', 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
        [blob_id],
    )
    .unwrap();
    blob_id
}

fn seal(conn: &Connection, blob_id: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE source_fact_manifests
            SET publication_state = 'complete'
          WHERE blob_id = ?1",
        [blob_id],
    )
}

#[test]
fn schema62_distinguishes_unavailable_from_empty_structured_path() {
    let conn = connection_through(CURRENT_MIGRATION_VERSION);
    let unavailable = insert_import_fixture(&conn, "schema62-unavailable", Some(0), None, None);
    let empty = insert_import_fixture(&conn, "schema62-empty", Some(1), None, None);
    seal(&conn, unavailable).unwrap();
    seal(&conn, empty).unwrap();

    let read = |blob_id| {
        conn.query_row(
            "SELECT path_kind, declaration_start_byte, declaration_occurrence_id,
                    has_structured_path
               FROM source_import_statements
              WHERE blob_id = ?1",
            [blob_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .unwrap()
    };
    assert_eq!(read(unavailable), (None, Some(0), Some(0), 0));
    assert_eq!(read(empty), (None, Some(0), Some(0), 1));
}

#[test]
fn schema62_rejects_path_properties_and_children_for_unavailable_paths() {
    let conn = connection_through(CURRENT_MIGRATION_VERSION);
    let path_kind = insert_import_fixture(
        &conn,
        "schema62-path-kind",
        Some(0),
        Some("namespace"),
        None,
    );
    let path_child =
        insert_import_fixture(&conn, "schema62-path-child", Some(0), None, Some("member"));

    for blob_id in [path_kind, path_child] {
        let error = seal(&conn, blob_id).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("canonical import path availability is inconsistent"),
            "{error}"
        );
    }
}

#[test]
fn schema62_sealed_path_availability_is_immutable() {
    let conn = connection_through(CURRENT_MIGRATION_VERSION);
    let blob_id = insert_import_fixture(&conn, "schema62-immutable", Some(0), None, None);
    seal(&conn, blob_id).unwrap();

    let error = conn
        .execute(
            "UPDATE source_imports
                SET has_structured_path = 1
              WHERE blob_id = ?1 AND import_id = 0",
            [blob_id],
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("sealed source facts are immutable"),
        "{error}"
    );
}
