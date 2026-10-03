//! Schema 59 compound Rust type-form laws.
//!
//! These tests deliberately build the smallest complete source publication
//! containing a compound type.  The rows are inserted while the publication
//! is building, so the publication trigger is the authority under test.

use super::*;
use rusqlite::params;

fn current_connection() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    configure_connection(&mut conn).unwrap();
    migrate(&mut conn).unwrap();
    conn
}

/// Insert one complete canonical source publication with a compound type at
/// occurrence 1 and one path child at occurrence 2.  Occurrence 0 is the
/// source-file/item root.  The returned blob is sealed by this helper.
fn seed_compound_blob(conn: &mut Connection, seed: &str) -> i64 {
    let blob_id = seed_compound_blob_building(conn, seed);
    conn.execute(
        "UPDATE source_fact_manifests
            SET publication_state = 'complete'
          WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    blob_id
}

/// Insert the same publication as `seed_compound_blob`, leaving its source
/// manifest in the building state for a negative sealing test.
fn seed_compound_blob_building(conn: &mut Connection, seed: &str) -> i64 {
    conn.execute(
        "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'rust', 0)",
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
         ) VALUES(?1, 'rust', 0, '', 0, 0, 0, 0, 0, 0, 0, 0, 1)",
        [blob_id],
    )
    .unwrap();

    // The source manifest has four occurrences, no declarations, three
    // module rows, and seven Rust item rows (marker, syntax, context, two
    // types, one type child, and one path segment).  The leading one in the
    // manifest logical-row equation is its own marker.
    conn.execute(
        "INSERT INTO source_fact_manifests(
           blob_id, facts_version, source_bytes, occurrence_count,
           declaration_count, declaration_unit_count, node_count, role_count,
           occurrence_role_count, logical_rows, payload_bytes, publication_state)
         VALUES(?1, 1, 10, 4, 0, 0, 0, 0, 0, 15, 5, 'building')",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_occurrence_arenas(blob_id, spans)
         VALUES(?1, jsonb('[[0,10,1,1,0],[1,9,1,1,0],[2,7,1,1,0],[2,7,1,1,0]]'))",
        [blob_id],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO source_rust_module_manifests(
               blob_id, facts_version, root_occurrence_id,
               root_start_byte, root_end_byte, root_provenance)
             SELECT ?1, 1, 0, json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]'), json_extract(arena.spans, '$[0][4]')
             FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_module_scopes(
           blob_id, ordinal, parent_ordinal, declaration_id,
           module_name, imports_macros, resolution_scope)
         VALUES(?1, 0, NULL, NULL, '', 1, NULL)",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_module_inventory(
           blob_id, ordinal, parent_scope_ordinal, declaration_id, module_name)
         VALUES(?1, 0, 0, NULL, '')",
        [blob_id],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO source_rust_item_manifests(
           blob_id, facts_version, logical_rows, payload_bytes,
           macro_facts_version, type_forms_version)
         VALUES(?1, 1, 7, 5, 1, 1)",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_item_syntax(blob_id, occurrence_id, has_error)
         VALUES(?1, 0, 0)",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_item_contexts(
           blob_id, occurrence_id, ordinal, parent_occurrence_id,
           owner_declaration_id, context_kind, start_byte, end_byte, provenance)
         SELECT ?1, 0, 0, NULL, NULL, 0, json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]'), json_extract(arena.spans, '$[0][4]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO source_rust_types(blob_id, occurrence_id, path_kind, leading_absolute, unsupported_occurrence_id, unsupported_syntax_kind, compound_occurrence_id, type_parameters_occurrence_id, start_byte, end_byte, provenance, unsupported_start_byte, unsupported_end_byte, unsupported_provenance, compound_start_byte, compound_end_byte, compound_provenance, type_parameters_start_byte, type_parameters_end_byte, type_parameters_provenance)
         VALUES(?1, 1, 2, NULL, NULL, NULL, 1, NULL, (SELECT json_extract(spans, '$[1][0]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[1][1]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[1][4]') FROM source_occurrence_arenas WHERE blob_id=?1), NULL, NULL, NULL, (SELECT json_extract(spans, '$[1][0]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[1][1]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[1][4]') FROM source_occurrence_arenas WHERE blob_id=?1), NULL, NULL, NULL),
               (?1, 2, 0, 0, NULL, NULL, NULL, NULL, (SELECT json_extract(spans, '$[2][0]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[2][1]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[2][4]') FROM source_occurrence_arenas WHERE blob_id=?1), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_type_children(
           blob_id, type_occurrence_id, ordinal, occurrence_id)
         VALUES(?1, 1, 0, 2)",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_type_segments(blob_id, type_occurrence_id, ordinal, occurrence_id, name, start_byte, end_byte, provenance)
         VALUES(?1, 2, 0, 3, 'Trait', (SELECT json_extract(spans, '$[3][0]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[3][1]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[3][4]') FROM source_occurrence_arenas WHERE blob_id=?1))",
        [blob_id],
    )
    .unwrap();

    blob_id
}

fn seal_building_blob(conn: &Connection, blob_id: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE source_fact_manifests
            SET publication_state = 'complete'
          WHERE blob_id = ?1",
        [blob_id],
    )?;
    Ok(())
}

fn assert_seal_rejected(conn: &Connection, blob_id: i64) {
    let error = seal_building_blob(conn, blob_id).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("canonical Rust compound type shape is inconsistent"),
        "compound shape law must reject blob {blob_id}: {error}"
    );
    assert_eq!(
        conn.query_row(
            "SELECT publication_state FROM source_fact_manifests WHERE blob_id = ?1",
            [blob_id],
            |row| row.get::<_, String>(0),
        )
        .unwrap(),
        "building"
    );
}

#[test]
fn compound_type_seals_and_preserves_ordered_child_lookup() {
    let mut conn = current_connection();
    let blob_id = seed_compound_blob(&mut conn, "schema59-compound-accepted");

    let children = conn
        .prepare(
            "SELECT occurrence_id FROM source_rust_type_children
               WHERE blob_id = ?1 AND type_occurrence_id = ?2
               ORDER BY ordinal",
        )
        .unwrap()
        .query_map(params![blob_id, 1], |row| row.get::<_, i64>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(children, vec![2]);
    assert_eq!(
        conn.query_row(
            "SELECT path_kind, compound_occurrence_id, type_parameters_occurrence_id
               FROM source_rust_types WHERE blob_id = ?1 AND occurrence_id = 1",
            [blob_id],
            |row| Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<i64>>(2)?
            )),
        )
        .unwrap(),
        (2, 1, None)
    );
}

#[test]
fn compound_type_rejects_wrong_cardinality_and_sparse_ordinals() {
    let mut conn = current_connection();
    let blob_id = seed_compound_blob_building(&mut conn, "schema59-compound-cardinality");
    assert!(
        conn.execute(
            "INSERT INTO source_rust_type_children(
           blob_id, type_occurrence_id, ordinal, occurrence_id)
         VALUES(?1, 1, 1, 2)",
            [blob_id],
        )
        .is_err(),
        "one source child cannot occupy two ordinal positions"
    );
    conn.execute(
        "DELETE FROM source_rust_type_children WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "UPDATE source_rust_item_manifests SET logical_rows = 6 WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    // The fixture changes its declared totals, not the sealing constraints.
    conn.execute_batch("DROP TRIGGER source_fact_manifests_declared_fields_are_immutable")
        .unwrap();
    conn.execute(
        "UPDATE source_fact_manifests SET logical_rows = 14 WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    assert_seal_rejected(&conn, blob_id);

    let mut conn = current_connection();
    let blob_id = seed_compound_blob_building(&mut conn, "schema59-compound-sparse");
    conn.execute(
        "UPDATE source_rust_type_children SET ordinal = 1
          WHERE blob_id = ?1 AND type_occurrence_id = 1 AND ordinal = 0",
        [blob_id],
    )
    .unwrap();
    assert_seal_rejected(&conn, blob_id);
}

#[test]
fn compound_type_rejects_wrong_owner_provenance_and_child_cycle() {
    let mut conn = current_connection();
    let blob_id = seed_compound_blob_building(&mut conn, "schema59-compound-owner");
    conn.execute(
        "UPDATE source_rust_type_children SET type_occurrence_id = 2
          WHERE blob_id = ?1 AND type_occurrence_id = 1",
        [blob_id],
    )
    .unwrap();
    assert_seal_rejected(&conn, blob_id);

    let mut conn = current_connection();
    let blob_id = seed_compound_blob_building(&mut conn, "schema59-compound-provenance");
    conn.execute(
        // provenance code 2 is `embedded`, at position 4 of each arena entry.
        "UPDATE source_occurrence_arenas
            SET spans = jsonb_set(jsonb_set(spans, '$[2][4]', 2), '$[3][4]', 2)
          WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    // Keep both copies consistent so the original compound provenance law,
    // rather than the shared equality guard, rejects this publication.
    conn.execute(
        "UPDATE source_rust_types SET provenance=2 WHERE blob_id=?1 AND occurrence_id=2",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "UPDATE source_rust_type_segments SET provenance=2 WHERE blob_id=?1 AND occurrence_id=3",
        [blob_id],
    )
    .unwrap();
    // Preserve the fixture's declared payload accounting.
    conn.execute_batch("DROP TRIGGER source_fact_manifests_declared_fields_are_immutable")
        .unwrap();
    conn.execute(
        "UPDATE source_fact_manifests SET payload_bytes = 45 WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    assert_seal_rejected(&conn, blob_id);

    let mut conn = current_connection();
    let blob_id = seed_compound_blob_building(&mut conn, "schema59-compound-cycle");
    conn.execute(
        "UPDATE source_rust_type_children SET occurrence_id = 1
          WHERE blob_id = ?1 AND type_occurrence_id = 1",
        [blob_id],
    )
    .unwrap();
    assert_seal_rejected(&conn, blob_id);
}

#[test]
fn compound_type_rejects_equal_span_and_non_hrtb_parameters() {
    let mut conn = current_connection();
    let blob_id = seed_compound_blob_building(&mut conn, "schema59-compound-span");
    conn.execute(
        "UPDATE source_occurrence_arenas
            SET spans = jsonb_set(jsonb_set(jsonb_set(jsonb_set(
                  spans, '$[2][0]', 1), '$[2][1]', 9), '$[3][0]', 1), '$[3][1]', 9)
          WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "UPDATE source_rust_types SET start_byte=1,end_byte=9 WHERE blob_id=?1 AND occurrence_id=2",
        [blob_id],
    )
    .unwrap();
    conn.execute("UPDATE source_rust_type_segments SET start_byte=1,end_byte=9 WHERE blob_id=?1 AND occurrence_id=3", [blob_id]).unwrap();
    assert_seal_rejected(&conn, blob_id);

    let mut conn = current_connection();
    let blob_id = seed_compound_blob_building(&mut conn, "schema59-compound-parameters");
    assert!(
        conn.execute(
            "UPDATE source_rust_types
                SET path_kind = 4, type_parameters_occurrence_id = 2, type_parameters_start_byte=2, type_parameters_end_byte=8, type_parameters_provenance=0
              WHERE blob_id = ?1 AND occurrence_id = 1",
            [blob_id],
        )
        .is_err()
    );
    assert_eq!(
        conn.query_row(
            "SELECT type_parameters_occurrence_id FROM source_rust_types
              WHERE blob_id = ?1 AND occurrence_id = 1",
            [blob_id],
            |row| row.get::<_, Option<i64>>(0),
        )
        .unwrap(),
        None
    );
}

#[test]
fn compound_type_rows_are_immutable_after_seal_and_cascade_with_blob() {
    let mut conn = current_connection();
    let blob_id = seed_compound_blob(&mut conn, "schema59-compound-immutable");

    assert!(
        conn.execute(
            "UPDATE source_rust_types SET path_kind = 3
              WHERE blob_id = ?1 AND occurrence_id = 1",
            [blob_id],
        )
        .is_err()
    );
    assert!(
        conn.execute(
            "UPDATE source_rust_type_children SET ordinal = 1
              WHERE blob_id = ?1 AND type_occurrence_id = 1",
            [blob_id],
        )
        .is_err()
    );
    assert!(
        conn.execute(
            "DELETE FROM source_rust_type_children WHERE blob_id = ?1",
            [blob_id],
        )
        .is_err()
    );
    assert!(
        conn.execute(
            "INSERT INTO source_rust_type_children(
               blob_id, type_occurrence_id, ordinal, occurrence_id)
             VALUES(?1, 1, 1, 2)",
            [blob_id],
        )
        .is_err()
    );

    conn.execute("DELETE FROM blobs WHERE id = ?1", [blob_id])
        .unwrap();
    for table in ["source_rust_types", "source_rust_type_children"] {
        let count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE blob_id = ?1"),
                [blob_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "blob cascade left rows in {table}");
    }
}

#[test]
fn compound_type_cardinality_lookup_stays_bound_after_analyze() {
    let mut conn = current_connection();
    let mut blob_ids = Vec::new();
    for index in 0..12 {
        blob_ids.push(seed_compound_blob(
            &mut conn,
            &format!("type-form-{index}-query"),
        ));
    }
    let selected_blob = blob_ids[7];
    let sql = "EXPLAIN QUERY PLAN
        SELECT COUNT(*) FROM source_rust_type_children
         WHERE blob_id = ?1 AND type_occurrence_id = ?2";
    let explain = |conn: &Connection| {
        conn.prepare(sql)
            .unwrap()
            .query_map(params![selected_blob, 1], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };

    let before = explain(&conn);
    assert!(
        before.iter().any(|detail| {
            detail.contains("SEARCH source_rust_type_children")
                && detail.contains("blob_id=? AND type_occurrence_id=?")
        }),
        "compound child lookup was not primary-key bound before ANALYZE: {before:?}"
    );
    conn.execute_batch("ANALYZE").unwrap();
    let after = explain(&conn);
    assert!(
        after.iter().any(|detail| {
            detail.contains("SEARCH source_rust_type_children")
                && detail.contains("blob_id=? AND type_occurrence_id=?")
        }),
        "compound child lookup was not primary-key bound after ANALYZE: {after:?}"
    );
    assert_eq!(
        conn.prepare(
            "SELECT occurrence_id FROM source_rust_type_children
               WHERE blob_id = ?1 AND type_occurrence_id = ?2 ORDER BY ordinal",
        )
        .unwrap()
        .query_map(params![selected_blob, 1], |row| row.get::<_, i64>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap(),
        vec![2]
    );
}
