//! Schema 60 Rust macro-definition context laws.
//!
//! The fixture is deliberately small, but it is a complete published source
//! fact set.  In particular, the macro arm and pattern rows stay present while
//! the definition table is rebuilt, which exercises the deferred incoming FK.

use super::*;
use rusqlite::params;

fn current_connection() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    configure_connection(&mut conn).unwrap();
    migrate(&mut conn).unwrap();
    conn
}

fn seal(conn: &Connection, blob_id: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE source_fact_manifests
            SET publication_state = 'complete'
          WHERE blob_id = ?1",
        [blob_id],
    )?;
    conn.execute_batch("COMMIT")?;
    Ok(())
}

/// Insert one schema-59-shaped macro publication.  The extra context
/// occurrence (5) is an embedded FileRoot child of the source root, backed by
/// the corresponding expansion row required by the existing context laws.  A
/// separate fresh helper below adds the schema-60 marker and context value.
fn seed_macro_blob_building(conn: &mut Connection, seed: &str) -> i64 {
    // Arms and pattern roots have deferred circular references, as in the
    // production writer's atomic source publication transaction.
    conn.execute_batch("BEGIN").unwrap();
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

    // 1 marker + 6 occurrences + 1 declaration + 3 module rows + 11 item
    // rows.  Payload is the six provenance strings (five primary_node and one
    // embedded) plus the binding and role names.
    conn.execute(
        "INSERT INTO source_fact_manifests(
           blob_id, facts_version, source_bytes, occurrence_count,
           declaration_count, declaration_unit_count, node_count, role_count,
           occurrence_role_count, logical_rows, payload_bytes, publication_state)
         VALUES(?1, 1, 100, 6, 1, 0, 0, 0, 0, 22, 2, 'building')",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_occurrence_arenas(blob_id, spans)
         VALUES(?1, jsonb('[[0,100,1,1,0],[10,90,1,1,0],[20,50,1,1,0],[20,30,1,1,0],[22,23,1,1,0],[0,100,1,1,2]]'))",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_declarations(
               blob_id, declaration_id, occurrence_id, name_occurrence_id,
               start_byte, end_byte, start_line, end_line,
               name_start_byte, name_end_byte, name_start_line, name_end_line,
               provenance)
             SELECT ?1, 0, 1, 1, json_extract(arena.spans, '$[1][0]'), json_extract(arena.spans, '$[1][1]'), json_extract(arena.spans, '$[1][2]'), json_extract(arena.spans, '$[1][3]'), json_extract(arena.spans, '$[1][0]'), json_extract(arena.spans, '$[1][1]'), json_extract(arena.spans, '$[1][2]'), json_extract(arena.spans, '$[1][3]'), json_extract(arena.spans, '$[1][4]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
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
         VALUES(?1, 1, 11, 2, 1, 1)",
        [blob_id],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO source_rust_item_syntax(blob_id, occurrence_id, has_error)
         VALUES(?1, 0, 0), (?1, 5, 0)",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_item_contexts(
           blob_id, occurrence_id, ordinal, parent_occurrence_id,
           owner_declaration_id, context_kind, start_byte, end_byte, provenance)
         SELECT ?1, 0, 0, NULL, NULL, 0, json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]'), json_extract(arena.spans, '$[0][4]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1
         UNION ALL SELECT ?1, 5, 1, 0, NULL, 0, json_extract(arena.spans, '$[5][0]'), json_extract(arena.spans, '$[5][1]'), json_extract(arena.spans, '$[5][4]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO source_rust_item_macro_expansions(
           blob_id, invocation_occurrence_id, context_occurrence_id,
           source_position, expansion_kind, root_occurrence_id,
           invocation_start_byte, invocation_end_byte)
         SELECT ?1, 0, 0, 1, 0, 5, json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_macro_definitions(
           blob_id, declaration_id, ordinal, is_macro_rules)
         VALUES(?1, 0, 0, 1)",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_macro_arms(blob_id, declaration_id, ordinal, occurrence_id, pattern_occurrence_id, start_byte, end_byte, provenance)
         VALUES(?1, 0, 0, 2, 3, (SELECT json_extract(spans, '$[2][0]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[2][1]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[2][4]') FROM source_occurrence_arenas WHERE blob_id=?1))",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_macro_pattern_nodes(blob_id, declaration_id, arm_ordinal, ordinal, occurrence_id, parent_occurrence_id, node_kind, delimiter, start_byte, end_byte, provenance)
         VALUES(?1, 0, 0, 0, 3, NULL, 2, 0, (SELECT json_extract(spans, '$[3][0]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[3][1]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[3][4]') FROM source_occurrence_arenas WHERE blob_id=?1))",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_macro_pattern_nodes(blob_id, declaration_id, arm_ordinal, ordinal, occurrence_id, parent_occurrence_id, node_kind, binding_name, fragment_kind, start_byte, end_byte, provenance)
         VALUES(?1, 0, 0, 1, 4, 3, 1, 'x', 0, (SELECT json_extract(spans, '$[4][0]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[4][1]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[4][4]') FROM source_occurrence_arenas WHERE blob_id=?1))",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_macro_ident_roles(
           blob_id, declaration_id, arm_ordinal, ordinal, name, role)
         VALUES(?1, 0, 0, 0, 'x', 0)",
        [blob_id],
    )
    .unwrap();

    blob_id
}

fn seed_fresh_macro_blob_building(
    conn: &mut Connection,
    seed: &str,
    context_occurrence_id: Option<i64>,
) -> i64 {
    let blob_id = seed_macro_blob_building(conn, seed);
    conn.execute(
        "UPDATE source_rust_item_manifests
            SET macro_contexts_version = 1
          WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "UPDATE source_rust_macro_definitions
            SET context_occurrence_id = ?2
          WHERE blob_id = ?1 AND declaration_id = 0",
        params![blob_id, context_occurrence_id],
    )
    .unwrap();
    blob_id
}

fn seed_fresh_macro_blob(
    conn: &mut Connection,
    seed: &str,
    context_occurrence_id: Option<i64>,
) -> i64 {
    let blob_id = seed_fresh_macro_blob_building(conn, seed, context_occurrence_id);
    seal(conn, blob_id).unwrap();
    blob_id
}

fn assert_context_rejected(conn: &Connection, blob_id: i64, reason: &str) {
    let error = seal(conn, blob_id).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("canonical Rust macro definition contexts are inconsistent"),
        "{reason} must be rejected by macro-context validation: {error}"
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
fn fresh_macro_context_accepts_enclosing_primary_context() {
    let mut conn = current_connection();
    let blob_id = seed_fresh_macro_blob(&mut conn, "macro-context-positive", Some(0));
    assert_eq!(
        conn.query_row(
            "SELECT macro_contexts_version FROM source_rust_item_manifests
              WHERE blob_id = ?1",
            [blob_id],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row(
            "SELECT context_occurrence_id FROM source_rust_macro_definitions
              WHERE blob_id = ?1",
            [blob_id],
            |row| row.get::<_, Option<i64>>(0),
        )
        .unwrap(),
        Some(0)
    );
}

#[test]
fn fresh_macro_context_rejects_missing_wrong_provenance_outside_and_self() {
    let mut conn = current_connection();
    let blob_id = seed_fresh_macro_blob_building(&mut conn, "macro-context-missing", None);
    assert_context_rejected(&conn, blob_id, "missing context");

    let mut conn = current_connection();
    let blob_id = seed_fresh_macro_blob_building(&mut conn, "macro-context-provenance", Some(5));
    // The base fixture's embedded FileRoot is itself valid because of its
    // matching macro-expansion row; only this mismatch belongs to schema 60.
    assert_context_rejected(&conn, blob_id, "wrong context provenance");

    let mut conn = current_connection();
    let blob_id = seed_fresh_macro_blob_building(&mut conn, "macro-context-span", Some(5));
    conn.execute(
        "UPDATE source_occurrence_arenas
            SET spans = jsonb_set(jsonb_set(jsonb_set(
                  spans, '$[5][0]', 11), '$[5][1]', 89), '$[5][4]', 0)
          WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "UPDATE source_rust_item_contexts SET context_kind = 6, start_byte=11, end_byte=89, provenance=0
          WHERE blob_id = ?1 AND occurrence_id = 5",
        [blob_id],
    )
    .unwrap();
    // This rollback-only negative fixture changes an arena provenance code after
    // seeding. A code is one byte whatever it is, so payload_bytes no longer
    // moves with it and the fixture needs no compensation.
    conn.execute(
        "UPDATE source_rust_item_macro_expansions
            SET expansion_kind = 1, root_occurrence_id = NULL
          WHERE blob_id = ?1 AND invocation_occurrence_id = 0",
        [blob_id],
    )
    .unwrap();
    assert_context_rejected(&conn, blob_id, "outside context span");
    conn.execute_batch("ROLLBACK").unwrap();

    let mut conn = current_connection();
    let blob_id = seed_fresh_macro_blob_building(&mut conn, "macro-context-self", Some(0));
    conn.execute(
        "UPDATE source_declarations
            SET occurrence_id = 0, name_occurrence_id = 0, start_byte=0, end_byte=100, name_start_byte=0, name_end_byte=100, start_line=1, end_line=1, name_start_line=1, name_end_line=1, provenance=0
          WHERE blob_id = ?1 AND declaration_id = 0",
        [blob_id],
    )
    .unwrap();
    assert_context_rejected(&conn, blob_id, "self context");
}

#[test]
fn sealed_macro_definition_context_is_immutable() {
    let mut conn = current_connection();
    let blob_id = seed_fresh_macro_blob(&mut conn, "macro-context-sealed", Some(0));
    assert!(
        conn.execute(
            "UPDATE source_rust_macro_definitions
                SET context_occurrence_id = 5
              WHERE blob_id = ?1 AND declaration_id = 0",
            [blob_id],
        )
        .is_err(),
        "sealed definition context must be immutable"
    );
}

#[test]
fn populated_macro_context_validation_lookup_stays_bound_after_analyze() {
    let mut conn = current_connection();
    let mut blob_ids = Vec::new();
    for index in 0..12 {
        blob_ids.push(seed_fresh_macro_blob(
            &mut conn,
            &format!("{index}-macro-context-query"),
            Some(0),
        ));
    }
    let selected_blob = blob_ids[7];
    // The body of source_fact_manifests_validate_rust_macro_contexts. Both
    // tables carry their span and provenance inline (lane ST stage B), so the
    // validation is four column reads and stays primary-key bound.
    const VALIDATION_SQL: &str = "SELECT 1
          FROM source_rust_macro_definitions AS definition
          JOIN source_declarations AS declaration
            ON declaration.blob_id = definition.blob_id
           AND declaration.declaration_id = definition.declaration_id
          LEFT JOIN source_rust_item_contexts AS context
            ON context.blob_id = definition.blob_id
           AND context.occurrence_id = definition.context_occurrence_id
         WHERE definition.blob_id = ?1
           AND (context.occurrence_id IS NULL
                OR context.occurrence_id = declaration.occurrence_id
                OR context.provenance IS NOT declaration.provenance
                OR context.start_byte > declaration.start_byte
                OR context.end_byte < declaration.end_byte)";
    let invalid_rows = |conn: &Connection| {
        conn.prepare(VALIDATION_SQL)
            .unwrap()
            .query_map([selected_blob], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };
    assert_eq!(
        invalid_rows(&conn),
        Vec::<i64>::new(),
        "the populated fresh fixture must satisfy the actual validation SELECT"
    );

    let explain_sql = format!("EXPLAIN QUERY PLAN {VALIDATION_SQL}");
    let explain = |conn: &Connection| {
        conn.prepare(&explain_sql)
            .unwrap()
            .query_map([selected_blob], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };
    let before = explain(&conn);
    let required_searches = ["definition", "declaration", "context"];
    assert!(
        required_searches.iter().all(|alias| {
            before.iter().any(|detail| {
                detail.contains(&format!("SEARCH {alias} ")) && detail.contains("blob_id=?")
            })
        }) && before.iter().all(|detail| !detail.contains("SCAN")),
        "macro context validation was not primary-key bound before ANALYZE: {before:?}"
    );
    conn.execute_batch("ANALYZE").unwrap();
    assert_eq!(
        invalid_rows(&conn),
        Vec::<i64>::new(),
        "ANALYZE must not change the actual validation result"
    );
    let after = explain(&conn);
    assert!(
        required_searches.iter().all(|alias| {
            after.iter().any(|detail| {
                detail.contains(&format!("SEARCH {alias} ")) && detail.contains("blob_id=?")
            })
        }) && after.iter().all(|detail| !detail.contains("SCAN")),
        "macro context validation was not primary-key bound after ANALYZE: {after:?}"
    );
    assert_eq!(
        conn.query_row(
            "SELECT context_occurrence_id
               FROM source_rust_macro_definitions
              WHERE blob_id = ?1",
            [selected_blob],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        0
    );
}
