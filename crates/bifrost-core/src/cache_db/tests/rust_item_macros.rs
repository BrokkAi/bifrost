//! Schema 61 Rust macro-route projection and sealing laws.

use super::*;
use rusqlite::params;

fn current_connection() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    configure_connection(&mut conn).unwrap();
    migrate(&mut conn).unwrap();
    conn
}

fn seed_macro_route(conn: &Connection, seed: &str, context_occurrence_id: Option<i64>) -> i64 {
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
    let item_logical_rows = 4;
    // Include the canonical module root, scope and inventory used by the
    // FileRoot context law, even though this fixture has no child modules.
    let source_logical_rows = 13;
    conn.execute(
        "INSERT INTO source_fact_manifests(
           blob_id, facts_version, source_bytes, occurrence_count,
           declaration_count, declaration_unit_count, node_count, role_count,
           occurrence_role_count, rust_declaration_property_count,
           rust_constructor_field_count, logical_rows, payload_bytes,
           publication_state)
         VALUES(?1, 12, 30, 3, 1, 0, 0, 0, 0, 1, 0, ?2, 13, 'building')",
        params![blob_id, source_logical_rows],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_occurrence_arenas(blob_id, spans)
         VALUES(?1, jsonb('[[0,30,1,1,0],[10,20,1,1,0],[10,12,1,1,0]]'))",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_declarations(
               blob_id, declaration_id, occurrence_id, name_occurrence_id,
               start_byte, end_byte, start_line, end_line,
               name_start_byte, name_end_byte, name_start_line, name_end_line,
               provenance)
             SELECT ?1, 0, 1, 2, json_extract(arena.spans, '$[1][0]'), json_extract(arena.spans, '$[1][1]'), json_extract(arena.spans, '$[1][2]'), json_extract(arena.spans, '$[1][3]'), json_extract(arena.spans, '$[2][0]'), json_extract(arena.spans, '$[2][1]'), json_extract(arena.spans, '$[2][2]'), json_extract(arena.spans, '$[2][3]'), json_extract(arena.spans, '$[1][4]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_declaration_properties(
           blob_id, declaration_id, visibility, cfg_condition,
           constructor_non_exhaustive, declaration_kind, macro_exported,
           trait_impl_member, has_impl_or_trait_ancestor,
           nearest_declaration_boundary)
         VALUES(?1, 0, 'private', 'always', NULL, 12, 0, 0, 0, 0)",
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
           macro_contexts_version)
         VALUES(?1, 1, ?2, 0, 1)",
        params![blob_id, item_logical_rows],
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
        "INSERT INTO source_rust_macro_definitions(
           blob_id, declaration_id, ordinal, is_macro_rules,
           context_occurrence_id)
         VALUES(?1, 0, 0, 1, ?2)",
        params![blob_id, context_occurrence_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_item_macros(
           blob_id, lang, ordinal, macro_name, passthrough, arguments_only, decoration_cfg, declaration_id)
         VALUES(?1, 'rust', 0, 'declare', 0, 0, NULL, 0)",
        [blob_id],
    )
    .unwrap();
    blob_id
}

fn seal(conn: &Connection, blob_id: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE source_fact_manifests
            SET publication_state = 'complete'
          WHERE blob_id = ?1",
        [blob_id],
    )?;
    Ok(())
}

#[test]
fn fresh_macro_routes_require_definition_and_context_links_before_seal() {
    let conn = current_connection();
    let valid = seed_macro_route(&conn, "macro-route-valid", Some(0));
    seal(&conn, valid).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT visible_after, scope_start, scope_end
               FROM rust_item_macros WHERE blob_id = ?1",
            [valid],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .unwrap(),
        (Some(20), Some(0), Some(30))
    );

    let missing_definition = seed_macro_route(&conn, "macro-route-no-definition", Some(0));
    conn.execute_batch(
        "SAVEPOINT missing_macro_definition;
         DROP TRIGGER source_fact_manifests_declared_fields_are_immutable;",
    )
    .unwrap();
    for sql in [
        "UPDATE source_fact_manifests SET logical_rows = logical_rows - 1 WHERE blob_id = ?1",
        "UPDATE source_rust_item_manifests SET logical_rows = logical_rows - 1 WHERE blob_id = ?1",
        "DELETE FROM source_rust_macro_definitions WHERE blob_id = ?1",
    ] {
        conn.execute(sql, [missing_definition]).unwrap();
    }
    let error = seal(&conn, missing_definition).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("canonical Rust macro route links are inconsistent"),
        "missing active definition link must be rejected: {error}"
    );
    conn.execute_batch("ROLLBACK TO missing_macro_definition; RELEASE missing_macro_definition")
        .unwrap();

    let missing_context = seed_macro_route(&conn, "macro-route-no-context", None);
    let error = seal(&conn, missing_context).unwrap_err();
    assert!(
        error.to_string().contains("canonical Rust macro"),
        "missing definition context must remain rejected by a macro link law: {error}"
    );
}

#[test]
fn sealed_macro_route_source_rows_remain_immutable_after_rebuild() {
    let conn = current_connection();
    let blob_id = seed_macro_route(&conn, "macro-route-immutable", Some(0));
    seal(&conn, blob_id).unwrap();
    for sql in [
        "UPDATE source_rust_item_macros SET passthrough = 1 WHERE blob_id = ?1",
        "DELETE FROM source_rust_item_macros WHERE blob_id = ?1",
        "INSERT INTO source_rust_item_macros(
            blob_id, lang, ordinal, macro_name, passthrough, arguments_only, decoration_cfg, declaration_id)
         VALUES(?1, 'rust', 1, 'other', 0, 0, NULL, 0)",
    ] {
        let error = conn.execute(sql, [blob_id]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("sealed source facts are immutable"),
            "{sql}: {error}"
        );
    }
}
