//! Resolution schema, migration, sealing, and indexed-query laws.

use super::*;
use rusqlite::params;

#[path = "native_fk_probes.rs"]
mod native_fk_probes;

fn seed_complete_blob_meta(conn: &Connection, blob_id: i64, lang: &str) {
    conn.execute(
        "INSERT INTO blob_meta(
               blob_id, lang, contains_tests, content_package,
               stored_unit_count, range_count, signature_count,
               signature_metadata_count, supertype_count, child_count,
               import_statement_count, type_identifier_count, is_complete
             ) VALUES(?1, ?2, 0, 'base', 0, 0, 0, 0, 0, 0, 0, 0, 1)",
        rusqlite::params![blob_id, lang],
    )
    .unwrap();
}

fn insert_resolution_test_blob(conn: &Connection, label: &str, lang: &str) -> i64 {
    let oid = seeded_oid(label);
    conn.execute(
        "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, ?2, 0)",
        rusqlite::params![oid, lang],
    )
    .unwrap();
    let blob_id = conn.last_insert_rowid();
    seed_complete_blob_meta(conn, blob_id, lang);
    blob_id
}

fn insert_reference_enumeration_impact_interior(
    conn: &Connection,
    label: &str,
    storage_language: &str,
    semantic_language: &str,
    expected_impact_count: i64,
) -> i64 {
    assert_eq!(expected_impact_count, 0);
    let blob_id = insert_resolution_test_blob(conn, label, storage_language);
    conn.execute(
        "INSERT INTO resolution_fragment_interiors(
               blob_id, lang, semantic_language, producer_epoch, interior_digest, expected_semantic_site_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, ?2, ?3, 'resolution-v1', zeroblob(32), 0, 1, 0, 'building')",
        rusqlite::params![blob_id, storage_language, semantic_language],
    )
    .unwrap();
    blob_id
}

fn resolution_table_columns(conn: &Connection, table: &str) -> Vec<String> {
    conn.prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")
        .unwrap()
        .query_map([table], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap()
}

fn assert_resolution_canonical_schema_names(conn: &Connection) {
    for removed in [
        "structural_fact_manifests",
        "structural_fact_nodes",
        "structural_fact_roles",
        "structural_fact_occurrence_roles",
        "legacy_rust_module_manifests",
        "legacy_rust_modules",
        "legacy_rust_module_scopes",
        "legacy_rust_module_routes",
        "import_path_segments",
        "import_lexical_scopes",
        "import_lexical_prefixes",
        "rust_import_module_segments",
        "unit_visibility_containers",
        "unit_cpp_template_metadata",
        "resolution_reference_enumeration_impacts",
        "resolution_fragment_interiors_validate_child_manifests",
        "resolution_fragment_interiors_validate_top_level_manifest",
        "resolution_fragment_interiors_validate_type_transfer_rule_children",
        "resolution_fragment_interiors_validate_typed_children",
        // The rows-era tables, their indexes and the validators that mixed
        // them with tier 1. Milestone 6 is writing tier 2 as rows again, so
        // this list is not "tier 2 must not exist": it is the old design's
        // object names, which no writer produces. Two names left it when
        // milestone 6 port block 4 (lane TF) gave the milestone 5 draft's
        // tables the names the draft gives them,
        // `resolution_type_frontiers` and `resolution_binding_projections`;
        // those two are live tables with the draft's columns and keys, not
        // survivors of the old schema.
        "resolution_nodes",
        "resolution_partial_paths",
        "resolution_reference_sites",
        "resolution_lookup_semantic_recipes",
        "resolution_root_path_demands",
        "resolution_root_path_segments",
        "resolution_type_transfer_rules",
        "resolution_qualified_seeded_routes",
        "resolution_declared_type_relations",
        "resolution_relation_members",
        "source_reference_sites",
        "resolution_root_path_segment_inputs",
        "resolution_fragment_interiors_validate_callable_receiver_origins",
        "resolution_fragment_interiors_validate_semantic_sites",
        "resolution_type_identity_observations_validate",
    ] {
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name = ?1",
                [removed],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            0,
            "obsolete cache schema object {removed} survived baseline 117"
        );
    }
    for retained in [
        "legacy_resolution_declaration_visibility_properties",
        "resolution_fragment_interiors_validate_source_native_declaration_bridges",
    ] {
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name = ?1",
                [retained],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            1,
            "live cache schema object {retained} was removed from baseline 117"
        );
    }

    for (table, expected) in [
        (
            "resolution_semantic_sites",
            &[
                "blob_id",
                "source_site",
                "namespace",
                "semantic_role",
                "semantic_key",
            ][..],
        ),
        (
            "resolution_additional_definition_namespaces",
            &[
                "blob_id",
                "definition_semantic_key",
                "namespace",
                "hoisting",
            ][..],
        ),
        (
            "resolution_root_route_segments",
            &[
                "blob_id",
                "path_key",
                "position",
                "segment",
                "terminal_spelling",
                "reference_source_site",
                "reference_start_byte",
                "reference_end_byte",
            ][..],
        ),
        (
            "resolution_reference_lookup_identities",
            &["blob_id", "semantic_key", "identity_id"][..],
        ),
        (
            "resolution_typed_fact_lookups",
            &["blob_id", "relation", "identity_id"][..],
        ),
        (
            "resolution_trait_implementations",
            &[
                "blob_id",
                "relation_key",
                "side",
                "position",
                "segment",
                "terminal_spelling",
                "impl_site",
                "impl_start_byte",
                "impl_end_byte",
            ][..],
        ),
    ] {
        let expected = expected
            .iter()
            .map(|column| (*column).to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            resolution_table_columns(conn, table),
            expected,
            "resolution table {table} carries a noncanonical column name"
        );
    }

    let lookup_index_columns = conn
        .prepare(
            "SELECT name FROM pragma_index_info('resolution_reference_lookup_identities_identity')
                 ORDER BY seqno",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        lookup_index_columns,
        ["identity_id", "blob_id", "semantic_key"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        "the cross-blob discovery index must retain its covering order"
    );

    // The route family is a two-shape relation: a segment row spells one
    // position of the module path, and the terminal row closes the route with
    // the name it demands and the reference site that demands it.
    let route_sql = conn
        .query_row(
            "SELECT sql FROM sqlite_schema
                 WHERE type = 'table' AND name = 'resolution_root_route_segments'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    for required in [
        "FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE",
        "CHECK((segment IS NULL) = (terminal_spelling IS NOT NULL))",
        "CHECK((terminal_spelling IS NULL) = (reference_source_site IS NULL))",
    ] {
        assert!(
            route_sql.contains(required),
            "root-route family omits required relational shape {required:?}: {route_sql}"
        );
    }

    // The trait-implementation family is the same two-shape relation, once per
    // half of `impl Trait for Type`: a segment row spells one position of that
    // half's module path and the row after them closes it with the head
    // nominal name. The impl's site and span ride every row, so a derivation
    // that reaches any row can place the impl in its module.
    let implementation_sql = conn
        .query_row(
            "SELECT sql FROM sqlite_schema
                 WHERE type = 'table' AND name = 'resolution_trait_implementations'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    for required in [
        "FOREIGN KEY(blob_id) REFERENCES resolution_fragment_interiors(blob_id) ON DELETE CASCADE",
        "CHECK((segment IS NULL) = (terminal_spelling IS NOT NULL))",
        "side TEXT NOT NULL CHECK(side IN ('subject', 'trait'))",
        "PRIMARY KEY(blob_id, relation_key, side, position)",
    ] {
        assert!(
            implementation_sql.contains(required),
            "trait-implementation family omits required relational shape {required:?}: \
             {implementation_sql}"
        );
    }
}

fn insert_empty_resolution_interior(conn: &Connection, label: &str) -> i64 {
    let blob_id = insert_resolution_test_blob(conn, label, "rust");
    conn.execute(
        "INSERT INTO resolution_fragment_interiors(
               blob_id, lang, semantic_language, producer_epoch, interior_digest, expected_semantic_site_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 'rust', 'rust', 'resolution-v1', zeroblob(32), 0, 1, 0, 'building')",
        [blob_id],
    )
    .unwrap();
    blob_id
}

#[test]
fn resolution_inline_closed_domain_rejects_unknown_label() {
    let mut conn = Connection::open_in_memory().unwrap();
    configure_connection(&mut conn).unwrap();
    migrate(&mut conn).unwrap();
    let blob_id = insert_empty_resolution_interior(&conn, "closed-resolution-domain");

    let error = conn
        .execute(
            "INSERT INTO resolution_semantic_sites(
                   blob_id, source_site, namespace, semantic_role, semantic_key
                 ) VALUES(?1, 0, 'value', 'future_role', 0)",
            [blob_id],
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("CHECK constraint failed"),
        "a closed engine domain accepted an unknown label: {error}"
    );
}

#[test]
fn definition_namespace_authority_requires_declared_hoisting() {
    let mut conn = Connection::open_in_memory().unwrap();
    configure_connection(&mut conn).unwrap();
    migrate(&mut conn).unwrap();
    let blob_id = insert_empty_resolution_interior(&conn, "definition-namespace-hoisting");

    let error = conn
        .execute(
            "INSERT INTO resolution_additional_definition_namespaces(
                   blob_id, definition_semantic_key, namespace, hoisting
                 ) VALUES(?1, 0, 'value', 'future_hoisting')",
            [blob_id],
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("CHECK constraint failed"),
        "definition namespace authority accepted unknown hoisting: {error}"
    );
}

const MUTABLE_RESOLUTION_INTERIOR_TABLES: [&str; 10] = [
    "resolution_semantic_sites",
    "resolution_additional_definition_namespaces",
    "resolution_definition_unit_crosswalks",
    "resolution_declaration_visibility_properties",
    "resolution_member_scope_properties",
    "resolution_member_owner_properties",
    "resolution_reference_lookup_identities",
    "resolution_root_route_segments",
    "resolution_trait_implementations",
    "resolution_typed_fact_lookups",
];

fn seal_resolution_interior(conn: &Connection, blob_id: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE resolution_fragment_interiors
             SET publication_state = 'complete' WHERE blob_id = ?1",
        [blob_id],
    )
}

fn insert_json_evidence_interior(conn: &Connection, label: &str, count: i64) -> i64 {
    let blob_id = insert_resolution_test_blob(conn, label, "rust");
    conn.execute(
        "INSERT INTO resolution_fragment_interiors(
           blob_id, lang, semantic_language, producer_epoch, interior_digest,
           expected_reference_lookup_identity_count, expected_root_route_segment_count,
           expected_semantic_site_count, logical_rows, payload_bytes, publication_state
         ) VALUES(?1, 'rust', 'rust', 'resolution-v1', zeroblob(32),
                  ?2, ?2, ?2, 1 + 3 * ?2, 0, 'building')",
        params![blob_id, count],
    )
    .unwrap();
    for index in 0..count {
        // The lookup rows name the workspace-wide intern table, so the digest
        // has to be interned before the row that points at it exists. Several
        // fixture blobs share the same identity ids, as real blobs do.
        let mut digest = [0u8; 32];
        digest[..8].copy_from_slice(&(index as u64).to_le_bytes());
        conn.execute(
            "INSERT OR IGNORE INTO resolution_identities(id, identity_digest) VALUES(?1, ?2)",
            params![index + 1, digest],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_reference_lookup_identities
               (blob_id, semantic_key, identity_id)
             VALUES(?1, ?2, ?2 + 1)",
            params![blob_id, index],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_semantic_sites
               (blob_id, source_site, namespace, semantic_role, semantic_key)
             VALUES(?1, ?2, 'value', 'reference', ?2)",
            params![blob_id, index],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_root_route_segments(
               blob_id, path_key, position, segment, terminal_spelling,
               reference_source_site, reference_start_byte, reference_end_byte
             ) VALUES(?1, ?2, 0, NULL, ?3, ?2, 0, 1)",
            params![blob_id, index, format!("target_{index}")],
        )
        .unwrap();
    }
    blob_id
}

fn query_plan(conn: &Connection, sql: &str) -> Vec<String> {
    conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap()
        .query_map([], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap()
}

#[test]
fn current_resolution_schema_ddl_drift_rebuilds_at_the_same_user_version() {
    let mut conn = open_in_memory_cache();
    conn.execute(
        "INSERT INTO resolution_producer_epochs(lang, producer_epoch)
             VALUES('rust', 'must-be-rebuilt')",
        [],
    )
    .unwrap();
    conn.execute_batch(
        "DROP INDEX resolution_reference_lookup_identities_identity;
             DROP TRIGGER resolution_fragment_interiors_validate_source_native_declaration_bridges;
             CREATE TRIGGER resolution_fragment_interiors_validate_source_native_declaration_bridges
             BEFORE UPDATE ON resolution_fragment_interiors
             BEGIN
               SELECT RAISE(ABORT, 'drifted resolution manifest guard');
             END;",
    )
    .unwrap();
    assert_eq!(
        cache_migration_version(&conn).unwrap(),
        CURRENT_MIGRATION_VERSION
    );
    assert!(!current_schema_is_valid(&conn).unwrap());

    migrate(&mut conn).unwrap();

    assert!(current_schema_is_valid(&conn).unwrap());
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM resolution_producer_epochs",
            [],
            |row| { row.get::<_, i64>(0) }
        )
        .unwrap(),
        0,
        "same-version DDL drift must rebuild rather than retain stale resolution rows"
    );
    assert_resolution_canonical_schema_names(&conn);
}

#[test]
fn current_resolution_schema_missing_root_index_rebuilds_at_the_same_version() {
    let mut conn = open_in_memory_cache();
    conn.execute(
        "INSERT INTO resolution_producer_epochs(lang, producer_epoch)
             VALUES('rust', 'missing-root-index-must-rebuild')",
        [],
    )
    .unwrap();
    conn.execute_batch("DROP INDEX resolution_reference_lookup_identities_identity;")
        .unwrap();
    assert_eq!(
        cache_migration_version(&conn).unwrap(),
        CURRENT_MIGRATION_VERSION
    );
    assert!(!current_schema_is_valid(&conn).unwrap());

    migrate(&mut conn).unwrap();

    assert!(current_schema_is_valid(&conn).unwrap());
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM resolution_producer_epochs",
            [],
            |row| { row.get::<_, i64>(0) }
        )
        .unwrap(),
        0,
        "index-only same-version drift must rebuild rather than retain stale resolution rows"
    );
    assert_resolution_canonical_schema_names(&conn);
}

#[test]
fn resolution_interior_manifest_accepts_writer_asserted_parent_state() {
    let mut conn = Connection::open_in_memory().unwrap();
    configure_connection(&mut conn).unwrap();
    migrate(&mut conn).unwrap();
    let first_oid = seeded_oid("empty-resolution-interior");
    conn.execute(
        "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'java', 0)",
        [&first_oid],
    )
    .unwrap();
    let first_blob = conn.last_insert_rowid();
    seed_complete_blob_meta(&conn, first_blob, "java");
    let insert_empty = "INSERT INTO resolution_fragment_interiors(
               blob_id, lang, semantic_language, producer_epoch, interior_digest, expected_semantic_site_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 'java', 'java', 'resolution-v1', zeroblob(32), ?2, ?3, 0, 'building')";
    conn.execute(insert_empty, rusqlite::params![first_blob, 0, 1])
        .unwrap();
    conn.execute(
        "UPDATE resolution_fragment_interiors
             SET publication_state = 'complete' WHERE blob_id = ?1",
        [first_blob],
    )
    .unwrap();
}

#[test]
fn resolution_children_omit_seal_guards_but_parent_cascade_remains_legal() {
    let mut conn = Connection::open_in_memory().unwrap();
    configure_connection(&mut conn).unwrap();
    migrate(&mut conn).unwrap();
    let oid = seeded_oid("immutable-resolution-interior");
    conn.execute(
        "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'java', 0)",
        [&oid],
    )
    .unwrap();
    let blob_id = conn.last_insert_rowid();
    seed_complete_blob_meta(&conn, blob_id, "java");
    conn.execute(
        "INSERT INTO resolution_fragment_interiors(
               blob_id, lang, semantic_language, producer_epoch, interior_digest, expected_semantic_site_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 'java', 'java', 'resolution-v1', zeroblob(32), 0, 2, 32, 'building')",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "UPDATE resolution_fragment_interiors
             SET publication_state = 'complete' WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();

    for table in MUTABLE_RESOLUTION_INTERIOR_TABLES {
        for event in ["insert", "update", "delete"] {
            let trigger = format!("{table}_no_{event}_after_seal");
            assert_eq!(
                conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                         WHERE type = 'trigger' AND name = ?1",
                    [trigger],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap(),
                0,
                "obsolete durable guard remains for {table} {event}"
            );
        }
    }

    conn.execute("DELETE FROM blobs WHERE id = ?1", [blob_id])
        .unwrap();
    for table in [
        "resolution_fragment_interiors",
        "resolution_reference_lookup_identities",
    ] {
        assert_eq!(
            conn.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE blob_id = ?1"),
                [blob_id],
                |row| row.get::<_, usize>(0),
            )
            .unwrap(),
            0,
            "blob deletion must cascade through {table}"
        );
    }
    validate_foreign_keys(&conn).unwrap();
}

#[test]
fn semantic_language_is_stored_in_the_writer_owned_header() {
    let mut conn = Connection::open_in_memory().unwrap();
    configure_connection(&mut conn).unwrap();
    migrate(&mut conn).unwrap();

    let mut sealed = Vec::new();
    for (label, storage_language, semantic_language) in [
        ("semantic-tsx", "typescript:tsx", "typescript"),
        ("semantic-c", "cpp:c", "cpp"),
    ] {
        let blob_id = insert_reference_enumeration_impact_interior(
            &conn,
            label,
            storage_language,
            semantic_language,
            0,
        );
        seal_resolution_interior(&conn, blob_id).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT lang, semantic_language
                     FROM resolution_fragment_interiors WHERE blob_id = ?1",
                [blob_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap(),
            (storage_language.to_string(), semantic_language.to_string())
        );
        sealed.push(blob_id);
    }

    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'trigger'
               AND name IN (
                 'resolution_fragment_interiors_declared_manifest_is_immutable',
                 'resolution_fragment_interiors_must_start_building',
                 'resolution_fragment_interiors_no_reopen',
                 'resolution_fragment_interiors_require_complete_parent'
               )",
            [],
            |row| row.get::<_, usize>(0),
        )
        .unwrap(),
        0
    );
    conn.execute(
        "DELETE FROM resolution_fragment_interiors WHERE blob_id = ?1",
        [sealed[1]],
    )
    .unwrap();
}

#[test]
fn member_definitions_cannot_publish_two_structural_owners() {
    let mut conn = Connection::open_in_memory().unwrap();
    configure_connection(&mut conn).unwrap();
    migrate(&mut conn).unwrap();
    let oid = seeded_oid("duplicate-member-owner");
    conn.execute(
        "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'rust', 0)",
        [&oid],
    )
    .unwrap();
    let blob_id = conn.last_insert_rowid();
    seed_complete_blob_meta(&conn, blob_id, "rust");
    conn.execute(
        "INSERT INTO resolution_fragment_interiors(
               blob_id, lang, semantic_language, producer_epoch, interior_digest, expected_semantic_site_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 'rust', 'rust', 'resolution-v1', zeroblob(32), 0, 1, 0, 'building')",
        [blob_id],
    )
    .unwrap();
    conn.execute_batch(&format!(
        "INSERT INTO resolution_member_scope_properties(
               blob_id, definition_semantic_key, scope_head_node_key
             ) VALUES
               ({blob_id}, 1, 0),
               ({blob_id}, 2, 1);
             INSERT INTO resolution_member_owner_properties(
               blob_id, definition_semantic_key, owner_definition_semantic_key,
               owner_scope_head_node_key, member_kind, member_access,
               qualifier_compatibility
             ) VALUES(
               {blob_id}, 0, 1, 0, 'field', 'instance', 'runtime_only'
             );"
    ))
    .unwrap();

    let error = conn
        .execute(
            "INSERT INTO resolution_member_owner_properties(
                   blob_id, definition_semantic_key, owner_definition_semantic_key,
                   owner_scope_head_node_key, member_kind, member_access,
                   qualifier_compatibility
                 ) VALUES(?1, 0, 2, 1, 'field', 'instance', 'runtime_only')",
            [blob_id],
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("UNIQUE constraint failed"),
        "unexpected duplicate member-owner result: {error}"
    );
}

#[test]
fn canonical_source_facts_seal_counts_bounds_and_cascade() {
    let mut conn = Connection::open_in_memory().unwrap();
    configure_connection(&mut conn).unwrap();
    migrate(&mut conn).unwrap();

    let blob_id = insert_resolution_test_blob(&conn, "canonical-source-valid", "rust");
    conn.execute(
        "INSERT INTO code_units(
               blob_id, lang, unit_key, kind, short_name, identifier,
               content_qualifier, synthetic, is_type_alias,
               in_declarations, in_definition_lookup
             ) VALUES(?1, 'rust', 0, 0, 'function', 'function',
                      'base', 0, 0, 1, 1)",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes,
               occurrence_count, declaration_count, declaration_unit_count,
               node_count, role_count, occurrence_role_count,
               rust_declaration_property_count,
               logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 12, 20, 4, 1, 1, 2, 1, 1, 1, 9, 13, 'building')",
        [blob_id],
    )
    .unwrap();
    // The arena, in occurrence-id order: [start, end, start_line, end_line,
    // provenance code] with 0 primary_node, 1 explicit_subspan, 2 embedded.
    conn.execute(
        "INSERT INTO source_occurrence_arenas(blob_id, spans)
             VALUES(?1, jsonb('[[0,10,1,1,0],[1,2,1,1,1],[4,8,1,1,2],[5,6,1,1,0]]'))",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_declarations(
               blob_id, declaration_id, occurrence_id, name_occurrence_id,
               start_byte, end_byte, start_line, end_line,
               name_start_byte, name_end_byte, name_start_line, name_end_line,
               provenance)
             SELECT ?1, 0, 0, 1, json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]'), json_extract(arena.spans, '$[0][2]'), json_extract(arena.spans, '$[0][3]'), json_extract(arena.spans, '$[1][0]'), json_extract(arena.spans, '$[1][1]'), json_extract(arena.spans, '$[1][2]'), json_extract(arena.spans, '$[1][3]'), json_extract(arena.spans, '$[0][4]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_declaration_units(blob_id, declaration_id, unit_key)
             VALUES(?1, 0, 0)",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_declaration_properties(
               blob_id, declaration_id, visibility, cfg_condition,
               constructor_non_exhaustive, declaration_kind, macro_exported, trait_impl_member,
               has_impl_or_trait_ancestor, nearest_declaration_boundary
         ) VALUES(?1, 0, 'private', 'always', NULL, 6, 0, 0, 0, 0)",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        // Codes are NormalizedKind declaration ordinals: 0 declaration,
        // 10 call. Spans are inline: the old occurrence 0 is [0,10), 1 is
        // [1,2) and 2 is [4,8). Role code 0 is Role::Callee (the span is the
        // target node's own) and occurrence role code 0 is
        // OccurrenceRole::DeclarationName.
        "INSERT INTO source_structural_facts(blob_id, nodes, roles, occurrence_roles)
         VALUES(?1,
                jsonb('[[0,null,null,0,10,1,2,null,2,null,null,null],
                        [10,null,null,4,8,null,null,0,2,null,null,null]]'),
                jsonb('[[0,0,0,1,4,8,null,null,null,null]]'),
                jsonb('[[0,0]]'))",
        [blob_id],
    )
    .unwrap();

    conn.execute(
        "UPDATE source_fact_manifests
             SET publication_state = 'complete' WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT facts_version, source_bytes, logical_rows, payload_bytes,
                    publication_state
             FROM source_fact_manifests WHERE blob_id = ?1",
            [blob_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .unwrap(),
        (12, 20, 9, 13, "complete".to_owned())
    );
    assert_eq!(
        conn.query_row(
            "SELECT facts_version, source_bytes, node_count,
                    role_count, occurrence_role_count
             FROM structural_source_manifests WHERE blob_id = ?1",
            [blob_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .unwrap(),
        (12, 20, 2, 1, 1)
    );
    assert_eq!(
        conn.query_row(
            "SELECT nodes, roles, occurrence_roles
             FROM structural_source_facts WHERE blob_id = ?1",
            [blob_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .unwrap(),
        (
            "[[0,null,null,0,10,1,2,null,2,null,null,null],\
             [10,null,null,4,8,null,null,0,2,null,null,null]]"
                .to_owned(),
            "[[0,0,0,1,4,8,null,null,null,null]]".to_owned(),
            "[[0,0]]".to_owned(),
        )
    );

    for sql in [
        "INSERT INTO source_occurrence_arenas(blob_id, spans)
             VALUES(?1, jsonb('[[0,1,1,1,0]]'))",
        "UPDATE source_occurrence_arenas SET spans = jsonb('[[0,9,1,1,0]]') WHERE blob_id = ?1",
        "DELETE FROM source_occurrence_arenas WHERE blob_id = ?1",
        "UPDATE source_fact_manifests SET source_bytes = 21 WHERE blob_id = ?1",
        "UPDATE source_fact_manifests SET publication_state = 'building' WHERE blob_id = ?1",
        "DELETE FROM source_fact_manifests WHERE blob_id = ?1",
    ] {
        let error = conn.execute(sql, [blob_id]).unwrap_err();
        assert!(
            error.to_string().contains("sealed source facts")
                || error
                    .to_string()
                    .contains("source fact manifest is immutable")
                || error
                    .to_string()
                    .contains("source facts can only seal once")
                || error
                    .to_string()
                    .contains("source facts are deleted through"),
            "unexpected sealed source-facts mutation result: {error}"
        );
    }

    conn.execute("DELETE FROM blobs WHERE id = ?1", [blob_id])
        .unwrap();
    for table in [
        "source_fact_manifests",
        "source_occurrences",
        "source_declarations",
        "source_declaration_units",
        "source_structural_facts",
    ] {
        assert_eq!(
            conn.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE blob_id = ?1"),
                [blob_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0,
            "blob cascade must remove {table}"
        );
    }
}

fn insert_shared_import_fixture(
    conn: &Connection,
    label: &str,
    module_path: &str,
    exported_name: &str,
) -> i64 {
    let blob_id = insert_resolution_test_blob(conn, label, "rust");
    conn.execute(
        "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes,
               occurrence_count, declaration_count, declaration_unit_count,
               node_count, role_count, occurrence_role_count,
               import_count, import_segment_count, import_scope_count,
               import_prefix_count, logical_rows, payload_bytes, publication_state
         ) VALUES(?1, 12, 20, 2, 0, 0, 0, 0, 0, 1, 2, 0, 0, 6, 41, 'building')",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_occurrence_arenas(blob_id, spans)
             VALUES(?1, jsonb('[[0,17,1,1,0],[11,16,1,1,1]]'))",
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
             SELECT ?1, 0, 'use crate::Thing;', 0, 0, 'Thing', NULL, 'namespace', 0, 1, NULL, json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]'), json_extract(arena.spans, '$[1][0]'), json_extract(arena.spans, '$[1][1]'), NULL, NULL FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_import_segments(
               blob_id, import_id, ordinal, segment
         ) VALUES(?1, 0, 0, 'crate'), (?1, 0, 1, 'Thing')",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO import_statements(blob_id, lang, ordinal, source_import_id, statement, is_wildcard, is_global, identifier, alias, path_kind, declaration_start_byte, binder_start, binder_end, declaration_occurrence_id, binder_occurrence_id, occurrence_declaration_start_byte, occurrence_declaration_end_byte, occurrence_binder_start_byte, occurrence_binder_end_byte)  VALUES(?1, 'rust', 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO rust_import_targets(blob_id, lang, ordinal, source_import_id, module_path, bound_name, imported_name, is_glob, visibility, owner_module, owner_start, owner_end, local_start, local_end, cfg_condition, is_extern_crate, leading_absolute, declaration_occurrence_id, target_occurrence_id, alias_occurrence_id, is_macro_use, declaration_start_byte, declaration_end_byte, target_start_byte, target_end_byte, alias_start_byte, alias_end_byte)  VALUES(?1, 'rust', 0, 0, ?2, 'Thing', NULL, NULL, 'private', 'crate', 0, 17, NULL, NULL, 'always', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
        params![blob_id, module_path],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO rust_exports(
               blob_id, lang, ordinal, source_import_id,
               exported_name, source_path, imported_name, is_glob
         ) VALUES(?1, 'rust', 0, 0, ?2, NULL, NULL, NULL)",
        params![blob_id, exported_name],
    )
    .unwrap();
    blob_id
}

#[test]
fn canonical_shared_import_properties_reject_bad_headers() {
    let conn = open_in_memory_cache();
    for (label, module_path, exported_name, expected) in [
        (
            "shared-import-bad-module",
            "wrong",
            "Thing",
            "shared canonical import projections are inconsistent",
        ),
        (
            "shared-import-bad-export",
            "crate",
            "Wrong",
            "shared canonical import projections are inconsistent",
        ),
    ] {
        let blob_id = insert_shared_import_fixture(&conn, label, module_path, exported_name);
        let error = conn
            .execute(
                "UPDATE source_fact_manifests SET publication_state = 'complete'
                 WHERE blob_id = ?1",
                [blob_id],
            )
            .unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn canonical_shared_import_properties_reject_invalid_source_shapes() {
    let conn = open_in_memory_cache();
    let blob_id = insert_shared_import_fixture(&conn, "import-shape-law", "crate", "Thing");
    for mutation in [
        "UPDATE source_imports SET target_occurrence_id = NULL,
                target_start_byte = NULL, target_end_byte = NULL WHERE blob_id = ?1",
        "UPDATE source_imports SET is_wildcard = 1 WHERE blob_id = ?1",
        "UPDATE source_imports SET alias_occurrence_id = 1,
                alias_start_byte = 1, alias_end_byte = 2 WHERE blob_id = ?1",
        "UPDATE import_statements SET ordinal = 2 WHERE blob_id = ?1",
    ] {
        conn.execute_batch("SAVEPOINT malformed_import").unwrap();
        conn.execute(mutation, [blob_id]).unwrap();
        let error = conn.execute(
            "UPDATE source_fact_manifests SET publication_state = 'complete' WHERE blob_id = ?1",
            [blob_id],
        ).unwrap_err();
        assert!(
            error.to_string().contains("inconsistent"),
            "{mutation}: {error}"
        );
        conn.execute_batch("ROLLBACK TO malformed_import; RELEASE malformed_import")
            .unwrap();
    }
    conn.execute(
        "UPDATE source_fact_manifests SET publication_state = 'complete' WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();
}

#[test]
fn canonical_shared_import_properties_publish_through_all_projection_views() {
    let conn = open_in_memory_cache();
    let blob_id = insert_resolution_test_blob(&conn, "shared-import-properties", "rust");
    conn.execute(
        "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes,
               occurrence_count, declaration_count, declaration_unit_count,
               node_count, role_count, occurrence_role_count,
               import_count, import_segment_count, import_scope_count,
               import_prefix_count, logical_rows, payload_bytes, publication_state
         ) VALUES(?1, 12, 20, 2, 0, 0, 0, 0, 0, 1, 2, 0, 0, 6, 41, 'building')",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_occurrence_arenas(blob_id, spans)\n             VALUES(?1, jsonb('[[0,17,1,1,0],[11,16,1,1,1]]'))",
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
             SELECT ?1, 0, 'use crate::Thing;', 0, 0, 'Thing', NULL, 'namespace', 0, 1, NULL, json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]'), json_extract(arena.spans, '$[1][0]'), json_extract(arena.spans, '$[1][1]'), NULL, NULL FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_import_segments(
               blob_id, import_id, ordinal, segment
         ) VALUES(?1, 0, 0, 'crate'), (?1, 0, 1, 'Thing')",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO import_statements(blob_id, lang, ordinal, source_import_id, statement, is_wildcard, is_global, identifier, alias, path_kind, declaration_start_byte, binder_start, binder_end, declaration_occurrence_id, binder_occurrence_id, occurrence_declaration_start_byte, occurrence_declaration_end_byte, occurrence_binder_start_byte, occurrence_binder_end_byte)  VALUES(?1, 'rust', 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO rust_import_targets(blob_id, lang, ordinal, source_import_id, module_path, bound_name, imported_name, is_glob, visibility, owner_module, owner_start, owner_end, local_start, local_end, cfg_condition, is_extern_crate, leading_absolute, declaration_occurrence_id, target_occurrence_id, alias_occurrence_id, is_macro_use, declaration_start_byte, declaration_end_byte, target_start_byte, target_end_byte, alias_start_byte, alias_end_byte)  VALUES(?1, 'rust', 0, 0, 'crate', 'Thing', NULL, NULL, 'private', 'crate', 0, 17, NULL, NULL, 'always', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO rust_exports(
               blob_id, lang, ordinal, source_import_id,
               exported_name, source_path, imported_name, is_glob
         ) VALUES(?1, 'rust', 0, 0, 'Thing', NULL, NULL, NULL)",
        [blob_id],
    )
    .unwrap();

    conn.execute(
        "UPDATE source_fact_manifests SET publication_state = 'complete'
         WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT statement, identifier, declaration_start_byte,
                    binder_start, binder_end
             FROM source_import_statements WHERE blob_id = ?1",
            [blob_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .unwrap(),
        (
            "use crate::Thing;".to_owned(),
            "Thing".to_owned(),
            0,
            11,
            16
        )
    );
    assert_eq!(
        conn.query_row(
            "SELECT module_path, bound_name, imported_name, is_glob,
                    leading_absolute, source_import_id
             FROM source_rust_import_targets WHERE blob_id = ?1",
            [blob_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .unwrap(),
        (
            "crate".to_owned(),
            "Thing".to_owned(),
            "Thing".to_owned(),
            0,
            0,
            0,
        )
    );
    assert_eq!(
        conn.query_row(
            "SELECT exported_name, source_path, imported_name, is_glob,
                    source_import_id
             FROM source_rust_exports WHERE blob_id = ?1",
            [blob_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .unwrap(),
        (
            "Thing".to_owned(),
            "crate".to_owned(),
            "Thing".to_owned(),
            0,
            0,
        )
    );
    assert_eq!(
        conn.query_row(
            "SELECT GROUP_CONCAT(segment, '::' ORDER BY seg_ordinal)
             FROM source_import_path_segments WHERE blob_id = ?1",
            [blob_id],
            |row| row.get::<_, String>(0),
        )
        .unwrap(),
        "crate::Thing"
    );

    let error = conn
        .execute(
            "UPDATE source_imports SET alias = 'Other'
             WHERE blob_id = ?1 AND import_id = 0",
            [blob_id],
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("sealed source facts are immutable")
    );
    conn.execute("DELETE FROM blobs WHERE id = ?1", [blob_id])
        .unwrap();
    for table in [
        "source_imports",
        "source_import_segments",
        "import_statements",
        "rust_import_targets",
        "rust_exports",
    ] {
        assert_eq!(
            conn.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE blob_id = ?1"),
                [blob_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0,
            "blob cascade must remove {table}"
        );
    }
}

fn insert_rust_declaration_property_fixture(
    conn: &Connection,
    label: &str,
    properties: &[(i64, &str, &str, Option<i64>)],
    fields: &[(i64, i64, &str)],
) -> i64 {
    let blob_id = insert_resolution_test_blob(conn, label, "rust");
    for unit_key in [0_i64, 1] {
        conn.execute(
            "INSERT INTO code_units(
                   blob_id, lang, unit_key, kind, short_name, identifier,
                   content_qualifier, synthetic, is_type_alias,
                   in_declarations, in_definition_lookup
             ) VALUES(?1, 'rust', ?2, 0, ?3, ?3,
                      'base', 0, 0, 1, 1)",
            params![blob_id, unit_key, format!("unit_{unit_key}")],
        )
        .unwrap();
    }

    let property_count = properties.len() as i64;
    let field_count = fields.len() as i64;
    let logical_rows = 1 + 4 + 2 + 3 + property_count + field_count;
    // The arena holds a one-byte provenance code, so no occurrence text counts.
    let payload_bytes = properties
        .iter()
        .map(|(_, visibility, cfg_condition, _)| (visibility.len() + cfg_condition.len()) as i64)
        .sum::<i64>()
        + fields
            .iter()
            .map(|(_, _, visibility)| visibility.len() as i64)
            .sum::<i64>();
    conn.execute(
        "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes,
               occurrence_count, declaration_count, declaration_unit_count,
               node_count, role_count, occurrence_role_count,
               rust_declaration_property_count, rust_constructor_field_count,
               logical_rows, payload_bytes, publication_state
         ) VALUES(?1, 12, 20, 4, 2, 3, 0, 0, 0, ?2, ?3, ?4, ?5, 'building')",
        params![
            blob_id,
            property_count,
            field_count,
            logical_rows,
            payload_bytes,
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_occurrence_arenas(blob_id, spans)\n             VALUES(?1, jsonb('[[0,10,1,1,0],[1,2,1,1,0],[10,20,1,1,0],[11,13,1,1,0]]'))",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_declarations(
               blob_id, declaration_id, occurrence_id, name_occurrence_id,
               start_byte, end_byte, start_line, end_line,
               name_start_byte, name_end_byte, name_start_line, name_end_line,
               provenance)
             SELECT ?1, 0, 0, 1, json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]'), json_extract(arena.spans, '$[0][2]'), json_extract(arena.spans, '$[0][3]'), json_extract(arena.spans, '$[1][0]'), json_extract(arena.spans, '$[1][1]'), json_extract(arena.spans, '$[1][2]'), json_extract(arena.spans, '$[1][3]'), json_extract(arena.spans, '$[0][4]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1
             UNION ALL SELECT ?1, 1, 2, 3, json_extract(arena.spans, '$[2][0]'), json_extract(arena.spans, '$[2][1]'), json_extract(arena.spans, '$[2][2]'), json_extract(arena.spans, '$[2][3]'), json_extract(arena.spans, '$[3][0]'), json_extract(arena.spans, '$[3][1]'), json_extract(arena.spans, '$[3][2]'), json_extract(arena.spans, '$[3][3]'), json_extract(arena.spans, '$[2][4]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_declaration_units(blob_id, declaration_id, unit_key)
         VALUES(?1, 0, 0), (?1, 1, 0), (?1, 1, 1)",
        [blob_id],
    )
    .unwrap();
    for &(declaration_id, visibility, cfg_condition, constructor_non_exhaustive) in properties {
        conn.execute(
            "INSERT INTO source_rust_declaration_properties(
                   blob_id, declaration_id, visibility, cfg_condition,
                   constructor_non_exhaustive, declaration_kind, macro_exported, trait_impl_member,
                   has_impl_or_trait_ancestor, nearest_declaration_boundary
             ) VALUES(?1, ?2, ?3, ?4, ?5, 0, 0, 0, 0, 0)",
            params![
                blob_id,
                declaration_id,
                visibility,
                cfg_condition,
                constructor_non_exhaustive,
            ],
        )
        .unwrap();
    }
    for &(declaration_id, ordinal, visibility) in fields {
        conn.execute(
            "INSERT INTO source_rust_constructor_fields(
                   blob_id, declaration_id, ordinal, visibility
             ) VALUES(?1, ?2, ?3, ?4)",
            params![blob_id, declaration_id, ordinal, visibility],
        )
        .unwrap();
    }
    blob_id
}

fn valid_rust_declaration_properties() -> [(i64, &'static str, &'static str, Option<i64>); 2] {
    [
        (0, "private", "always", None),
        (1, "pub", "cfg(test)", Some(1)),
    ]
}

fn valid_rust_constructor_fields() -> [(i64, i64, &'static str); 2] {
    [(1, 0, "pub"), (1, 1, "private")]
}

#[test]
fn rust_declaration_boundaries_require_complete_consistent_ancestry() {
    let conn = open_in_memory_cache();
    for (index, corruption) in [
        "has_impl_or_trait_ancestor = NULL",
        "nearest_declaration_boundary = NULL",
        "nearest_declaration_boundary = 2",
        "nearest_declaration_boundary = 3",
        "trait_impl_member = 1",
    ]
    .into_iter()
    .enumerate()
    {
        let blob_id = insert_rust_declaration_property_fixture(
            &conn,
            &format!("boundary-invalid-{index}"),
            &valid_rust_declaration_properties(),
            &valid_rust_constructor_fields(),
        );
        conn.execute(
            &format!("UPDATE source_rust_declaration_properties SET {corruption} WHERE blob_id = ?1 AND declaration_id = 0"),
            [blob_id],
        ).unwrap();
        let error = conn.execute(
            "UPDATE source_fact_manifests SET publication_state = 'complete' WHERE blob_id = ?1",
            [blob_id],
        ).unwrap_err();
        assert!(
            error.to_string().contains("Rust declaration boundaries"),
            "{corruption}: {error}"
        );
    }
    for boundary in 0..=3 {
        let blob_id = insert_rust_declaration_property_fixture(
            &conn,
            &format!("boundary-valid-{boundary}"),
            &valid_rust_declaration_properties(),
            &valid_rust_constructor_fields(),
        );
        // A trait impl can remain an ancestor beyond a nearer block or module.
        conn.execute(
            "UPDATE source_rust_declaration_properties
             SET has_impl_or_trait_ancestor = 1, nearest_declaration_boundary = ?2,
                 trait_impl_member = 1 WHERE blob_id = ?1",
            params![blob_id, boundary],
        )
        .unwrap();
        conn.execute(
            "UPDATE source_fact_manifests SET publication_state = 'complete' WHERE blob_id = ?1",
            [blob_id],
        )
        .unwrap();
        let error = conn.execute(
            "UPDATE source_rust_declaration_properties SET nearest_declaration_boundary = 0 WHERE blob_id = ?1",
            [blob_id],
        ).unwrap_err();
        assert!(error.to_string().contains("immutable"), "{error}");
    }
}

#[test]
fn rust_classification_and_macro_links_are_validated_at_sealing() {
    for mutation in [
        "UPDATE source_rust_declaration_properties SET declaration_kind = NULL WHERE declaration_id = 0",
        "UPDATE source_rust_declaration_properties SET macro_exported = NULL WHERE declaration_id = 0",
        "UPDATE source_rust_declaration_properties SET trait_impl_member = NULL WHERE declaration_id = 0",
        "UPDATE source_rust_declaration_properties SET macro_exported = 1 WHERE declaration_id = 0",
        "UPDATE source_rust_declaration_properties SET declaration_kind = 6 WHERE declaration_id = 1",
        "INSERT INTO source_rust_item_macros(
            blob_id, lang, ordinal, macro_name, passthrough, arguments_only, decoration_cfg, declaration_id
         ) VALUES(1, 'rust', 0, 'm', 0, 0, NULL, NULL)",
        "INSERT INTO source_rust_item_macros(
            blob_id, lang, ordinal, macro_name, passthrough, arguments_only, decoration_cfg, declaration_id
         ) VALUES(1, 'rust', 0, 'm', 0, 0, NULL, 0)",
    ] {
        let mut conn = Connection::open_in_memory().unwrap();
        configure_connection(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        let blob_id = insert_rust_declaration_property_fixture(
            &conn,
            "classification-invalid",
            &valid_rust_declaration_properties(),
            &valid_rust_constructor_fields(),
        );
        assert_eq!(blob_id, 1);
        conn.execute(mutation, []).unwrap();
        let error = conn.execute(
            "UPDATE source_fact_manifests SET publication_state = 'complete' WHERE blob_id = ?1",
            [blob_id],
        ).unwrap_err();
        assert!(
            error.to_string().contains("classification is inconsistent"),
            "{mutation}: {error}"
        );
    }
}

#[test]
fn rust_macro_projection_uses_sealed_same_blob_declaration_authority() {
    let mut conn = Connection::open_in_memory().unwrap();
    configure_connection(&mut conn).unwrap();
    migrate(&mut conn).unwrap();
    let blob_id = insert_rust_declaration_property_fixture(
        &conn,
        "classification-valid",
        &valid_rust_declaration_properties(),
        &valid_rust_constructor_fields(),
    );
    conn.execute(
        "UPDATE source_rust_declaration_properties SET declaration_kind = 12, macro_exported = 1
         WHERE blob_id = ?1 AND declaration_id = 0",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_item_macros(
            blob_id, lang, ordinal, macro_name, passthrough, arguments_only, decoration_cfg, declaration_id
         ) VALUES(?1, 'rust', 0, 'm', 0, 0, NULL, 0)",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "UPDATE source_fact_manifests SET publication_state = 'complete' WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT declaration_id, exported FROM rust_item_macros WHERE blob_id = ?1",
            [blob_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?)),
        )
        .unwrap(),
        (0, true)
    );
    for mutation in [
        "UPDATE source_rust_item_macros SET declaration_id = 1 WHERE blob_id = ?1",
        "DELETE FROM source_rust_item_macros WHERE blob_id = ?1",
        "INSERT INTO source_rust_item_macros(
            blob_id, lang, ordinal, macro_name, passthrough, arguments_only, decoration_cfg, declaration_id
         ) VALUES(?1, 'rust', 1, 'm', 0, 0, NULL, 0)",
        "UPDATE source_rust_declaration_properties SET macro_exported = 0 WHERE blob_id = ?1",
    ] {
        let error = conn.execute(mutation, [blob_id]).unwrap_err();
        assert!(
            error.to_string().contains("sealed source facts"),
            "{mutation}: {error}"
        );
    }
    let other = insert_resolution_test_blob(&conn, "classification-other", "rust");
    assert!(
        conn.execute(
            "INSERT INTO source_rust_item_macros(
                blob_id, lang, ordinal, macro_name, passthrough, arguments_only, decoration_cfg, declaration_id
             ) VALUES(?1, 'rust', 0, 'm', 0, 0, NULL, 0)",
            [other],
        )
        .unwrap_err()
        .to_string()
        .contains("FOREIGN KEY")
    );
    conn.execute("DELETE FROM blobs WHERE id = ?1", [blob_id])
        .unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM source_rust_item_macros", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
}

#[test]
fn rust_declaration_properties_require_same_blob_named_declarations() {
    let conn = open_in_memory_cache();
    let foreign = insert_rust_declaration_property_fixture(
        &conn,
        "prop-foreign",
        &valid_rust_declaration_properties(),
        &valid_rust_constructor_fields(),
    );
    let target = insert_resolution_test_blob(&conn, "prop-target", "rust");
    conn.execute(
        "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes,
               occurrence_count, declaration_count, declaration_unit_count,
               node_count, role_count, occurrence_role_count,
               logical_rows, payload_bytes, publication_state
         ) VALUES(?1, 12, 0, 0, 0, 0, 0, 0, 0, 1, 0, 'building')",
        [target],
    )
    .unwrap();
    let error = conn
        .execute(
            "INSERT INTO source_rust_declaration_properties(
                   blob_id, declaration_id, visibility, cfg_condition,
                   constructor_non_exhaustive
             ) VALUES(?1, 0, 'private', 'always', NULL)",
            [target],
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("FOREIGN KEY constraint failed"),
        "property row borrowed a declaration from another blob ({foreign}): {error}"
    );

    let unnamed = insert_rust_declaration_property_fixture(
        &conn,
        "prop-unnamed",
        &valid_rust_declaration_properties(),
        &valid_rust_constructor_fields(),
    );
    conn.execute(
        "UPDATE source_declarations SET name_occurrence_id = NULL,
                name_start_byte = NULL, name_end_byte = NULL,
                name_start_line = NULL, name_end_line = NULL
         WHERE blob_id = ?1 AND declaration_id = 0",
        [unnamed],
    )
    .unwrap();
    let error = conn
        .execute(
            "UPDATE source_fact_manifests SET publication_state = 'complete'
             WHERE blob_id = ?1",
            [unnamed],
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("canonical Rust declaration properties are inconsistent"),
        "unnamed declaration reached canonical property publication: {error}"
    );
}

#[test]
fn rust_declaration_properties_cover_units_and_require_dense_constructor_fields() {
    let conn = open_in_memory_cache();
    let missing = insert_rust_declaration_property_fixture(
        &conn,
        "prop-missing-unit",
        &[(0, "private", "always", None)],
        &[],
    );
    let error = conn
        .execute(
            "UPDATE source_fact_manifests SET publication_state = 'complete'
             WHERE blob_id = ?1",
            [missing],
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("canonical Rust declaration properties are inconsistent"),
        "a Rust declaration unit without a property reached publication: {error}"
    );

    let no_constructor = insert_rust_declaration_property_fixture(
        &conn,
        "prop-no-constructor",
        &[
            (0, "private", "always", None),
            (1, "pub", "cfg(test)", None),
        ],
        &valid_rust_constructor_fields(),
    );
    let error = conn
        .execute(
            "UPDATE source_fact_manifests SET publication_state = 'complete'
             WHERE blob_id = ?1",
            [no_constructor],
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("canonical Rust declaration properties are inconsistent"),
        "constructor fields without a constructor reached publication: {error}"
    );

    let sparse = insert_rust_declaration_property_fixture(
        &conn,
        "prop-sparse-fields",
        &valid_rust_declaration_properties(),
        &[(1, 0, "pub"), (1, 2, "private")],
    );
    let error = conn
        .execute(
            "UPDATE source_fact_manifests SET publication_state = 'complete'
             WHERE blob_id = ?1",
            [sparse],
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("canonical Rust declaration properties are inconsistent"),
        "sparse constructor field ordinals reached publication: {error}"
    );
}

#[test]
fn rust_declaration_properties_are_immutable_after_seal_and_cascade() {
    let conn = open_in_memory_cache();
    let blob_id = insert_rust_declaration_property_fixture(
        &conn,
        "prop-sealed",
        &valid_rust_declaration_properties(),
        &valid_rust_constructor_fields(),
    );
    conn.execute(
        "UPDATE source_fact_manifests SET publication_state = 'complete'
         WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    for sql in [
        "INSERT INTO source_rust_declaration_properties(
             blob_id, declaration_id, visibility, cfg_condition,
             constructor_non_exhaustive
           ) VALUES(?1, 0, 'private', 'always', NULL)",
        "UPDATE source_rust_declaration_properties SET visibility = 'pub'
         WHERE blob_id = ?1 AND declaration_id = 0",
        "DELETE FROM source_rust_declaration_properties
         WHERE blob_id = ?1 AND declaration_id = 0",
        "INSERT INTO source_rust_constructor_fields(
             blob_id, declaration_id, ordinal, visibility
           ) VALUES(?1, 1, 0, 'pub')",
        "UPDATE source_rust_constructor_fields SET visibility = 'private'
         WHERE blob_id = ?1 AND declaration_id = 1 AND ordinal = 0",
        "DELETE FROM source_rust_constructor_fields
         WHERE blob_id = ?1 AND declaration_id = 1 AND ordinal = 0",
        "UPDATE source_fact_manifests
         SET rust_declaration_property_count = 1 WHERE blob_id = ?1",
        "UPDATE source_fact_manifests SET payload_bytes = 85 WHERE blob_id = ?1",
    ] {
        let error = conn.execute(sql, [blob_id]).unwrap_err();
        assert!(
            error.to_string().contains("sealed source facts")
                || error
                    .to_string()
                    .contains("source fact manifest is immutable"),
            "sealed declaration-property mutation was accepted: {sql}: {error}"
        );
    }

    conn.execute("DELETE FROM blobs WHERE id = ?1", [blob_id])
        .unwrap();
    for table in [
        "source_rust_declaration_properties",
        "source_rust_constructor_fields",
    ] {
        assert_eq!(
            conn.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE blob_id = ?1"),
                [blob_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0,
            "blob deletion must cascade {table}"
        );
    }
}

fn insert_rust_import_context_fixture(
    conn: &Connection,
    label: &str,
    owner_scope: (i64, i64),
    local_scope: (i64, i64),
) -> i64 {
    let blob_id = insert_resolution_test_blob(conn, label, "rust");
    conn.execute(
        "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes,
               occurrence_count, declaration_count, declaration_unit_count,
               node_count, role_count, occurrence_role_count,
               import_count, import_segment_count, import_scope_count,
               import_prefix_count, rust_import_context_count,
               logical_rows, payload_bytes, publication_state
         ) VALUES(?1, 12, 40, 4, 0, 0, 0, 0, 0, 1, 2, 0, 0, 1, 9, 58, 'building')",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_occurrence_arenas(blob_id, spans)\n             VALUES(?1, jsonb('[' || '[10,20,1,1,0],[15,18,1,1,0],[' || ?2 || ',' || ?3 || ',1,1,0],[' || ?4 || ',' || ?5 || ',1,1,0]' || ']'))",
        params![
            blob_id,
            owner_scope.0,
            owner_scope.1,
            local_scope.0,
            local_scope.1
        ],
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
             SELECT ?1, 0, 'use crate::Thing;', 0, 0, 'Thing', NULL, 'namespace', 0, 1, NULL, json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]'), json_extract(arena.spans, '$[1][0]'), json_extract(arena.spans, '$[1][1]'), NULL, NULL FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_import_segments(blob_id, import_id, ordinal, segment)
         VALUES(?1, 0, 0, 'crate'), (?1, 0, 1, 'Thing')",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_import_contexts(
               blob_id, declaration_occurrence_id, owner_module,
               owner_scope_occurrence_id, local_scope_occurrence_id,
               visibility, cfg_condition,
               owner_scope_start_byte, owner_scope_end_byte,
               local_scope_start_byte, local_scope_end_byte, declaration_start_byte, declaration_end_byte)
             SELECT ?1, 0, 'crate::m', 2, 3, 'pub', 'always', json_extract(arena.spans, '$[2][0]'), json_extract(arena.spans, '$[2][1]'), json_extract(arena.spans, '$[3][0]'), json_extract(arena.spans, '$[3][1]'), json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO rust_import_targets(blob_id, lang, ordinal, source_import_id, source_context_occurrence_id, module_path, bound_name, imported_name, is_glob, visibility, owner_module, owner_start, owner_end, local_start, local_end, cfg_condition, is_extern_crate, leading_absolute, is_macro_use)  VALUES(?1, 'rust', 0, 0, 0, 'crate', 'Thing', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
        [blob_id],
    )
    .unwrap();
    blob_id
}

#[test]
fn rust_import_contexts_publish_owner_ranges_and_seal() {
    let conn = open_in_memory_cache();
    let blob_id = insert_resolution_test_blob(&conn, "rust-context-publish", "rust");
    conn.execute(
        "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes,
               occurrence_count, declaration_count, declaration_unit_count,
               node_count, role_count, occurrence_role_count,
               import_count, import_segment_count, import_scope_count,
               import_prefix_count, rust_import_context_count,
               logical_rows, payload_bytes, publication_state
         ) VALUES(?1, 12, 40, 4, 0, 0, 0, 0, 0, 1, 2, 0, 0, 1, 9, 58, 'building')",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_occurrence_arenas(blob_id, spans)\n             VALUES(?1, jsonb('[[10,20,1,1,0],[15,18,1,1,0],[0,30,1,1,0],[0,40,1,1,0]]'))",
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
             SELECT ?1, 0, 'use crate::Thing;', 0, 0, 'Thing', NULL, 'namespace', 0, 1, NULL, json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]'), json_extract(arena.spans, '$[1][0]'), json_extract(arena.spans, '$[1][1]'), NULL, NULL FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_import_segments(
               blob_id, import_id, ordinal, segment
         ) VALUES(?1, 0, 0, 'crate'), (?1, 0, 1, 'Thing')",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_import_contexts(
               blob_id, declaration_occurrence_id, owner_module,
               owner_scope_occurrence_id, local_scope_occurrence_id,
               visibility, cfg_condition,
               owner_scope_start_byte, owner_scope_end_byte,
               local_scope_start_byte, local_scope_end_byte, declaration_start_byte, declaration_end_byte)
             SELECT ?1, 0, 'crate::m', 2, 3, 'pub', 'always', json_extract(arena.spans, '$[2][0]'), json_extract(arena.spans, '$[2][1]'), json_extract(arena.spans, '$[3][0]'), json_extract(arena.spans, '$[3][1]'), json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    let declaration_join_plan = query_plan(
        &conn,
        &format!(
            "SELECT context.declaration_occurrence_id
             FROM source_rust_import_contexts AS context
             LEFT JOIN source_imports AS source
               ON source.blob_id = context.blob_id
              AND source.declaration_occurrence_id = context.declaration_occurrence_id
             WHERE context.blob_id = {blob_id}"
        ),
    );
    assert!(
        declaration_join_plan
            .iter()
            .any(|detail| detail.contains("idx_source_imports_declaration")),
        "context declaration joins must use the declaration index: {declaration_join_plan:?}"
    );
    conn.execute(
        "INSERT INTO rust_import_targets(blob_id, lang, ordinal, source_import_id, source_context_occurrence_id, module_path, bound_name, imported_name, is_glob, visibility, owner_module, owner_start, owner_end, local_start, local_end, cfg_condition, is_extern_crate, leading_absolute, is_macro_use)  VALUES(?1, 'rust', 0, 0, 0, 'crate', 'Thing', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "UPDATE source_fact_manifests SET publication_state = 'complete'
         WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();

    assert_eq!(
        conn.query_row(
            "SELECT owner_module, owner_start, owner_end, local_start,
                    local_end, visibility, cfg_condition
             FROM source_rust_import_targets WHERE blob_id = ?1",
            [blob_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .unwrap(),
        (
            "crate::m".to_owned(),
            0,
            30,
            0,
            40,
            "pub".to_owned(),
            "always".to_owned(),
        )
    );

    let error = conn
        .execute(
            "UPDATE source_rust_import_contexts SET visibility = 'private'
             WHERE blob_id = ?1 AND declaration_occurrence_id = 0",
            [blob_id],
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("sealed source facts are immutable")
    );

    conn.execute("DELETE FROM blobs WHERE id = ?1", [blob_id])
        .unwrap();
    for table in ["source_rust_import_contexts", "rust_import_targets"] {
        assert_eq!(
            conn.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE blob_id = ?1"),
                [blob_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0,
            "blob cascade must remove {table}"
        );
    }
}

#[test]
fn rust_import_contexts_reject_target_link_to_different_declaration() {
    let conn = open_in_memory_cache();
    let blob_id = insert_resolution_test_blob(&conn, "rust-context-link-mismatch", "rust");
    conn.execute(
        "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes,
               occurrence_count, declaration_count, declaration_unit_count,
               node_count, role_count, occurrence_role_count,
               import_count, import_segment_count, import_scope_count,
               import_prefix_count, rust_import_context_count,
               logical_rows, payload_bytes, publication_state
         ) VALUES(?1, 12, 40, 5, 0, 0, 0, 0, 0, 2, 4, 0, 0, 1, 13, 87, 'building')",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_occurrence_arenas(blob_id, spans)\n             VALUES(?1, jsonb('[[10,20,1,1,0],[10,20,1,1,0],[15,18,1,1,0],[0,30,1,1,0],[0,40,1,1,0]]'))",
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
             SELECT ?1, 0, 'use crate::Thing;', 0, 0, 'Thing', NULL, 'namespace', 0, 2, NULL, json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]'), json_extract(arena.spans, '$[2][0]'), json_extract(arena.spans, '$[2][1]'), NULL, NULL FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1
             UNION ALL SELECT ?1, 1, 'use crate::Other;', 0, 0, 'Other', NULL, 'namespace', 1, 2, NULL, json_extract(arena.spans, '$[1][0]'), json_extract(arena.spans, '$[1][1]'), json_extract(arena.spans, '$[2][0]'), json_extract(arena.spans, '$[2][1]'), NULL, NULL FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_import_segments(blob_id, import_id, ordinal, segment)
         VALUES(?1, 0, 0, 'crate'), (?1, 0, 1, 'Thing'),
                (?1, 1, 0, 'crate'), (?1, 1, 1, 'Other')",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_import_contexts(
               blob_id, declaration_occurrence_id, owner_module,
               owner_scope_occurrence_id, local_scope_occurrence_id,
               visibility, cfg_condition,
               owner_scope_start_byte, owner_scope_end_byte,
               local_scope_start_byte, local_scope_end_byte, declaration_start_byte, declaration_end_byte)
             SELECT ?1, 1, 'crate::m', 3, 4, 'pub', 'always', json_extract(arena.spans, '$[3][0]'), json_extract(arena.spans, '$[3][1]'), json_extract(arena.spans, '$[4][0]'), json_extract(arena.spans, '$[4][1]'), json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO rust_import_targets(blob_id, lang, ordinal, source_import_id, source_context_occurrence_id, module_path, bound_name, imported_name, is_glob, visibility, owner_module, owner_start, owner_end, local_start, local_end, cfg_condition, is_extern_crate, leading_absolute, is_macro_use)  VALUES(?1, 'rust', 0, 0, 1, 'crate', 'Thing', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
        [blob_id],
    )
    .unwrap();

    let error = conn
        .execute(
            "UPDATE source_fact_manifests SET publication_state = 'complete'
             WHERE blob_id = ?1",
            [blob_id],
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Rust import contexts are inconsistent"),
        "mismatched source/context declaration reached publication: {error}"
    );
}

#[test]
fn rust_import_contexts_reject_crossing_scopes_at_seal() {
    let conn = open_in_memory_cache();
    let blob_id = insert_resolution_test_blob(&conn, "rust-context-crossing", "rust");
    conn.execute(
        "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes,
               occurrence_count, declaration_count, declaration_unit_count,
               node_count, role_count, occurrence_role_count,
               import_count, import_segment_count, import_scope_count,
               import_prefix_count, rust_import_context_count,
               logical_rows, payload_bytes, publication_state
         ) VALUES(?1, 12, 40, 4, 0, 0, 0, 0, 0, 1, 2, 0, 0, 1, 9, 58, 'building')",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_occurrence_arenas(blob_id, spans)\n             VALUES(?1, jsonb('[[10,20,1,1,0],[15,18,1,1,0],[0,25,1,1,0],[5,40,1,1,0]]'))",
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
             SELECT ?1, 0, 'use crate::Thing;', 0, 0, 'Thing', NULL, 'namespace', 0, 1, NULL, json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]'), json_extract(arena.spans, '$[1][0]'), json_extract(arena.spans, '$[1][1]'), NULL, NULL FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_import_segments(blob_id, import_id, ordinal, segment)
         VALUES(?1, 0, 0, 'crate'), (?1, 0, 1, 'Thing')",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_rust_import_contexts(
               blob_id, declaration_occurrence_id, owner_module,
               owner_scope_occurrence_id, local_scope_occurrence_id,
               visibility, cfg_condition,
               owner_scope_start_byte, owner_scope_end_byte,
               local_scope_start_byte, local_scope_end_byte, declaration_start_byte, declaration_end_byte)
             SELECT ?1, 0, 'crate::m', 2, 3, 'pub', 'always', json_extract(arena.spans, '$[2][0]'), json_extract(arena.spans, '$[2][1]'), json_extract(arena.spans, '$[3][0]'), json_extract(arena.spans, '$[3][1]'), json_extract(arena.spans, '$[0][0]'), json_extract(arena.spans, '$[0][1]') FROM source_occurrence_arenas AS arena WHERE arena.blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    let error = conn
        .execute(
            "UPDATE source_fact_manifests SET publication_state = 'complete'
             WHERE blob_id = ?1",
            [blob_id],
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Rust import contexts are inconsistent")
    );
}

#[test]
fn rust_import_contexts_accept_nested_scopes_in_either_direction() {
    let conn = open_in_memory_cache();
    for (label, owner_scope, local_scope, expected_ranges) in [
        ("rust-context-owner-outer", (0, 40), (0, 30), (0, 40, 0, 30)),
        ("rust-context-local-outer", (0, 30), (0, 40), (0, 30, 0, 40)),
    ] {
        let blob_id = insert_rust_import_context_fixture(&conn, label, owner_scope, local_scope);
        conn.execute(
            "UPDATE source_fact_manifests SET publication_state = 'complete'
             WHERE blob_id = ?1",
            [blob_id],
        )
        .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT owner_start, owner_end, local_start, local_end
                 FROM source_rust_import_targets WHERE blob_id = ?1",
                [blob_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .unwrap(),
            expected_ranges
        );
    }
}

#[test]
fn root_prefix_seal_rejects_preseal_corruption_with_bounded_vm_growth() {
    for state in crate::cache_gc::PlannerStatisticsState::BOTH {
        let conn = open_in_memory_cache();
        let mut work = Vec::new();
        for length in [16, 64, 256, 1024, 4096] {
            let blob = insert_reference_enumeration_impact_interior(
                &conn,
                &format!("root-prefix-{length}"),
                "rust",
                "rust",
                0,
            );
            let symbols = (0..length).collect::<Vec<_>>();
            let body = serde_json::json!([[], null, [], null, symbols, null, [], null, [], [], []])
                .to_string();
            let key = serde_json::Value::Array(
                (0..length)
                    .map(|id| serde_json::json!([id, null, 0]))
                    .collect(),
            )
            .to_string();
            let insert = "INSERT INTO resolution_paths(blob_id,path,start_node,start_lead_scoped,end_node,end_lead_scoped,body,end_fixed_key,end_open_tail) VALUES(?1,0,-1,0,-1,0,jsonb(?2),?3,0)";
            conn.execute(insert, params![blob, body, key]).unwrap();
            state.install(&conn);
            // A same-length, validly shaped replacement must not evade the seal.
            conn.execute("UPDATE resolution_paths SET end_fixed_key = json_set(end_fixed_key, '$[0][0]', 9000) WHERE blob_id=?1", [blob]).unwrap();
            let error = seal_resolution_interior(&conn, blob).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("resolution root prefix key is inconsistent"),
                "{error}"
            );
            conn.execute(
                "UPDATE resolution_paths SET end_fixed_key=?2 WHERE blob_id=?1",
                params![blob, key],
            )
            .unwrap();
            let mut seal = conn.prepare("UPDATE resolution_fragment_interiors SET publication_state='complete' WHERE blob_id=?1").unwrap();
            seal.execute([blob]).unwrap();
            let steps = seal.get_status(rusqlite::StatementStatus::VmStep);
            work.push((length, steps));
            assert!(
                steps < length * 200 + 10000,
                "{state}: seal VM growth must be bounded: {work:?}"
            );
        }
        eprintln!("root prefix bundled SQLite {state} seal VM work: {work:?}");
    }
}

#[test]
fn root_prefix_seal_accepts_nested_scoped_shared_and_empty_open_endpoints() {
    for state in crate::cache_gc::PlannerStatisticsState::BOTH {
        let conn = open_in_memory_cache();
        for (index, (symbols, tail, key, open)) in [
            ("[]", "null", "[]", 0),
            ("[]", "7", "[]", 1),
            (
                "[3,-2000000000]",
                "null",
                "[[3,null,0],[null,2000000000,0]]",
                0,
            ),
            (
                "[[3,[4,5],null],[-2000000000,[],8]]",
                "9",
                "[[3,null,1],[null,2000000000,1]]",
                1,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let blob = insert_reference_enumeration_impact_interior(
                &conn,
                &format!("{index}-root-prefix-positive"),
                "rust",
                "rust",
                0,
            );
            let body = format!("[[],null,[],null,{symbols},{tail},[],null,[],[],[]]");
            conn.execute(
                "INSERT INTO resolution_paths(blob_id,path,start_node,start_lead_scoped,
                end_node,end_lead_scoped,body,end_fixed_key,end_open_tail)
                VALUES(?1,0,-1,0,-1,0,jsonb(?2),?3,?4)",
                params![blob, body, key, open],
            )
            .unwrap();
            state.install(&conn);
            seal_resolution_interior(&conn, blob).unwrap();
            assert_eq!(
                conn.query_row(
                    "SELECT publication_state FROM resolution_fragment_interiors WHERE blob_id=?1",
                    [blob],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
                "complete",
                "state={state}, body={body}, key={key}, open={open}"
            );
        }
    }
}

#[test]
fn root_prefix_columns_enforce_root_shape_tail_and_identity_spaces() {
    for state in crate::cache_gc::PlannerStatisticsState::BOTH {
        let conn = open_in_memory_cache();
        let blob = insert_reference_enumeration_impact_interior(
            &conn,
            "root-prefix-shape",
            "rust",
            "rust",
            0,
        );
        let empty_body = "[[],null,[],null,[],null,[],null,[],[],[]]";
        let insert = "INSERT INTO resolution_paths(blob_id,path,start_node,start_lead_scoped,end_node,end_lead_scoped,body,end_fixed_key,end_open_tail) VALUES(?1,0,-1,0,?2,0,jsonb(?3),?4,?5)";
        for (node, key, tail, body) in [
            (-1, None, None, empty_body),
            (0, Some("[]"), Some(0), empty_body),
            (-1, Some("{}"), Some(0), empty_body),
            (-1, Some("[]"), None, empty_body),
            (-1, Some("[]"), Some(2), empty_body),
            (-1, Some("[[]]"), Some(0), empty_body),
            (-1, Some("[]"), Some(0), "[]"),
            (-1, Some("[]"), Some(1), empty_body),
        ] {
            assert!(
                conn.execute(insert, params![blob, node, body, key, tail])
                    .is_err(),
                "accepted node={node}, key={key:?}, tail={tail:?}, body={body}"
            );
        }
        conn.execute(
            insert,
            params![
                blob,
                0,
                empty_body,
                Option::<String>::None,
                Option::<i64>::None
            ],
        )
        .unwrap();
        for (index, (key, symbol)) in [
            ("[[1.5,null,0]]", "1.5"),
            ("[[1,null,0]]", "true"),
            ("[[0,null,0]]", "false"),
            ("[[1,null,1]]", "[true,[],null]"),
            ("[[0,null,1]]", "[false,[],null]"),
            ("[[1,null,0]]", "1.0"),
            ("[[1,null,1]]", "[1.0,[],null]"),
            ("[[1,1,0]]", "1"),
            ("[[null,-1,0]]", "1"),
            ("[[1,null,2]]", "1"),
            ("[[1,null]]", "1"),
            ("[[null,1,0]]", "1"),
            ("[[1,null,0]]", "-1"),
            ("[[1,null,0]]", "[1,[],null]"),
        ]
        .into_iter()
        .enumerate()
        {
            let blob = insert_reference_enumeration_impact_interior(
                &conn,
                &format!("{index}-root-prefix-invalid-cell"),
                "rust",
                "rust",
                0,
            );
            let body = format!("[[],null,[],null,[{symbol}],null,[],null,[],[],[]]");
            conn.execute(insert, params![blob, -1, body, key, 0])
                .unwrap();
            state.install(&conn);
            let error = seal_resolution_interior(&conn, blob).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("resolution root prefix key is inconsistent"),
                "key={key}, symbol={symbol}: {error}"
            );
        }
    }
}

/// Every view in the schema answers on a store built at the current DDL, and
/// the `source_occurrences` view reports an arena row for row.
///
/// Lane ST stage B folded `source_occurrences` from 1.24 million rows into one
/// JSONB arena row a blob and left a view of the same shape in its place.
#[test]
fn every_view_answers_and_the_occurrence_view_reads_the_arena() {
    let conn = open_in_memory_cache();

    let views: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'view' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        views.len() > 30,
        "expected the full view set, got {}",
        views.len()
    );
    for view in &views {
        conn.prepare(&format!("SELECT * FROM \"{view}\" LIMIT 1"))
            .unwrap_or_else(|error| panic!("view {view} does not compile: {error}"))
            .query_map([], |_| Ok(()))
            .unwrap_or_else(|error| panic!("view {view} does not answer: {error}"))
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap_or_else(|error| panic!("view {view} fails mid-scan: {error}"));
    }

    let blob_id = insert_resolution_test_blob(&conn, "arena-view", "rust");
    conn.execute(
        "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes, occurrence_count,
               declaration_count, declaration_unit_count, node_count, role_count,
               occurrence_role_count, logical_rows, payload_bytes, publication_state
             ) VALUES(?1, 12, 4, 1, 0, 0, 0, 0, 0, 2, 0, 'building')",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_occurrence_arenas(blob_id, spans)
             VALUES(?1, jsonb('[[0,4,1,1,0]]'))",
        [blob_id],
    )
    .unwrap();
    conn.execute(
        "UPDATE source_fact_manifests SET publication_state = 'complete' WHERE blob_id = ?1",
        [blob_id],
    )
    .unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT occurrence_id, start_byte, end_byte, start_line, end_line, provenance
                 FROM source_occurrences WHERE blob_id = ?1",
            [blob_id],
            |row| Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
            )),
        )
        .unwrap(),
        (0, 0, 4, 1, 1, "primary_node".to_owned())
    );
}

#[test]
fn occurrence_arena_column_holds_only_a_json_array() {
    let conn = open_in_memory_cache();
    let blob_id = insert_resolution_test_blob(&conn, "arena-shape", "rust");
    conn.execute(
        "INSERT INTO source_fact_manifests(
           blob_id, facts_version, source_bytes, occurrence_count,
           declaration_count, declaration_unit_count, node_count, role_count,
           occurrence_role_count, logical_rows, payload_bytes, publication_state
         ) VALUES(?1, 23, 100, 1, 0, 0, 0, 0, 0, 2, 0, 'building')",
        [blob_id],
    )
    .unwrap();
    let error = conn
        .execute(
            "INSERT INTO source_occurrence_arenas VALUES(?1, jsonb('{}'))",
            [blob_id],
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("CHECK constraint failed"),
        "{error}"
    );
}

#[test]
fn occurrence_seal_joins_decode_one_blob_and_scale_with_rows() {
    use crate::cache_gc::PlannerStatisticsState;
    for statistics in PlannerStatisticsState::BOTH {
        let mut measured = Vec::new();
        let mut body_measured = Vec::new();
        for count in [128, 512] {
            let mut conn = Connection::open_in_memory().unwrap();
            configure_connection(&mut conn).unwrap();
            migrate(&mut conn).unwrap();
            let blob_id = insert_resolution_test_blob(&conn, "arena-join-work", "rust");
            conn.execute(
                "INSERT INTO source_fact_manifests(
                   blob_id, facts_version, source_bytes, occurrence_count,
                   declaration_count, declaration_unit_count, node_count, role_count,
                   occurrence_role_count, logical_rows, payload_bytes, publication_state
                 ) VALUES(?1, 23, 100, ?2, 0, 0, 0, 0, 0, 1+?2, 0, 'building')",
                params![blob_id, count * 2],
            )
            .unwrap();
            let spans = format!(
                "[{}]",
                vec!["[0,8,1,1,0],[2,4,1,1,0]"; count as usize].join(",")
            );
            conn.execute(
                "INSERT INTO source_occurrence_arenas VALUES(?1,jsonb(?2))",
                params![blob_id, spans],
            )
            .unwrap();
            for ordinal in 0..count {
                conn.execute(
                    "INSERT INTO import_statements(blob_id, lang, ordinal, statement, declaration_occurrence_id, binder_occurrence_id, occurrence_declaration_start_byte, occurrence_declaration_end_byte, occurrence_binder_start_byte, occurrence_binder_end_byte)
                     VALUES(?1, 'rust', ?2, 'use x', ?3, ?4, (SELECT json_extract(spans, '$[' || (?3) || '][0]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[' || (?3) || '][1]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[' || (?4) || '][0]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[' || (?4) || '][1]') FROM source_occurrence_arenas WHERE blob_id=?1))",
                    params![blob_id, ordinal, ordinal*2, ordinal*2+1],
                ).unwrap();
            }
            for ordinal in 0..count {
                conn.execute(
                    "INSERT INTO source_declarations(
                       blob_id,declaration_id,occurrence_id,name_occurrence_id,
                       start_byte,end_byte,start_line,end_line,
                       name_start_byte,name_end_byte,name_start_line,name_end_line,provenance)
                     VALUES(?1,?2,?3,?3,2,4,1,1,2,4,1,1,0)",
                    params![blob_id, ordinal, ordinal * 2 + 1],
                )
                .unwrap();
                conn.execute(
                    "INSERT INTO source_java_local_types (blob_id, declaration_id, lexical_scope_occurrence_id, lexical_scope_start_byte, lexical_scope_end_byte) VALUES(?1, ?2, ?3, (SELECT json_extract(spans, '$[' || (?3) || '][0]') FROM source_occurrence_arenas WHERE blob_id=?1), (SELECT json_extract(spans, '$[' || (?3) || '][1]') FROM source_occurrence_arenas WHERE blob_id=?1))",
                    params![blob_id, ordinal, ordinal * 2],
                )
                .unwrap();
            }
            statistics.install(&conn);
            // Execute the real schema predicate, not a separately maintained
            // imitation of its keyed joins. This is a scalar WHEN expression.
            let trigger: String = conn.query_row(
                "SELECT sql FROM sqlite_master WHERE name='source_fact_manifests_validate_import_occurrences'", [], |row| row.get(0)
            ).unwrap();
            let condition = trigger
                .split_once("\nWHEN ")
                .unwrap()
                .1
                .split_once("\nBEGIN")
                .unwrap()
                .0;
            let sql = format!(
                "SELECT {}",
                condition
                    .replace("OLD.publication_state", "'building'")
                    .replace("NEW.publication_state", "'complete'")
                    .replace("NEW.blob_id", "?1")
                    .replace("NEW.occurrence_count", &(count * 2).to_string())
            );
            let plan: Vec<String> = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map([blob_id], |row| row.get(3))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert!(
                plan.iter()
                    .all(|line| !line.contains("VIRTUAL TABLE") && !line.contains("AUTOMATIC")),
                "{statistics:?}: {plan:?}"
            );
            assert!(
                plan.iter()
                    .any(|line| line.contains("SEARCH import USING PRIMARY KEY (blob_id=?)")),
                "{statistics:?}: {plan:?}"
            );
            let mut statement = conn.prepare(&sql).unwrap();
            assert!(
                !statement
                    .query_row([blob_id], |row| row.get::<_, bool>(0))
                    .unwrap()
            );
            measured.push(statement.get_status(rusqlite::StatementStatus::VmStep));
            drop(statement);
            // Exercise the actual BEGIN-body validation as well as WHEN.
            // Both now consume indexed owning facts, without arena joins.
            let body_trigger: String = conn.query_row(
                "SELECT sql FROM sqlite_master WHERE name='source_java_declaration_manifests_validate'", [], |row| row.get(0)
            ).unwrap();
            // Git may check this migration out with CRLF on Windows. Normalize
            // line endings before extracting the trigger body so this test
            // exercises the same SQL on either checkout style.
            let body_trigger = body_trigger.replace("\r\n", "\n");
            let body = body_trigger
                .split_once("  SELECT CASE WHEN (\n")
                .unwrap()
                .1
                .split_once(" THEN RAISE")
                .unwrap()
                .0;
            let body_sql = format!("SELECT ({body}")
                .replace("SELECT CASE WHEN", "SELECT")
                .replace("NEW.blob_id", "?1");
            let body_plan: Vec<String> = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {body_sql}"))
                .unwrap()
                .query_map([blob_id], |row| row.get(3))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert!(
                body_plan
                    .iter()
                    .all(|line| !line.contains("VIRTUAL TABLE") && !line.contains("AUTOMATIC")),
                "{statistics:?}: {body_plan:?}"
            );
            assert!(
                body_plan.iter().any(|line| line
                    .contains("SEARCH local USING PRIMARY KEY (blob_id=? AND declaration_id=?)")),
                "{statistics:?}: {body_plan:?}"
            );
            let mut body_statement = conn.prepare(&body_sql).unwrap();
            assert!(
                !body_statement
                    .query_row([blob_id], |row| row.get::<_, bool>(0))
                    .unwrap()
            );
            body_measured.push(body_statement.get_status(rusqlite::StatementStatus::VmStep));
            drop(body_statement);
            conn.execute("UPDATE source_occurrence_arenas SET spans=jsonb_set(spans,'$[1][0]',9,'$[1][1]',10) WHERE blob_id=?1", [blob_id]).unwrap();
            conn.execute("UPDATE import_statements SET occurrence_binder_start_byte=9, occurrence_binder_end_byte=10 WHERE blob_id=?1 AND ordinal=0", [blob_id]).unwrap();
            conn.execute("UPDATE source_declarations SET start_byte=9,end_byte=10,name_start_byte=9,name_end_byte=10 WHERE blob_id=?1 AND declaration_id=0", [blob_id]).unwrap();
            assert!(
                conn.query_row(&sql, [blob_id], |row| row.get::<_, bool>(0))
                    .unwrap(),
                "a binder outside its declaration must fail"
            );
            assert!(
                conn.query_row(&body_sql, [blob_id], |row| row.get::<_, bool>(0))
                    .unwrap(),
                "a local declaration outside its lexical scope must fail"
            );
        }
        assert!(
            body_measured[1] < body_measured[0] * 6,
            "body joins must not do quadratic work: {statistics:?}, {body_measured:?}"
        );
        assert!(
            measured[1] < measured[0] * 6,
            "four times the rows must not do quadratic join work: {statistics:?}, {measured:?}"
        );
    }
}

#[test]
fn optional_inline_ends_and_lines_have_the_occurrence_id_nullability() {
    let mut conn = Connection::open_in_memory().unwrap();
    configure_connection(&mut conn).unwrap();
    migrate(&mut conn).unwrap();
    // Isolate construction CHECKs from publication and deferred parent facts.
    conn.execute_batch("PRAGMA foreign_keys=OFF;
        INSERT INTO source_imports(blob_id,import_id,statement,is_wildcard,is_global,
          identifier,alias,path_kind,declaration_occurrence_id,target_occurrence_id,alias_occurrence_id,
          declaration_start_byte,declaration_end_byte,target_start_byte,target_end_byte,alias_start_byte,alias_end_byte)
        VALUES(1,0,'use X as Y;',0,0,'X','Y','namespace',0,1,2,0,10,2,3,4,5);
        INSERT INTO source_rust_import_contexts(blob_id,declaration_occurrence_id,owner_module,
          owner_scope_occurrence_id,local_scope_occurrence_id,visibility,cfg_condition,
          declaration_start_byte,declaration_end_byte,owner_scope_start_byte,owner_scope_end_byte,
          local_scope_start_byte,local_scope_end_byte)
        VALUES(1,0,'module',1,2,'private','always',3,4,0,10,2,8);
        INSERT INTO source_declarations(blob_id,declaration_id,occurrence_id,name_occurrence_id,
          start_byte,end_byte,start_line,end_line,name_start_byte,name_end_byte,name_start_line,name_end_line,provenance)
        VALUES(1,0,0,1,0,10,1,1,2,4,1,1,0);").unwrap();
    for (table, assignments, field) in [
        (
            "source_imports",
            "target_occurrence_id=NULL,target_start_byte=NULL",
            "target_end_byte",
        ),
        ("source_imports", "target_end_byte=NULL", "target_end_byte"),
        (
            "source_imports",
            "alias_occurrence_id=NULL,alias_start_byte=NULL",
            "alias_end_byte",
        ),
        ("source_imports", "alias_end_byte=NULL", "alias_end_byte"),
        (
            "source_rust_import_contexts",
            "owner_scope_occurrence_id=NULL,owner_scope_start_byte=NULL,owner_module=''",
            "owner_scope_end_byte",
        ),
        (
            "source_rust_import_contexts",
            "owner_scope_end_byte=NULL",
            "owner_scope_end_byte",
        ),
        (
            "source_rust_import_contexts",
            "local_scope_occurrence_id=NULL,local_scope_start_byte=NULL",
            "local_scope_end_byte",
        ),
        (
            "source_rust_import_contexts",
            "local_scope_end_byte=NULL",
            "local_scope_end_byte",
        ),
        (
            "source_declarations",
            "name_occurrence_id=NULL,name_start_byte=NULL,name_end_byte=NULL,name_end_line=NULL",
            "name_start_line",
        ),
        (
            "source_declarations",
            "name_start_line=NULL",
            "name_start_line",
        ),
        (
            "source_declarations",
            "name_occurrence_id=NULL,name_start_byte=NULL,name_end_byte=NULL,name_start_line=NULL",
            "name_end_line",
        ),
        ("source_declarations", "name_end_line=NULL", "name_end_line"),
    ] {
        let error = conn
            .execute(&format!("UPDATE {table} SET {assignments}"), [])
            .unwrap_err();
        assert!(
            error.to_string().contains("CHECK constraint failed")
                && error.to_string().contains(field),
            "{table}: {assignments}: {error}"
        );
    }
}
