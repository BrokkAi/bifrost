//! Seal, cascade and completeness laws for the five relational C++
//! class-template families that replaced the opaque
//! `unit_cpp_template_metadata` blob (R5.2).
//!
//! The families are `unit_cpp_class_templates` (the per-unit header),
//! `unit_cpp_class_template_parameters`, `unit_cpp_class_template_alias_components`,
//! `unit_cpp_class_template_expressions` and `unit_cpp_class_template_terms`.
//! They are published while the blob's optional-fact manifest row is absent
//! and sealed by inserting that row with `fact_kind = 1`, which is also where
//! every cross-family completeness check runs.

use super::*;
use rusqlite::params;

/// The five families in child-to-parent order, which is also the order a
/// cascade has to empty them.
const CPP_CLASS_TEMPLATE_TABLES: [&str; 5] = [
    "unit_cpp_class_template_terms",
    "unit_cpp_class_template_expressions",
    "unit_cpp_class_template_alias_components",
    "unit_cpp_class_template_parameters",
    "unit_cpp_class_templates",
];

const SEAL_MESSAGE: &str = "sealed C++ class-template facts are immutable";

/// Expression roles, as `unit_cpp_class_template_expressions.role` stores them
/// and as `store/cpp_template.rs` names them.
const ROLE_PARAMETER_DEFAULT: i64 = 0;
const ROLE_SPECIALIZATION_ARGUMENT: i64 = 1;
const ROLE_ALIAS_ARGUMENT: i64 = 2;

/// One C++ blob with a single class unit, ready for class-template rows.
fn insert_cpp_template_blob(conn: &Connection, seed: &str, is_complete: i64) -> i64 {
    conn.execute(
        "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'cpp', 0)",
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
         ) VALUES(?1, 'cpp', 0, '', 1, 0, 0, 0, 0, 0, 0, 0, ?2)",
        params![blob_id, is_complete],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO code_units(
           blob_id, lang, unit_key, kind, short_name, identifier,
           content_qualifier, synthetic, is_type_alias,
           in_declarations, in_definition_lookup
         ) VALUES(?1, 'cpp', 1, 3, 'Bundle', 'Bundle', '', 0, 0, 1, 1)",
        [blob_id],
    )
    .unwrap();
    blob_id
}

/// One expression and its three-term tree: a `Node` root owning a `Parameter`
/// leaf and an `Atom` leaf. Returns the next free term id.
fn insert_expression(
    conn: &Connection,
    blob_id: i64,
    expression_id: i64,
    role: i64,
    owner_ordinal: i64,
    text: &str,
    first_term_id: i64,
) -> i64 {
    conn.execute(
        "INSERT INTO unit_cpp_class_template_expressions(
           blob_id, expression_id, unit_key, role, owner_ordinal, text, root_term_id
         ) VALUES(?1, ?2, 1, ?3, ?4, ?5, ?6)",
        params![
            blob_id,
            expression_id,
            role,
            owner_ordinal,
            text,
            first_term_id
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO unit_cpp_class_template_terms(
           blob_id, term_id, expression_id, parent_term_id, ordinal, kind, text, atom_kind
         ) VALUES(?1, ?2, ?3, NULL, 0, 2, NULL, 'template_type')",
        params![blob_id, first_term_id, expression_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO unit_cpp_class_template_terms(
           blob_id, term_id, expression_id, parent_term_id, ordinal, kind, text, atom_kind
         ) VALUES(?1, ?2, ?3, ?4, 0, 0, 'T', NULL)",
        params![blob_id, first_term_id + 1, expression_id, first_term_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO unit_cpp_class_template_terms(
           blob_id, term_id, expression_id, parent_term_id, ordinal, kind, text, atom_kind
         ) VALUES(?1, ?2, ?3, ?4, 1, 1, '4', 'number_literal')",
        params![blob_id, first_term_id + 2, expression_id, first_term_id],
    )
    .unwrap();
    first_term_id + 3
}

/// The complete family set this suite seals: three parameters (one defaulted,
/// one variadic), two specialization arguments, a two-component alias target
/// with one argument.
///
/// The rows go into the caller's open transaction. The header's deferred
/// foreign key to `blob_optional_fact_manifest` means a family and the
/// manifest row that seals it must commit together, and the seal triggers
/// mean the family rows must be written first; that is also how the writer
/// publishes one.
fn insert_complete_cpp_template_family(conn: &Connection, blob_id: i64) {
    for (ordinal, name, kind, variadic, default_present) in
        [(0, "T", 0, 0, 0), (1, "U", 0, 0, 1), (2, "Rest", 0, 1, 0)]
    {
        conn.execute(
            "INSERT INTO unit_cpp_class_template_parameters(
               blob_id, unit_key, ordinal, name, kind, variadic, default_present
             ) VALUES(?1, 1, ?2, ?3, ?4, ?5, ?6)",
            params![blob_id, ordinal, name, kind, variadic, default_present],
        )
        .unwrap();
    }
    for (ordinal, component) in [(0, "demo"), (1, "Holder")] {
        conn.execute(
            "INSERT INTO unit_cpp_class_template_alias_components(
               blob_id, unit_key, ordinal, component
             ) VALUES(?1, 1, ?2, ?3)",
            params![blob_id, ordinal, component],
        )
        .unwrap();
    }
    let mut next_term = 0;
    next_term = insert_expression(conn, blob_id, 0, ROLE_PARAMETER_DEFAULT, 1, "T*", next_term);
    next_term = insert_expression(
        conn,
        blob_id,
        1,
        ROLE_SPECIALIZATION_ARGUMENT,
        0,
        "T",
        next_term,
    );
    next_term = insert_expression(
        conn,
        blob_id,
        2,
        ROLE_SPECIALIZATION_ARGUMENT,
        1,
        "T*",
        next_term,
    );
    insert_expression(conn, blob_id, 3, ROLE_ALIAS_ARGUMENT, 0, "T", next_term);
    conn.execute(
        "INSERT INTO unit_cpp_class_templates(
           blob_id, unit_key, primary_name, primary_fq_name, alias_global,
           alias_arguments_present, parameter_count, specialization_argument_count,
           alias_component_count, alias_argument_count
         ) VALUES(?1, 1, 'Bundle', 'demo.Bundle', 1, 1, 3, 2, 2, 1)",
        [blob_id],
    )
    .unwrap();
}

/// Publish and seal one complete family as a single transaction.
fn publish_complete_cpp_template_family(conn: &Connection, blob_id: i64) {
    conn.execute_batch("BEGIN").unwrap();
    insert_complete_cpp_template_family(conn, blob_id);
    seal(conn, blob_id, 1).unwrap();
    conn.execute_batch("COMMIT").unwrap();
}

fn seal(conn: &Connection, blob_id: i64, row_count: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO blob_optional_fact_manifest(blob_id, fact_kind, row_count)
         VALUES(?1, 1, ?2)",
        params![blob_id, row_count],
    )
}

fn family_row_count(conn: &Connection, table: &str, blob_id: i64) -> i64 {
    conn.query_row(
        &format!("SELECT COUNT(*) FROM {table} WHERE blob_id = ?1"),
        [blob_id],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn sealed_cpp_class_template_families_reject_every_mutation() {
    let conn = open_in_memory_cache();
    let blob_id = insert_cpp_template_blob(&conn, "cpp-tpl-seal", 1);
    publish_complete_cpp_template_family(&conn, blob_id);

    for sql in [
        // unit_cpp_class_templates
        "INSERT INTO unit_cpp_class_templates(
           blob_id, unit_key, primary_name, primary_fq_name, alias_global,
           alias_arguments_present, parameter_count, specialization_argument_count,
           alias_component_count, alias_argument_count
         ) VALUES(?1, 2, 'Other', 'demo.Other', NULL, NULL, 0, 0, 0, 0)",
        "UPDATE unit_cpp_class_templates SET primary_name = 'Changed' WHERE blob_id = ?1",
        "DELETE FROM unit_cpp_class_templates WHERE blob_id = ?1",
        // unit_cpp_class_template_parameters
        "INSERT INTO unit_cpp_class_template_parameters(
           blob_id, unit_key, ordinal, name, kind, variadic, default_present
         ) VALUES(?1, 1, 3, 'Extra', 0, 0, 0)",
        "UPDATE unit_cpp_class_template_parameters SET name = 'Changed'
           WHERE blob_id = ?1 AND unit_key = 1 AND ordinal = 0",
        "DELETE FROM unit_cpp_class_template_parameters
           WHERE blob_id = ?1 AND unit_key = 1 AND ordinal = 0",
        // unit_cpp_class_template_alias_components
        "INSERT INTO unit_cpp_class_template_alias_components(
           blob_id, unit_key, ordinal, component
         ) VALUES(?1, 1, 2, 'Extra')",
        "UPDATE unit_cpp_class_template_alias_components SET component = 'Changed'
           WHERE blob_id = ?1 AND unit_key = 1 AND ordinal = 0",
        "DELETE FROM unit_cpp_class_template_alias_components
           WHERE blob_id = ?1 AND unit_key = 1 AND ordinal = 0",
        // unit_cpp_class_template_expressions
        "INSERT INTO unit_cpp_class_template_expressions(
           blob_id, expression_id, unit_key, role, owner_ordinal, text, root_term_id
         ) VALUES(?1, 9, 1, 1, 2, 'Extra', 0)",
        "UPDATE unit_cpp_class_template_expressions SET text = 'Changed'
           WHERE blob_id = ?1 AND expression_id = 0",
        "DELETE FROM unit_cpp_class_template_expressions
           WHERE blob_id = ?1 AND expression_id = 0",
        // unit_cpp_class_template_terms
        "INSERT INTO unit_cpp_class_template_terms(
           blob_id, term_id, expression_id, parent_term_id, ordinal, kind, text, atom_kind
         ) VALUES(?1, 99, 0, 0, 2, 0, 'Extra', NULL)",
        "UPDATE unit_cpp_class_template_terms SET text = 'Changed'
           WHERE blob_id = ?1 AND term_id = 1",
        "DELETE FROM unit_cpp_class_template_terms WHERE blob_id = ?1 AND term_id = 1",
    ] {
        let error = conn.execute(sql, [blob_id]).unwrap_err();
        assert!(
            error.to_string().contains(SEAL_MESSAGE),
            "unexpected failure for `{sql}`: {error}"
        );
    }

    for table in CPP_CLASS_TEMPLATE_TABLES {
        for event in ["insert", "update", "delete"] {
            let trigger = format!("{table}_no_{event}_after_seal");
            assert_eq!(
                conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'trigger' AND name = ?1",
                    [trigger.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
                1,
                "missing durable guard {trigger}"
            );
        }
    }
    validate_foreign_keys(&conn).unwrap();
}

#[test]
fn deleting_the_blob_cascades_every_cpp_class_template_family() {
    let conn = open_in_memory_cache();
    let blob_id = insert_cpp_template_blob(&conn, "cpp-tpl-cascade", 1);
    publish_complete_cpp_template_family(&conn, blob_id);
    for table in CPP_CLASS_TEMPLATE_TABLES {
        assert!(
            family_row_count(&conn, table, blob_id) > 0,
            "{table} must hold rows before the cascade"
        );
    }

    conn.execute("DELETE FROM blobs WHERE id = ?1", [blob_id])
        .unwrap();

    for table in CPP_CLASS_TEMPLATE_TABLES
        .into_iter()
        .chain(["blob_optional_fact_manifest", "code_units"])
    {
        assert_eq!(
            family_row_count(&conn, table, blob_id),
            0,
            "blob deletion must cascade {table}"
        );
    }
    validate_foreign_keys(&conn).unwrap();
}

/// Every cross-family completeness rule runs when the manifest row seals the
/// family, so each damaged publication below is rejected at seal time and
/// leaves no partial family sealed.
#[test]
fn sealing_rejects_a_partial_cpp_class_template_family() {
    let conn = open_in_memory_cache();

    let incomplete_blob = insert_cpp_template_blob(&conn, "cpp-tpl-incomplete", 0);
    conn.execute_batch("BEGIN").unwrap();
    insert_complete_cpp_template_family(&conn, incomplete_blob);
    let error = seal(&conn, incomplete_blob, 1).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("C++ class-template manifest requires a complete blob"),
        "{error}"
    );
    conn.execute_batch("ROLLBACK").unwrap();

    let miscounted = insert_cpp_template_blob(&conn, "cpp-tpl-miscount", 1);
    conn.execute_batch("BEGIN").unwrap();
    insert_complete_cpp_template_family(&conn, miscounted);
    let error = seal(&conn, miscounted, 2).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("C++ class-template manifest count is inconsistent"),
        "{error}"
    );
    conn.execute_batch("ROLLBACK").unwrap();

    // Each case below damages one family of an otherwise complete
    // publication, then proves the seal names the rule it broke.
    for (seed, damage, message) in [
        (
            "cpp-tpl-no-param",
            "DELETE FROM unit_cpp_class_template_parameters
               WHERE blob_id = ?1 AND ordinal = 2",
            "C++ class-template child counts are inconsistent",
        ),
        (
            "cpp-tpl-no-comp",
            "DELETE FROM unit_cpp_class_template_alias_components
               WHERE blob_id = ?1 AND ordinal = 1",
            "C++ class-template child counts are inconsistent",
        ),
        (
            "cpp-tpl-unclaimed",
            "UPDATE unit_cpp_class_template_parameters SET default_present = 0
               WHERE blob_id = ?1 AND ordinal = 1",
            "C++ class-template parameter defaults are inconsistent",
        ),
        (
            "cpp-tpl-absent-def",
            "UPDATE unit_cpp_class_template_parameters SET default_present = 1
               WHERE blob_id = ?1 AND ordinal = 0",
            "C++ class-template parameter defaults are inconsistent",
        ),
        (
            "cpp-tpl-sparse-par",
            "UPDATE unit_cpp_class_template_parameters SET ordinal = 7
               WHERE blob_id = ?1 AND ordinal = 2",
            "C++ class-template child ordinals are not dense",
        ),
        (
            "cpp-tpl-sparse-arg",
            "UPDATE unit_cpp_class_template_expressions SET owner_ordinal = 5
               WHERE blob_id = ?1 AND expression_id = 2",
            "C++ class-template child ordinals are not dense",
        ),
        (
            "cpp-tpl-bad-root",
            "UPDATE unit_cpp_class_template_expressions SET root_term_id = 1
               WHERE blob_id = ?1 AND expression_id = 0",
            "C++ class-template expression root is inconsistent",
        ),
        (
            "cpp-tpl-sparse-kid",
            "UPDATE unit_cpp_class_template_terms SET ordinal = 3
               WHERE blob_id = ?1 AND term_id = 2",
            "C++ class-template child term ordinals are not dense",
        ),
        (
            "cpp-tpl-leaf-parent",
            "UPDATE unit_cpp_class_template_terms SET parent_term_id = 1, ordinal = 0
               WHERE blob_id = ?1 AND term_id = 2",
            "C++ class-template leaf term cannot own children",
        ),
    ] {
        let blob_id = insert_cpp_template_blob(&conn, seed, 1);
        conn.execute_batch("BEGIN").unwrap();
        insert_complete_cpp_template_family(&conn, blob_id);
        conn.execute(damage, [blob_id])
            .unwrap_or_else(|error| panic!("damaging {seed}: {error}"));
        let error = seal(&conn, blob_id, 1).unwrap_err();
        assert!(
            error.to_string().contains(message),
            "sealing {seed} reported {error} instead of {message}"
        );
        conn.execute_batch("ROLLBACK").unwrap();
        for table in CPP_CLASS_TEMPLATE_TABLES
            .into_iter()
            .chain(["blob_optional_fact_manifest"])
        {
            assert_eq!(
                family_row_count(&conn, table, blob_id),
                0,
                "a rejected seal must leave no {table} rows for {seed}"
            );
        }
    }
    validate_foreign_keys(&conn).unwrap();
}
