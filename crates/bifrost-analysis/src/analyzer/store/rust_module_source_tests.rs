//! Integrity tests for the canonical Rust module source publication.
//!
//! These tests deliberately use the SQL publication boundary rather than the
//! legacy module DTOs.  A malformed row must be rejected before the source
//! manifest becomes complete, and a completed publication must remain
//! immutable.

use super::tests::{oid_for, parse_state};
use super::*;

use crate::analyzer::rust::RustAdapter;
use crate::analyzer::rust::source_publication::SOURCE_STORAGE;
use crate::inline_project::InlineTestProject;
use git2::Oid;
use rusqlite::Connection;

const MODULE_SOURCE: &str = concat!(
    r#"
macro_rules! discard { ($($tokens:tt)*) => {}; }
#[path = "u"#,
    "\u{fc}",
    r#"mlaut/target.rs"]
pub mod external;
mod source_only;
pub mod inline { pub mod nested {} }
outer! { pub mod first; nested! { pub(crate) mod deep; } }
discard! { pub mod hidden { mod child; } }
outer! { mod repeated; }
other! { }
"#
);
const UTF8_MODULE_PATH: &str = concat!("u", "\u{fc}", "mlaut/target.rs");

fn published_module_fixture() -> (AnalyzerStore, Oid, FileState) {
    let fixture = InlineTestProject::new()
        .file("src/lib.rs", MODULE_SOURCE)
        .build();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let source_facts = state
        .source_facts
        .as_ref()
        .expect("Rust fixture has canonical source facts");
    let module_facts = source_facts
        .rust_modules
        .as_ref()
        .expect("Rust fixture has canonical module facts");
    assert!(module_facts.scopes.len() > 1);
    assert!(module_facts.inventory.len() > 1);
    assert!(module_facts.routes.len() > 1);
    assert!(
        module_facts
            .routes
            .iter()
            .any(|route| route.gates.len() > 1)
    );
    assert!(
        module_facts
            .declarations
            .iter()
            .any(|declaration| declaration.path_attribute.as_deref() == Some(UTF8_MODULE_PATH))
    );

    let oid = oid_for(MODULE_SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral analyzer store");
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .expect("canonical module fixture publishes");
    (store, oid, state)
}

#[test]
fn rust_source_capability_cost_matches_each_persisted_extension_family() {
    let (store, oid, state) = published_module_fixture();
    let facts = state
        .source_facts
        .as_ref()
        .expect("Rust fixture has canonical source facts");
    let (expected_rows, _) = (SOURCE_STORAGE.cost)(facts).expect("Rust family is published");
    let id = store.conn.execute(move |conn| blob_id(conn, oid));
    let actual_rows: usize = store
        .conn
        .execute(move |conn| {
            conn.query_row(
                "SELECT manifest.rust_import_context_count
                        + manifest.rust_declaration_property_count
                        + manifest.rust_constructor_field_count
                        + 1
                        + (SELECT COUNT(*) FROM source_rust_module_declarations WHERE blob_id = manifest.blob_id)
                        + (SELECT COUNT(*) FROM source_rust_macro_invocations WHERE blob_id = manifest.blob_id)
                        + (SELECT COUNT(*) FROM source_rust_module_scopes WHERE blob_id = manifest.blob_id)
                        + (SELECT COUNT(*) FROM source_rust_module_inventory WHERE blob_id = manifest.blob_id)
                        + (SELECT COUNT(*) FROM source_rust_module_routes WHERE blob_id = manifest.blob_id)
                        + (SELECT COUNT(*) FROM source_rust_module_route_gates WHERE blob_id = manifest.blob_id)
                        + item.logical_rows
                   FROM source_fact_manifests AS manifest
                   JOIN source_rust_item_manifests AS item ON item.blob_id = manifest.blob_id
                  WHERE manifest.blob_id = ?1",
                [id],
                |row| row.get(0),
            )
        })
        .expect("Rust extension families are persisted");
    assert_eq!(actual_rows, expected_rows);
}

fn blob_id(conn: &Connection, oid: Oid) -> i64 {
    conn.query_row(
        "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'",
        [oid.to_string()],
        |row| row.get(0),
    )
    .expect("published Rust blob id")
}

fn assert_seal_rejects<F>(
    store: &AnalyzerStore,
    oid: Oid,
    expected_errors: &'static [&'static str],
    mutate: F,
) where
    F: FnOnce(&Connection, i64) + Send + 'static,
{
    let expected = store
        .rust_usage_facts(oid, "rust")
        .expect("canonical module publication before rollback test");
    store.conn.execute(move |conn| {
        let id = blob_id(conn, oid);
        conn.execute_batch(
            "SAVEPOINT rust_module_integrity_fault;
             DROP TRIGGER source_fact_manifests_no_reopen;",
        )
        .expect("stage source-fact corruption savepoint");
        conn.execute(
            "UPDATE source_fact_manifests SET publication_state = 'building'
             WHERE blob_id = ?1",
            [id],
        )
        .expect("reopen source manifest inside test savepoint");
        mutate(conn, id);
        let error = conn
            .execute(
                "UPDATE source_fact_manifests SET publication_state = 'complete'
                 WHERE blob_id = ?1",
                [id],
            )
            .expect_err("malformed canonical module rows must not seal");
        assert!(
            expected_errors
                .iter()
                .any(|expected| error.to_string().contains(expected)),
            "{error}"
        );
        conn.execute_batch(
            "ROLLBACK TO rust_module_integrity_fault;
             RELEASE rust_module_integrity_fault;",
        )
        .expect("restore source-fact publication after corruption test");
        let state: String = conn
            .query_row(
                "SELECT publication_state FROM source_fact_manifests WHERE blob_id = ?1",
                [id],
                |row| row.get(0),
            )
            .expect("source manifest remains present");
        assert_eq!(state, "complete");
    });
    assert_eq!(
        store.rust_usage_facts(oid, "rust").unwrap(),
        expected,
        "failed canonical module seal changed the consumer view"
    );
}

#[test]
fn canonical_module_seal_rejects_bad_paths_headers_placement_gates_and_ordinals() {
    let (store, oid, _) = published_module_fixture();
    assert_seal_rejects(
        &store,
        oid,
        &["canonical Rust module", "canonical Rust item or type"],
        |conn, id| {
            conn.execute(
                "UPDATE source_rust_module_scopes SET module_name = UPPER(module_name)
             WHERE blob_id = ?1
               AND ordinal = (SELECT MIN(ordinal) FROM source_rust_module_scopes
                              WHERE blob_id = ?1 AND ordinal > 0)",
                [id],
            )
            .unwrap();
        },
    );

    assert_seal_rejects(
        &store,
        oid,
        &["canonical Rust module", "canonical Rust item or type"],
        |conn, id| {
            conn.execute(
                "UPDATE source_rust_module_inventory SET module_name = UPPER(module_name)
             WHERE blob_id = ?1
               AND ordinal = (SELECT MIN(ordinal) FROM source_rust_module_inventory
                              WHERE blob_id = ?1 AND ordinal > 0)",
                [id],
            )
            .unwrap();
        },
    );

    assert_seal_rejects(
        &store,
        oid,
        &["canonical Rust module", "canonical Rust item or type"],
        |conn, id| {
            conn.execute(
                "UPDATE source_rust_module_scopes
             SET imports_macros = CASE imports_macros WHEN 0 THEN 1 ELSE 0 END
             WHERE blob_id = ?1
               AND ordinal = (SELECT MIN(ordinal) FROM source_rust_module_scopes
                              WHERE blob_id = ?1 AND ordinal > 0)",
                [id],
            )
            .unwrap();
        },
    );

    assert_seal_rejects(
        &store,
        oid,
        &["canonical Rust module", "canonical Rust item or type"],
        |conn, id| {
            conn.execute(
                "UPDATE source_rust_module_declarations
             SET (body_occurrence_id, body_start_byte, body_end_byte, body_provenance) = (
                 SELECT source.name_occurrence_id, source.name_start_byte,
                        source.name_end_byte,
                        CASE name.provenance WHEN 'primary_node' THEN 0
                             WHEN 'explicit_subspan' THEN 1 WHEN 'embedded' THEN 2 END
                 FROM source_declarations AS source
                 JOIN source_occurrences AS name
                   ON name.blob_id = source.blob_id
                  AND name.occurrence_id = source.name_occurrence_id
                 WHERE source.blob_id = ?1
                   AND source.declaration_id = (
                       SELECT scope.declaration_id
                       FROM source_rust_module_scopes AS scope
                       WHERE scope.blob_id = ?1 AND scope.module_name = 'inline'
                       LIMIT 1
                   )
             )
             WHERE blob_id = ?1
               AND declaration_id = (
                 SELECT scope.declaration_id
                 FROM source_rust_module_scopes AS scope
                 WHERE scope.blob_id = ?1
                   AND scope.module_name = 'inline'
                 LIMIT 1
             )",
                [id],
            )
            .unwrap();
        },
    );

    assert_seal_rejects(
        &store,
        oid,
        &["canonical Rust module", "canonical Rust item or type"],
        |conn, id| {
            conn.execute(
                "UPDATE source_rust_module_scopes SET ordinal = 99
             WHERE blob_id = ?1
               AND ordinal = (SELECT MAX(ordinal) FROM source_rust_module_scopes
                              WHERE blob_id = ?1)",
                [id],
            )
            .unwrap();
        },
    );

    assert_seal_rejects(
        &store,
        oid,
        &["canonical Rust module", "canonical Rust item or type"],
        |conn, id| {
            conn.execute(
                "UPDATE source_rust_module_inventory SET ordinal = 99
             WHERE blob_id = ?1
               AND ordinal = (SELECT MAX(ordinal) FROM source_rust_module_inventory
                              WHERE blob_id = ?1)",
                [id],
            )
            .unwrap();
        },
    );

    assert_seal_rejects(
        &store,
        oid,
        &["canonical Rust module", "canonical Rust item or type"],
        |conn, id| {
            conn.execute(
                "UPDATE source_rust_module_route_gates
             SET gate_ordinal = 2
             WHERE blob_id = ?1
               AND route_ordinal = (
                   SELECT route_ordinal FROM source_rust_module_route_gates
                   WHERE blob_id = ?1
                   GROUP BY route_ordinal HAVING COUNT(*) > 1
                   ORDER BY route_ordinal LIMIT 1
               )
               AND gate_ordinal = 1",
                [id],
            )
            .unwrap();
        },
    );

    assert_seal_rejects(
        &store,
        oid,
        &["canonical Rust module", "canonical Rust item or type"],
        |conn, id| {
            conn.execute(
                "UPDATE source_rust_module_route_gates
             SET invocation_occurrence_id = (
                 SELECT occurrence_id FROM source_rust_macro_invocations
                 WHERE blob_id = ?1 AND macro_name = 'other'
                 LIMIT 1
             )
             WHERE blob_id = ?1
               AND route_ordinal = (
                   SELECT route_ordinal FROM source_rust_module_route_gates
                   WHERE blob_id = ?1
                   GROUP BY route_ordinal HAVING COUNT(*) > 1
                   ORDER BY route_ordinal LIMIT 1
               )
               AND gate_ordinal = 1",
                [id],
            )
            .unwrap();
        },
    );
}

#[test]
fn canonical_module_facts_are_immutable_after_seal() {
    let (store, oid, _) = published_module_fixture();
    let conn = store.read_conn().unwrap();
    let id = blob_id(&conn, oid);
    drop(conn);
    store.conn.execute(move |conn| {
        let statements = [
            "INSERT INTO source_rust_module_manifests(blob_id, facts_version, root_occurrence_id, root_start_byte, root_end_byte, root_provenance)
             SELECT blob_id, facts_version, root_occurrence_id, root_start_byte, root_end_byte, root_provenance FROM source_rust_module_manifests WHERE blob_id = ?1",
            "INSERT INTO source_rust_module_declarations(blob_id, declaration_id, module_name, body_occurrence_id, path_attribute, macro_use, test_gated, body_start_byte, body_end_byte, body_provenance)
             SELECT blob_id, declaration_id, module_name, body_occurrence_id, path_attribute, macro_use, test_gated, body_start_byte, body_end_byte, body_provenance FROM source_rust_module_declarations WHERE blob_id = ?1 LIMIT 1",
            "INSERT INTO source_rust_macro_invocations(blob_id, occurrence_id, macro_name, start_byte, end_byte, provenance)
             SELECT blob_id, occurrence_id, macro_name, start_byte, end_byte, provenance FROM source_rust_macro_invocations WHERE blob_id = ?1 LIMIT 1",
            "INSERT INTO source_rust_module_scopes(blob_id, ordinal, parent_ordinal, declaration_id, module_name, imports_macros, resolution_scope)
             SELECT blob_id, ordinal, parent_ordinal, declaration_id, module_name, imports_macros, resolution_scope FROM source_rust_module_scopes WHERE blob_id = ?1 LIMIT 1",
            "INSERT INTO source_rust_module_inventory(blob_id, ordinal, parent_scope_ordinal, declaration_id, module_name)
             SELECT blob_id, ordinal, parent_scope_ordinal, declaration_id, module_name FROM source_rust_module_inventory WHERE blob_id = ?1 LIMIT 1",
            "INSERT INTO source_rust_module_routes(blob_id, ordinal, scope_ordinal, declaration_id, imports_macros)
             SELECT blob_id, ordinal, scope_ordinal, declaration_id, imports_macros FROM source_rust_module_routes WHERE blob_id = ?1 LIMIT 1",
            "INSERT INTO source_rust_module_route_gates(blob_id, route_ordinal, gate_ordinal, invocation_occurrence_id)
             SELECT blob_id, route_ordinal, gate_ordinal, invocation_occurrence_id FROM source_rust_module_route_gates WHERE blob_id = ?1 LIMIT 1",
        ];
        for statement in statements {
            let error = conn
                .execute(statement, [id])
                .expect_err("sealed canonical module insert unexpectedly succeeded");
            assert!(error.to_string().contains("immutable"), "{error}");
        }

        let updates = [
            "UPDATE source_fact_manifests SET rust_import_context_count = rust_import_context_count WHERE blob_id = ?1",
            "UPDATE source_fact_manifests SET rust_declaration_property_count = rust_declaration_property_count WHERE blob_id = ?1",
            "UPDATE source_fact_manifests SET rust_constructor_field_count = rust_constructor_field_count WHERE blob_id = ?1",
            "UPDATE source_rust_module_manifests SET facts_version = facts_version WHERE blob_id = ?1",
            "UPDATE source_rust_module_declarations SET module_name = module_name
             WHERE blob_id = ?1 AND declaration_id = (SELECT MIN(declaration_id)
             FROM source_rust_module_declarations WHERE blob_id = ?1)",
            "UPDATE source_rust_macro_invocations SET macro_name = macro_name
             WHERE blob_id = ?1 AND occurrence_id = (SELECT MIN(occurrence_id)
             FROM source_rust_macro_invocations WHERE blob_id = ?1)",
            "UPDATE source_rust_module_scopes SET module_name = module_name
             WHERE blob_id = ?1 AND ordinal = (SELECT MIN(ordinal)
             FROM source_rust_module_scopes WHERE blob_id = ?1)",
            "UPDATE source_rust_module_inventory SET module_name = module_name
             WHERE blob_id = ?1 AND ordinal = (SELECT MIN(ordinal)
             FROM source_rust_module_inventory WHERE blob_id = ?1)",
            "UPDATE source_rust_module_routes SET imports_macros = imports_macros
             WHERE blob_id = ?1 AND ordinal = (SELECT MIN(ordinal)
             FROM source_rust_module_routes WHERE blob_id = ?1)",
            "UPDATE source_rust_module_route_gates SET gate_ordinal = gate_ordinal
             WHERE blob_id = ?1 AND route_ordinal = (SELECT MIN(route_ordinal)
             FROM source_rust_module_route_gates WHERE blob_id = ?1)
               AND gate_ordinal = (SELECT MIN(gate_ordinal)
             FROM source_rust_module_route_gates WHERE blob_id = ?1)",
        ];
        for statement in updates {
            let error = conn
                .execute(statement, [id])
                .expect_err("sealed canonical module update unexpectedly succeeded");
            assert!(error.to_string().contains("immutable"), "{error}");
        }

        let deletes = [
            "DELETE FROM source_rust_module_manifests WHERE blob_id = ?1",
            "DELETE FROM source_rust_module_declarations
             WHERE blob_id = ?1 AND declaration_id = (SELECT MIN(declaration_id)
             FROM source_rust_module_declarations WHERE blob_id = ?1)",
            "DELETE FROM source_rust_macro_invocations
             WHERE blob_id = ?1 AND occurrence_id = (SELECT MIN(occurrence_id)
             FROM source_rust_macro_invocations WHERE blob_id = ?1)",
            "DELETE FROM source_rust_module_scopes
             WHERE blob_id = ?1 AND ordinal = (SELECT MIN(ordinal)
             FROM source_rust_module_scopes WHERE blob_id = ?1)",
            "DELETE FROM source_rust_module_inventory
             WHERE blob_id = ?1 AND ordinal = (SELECT MIN(ordinal)
             FROM source_rust_module_inventory WHERE blob_id = ?1)",
            "DELETE FROM source_rust_module_routes
             WHERE blob_id = ?1 AND ordinal = (SELECT MIN(ordinal)
             FROM source_rust_module_routes WHERE blob_id = ?1)",
            "DELETE FROM source_rust_module_route_gates
             WHERE blob_id = ?1 AND route_ordinal = (SELECT MIN(route_ordinal)
             FROM source_rust_module_route_gates WHERE blob_id = ?1)
               AND gate_ordinal = (SELECT MIN(gate_ordinal)
             FROM source_rust_module_route_gates WHERE blob_id = ?1)",
        ];
        for statement in deletes {
            let error = conn
                .execute(statement, [id])
                .expect_err("sealed canonical module delete unexpectedly succeeded");
            assert!(error.to_string().contains("immutable"), "{error}");
        }
    });
}

#[test]
fn failed_canonical_module_replacement_preserves_the_old_sealed_publication() {
    let (store, oid, state) = published_module_fixture();
    let before = store.conn.execute(move |conn| {
        let id = blob_id(conn, oid);
        conn.query_row(
            "SELECT publication_state, COUNT(*), MIN(module_name)
             FROM source_fact_manifests AS manifest
             JOIN source_rust_module_declarations AS declaration USING (blob_id)
             WHERE manifest.blob_id = ?1
             GROUP BY manifest.publication_state",
            [id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .expect("old module publication")
    });

    let mut invalid = state.clone();
    invalid
        .source_facts
        .as_mut()
        .expect("canonical source facts")
        .rust_modules
        .as_mut()
        .expect("canonical module source facts")
        .declarations[0]
        .name
        .clear();
    assert!(
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &invalid)
            .is_err(),
        "invalid replacement must fail at the canonical module CHECK"
    );

    let after = store.conn.execute(move |conn| {
        let id = blob_id(conn, oid);
        conn.query_row(
            "SELECT publication_state, COUNT(*), MIN(module_name)
             FROM source_fact_manifests AS manifest
             JOIN source_rust_module_declarations AS declaration USING (blob_id)
             WHERE manifest.blob_id = ?1
             GROUP BY manifest.publication_state",
            [id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .expect("old module publication after failed replacement")
    });
    assert_eq!(after, before);
}

#[test]
fn raw_qualified_and_error_modules_reopen_with_exact_embedded_source_ids() {
    use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance;

    let source = r#"
mod retained;
qualified::wrap! { mod qualified_module; }
broken! { mod malformed_module; let = ; }
"#;
    let fixture = InlineTestProject::new().file("src/lib.rs", source).build();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let source_facts = state
        .source_facts
        .as_ref()
        .expect("Rust fixture has canonical source facts");
    let modules = source_facts
        .rust_modules
        .as_ref()
        .expect("Rust fixture has canonical module source facts");

    let mut expected = modules
        .declarations
        .iter()
        .filter(|module| {
            matches!(
                module.name.as_str(),
                "qualified_module" | "malformed_module"
            )
        })
        .map(|module| {
            let declaration = source_facts.occurrences.declaration(module.declaration);
            let name = declaration
                .name
                .expect("module source declaration has a name occurrence");
            let occurrence = source_facts.occurrences.occurrence(declaration.occurrence);
            assert_eq!(
                occurrence.provenance,
                SourceOccurrenceProvenance::Embedded,
                "raw module declaration keeps embedded provenance"
            );
            (
                module.name.clone(),
                i64::from(module.declaration.get()),
                i64::from(declaration.occurrence.get()),
                i64::from(name.get()),
                module.body.map(|body| i64::from(body.get())),
            )
        })
        .collect::<Vec<_>>();
    expected.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(expected.len(), 2, "raw module declarations: {expected:?}");

    assert!(
        state
            .source_declaration_units
            .iter()
            .all(|(declaration, _)| expected
                .iter()
                .all(|row| i64::from(declaration.get()) != row.1)),
        "raw modules remain outside display declaration admission"
    );
    assert!(
        expected.iter().all(|row| {
            !source_facts
                .native_declaration_sources
                .iter()
                .any(|(_, declaration)| i64::from(declaration.get()) == row.1)
        }),
        "raw modules remain outside native declaration admission"
    );
    let expected_usage = state.rust_usage_facts.clone();
    assert!(
        expected_usage
            .modules
            .iter()
            .any(|module| module.module_name == "retained")
    );
    assert!(
        expected_usage
            .module_routes
            .routes
            .iter()
            .any(|route| route.module_name == "retained")
    );
    assert!(
        expected_usage.modules.iter().all(|module| !matches!(
            module.module_name.as_str(),
            "qualified_module" | "malformed_module"
        )),
        "raw modules remain outside the legacy module inventory"
    );
    assert!(
        expected_usage
            .module_routes
            .routes
            .iter()
            .all(|route| !matches!(
                route.module_name.as_str(),
                "qualified_module" | "malformed_module"
            )),
        "raw modules remain outside legacy module-route admission"
    );

    let oid = oid_for(source.as_bytes());
    let path = fixture.root().join("raw-module-source.db");
    let store = AnalyzerStore::open_persistent(&path).expect("persistent analyzer store");
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .expect("raw module source facts publish");
    drop(store);

    let reopened = AnalyzerStore::open_persistent(&path).expect("reopen persistent store");
    assert_eq!(
        reopened.rust_usage_facts(oid, "rust").unwrap(),
        expected_usage,
        "reopen preserves the legacy module projections"
    );
    let conn = reopened.read_conn().unwrap();
    let id = blob_id(&conn, oid);
    let actual = conn
        .prepare(
            "SELECT module.module_name, module.declaration_id,
                    declaration.occurrence_id, declaration.name_occurrence_id,
                    occurrence.provenance, module.body_occurrence_id
             FROM source_rust_module_declarations AS module
             JOIN source_declarations AS declaration
               ON declaration.blob_id = module.blob_id
              AND declaration.declaration_id = module.declaration_id
             JOIN source_occurrences AS occurrence
               ON occurrence.blob_id = declaration.blob_id
              AND occurrence.occurrence_id = declaration.occurrence_id
             WHERE module.blob_id = ?1
               AND module.module_name IN ('qualified_module', 'malformed_module')
             ORDER BY module.module_name",
        )
        .unwrap()
        .query_map([id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<i64>>(5)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        actual,
        expected
            .iter()
            .map(|(name, declaration, occurrence, name_occurrence, body)| {
                (
                    name.clone(),
                    *declaration,
                    *occurrence,
                    *name_occurrence,
                    "embedded".to_owned(),
                    *body,
                )
            })
            .collect::<Vec<_>>(),
        "reopen retains exact raw module declaration and occurrence identities"
    );

    for (_, declaration, _, _, _, _) in actual {
        let display_links: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM source_declaration_units
                 WHERE blob_id = ?1 AND declaration_id = ?2",
                rusqlite::params![id, declaration],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(display_links, 0, "raw module has no display bridge");
    }

    let projected_modules = conn
        .prepare(
            "SELECT module_name FROM rust_modules
             WHERE blob_id = ?1 ORDER BY ordinal",
        )
        .unwrap()
        .query_map([id], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        !projected_modules
            .iter()
            .any(|name| matches!(name.as_str(), "qualified_module" | "malformed_module"))
    );
    let projected_routes = conn
        .prepare(
            "SELECT module_name FROM rust_module_routes
             WHERE blob_id = ?1 ORDER BY ordinal",
        )
        .unwrap()
        .query_map([id], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        !projected_routes
            .iter()
            .any(|name| matches!(name.as_str(), "qualified_module" | "malformed_module"))
    );
    assert!(projected_routes.iter().any(|name| name == "retained"));
}
