use std::cell::Cell;

use crate::analyzer::Language;
use crate::analyzer::php::PhpAdapter;
use crate::analyzer::store::AnalyzerStore;
use crate::analyzer::store::StoreError;
use crate::analyzer::store::tests::{oid_for, parse_state};
use crate::inline_project::InlineTestProject;

const SOURCE: &str = r#"<?php
namespace Example;

use Vendor\Package as PackageAlias;
use Vendor\{A as AliasA, B as AliasB};

class Base {}
class Child extends Base {
    /** @var list<int> */
    public array $items;

    public function __construct() {
        $this->items = [];
    }
}

function make(?PackageAlias $value): Child { return new Child(); }
"#;

#[test]
fn php_declaration_source_facts_reopen_without_source_and_mount_exact_bridges() {
    let fixture = InlineTestProject::with_language(Language::Php)
        .file("first/types.php", SOURCE)
        .file("second/types.php", SOURCE)
        .build();
    let file = fixture.file("first/types.php");
    let second = fixture.file("second/types.php");
    let state = parse_state(&PhpAdapter, &file);
    let expected = state.source_facts.as_ref().unwrap().php.as_ref().unwrap();
    assert!(!expected.contexts.is_empty());
    assert!(!expected.declarations.is_empty());
    let oid = oid_for(SOURCE.as_bytes());
    let path = fixture.root().join("php-source.db");
    {
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        store
            .write_parsed_blob(oid, "php", &PhpAdapter, &state)
            .unwrap();
        store
            .conn
            .execute(move |conn| {
                let mut statement = conn.prepare(
                    "SELECT imports.alias, imports.identifier
                       FROM source_php_aliases AS aliases
                       JOIN source_imports AS imports
                         ON imports.blob_id = aliases.blob_id
                        AND imports.import_id = aliases.source_import_id
                      WHERE aliases.blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'php')
                      ORDER BY aliases.alias_id",
                )?;
                let rows = statement
                    .query_map([oid.to_string()], |row| {
                        Ok((
                            row.get::<_, Option<String>>(0)?,
                            row.get::<_, Option<String>>(1)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                assert!(rows
                    .iter()
                    .any(|(alias, _)| alias.as_deref() == Some("AliasA")));
                assert!(rows
                    .iter()
                    .any(|(alias, _)| alias.as_deref() == Some("AliasB")));
                assert!(rows.iter().all(|(alias, identifier)| {
                    alias.as_deref().is_some_and(|alias| !alias.is_empty())
                        && identifier
                            .as_deref()
                            .is_some_and(|identifier| !identifier.is_empty())
                }));
                Ok::<_, StoreError>(())
            })
            .unwrap();
    }
    std::fs::remove_file(file.abs_path()).unwrap();
    let store = AnalyzerStore::open_persistent(&path).unwrap();
    let generation = store.current_generation("php").unwrap();
    let first = store
        .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    let mounted = store
        .php_source_facts(oid, generation, &PhpAdapter, &second, &|| true)
        .unwrap()
        .unwrap();
    assert_eq!(&first.facts, expected);
    assert_eq!(first.facts, mounted.facts);
    assert_eq!(first.imports, state.source_facts.as_ref().unwrap().imports);
    assert_eq!(first.imports, mounted.imports);
    assert_eq!(
        first.source,
        state.source_facts.as_ref().unwrap().occurrences
    );
    assert!(
        first
            .declaration_units
            .values()
            .flatten()
            .all(|unit| unit.source() == &file)
    );
    assert!(
        mounted
            .declaration_units
            .values()
            .flatten()
            .all(|unit| unit.source() == &second)
    );
    let visits = Cell::new(0);
    assert!(
        store
            .php_source_facts(oid, generation, &PhpAdapter, &file, &|| {
                visits.set(visits.get() + 1);
                visits.get() < 5
            })
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
            .unwrap()
            .is_some()
    );
}

#[test]
fn php_source_publication_rejects_invalid_context_and_sealed_mutation() {
    let fixture = InlineTestProject::with_language(Language::Php)
        .file("types.php", SOURCE)
        .build();
    let file = fixture.file("types.php");
    let state = parse_state(&PhpAdapter, &file);
    let oid = oid_for(SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("php").unwrap();
    store
        .write_parsed_blob(oid, "php", &PhpAdapter, &state)
        .unwrap();
    store
        .conn
        .execute(|conn| {
            assert!(
                conn.execute("UPDATE source_php_contexts SET namespace = namespace", [])
                    .is_err()
            );
            assert!(
                conn.execute(
                    "UPDATE source_php_manifests SET payload_bytes = payload_bytes",
                    []
                )
                .is_err()
            );
            conn.execute_batch(
                "DROP TRIGGER source_php_declarations_no_update_after_seal;",
            )?;
            assert!(conn.execute(
                "UPDATE source_php_declarations SET context_id = (SELECT MAX(context_id) + 1 FROM source_php_contexts)",
                [],
            ).is_err());
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
    assert!(
        store
            .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
            .unwrap()
            .is_some()
    );
}

#[test]
fn php_source_requires_a_sealed_canonical_source_manifest() {
    let fixture = InlineTestProject::with_language(Language::Php)
        .file("types.php", SOURCE)
        .build();
    let file = fixture.file("types.php");
    let state = parse_state(&PhpAdapter, &file);
    let oid = oid_for(SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("php").unwrap();
    store
        .write_parsed_blob(oid, "php", &PhpAdapter, &state)
        .unwrap();
    store
        .conn
        .execute(|conn| {
            conn.execute_batch("DROP TRIGGER source_fact_manifests_no_reopen; UPDATE source_fact_manifests SET publication_state = 'building';")?;
            Ok::<_, StoreError>(())
        })
        .unwrap();
    assert!(
        store
            .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
            .is_err()
    );
}

#[test]
fn php_source_publication_count_and_cascade_are_enforced() {
    let fixture = InlineTestProject::with_language(Language::Php)
        .file("types.php", "<?php\n")
        .build();
    let file = fixture.file("types.php");
    let state = parse_state(&PhpAdapter, &file);
    let oid = oid_for(b"<?php\n");
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("php").unwrap();
    store
        .write_parsed_blob(oid, "php", &PhpAdapter, &state)
        .unwrap();
    assert!(
        store
            .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
            .unwrap()
            .is_some()
    );
    store
        .conn
        .execute(|conn| {
            conn.execute("DELETE FROM blobs", [])?;
            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM source_php_manifests", [], |row| {
                    row.get(0)
                })?;
            assert_eq!(count, 0, "blob deletion must cascade PHP publications");
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
}

#[test]
fn php_source_populated_cascade_removes_nested_rows() {
    let fixture = InlineTestProject::with_language(Language::Php)
        .file("types.php", SOURCE)
        .build();
    let file = fixture.file("types.php");
    let state = parse_state(&PhpAdapter, &file);
    let oid = oid_for(SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, "php", &PhpAdapter, &state)
        .unwrap();
    store
        .conn
        .execute(|conn| {
            let writes: i64 =
                conn.query_row("SELECT COUNT(*) FROM source_php_writes", [], |row| {
                    row.get(0)
                })?;
            assert!(writes > 0);
            conn.execute("DELETE FROM blobs", [])?;
            for table in [
                "source_php_writes",
                "source_php_declarations",
                "source_php_aliases",
                "source_php_manifests",
            ] {
                let count: i64 =
                    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })?;
                assert_eq!(count, 0, "blob deletion must cascade {table}");
            }
            Ok::<_, StoreError>(())
        })
        .unwrap();
}

#[test]
fn php_source_lookup_seeks_populated_publications_before_and_after_statistics() {
    let fixture = InlineTestProject::with_language(Language::Php)
        .file("types.php", SOURCE)
        .build();
    let file = fixture.file("types.php");
    let state = parse_state(&PhpAdapter, &file);
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("php").unwrap();
    let oid = oid_for(SOURCE.as_bytes());
    store
        .write_parsed_blob(oid, "php", &PhpAdapter, &state)
        .unwrap();
    for index in 0..32 {
        let other = oid_for(format!("planner PHP publication {index}").as_bytes());
        store
            .write_parsed_blob(other, "php", &PhpAdapter, &state)
            .unwrap();
    }
    for refreshed in [false, true] {
        if refreshed {
            store.refresh_planner_statistics().unwrap();
        }
        let conn = store.read_conn().unwrap();
        let plan = conn
            .prepare(&format!(
                "EXPLAIN QUERY PLAN {}",
                crate::analyzer::php::source_storage::PHP_SOURCE_HEADER_SQL
            ))
            .unwrap()
            .query_map(
                rusqlite::params![
                    oid.to_string(),
                    generation.get(),
                    1,
                    super::SOURCE_FACTS_VERSION
                ],
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            plan.iter()
                .any(|step| step.contains("SEARCH blob") && step.contains("INDEX")),
            "{plan:#?}"
        );
        assert!(
            plan.iter().all(|step| !step.starts_with("SCAN ")),
            "canonical PHP lookup must seek the content identity: {plan:#?}"
        );
        drop(conn);
        assert!(
            store
                .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn php_source_missing_family_is_unavailable_and_repaired_by_publication() {
    let fixture = InlineTestProject::with_language(Language::Php)
        .file("empty.php", "<?php\n")
        .build();
    let file = fixture.file("empty.php");
    let mut state = parse_state(&PhpAdapter, &file);
    let oid = oid_for(state.source.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("php").unwrap();
    let facts = state.source_facts.as_mut().unwrap().php.take().unwrap();
    assert!(
        store
            .write_parsed_blob(oid, "php", &PhpAdapter, &state)
            .is_err()
    );
    state.source_facts.as_mut().unwrap().php = Some(facts);
    store
        .write_parsed_blob(oid, "php", &PhpAdapter, &state)
        .unwrap();
    assert!(
        store
            .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
            .unwrap()
            .unwrap()
            .facts
            .declarations
            .is_empty()
    );
    store.conn.execute(|conn| {
        conn.execute("UPDATE blob_meta SET is_complete = 0", [])?;
        assert!(conn.execute("UPDATE blob_meta SET php_source_version = NULL", []).is_err());
        conn.execute("UPDATE blob_meta SET is_complete = 1", [])?;
        conn.execute_batch("DROP TRIGGER source_php_manifests_no_delete_after_seal; DELETE FROM source_php_manifests;")?;
        let available: i64 = conn.query_row("SELECT available FROM source_fact_readiness", [], |row| row.get(0))?;
        assert_eq!(available, 0);
        Ok::<_, StoreError>(())
    }).unwrap();
    assert!(
        store
            .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
            .is_err()
    );
    store
        .write_parsed_blob(oid, "php", &PhpAdapter, &state)
        .unwrap();
    assert!(
        store
            .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
            .unwrap()
            .is_some()
    );
}

#[test]
fn php_source_rejects_payload_accounting_corruption() {
    let fixture = InlineTestProject::with_language(Language::Php)
        .file("types.php", SOURCE)
        .build();
    let file = fixture.file("types.php");
    let state = parse_state(&PhpAdapter, &file);
    let oid = oid_for(SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("php").unwrap();
    store
        .write_parsed_blob(oid, "php", &PhpAdapter, &state)
        .unwrap();
    store.conn.execute(|conn| {
        conn.execute_batch("DROP TRIGGER source_php_manifests_no_update_after_seal; UPDATE source_php_manifests SET payload_bytes = payload_bytes + 1;")?;
        Ok::<_, StoreError>(())
    }).unwrap();
    assert!(
        store
            .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
            .is_err()
    );
}

#[test]
fn php_source_properties_preserve_sparse_shared_declaration_ids() {
    let fixture = InlineTestProject::with_language(Language::Php)
        .file("types.php", SOURCE)
        .build();
    let file = fixture.file("types.php");
    let mut state = parse_state(&PhpAdapter, &file);
    let facts = state.source_facts.as_mut().unwrap().php.as_mut().unwrap();
    // A shared declaration can have no PHP extension row. Later PHP rows
    // retain their shared identities; their vector positions are not IDs.
    facts.declarations.remove(0);
    let expected = facts.clone();
    assert!(expected.declarations[0].declaration.get() > 0);
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("php").unwrap();
    let oid = oid_for(SOURCE.as_bytes());
    store
        .write_parsed_blob(oid, "php", &PhpAdapter, &state)
        .unwrap();
    let read = store
        .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    assert_eq!(read.facts, expected);
}
