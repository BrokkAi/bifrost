use std::cell::Cell;

#[test]
fn go_source_reader_rejects_corrupt_type_edges_without_panicking() {
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("types.go", SOURCE)
        .build();
    let file = fixture.file("types.go");
    let state = parse_state(&GoAdapter, &file);
    let oid = oid_for(SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("go").unwrap();
    store
        .write_parsed_blob(oid, "go", &GoAdapter, &state)
        .unwrap();
    store
        .conn
        .execute(|conn| {
            assert!(
                conn.execute("UPDATE source_go_types SET child1=type_id WHERE kind=1", [])
                    .is_err()
            );
            conn.execute_batch(
                "DROP TRIGGER source_go_types_no_update_after_seal;
            PRAGMA ignore_check_constraints=ON;
            UPDATE source_go_types SET child1=type_id WHERE kind=1;
            PRAGMA ignore_check_constraints=OFF;",
            )?;
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
    assert!(
        store
            .go_source_facts(oid, generation, &GoAdapter, &file, &|| true)
            .is_err()
    );
}

#[test]
fn go_source_lookup_seeks_populated_publications_before_and_after_statistics() {
    use rusqlite::params;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("types.go", SOURCE)
        .build();
    let file = fixture.file("types.go");
    let state = parse_state(&GoAdapter, &file);
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("go").unwrap();
    let oid = oid_for(SOURCE.as_bytes());
    store
        .write_parsed_blob(oid, "go", &GoAdapter, &state)
        .unwrap();
    // Distinct content identities populate the publication inventory without
    // introducing extra parser work into a query-planner regression.
    for index in 0..32 {
        let other = oid_for(format!("planner publication {index}").as_bytes());
        store
            .write_parsed_blob(other, "go", &GoAdapter, &state)
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
                crate::analyzer::go::source_storage::GO_SOURCE_HEADER_SQL
            ))
            .unwrap()
            .query_map(
                params![
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
            "source publication lookup must seek its exact blob: {plan:#?}"
        );
        drop(conn);
        assert!(
            store
                .go_source_facts(oid, generation, &GoAdapter, &file, &|| true)
                .unwrap()
                .is_some()
        );
    }
    store
        .conn
        .execute(|conn| {
            conn.execute("DELETE FROM blobs", [])?;
            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM source_go_manifests", [], |row| {
                    row.get(0)
                })?;
            assert_eq!(
                count, 0,
                "blob deletion must cascade sealed source publications"
            );
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
}

use crate::analyzer::Language;
use crate::analyzer::go::GoAdapter;
use crate::analyzer::store::AnalyzerStore;
use crate::analyzer::store::tests::{oid_for, parse_state};
use crate::inline_project::InlineTestProject;

const SOURCE: &str = r#"package example
type Base struct{}
type Alias = Base
type Outer struct { X, Y struct { Nested *Base }; Base }
type Service interface { Run(a, b [4]*Base, tail ...chan<- Base) (Base, error) }
func (value *Outer) Run(a, b [4]*Base, tail ...chan<- Base) (Base, error) { return Base{}, nil }
func Make() *Outer { return &Outer{} }
"#;

#[test]
fn go_source_reader_keeps_unversioned_build_selection_metadata_unknown() {
    use rusqlite::params;

    let fixture = InlineTestProject::with_language(Language::Go)
        .file("types.go", SOURCE)
        .build();
    let file = fixture.file("types.go");
    let state = parse_state(&GoAdapter, &file);
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("go").unwrap();
    let oid = oid_for(SOURCE.as_bytes());
    store
        .write_parsed_blob(oid, "go", &GoAdapter, &state)
        .unwrap();
    let oid_text = oid.to_string();
    store
        .conn
        .execute(move |conn| {
            conn.execute_batch("DROP TRIGGER source_go_manifests_no_update_after_seal;")?;
            conn.execute(
                "UPDATE source_go_manifests SET build_selection_facts_version=0 WHERE blob_id=(SELECT id FROM blobs WHERE blob_oid=?1 AND lang='go')",
                params![oid_text],
            )?;
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();

    let facts = store
        .go_source_facts(oid, generation, &GoAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    assert_eq!(facts.facts.has_build_constraints, None);
}

#[test]
fn go_declaration_source_facts_reopen_without_source_and_mount_exact_bridges() {
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("first/types.go", SOURCE)
        .file("second/types.go", SOURCE)
        .build();
    let file = fixture.file("first/types.go");
    let second = fixture.file("second/types.go");
    let state = parse_state(&GoAdapter, &file);
    let expected = state.source_facts.as_ref().unwrap().go.as_ref().unwrap();
    assert!(!expected.callables.is_empty());
    assert!(!expected.aliases.is_empty());
    let oid = oid_for(SOURCE.as_bytes());
    let path = fixture.root().join("go-source.db");
    {
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        store
            .write_parsed_blob(oid, "go", &GoAdapter, &state)
            .unwrap();
    }
    std::fs::remove_file(file.abs_path()).unwrap();
    let store = AnalyzerStore::open_persistent(&path).unwrap();
    let generation = store.current_generation("go").unwrap();
    let first = store
        .go_source_facts(oid, generation, &GoAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    let mounted = store
        .go_source_facts(oid, generation, &GoAdapter, &second, &|| true)
        .unwrap()
        .unwrap();
    assert_eq!(&first.facts, expected);
    assert_eq!(first.facts, mounted.facts);
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
    let nested = first
        .facts
        .fields
        .iter()
        .find(|field| field.name == "Nested")
        .unwrap();
    let units = &first.declaration_units[&nested.declaration];
    assert_eq!(
        units.len(),
        2,
        "one written nested field must retain both projections: {units:?}"
    );
    let visits = Cell::new(0);
    assert!(
        store
            .go_source_facts(oid, generation, &GoAdapter, &file, &|| {
                visits.set(visits.get() + 1);
                visits.get() < 5
            })
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .go_source_facts(oid, generation, &GoAdapter, &file, &|| true)
            .unwrap()
            .is_some()
    );
}

#[test]
fn go_source_publication_distinguishes_empty_missing_and_sealed() {
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("empty.go", "package example\n")
        .build();
    let file = fixture.file("empty.go");
    let mut state = parse_state(&GoAdapter, &file);
    let oid = oid_for(state.source.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("go").unwrap();
    let facts = state.source_facts.as_mut().unwrap().go.take().unwrap();
    assert!(
        store
            .write_parsed_blob(oid, "go", &GoAdapter, &state)
            .is_err()
    );
    state.source_facts.as_mut().unwrap().go = Some(facts);
    store
        .write_parsed_blob(oid, "go", &GoAdapter, &state)
        .unwrap();
    let read = store
        .go_source_facts(oid, generation, &GoAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    assert!(read.facts.declarations.is_empty());
    assert!(read.facts.callables.is_empty());
    store
        .conn
        .execute(|conn| {
            assert!(
                conn.execute(
                    "UPDATE source_go_manifests SET payload_bytes = payload_bytes",
                    []
                )
                .is_err()
            );
            conn.execute("UPDATE blob_meta SET is_complete = 0", [])?;
            assert!(
                conn.execute("UPDATE blob_meta SET go_source_version = NULL", [])
                    .is_err()
            );
            conn.execute("UPDATE blob_meta SET is_complete = 1", [])?;
            conn.execute_batch(
                "DROP TRIGGER source_go_manifests_no_delete_after_seal;
                            DELETE FROM source_go_manifests;",
            )?;
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
    assert!(
        store
            .go_source_facts(oid, generation, &GoAdapter, &file, &|| true)
            .is_err()
    );
    store
        .write_parsed_blob(oid, "go", &GoAdapter, &state)
        .unwrap();
    assert!(
        store
            .go_source_facts(oid, generation, &GoAdapter, &file, &|| true)
            .unwrap()
            .is_some()
    );
}
