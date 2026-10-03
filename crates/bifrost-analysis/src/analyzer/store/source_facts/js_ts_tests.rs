use std::cell::Cell;

use crate::analyzer::Language;
use crate::analyzer::store::AnalyzerStore;
use crate::analyzer::store::tests::{oid_for, parse_state};
use crate::analyzer::typescript::TypescriptAdapter;
use crate::inline_project::InlineTestProject;

const SOURCE: &str = "import * as M from './module'; interface Props { title: string } type Alias<T = string> = Props; export function run(cb: (props: Alias) => void): Props { throw 0; } function empty(): Props { throw 0; } const Tools = { parse(value: Props): Props { return value; } }; export { Tools }; export * from './other';";

#[test]
fn js_ts_source_facts_reopen_without_source_and_mount_exact_bridges() {
    let fixture = InlineTestProject::with_language(Language::TypeScript)
        .file("first/types.ts", SOURCE)
        .file("second/types.ts", SOURCE)
        .build();
    let file = fixture.file("first/types.ts");
    let second = fixture.file("second/types.ts");
    let state = parse_state(&TypescriptAdapter, &file);
    let expected = state.source_facts.as_ref().unwrap().js_ts.as_ref().unwrap();
    assert!(!expected.types.is_empty());
    assert!(!expected.declaration_bindings.is_empty());
    assert!(!expected.property_receivers.is_empty());
    assert!(
        expected
            .declarations
            .iter()
            .any(|declaration| declaration.parameters.as_ref().is_some_and(Vec::is_empty))
    );
    let oid = oid_for(SOURCE.as_bytes());
    let path = fixture.root().join("js-ts-source.db");
    {
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        store
            .write_parsed_blob(oid, "typescript:ts", &TypescriptAdapter, &state)
            .unwrap();
    }
    std::fs::remove_file(file.abs_path()).unwrap();
    std::fs::remove_file(second.abs_path()).unwrap();
    let store = AnalyzerStore::open_persistent(&path).unwrap();
    let generation = store.current_generation("typescript:ts").unwrap();
    let first = store
        .js_ts_source_facts(oid, generation, &TypescriptAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    let mounted = store
        .js_ts_source_facts(oid, generation, &TypescriptAdapter, &second, &|| true)
        .unwrap()
        .unwrap();
    assert_eq!(&first.facts, expected);
    assert_eq!(first.facts, mounted.facts);
    assert_eq!(
        first.source,
        state.source_facts.as_ref().unwrap().occurrences
    );
    assert_eq!(first.imports, state.source_facts.as_ref().unwrap().imports);
    assert!(!first.declaration_units.is_empty());
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
            .js_ts_source_facts(oid, generation, &TypescriptAdapter, &file, &|| {
                visits.set(visits.get() + 1);
                visits.get() < 5
            })
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .js_ts_source_facts(oid, generation, &TypescriptAdapter, &file, &|| true)
            .unwrap()
            .is_some()
    );
    store
        .conn
        .execute(|conn| {
            conn.execute("DELETE FROM blobs", [])?;
            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM source_js_ts_manifests", [], |row| {
                    row.get(0)
                })?;
            assert_eq!(count, 0, "blob deletion must cascade sealed source facts");
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
}

#[test]
fn js_ts_source_publication_distinguishes_empty_missing_and_sealed() {
    let fixture = InlineTestProject::with_language(Language::TypeScript)
        .file("empty.ts", "")
        .build();
    let file = fixture.file("empty.ts");
    let mut state = parse_state(&TypescriptAdapter, &file);
    let oid = oid_for(state.source.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("typescript:ts").unwrap();
    let family = state.source_facts.as_mut().unwrap().js_ts.take().unwrap();
    assert!(
        store
            .write_parsed_blob(oid, "typescript:ts", &TypescriptAdapter, &state)
            .is_err()
    );
    state.source_facts.as_mut().unwrap().js_ts = Some(family);
    store
        .write_parsed_blob(oid, "typescript:ts", &TypescriptAdapter, &state)
        .unwrap();
    let read = store
        .js_ts_source_facts(oid, generation, &TypescriptAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    assert!(read.facts.declarations.is_empty());
    assert!(read.facts.types.is_empty());
    store.conn.execute(|conn| {
        assert!(conn.execute("UPDATE source_js_ts_manifests SET payload_bytes = payload_bytes", []).is_err());
        assert!(conn.execute("UPDATE blob_meta SET js_ts_source_version = NULL", []).is_err());
        conn.execute_batch("DROP TRIGGER source_js_ts_manifests_no_delete_after_seal; DELETE FROM source_js_ts_manifests;")?;
        Ok::<_, crate::analyzer::store::StoreError>(())
    }).unwrap();
    assert!(
        store
            .js_ts_source_facts(oid, generation, &TypescriptAdapter, &file, &|| true)
            .is_err()
    );
}

#[test]
fn js_ts_source_reader_rejects_invalid_type_links() {
    let fixture = InlineTestProject::with_language(Language::TypeScript)
        .file("types.ts", SOURCE)
        .build();
    let file = fixture.file("types.ts");
    let state = parse_state(&TypescriptAdapter, &file);
    let oid = oid_for(SOURCE.as_bytes());
    for corruption in [
        "UPDATE source_js_ts_types SET child_id = type_id WHERE child_id IS NOT NULL",
        "UPDATE source_js_ts_types SET result_type_id = 0 WHERE kind <> 6 AND type_id > 0",
    ] {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store.current_generation("typescript:ts").unwrap();
        store
            .write_parsed_blob(oid, "typescript:ts", &TypescriptAdapter, &state)
            .unwrap();
        store
            .conn
            .execute(|conn| {
                conn.execute_batch("DROP TRIGGER source_js_ts_types_no_update_after_seal;")?;
                assert!(conn.execute(corruption, []).is_err());
                conn.execute_batch("PRAGMA ignore_check_constraints=ON;")?;
                assert!(conn.execute(corruption, [])? > 0);
                conn.execute_batch("PRAGMA ignore_check_constraints=OFF;")?;
                Ok::<_, crate::analyzer::store::StoreError>(())
            })
            .unwrap();
        assert!(
            store
                .js_ts_source_facts(oid, generation, &TypescriptAdapter, &file, &|| true)
                .is_err(),
            "corrupted type links were accepted: {corruption}"
        );
    }
}
