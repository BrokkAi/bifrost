use brokk_bifrost_core::analyzer::model::{CallableArity, JavaTypeConstructorShape};
use brokk_bifrost_core::hash::HashMap;
use rusqlite::params;

use crate::analyzer::java::JavaAdapter;
use crate::analyzer::store::tests::{oid_for, parse_state};
use crate::analyzer::store::{AnalyzerStore, StoreError};
use crate::analyzer::{Language, SignatureMetadata};
use crate::inline_project::InlineTestProject;

const SOURCE: &str = r#"interface Contract {}
class Plain {}
class Explicit { Explicit(int value) {} }
record Pair(int value, String... labels) {}
class Host {
    void body() {
        class Local {}
        Object anonymous = new Object() {};
    }
}
"#;

#[test]
fn java_type_constructor_shapes_survive_all_metadata_readers_and_reopen() {
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("Shapes.java", SOURCE)
        .build();
    let file = fixture.file("Shapes.java");
    let state = parse_state(&JavaAdapter, &file);
    let oid = oid_for(SOURCE.as_bytes());
    let path = fixture.root().join("constructor-shapes.db");
    for (name, expected) in [
        ("Contract", JavaTypeConstructorShape::NoImplicit),
        ("Plain", JavaTypeConstructorShape::Default),
        ("Explicit", JavaTypeConstructorShape::NoImplicit),
        (
            "Pair",
            JavaTypeConstructorShape::RecordCanonical(CallableArity::new(1, 2, true)),
        ),
        ("Local", JavaTypeConstructorShape::Default),
    ] {
        let (_, metadata) = state
            .signature_metadata
            .iter()
            .find(|(unit, _)| unit.is_class() && unit.identifier() == name)
            .expect("source-owned type metadata");
        assert!(
            metadata
                .iter()
                .all(|row| row.java_type_constructor_shape() == Some(expected)),
            "unexpected constructor shape for {name}: {metadata:?}"
        );
    }
    assert!(
        state
            .signature_metadata
            .iter()
            .any(|(unit, _)| unit.is_synthetic() && unit.is_class())
    );
    for (unit, metadata) in &state.signature_metadata {
        if unit.is_synthetic() {
            assert!(
                metadata
                    .iter()
                    .all(|row| row.java_type_constructor_shape().is_none())
            );
        }
    }
    {
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let generation = store.current_generation("java").unwrap();
        store
            .write_parsed_blob_at_generation(oid, "java", generation, &JavaAdapter, &state)
            .unwrap();
    }
    let store = AnalyzerStore::open_persistent(&path).unwrap();
    let generation = store.current_generation("java").unwrap();
    let hydrated = store
        .hydrate_file_state_with_source(oid, "java", generation, &JavaAdapter, &file, SOURCE)
        .unwrap()
        .unwrap();
    assert_eq!(hydrated.signature_metadata, state.signature_metadata);
    let bulk = store
        .hydrate_file_states(
            &[(file.clone(), oid)],
            "java",
            &JavaAdapter,
            &HashMap::from_iter([(file.clone(), SOURCE.to_owned())]),
        )
        .unwrap();
    assert_eq!(bulk[&file].signature_metadata, state.signature_metadata);
    for (unit, expected) in &state.signature_metadata {
        assert_eq!(
            store
                .signature_metadata_for_unit(oid, "java", generation, unit)
                .unwrap(),
            *expected
        );
        let bounded = store
            .signature_metadata_for_unit_limited(oid, "java", generation, unit, expected.len() + 1)
            .unwrap();
        assert_eq!(bounded.rows, *expected);
    }
    let rows = store.usage_fact_rows_by_lang("java").unwrap();
    assert!(rows.iter().any(|row| {
        row.signature_metadata.as_ref().is_some_and(|metadata| {
            metadata.java_type_constructor_shape() == Some(JavaTypeConstructorShape::Default)
        })
    }));
}

#[test]
fn missing_java_type_constructor_metadata_fails_publication_atomically() {
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("Plain.java", "class Plain {}")
        .build();
    let state = parse_state(&JavaAdapter, &fixture.file("Plain.java"));
    let target = state
        .signature_metadata
        .keys()
        .find(|unit| unit.is_class())
        .unwrap()
        .clone();
    for missing_entire_row in [false, true] {
        let mut missing = state.clone();
        if missing_entire_row {
            missing.signature_metadata.remove(&target);
            missing
                .signature_metadata_signature_ordinals
                .remove(&target);
            missing
                .source_declaration_metadata
                .retain(|link| link.unit != target);
        } else {
            let original = &missing.signature_metadata[&target][0];
            let metadata = SignatureMetadata::new(original.label(), Vec::new())
                .with_source_declared_visibility(original.callable_declared_visibility().unwrap());
            missing
                .signature_metadata
                .insert(target.clone(), vec![metadata]);
        }
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store.current_generation("java").unwrap();
        let result = store.write_parsed_blob_at_generation(
            oid_for(b"missing-constructor-shape"),
            "java",
            generation,
            &JavaAdapter,
            &missing,
        );
        assert!(
            result.is_err(),
            "missing shape must reject publication: {missing_entire_row}"
        );
        let conn = store.read_conn().unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}

#[test]
fn damaged_java_type_constructor_shape_is_unavailable_not_no_implicit_constructor() {
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("Plain.java", "class Plain {}")
        .build();
    let file = fixture.file("Plain.java");
    let state = parse_state(&JavaAdapter, &file);
    let target = state
        .signature_metadata
        .keys()
        .find(|unit| unit.is_class())
        .unwrap();
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("java").unwrap();
    let oid = oid_for(b"class Plain {}");
    store
        .write_parsed_blob_at_generation(oid, "java", generation, &JavaAdapter, &state)
        .unwrap();
    assert!(
        store
            .signature_metadata_for_unit(oid, "java", generation, target)
            .is_ok()
    );
    store
        .conn
        .execute(move |conn| {
            assert!(
                conn.execute(
                    "UPDATE unit_signature_metadata SET java_constructor_shape = NULL",
                    []
                )
                .is_err()
            );
            assert!(
                conn.execute(
                    "UPDATE blob_meta SET java_type_constructor_version = NULL",
                    []
                )
                .is_err()
            );
            // Invalidation cannot turn a published requirement into legacy
            // metadata. Ordinary replacement deletes the root blob instead.
            conn.execute("UPDATE blob_meta SET is_complete = 0", [])?;
            assert!(
                conn.execute(
                    "UPDATE blob_meta SET java_type_constructor_version = NULL",
                    []
                )
                .is_err(),
                "the constructor requirement must survive published-blob invalidation"
            );
            conn.execute("UPDATE blob_meta SET is_complete = 1", [])?;
            conn.execute_batch("DROP TRIGGER unit_signature_metadata_no_update_after_pair_seal;")?;
            conn.execute(
                "UPDATE unit_signature_metadata SET java_constructor_shape = NULL,
                java_constructor_arity_required = NULL, java_constructor_arity_total = NULL,
                java_constructor_arity_repeated = NULL
             WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java')",
                params![oid.to_string()],
            )?;
            Ok::<(), StoreError>(())
        })
        .unwrap();
    assert!(
        store
            .signature_metadata_for_unit(oid, "java", generation, target)
            .is_err()
    );
    assert!(
        store
            .signature_metadata_for_unit_limited(oid, "java", generation, target, 10)
            .is_err()
    );
    assert!(
        store
            .hydrate_file_state_with_source(
                oid,
                "java",
                generation,
                &JavaAdapter,
                &file,
                "class Plain {}",
            )
            .is_err()
    );
    assert!(
        store
            .hydrate_file_states(
                &[(file.clone(), oid)],
                "java",
                &JavaAdapter,
                &HashMap::from_iter([(file, "class Plain {}".to_owned())]),
            )
            .is_err()
    );
    assert!(store.usage_fact_rows_by_lang("java").is_err());
}
