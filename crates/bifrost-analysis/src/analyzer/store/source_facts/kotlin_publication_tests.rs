use crate::analyzer::Language;
use crate::analyzer::kotlin::KotlinAdapter;
use crate::analyzer::store::AnalyzerStore;
use crate::analyzer::store::tests::{oid_for, parse_state};
use crate::analyzer::structural::facts::{FileFacts, STRUCTURAL_FACTS_VERSION};
use crate::analyzer::structural::kinds::NormalizedKind;
use crate::inline_project::InlineTestProject;
use brokk_bifrost_core::analyzer::structural::code::VocabularyCode;

#[test]
fn kotlin_metadata_bridges_are_required_sealed_and_repairable_without_visibility() {
    let source = "class Box { fun read(value: Int): Int = value }\n";
    let fixture = InlineTestProject::with_language(Language::Kotlin)
        .file("Box.kt", source)
        .build();
    let file = fixture.file("Box.kt");
    let state = parse_state(&KotlinAdapter, &file);
    assert!(!state.source_declaration_metadata.is_empty());
    assert!(
        state
            .source_facts
            .as_ref()
            .unwrap()
            .declaration_visibilities
            .is_none()
    );
    let oid = oid_for(source.as_bytes());
    let store = AnalyzerStore::open_ephemeral().expect("open store");
    let mut missing_links = state.clone();
    missing_links.source_declaration_metadata.clear();
    assert!(
        store
            .write_parsed_blob(oid, "kotlin", &KotlinAdapter, &missing_links)
            .is_err()
    );
    let mut missing_source = state.clone();
    missing_source.source_facts = None;
    assert!(
        store
            .write_parsed_blob(oid, "kotlin", &KotlinAdapter, &missing_source)
            .is_err()
    );

    store
        .write_parsed_blob(oid, "kotlin", &KotlinAdapter, &state)
        .unwrap();
    let expected_metadata_links = state.source_declaration_metadata.len() as i64;
    store.conn.execute(move |conn| {
        let (expected, actual): (i64, i64) = conn.query_row(
            "SELECT metadata_bridge_count, (SELECT COUNT(*) FROM source_declaration_metadata_bridges)
             FROM source_fact_manifests", [], |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(expected, expected_metadata_links);
        assert_eq!(actual, expected);
        for mutation in [
            "DELETE FROM source_declaration_metadata_bridges",
            "UPDATE source_declaration_metadata_bridges SET metadata_ordinal = metadata_ordinal + 1",
            "INSERT INTO source_declaration_metadata_bridges SELECT * FROM source_declaration_metadata_bridges",
            "UPDATE source_fact_manifests SET metadata_bridge_count = 0",
        ] {
            assert!(conn.execute(mutation, []).is_err(), "sealed mutation: {mutation}");
        }
        // Simulate damaged storage independently of the declared count. Readers
        // must reject the publication even though visibility is not requested.
        conn.execute_batch("DROP TRIGGER source_declaration_metadata_bridges_no_delete_after_seal;
            DELETE FROM source_declaration_metadata_bridges;")?;
        assert_eq!(conn.query_row("SELECT MAX(metadata_available) FROM unit_signature_metadata_values", [], |row| row.get::<_, i64>(0))?, 0);
        conn.execute_batch("DROP TRIGGER source_fact_manifests_no_reopen;
            UPDATE source_fact_manifests SET publication_state = 'building';")?;
        assert!(conn.execute("UPDATE source_fact_manifests SET publication_state = 'complete'", []).is_err());
        conn.execute("DELETE FROM blobs", [])?;
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM source_declaration_metadata_bridges", [], |row| row.get::<_, i64>(0))?, 0);
        Ok::<(), crate::analyzer::store::StoreError>(())
    }).unwrap();
    store
        .write_parsed_blob(oid, "kotlin", &KotlinAdapter, &state)
        .unwrap();
    assert_eq!(
        store
            .hydrate_file_state(oid, "kotlin", &KotlinAdapter, &file)
            .unwrap()
            .unwrap()
            .signature_metadata,
        state.signature_metadata
    );
    store
        .conn
        .execute(|conn| {
            conn.execute_batch(
                "DROP TRIGGER source_fact_manifests_no_direct_delete;
            DELETE FROM source_fact_manifests;",
            )?;
            assert_eq!(
                conn.query_row("SELECT available FROM source_fact_readiness", [], |row| row
                    .get::<_, i64>(0))?,
                0
            );
            Ok::<(), crate::analyzer::store::StoreError>(())
        })
        .unwrap();
}

#[test]
fn kotlin_canonical_publication_reopens_metadata_imports_and_structural_rows() {
    let source = "package sample\nimport other.Widget as Alias\nclass Box(val seed: Int) {\nconstructor(): this(0)\nfun read(value: Int = seed): Int = value\n}\n";
    let fixture = InlineTestProject::with_language(Language::Kotlin)
        .file("sample/Box.kt", source)
        .build();
    let file = fixture.file("sample/Box.kt");
    let state = parse_state(&KotlinAdapter, &file);
    let facts = state
        .source_facts
        .as_ref()
        .expect("canonical Kotlin source");
    let expected = FileFacts::from_source_and_rows(
        state.source.clone(),
        facts.occurrences.clone(),
        facts.structural.clone(),
    )
    .persisted_rows()
    .expect("structural publication");
    let constructors = expected
        .nodes
        .iter()
        .filter(|node| node.kind == NormalizedKind::Constructor.code())
        .collect::<Vec<_>>();
    assert_eq!(constructors.len(), 2, "primary and secondary constructors");
    for constructor in constructors {
        let name = constructor.name.expect("borrowed class name");
        assert_eq!(&source[name.start as usize..name.end as usize], "Box");
        assert!(
            name.end <= constructor.span.start,
            "class name precedes constructor"
        );
    }
    FileFacts::from_persisted_rows(source.to_owned(), expected.clone())
        .expect("constructor names hydrate through their recorded ancestors");
    let mut unrelated_name = expected.clone();
    let method_name = unrelated_name
        .nodes
        .iter()
        .find(|node| node.kind == NormalizedKind::Method.code())
        .expect("read method")
        .name;
    unrelated_name
        .nodes
        .iter_mut()
        .find(|node| node.kind == NormalizedKind::Constructor.code())
        .expect("constructor")
        .name = method_name;
    assert!(
        FileFacts::from_persisted_rows(source.to_owned(), unrelated_name).is_err(),
        "a contained token that is not an ancestor name must not hydrate"
    );
    let oid = oid_for(source.as_bytes());
    let path = fixture.root().join("canonical-kotlin.db");
    let store = AnalyzerStore::open_persistent(&path).expect("open store");
    store
        .write_parsed_blob(oid, "kotlin", &KotlinAdapter, &state)
        .expect("publish Kotlin");
    drop(store);
    let store = AnalyzerStore::open_persistent(&path).expect("reopen store");
    let generation = store.current_generation("kotlin").expect("generation");
    assert_eq!(
        store
            .load_structural_facts_rows(oid, "kotlin", generation, STRUCTURAL_FACTS_VERSION)
            .expect("canonical structural read"),
        Some(expected)
    );
    let hydrated = store
        .hydrate_file_state(oid, "kotlin", &KotlinAdapter, &file)
        .expect("hydrate Kotlin")
        .expect("published Kotlin state");
    assert_eq!(hydrated.imports, state.imports);
    assert_eq!(hydrated.signature_metadata, state.signature_metadata);
    let conn = store.read_conn().expect("read store");
    let (canonical, links, metadata_links): (i64, i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM source_fact_manifests),
                (SELECT count(*) FROM source_declaration_units),
                (SELECT count(*) FROM source_declaration_metadata_bridges)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("publication authority census");
    assert_eq!(canonical, 1);
    assert_eq!(links, state.source_declaration_units.len() as i64);
    assert_eq!(
        metadata_links,
        state.source_declaration_metadata.len() as i64
    );
    drop(conn);
}

/// A structural name outside its node's span is valid only when it is an
/// ancestor's name, as a Kotlin constructor borrows its class name. The store
/// writer checks this over the facts in memory before it inserts them.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "is no ancestor's name")]
fn kotlin_constructor_cannot_store_an_unrelated_name() {
    use brokk_bifrost_core::analyzer::structural::facts::StructuralFactRows;
    let source = "package sample\nclass Box(val seed: Int) {\nconstructor(): this(0)\nfun read(value: Int = seed): Int = value\n}\n";
    let fixture = InlineTestProject::with_language(Language::Kotlin)
        .file("sample/Box.kt", source)
        .build();
    let state = parse_state(&KotlinAdapter, &fixture.file("sample/Box.kt"));
    let mut facts = state.source_facts.clone().expect("canonical Kotlin source");
    // The real facts store: both constructors carry the class name.
    facts.assert_storable();
    let (mut nodes, roles, occurrence_roles) = facts.structural.into_parts();
    let method_name = nodes
        .iter()
        .find(|node| node.kind == NormalizedKind::Method)
        .and_then(|node| node.name)
        .expect("read method name");
    nodes
        .iter_mut()
        .find(|node| node.kind == NormalizedKind::Constructor)
        .expect("constructor")
        .name = Some(method_name);
    facts.structural = StructuralFactRows::new(nodes, roles, occurrence_roles);
    facts.assert_storable();
}
