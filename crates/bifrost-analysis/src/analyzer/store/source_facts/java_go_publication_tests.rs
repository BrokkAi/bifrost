//! Java and Go publication coverage for the shared canonical source contract.

use crate::analyzer::store_bridge::AnalyzerStoreEngineExt;
use brokk_bifrost_test_macros::hardwon;

use std::sync::Arc;

use crate::CancellationToken;

use crate::analyzer::Language;

use crate::analyzer::java::JavaAdapter;

use crate::analyzer::store::test_support::oid_for;
use crate::analyzer::store::test_support::parse_state;

use crate::analyzer::store::AnalyzerStore;
use crate::analyzer::store::PersistBatchTargets;

use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;

use crate::inline_project::InlineTestProject;

#[test]
fn java_shared_visibility_metadata_survives_file_state_and_reopen() {
    use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
    use brokk_bifrost_core::hash::HashMap;

    let source = r#"interface Contract {
    void run();
    private void hidden() {}
}
enum Choice { ONE; Choice() {} }
record Pair(int left, int right) {
    public Pair {}
}
class Container {
    void ordinary() {
        class Local { public void localMember() {} }
        Object value = new Object() { public void anonymousMember() {} };
    }
}
"#;
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("src/Container.java", source)
        .build();
    let file = fixture.file("src/Container.java");
    let state = parse_state(&JavaAdapter, &file);
    let facts = state.source_facts.as_ref().expect("Java source facts");
    let visibility = facts
        .declaration_visibilities
        .as_ref()
        .expect("Java publishes source visibility")
        .iter()
        .map(|fact| (fact.declaration, fact.visibility))
        .collect::<HashMap<_, _>>();
    assert!(!state.source_declaration_metadata.is_empty());
    for link in &state.source_declaration_metadata {
        let metadata = &state.signature_metadata[&link.unit][link.metadata_ordinal];
        assert_eq!(
            metadata.callable_declared_visibility(),
            Some(visibility[&link.declaration]),
            "exact source/metadata link for {link:?}"
        );
    }
    for (name, expected) in [
        ("run", DeclaredVisibility::Public),
        ("hidden", DeclaredVisibility::Private),
        ("Choice", DeclaredVisibility::Private),
        ("Pair", DeclaredVisibility::Public),
        ("ordinary", DeclaredVisibility::PackagePrivate),
        ("localMember", DeclaredVisibility::Public),
        ("anonymousMember", DeclaredVisibility::Public),
    ] {
        let unit = state
            .declarations
            .iter()
            .find(|unit| unit.is_function() && unit.identifier() == name)
            .unwrap_or_else(|| panic!("missing written callable {name}"));
        assert!(
            state.signature_metadata[unit].iter().all(|metadata| {
                metadata.callable_modifiers_recorded()
                    && metadata.callable_declared_visibility() == Some(expected)
            }),
            "{unit:?}: {:?}",
            state.signature_metadata[unit]
        );
    }
    assert!(
        state
            .signature_metadata
            .keys()
            .any(|unit| unit.is_synthetic())
    );
    assert!(
        state
            .source_declaration_metadata
            .iter()
            .all(|link| !link.unit.is_synthetic()),
        "synthetic class metadata must not manufacture source identities"
    );

    let oid = oid_for(source.as_bytes());
    let store_path = fixture.root().join("java-shared-visibility.db");
    let store = AnalyzerStore::open_persistent(&store_path).expect("open visibility store");
    store
        .write_parsed_blob(oid, "java", &JavaAdapter, &state)
        .expect("publish shared producer output");
    drop(store);
    let reopened = AnalyzerStore::open_persistent(&store_path).expect("reopen visibility store");
    let hydrated = reopened
        .hydrate_file_states(
            &[(file.clone(), oid)],
            "java",
            &JavaAdapter,
            &HashMap::default(),
        )
        .expect("hydrate metadata after reopen");
    assert_eq!(
        hydrated[&file].signature_metadata, state.signature_metadata,
        "all metadata alternatives and synthetic rows must survive publication"
    );
}

#[test]
fn failed_and_cancelled_java_publications_leave_no_partial_rows_and_retry() {
    let source = "class C { void run() { int value = 1; value++; } }\n";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("src/C.java", source)
        .build();
    let file = fixture.file("src/C.java");
    let state = Arc::new(parse_state(&JavaAdapter, &file));
    let store = AnalyzerStore::open_ephemeral().expect("open publication store");
    let generation = store.current_generation("java").expect("Java generation");
    let assert_no_publication_rows = |oid| {
        assert_eq!(
            store
                .content_row_count(oid, "java")
                .expect("content row count"),
            0
        );
        let conn = store.read_conn().expect("read failed publication store");
        let canonical_rows: i64 = conn
            .query_row(
                "SELECT
                    (SELECT count(*) FROM source_fact_manifests WHERE blob_id =
                        (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))
                  + (SELECT count(*) FROM source_occurrences WHERE blob_id =
                        (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))
                  + (SELECT count(*) FROM source_imports WHERE blob_id =
                        (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))
                  + (SELECT count(*) FROM source_import_segments WHERE blob_id =
                        (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))
                  + (SELECT count(*) FROM source_import_scopes WHERE blob_id =
                        (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))
                  + (SELECT count(*) FROM source_import_prefixes WHERE blob_id =
                        (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))
                  + (SELECT count(*) FROM source_declarations WHERE blob_id =
                        (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))
                  + (SELECT count(*) FROM source_declaration_units WHERE blob_id =
                        (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))
                  + (SELECT count(*) FROM source_structural_facts WHERE blob_id =
                        (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))
                  + (SELECT count(*) FROM resolution_semantic_sites WHERE blob_id =
                        (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))",
                [oid.to_string()],
                |row| row.get(0),
            )
            .expect("canonical source row count");
        assert_eq!(canonical_rows, 0);
    };

    let cancelled_oid = oid_for(b"cancelled-java-publication");
    let cancelled = AnalyzerStore::prepare_parsed_blob(
        cancelled_oid,
        "java",
        generation,
        &JavaAdapter,
        Arc::clone(&state),
    )
    .expect("prepare cancelled publication");
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let (outcomes, _) = store.persist_prepared_blobs_with_cancellation(
        vec![cancelled],
        &cancellation,
        PersistBatchTargets::PRODUCTION,
    );
    assert!(outcomes[0].error.is_some());
    assert!(
        !store
            .contains_parsed_blob(cancelled_oid, "java")
            .expect("check cancelled publication")
    );
    assert_no_publication_rows(cancelled_oid);
    store
        .write_parsed_blob(cancelled_oid, "java", &JavaAdapter, state.as_ref())
        .expect("retry cancelled publication");
    assert!(
        store
            .contains_parsed_blob(cancelled_oid, "java")
            .expect("check cancelled retry")
    );

    let failed_oid = oid_for(b"failed-java-publication");
    let mut failed = AnalyzerStore::prepare_parsed_blob(
        failed_oid,
        "java",
        store
            .current_generation("java")
            .expect("current Java generation"),
        &JavaAdapter,
        Arc::clone(&state),
    )
    .expect("prepare failed publication");
    failed.inject_invalid_range_for_test();
    let (outcomes, _) = store.persist_prepared_blobs(vec![failed], PersistBatchTargets::PRODUCTION);
    assert!(outcomes[0].error.is_some());
    assert!(
        !store
            .contains_parsed_blob(failed_oid, "java")
            .expect("check failed publication")
    );
    assert_no_publication_rows(failed_oid);
    store
        .write_parsed_blob(failed_oid, "java", &JavaAdapter, state.as_ref())
        .expect("retry failed publication");
    assert!(
        store
            .contains_parsed_blob(failed_oid, "java")
            .expect("check failed retry")
    );
}

#[test]
#[should_panic(expected = "canonical source facts contain an unhandled adapter family")]
fn prepared_java_publication_rejects_an_extra_empty_go_family() {
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("C.java", "class C {}")
        .build();
    let mut state = parse_state(&JavaAdapter, &fixture.file("C.java"));
    state.source_facts.as_mut().unwrap().go =
        Some(brokk_bifrost_core::analyzer::go_facts::GoSourceFacts::default());
    let oid = oid_for(state.source.as_bytes());
    AnalyzerStore::prepare_parsed_blob(
        oid,
        "java",
        crate::analyzer::store::GenerationId::BOOTSTRAP,
        &JavaAdapter,
        Arc::new(state),
    )
    .expect("preparation must reject unhandled families before publication");
}

struct SourceStorageFixtureAdapter(Option<&'static crate::analyzer::store::SourceFactStorage>);

impl LanguageAdapter for SourceStorageFixtureAdapter {
    fn language(&self) -> Language {
        Language::Java
    }

    fn query_directory(&self) -> &'static str {
        JavaAdapter.query_directory()
    }

    fn file_extension(&self) -> &'static str {
        JavaAdapter.file_extension()
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        JavaAdapter.extract_call_receiver(reference)
    }

    fn parse_file(
        &self,
        file: &crate::analyzer::ProjectFile,
        source: &str,
        tree: &tree_sitter::Tree,
    ) -> brokk_bifrost_core::analyzer::parsed_file::ParsedFile {
        JavaAdapter.parse_file(file, source, tree)
    }

    fn produces_canonical_source_facts(&self) -> bool {
        true
    }

    fn source_fact_storage(&self) -> Option<&'static crate::analyzer::store::SourceFactStorage> {
        self.0
    }
}

fn prepare_empty_java_with_storage(
    storage: Option<&'static crate::analyzer::store::SourceFactStorage>,
) {
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("Empty.java", "// empty Java publication\n")
        .build();
    let state = parse_state(&JavaAdapter, &fixture.file("Empty.java"));
    let oid = oid_for(state.source.as_bytes());
    AnalyzerStore::prepare_parsed_blob(
        oid,
        "java",
        crate::analyzer::store::GenerationId::BOOTSTRAP,
        &SourceStorageFixtureAdapter(storage),
        Arc::new(state),
    )
    .expect("preparation must reject unhandled families before publication");
}

#[test]
#[should_panic(expected = "canonical source facts contain an unhandled adapter family")]
#[hardwon("c8c2017cd61c: prepared Java facts outside the storage capability were silently omitted")]
fn prepared_java_publication_rejects_an_absent_storage_capability() {
    prepare_empty_java_with_storage(None);
}
