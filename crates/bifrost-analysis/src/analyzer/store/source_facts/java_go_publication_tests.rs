//! Java and Go publication coverage for the shared canonical source contract.

use std::sync::Arc;

use brokk_bifrost_core::analyzer::model::StructuredImportPathKind;

use crate::CancellationToken;
use crate::analyzer::Language;
use crate::analyzer::go::GoAdapter;
use crate::analyzer::java::JavaAdapter;
use crate::analyzer::store::tests::{oid_for, parse_state};
use crate::analyzer::store::{
    AnalyzerStore, PersistBatchTargets, read_import_infos, stored_unit_keys,
};
use crate::analyzer::structural::facts::{FileFacts, STRUCTURAL_FACTS_VERSION};
use crate::analyzer::tree_sitter_analyzer::{FileState, LanguageAdapter};
use crate::inline_project::InlineTestProject;

use super::import_read::read_source_imports;

fn assert_published_canonical_source<A: LanguageAdapter>(
    fixture: &crate::inline_project::BuiltInlineTestProject,
    relative_path: &str,
    lang: &str,
    adapter: &A,
    state: &FileState,
) {
    let facts = state.source_facts.as_ref().expect("canonical source facts");
    let expected_imports = facts.imports.clone();
    let expected_generic_imports = state.imports.clone();
    let expected_structural = FileFacts::from_source_and_rows(
        state.source.clone(),
        facts.occurrences.clone(),
        facts.structural.clone(),
    )
    .persisted_rows()
    .expect("canonical structural rows");
    let expected_occurrences = facts.occurrences.occurrence_count() as i64;
    let expected_declarations = facts.occurrences.declaration_count() as i64;
    let expected_structural_nodes = facts.structural.nodes().len() as i64;
    let unit_keys = stored_unit_keys(adapter, state);
    let mut expected_bridge_pairs = state
        .source_declaration_units
        .iter()
        .filter_map(|(declaration, unit)| unit_keys.get(unit).map(|key| (*declaration, *key)))
        .collect::<Vec<_>>();
    expected_bridge_pairs.sort_unstable_by_key(|(declaration, key)| (declaration.get(), *key));
    expected_bridge_pairs.dedup();
    let expected_bridge_rows = expected_bridge_pairs.len() as i64;
    assert!(
        expected_bridge_rows > 0,
        "fixture must publish declaration bridges"
    );
    let oid = oid_for(state.source.as_bytes());
    let store_path = fixture
        .root()
        .join(format!("{lang}-canonical-publication.db"));

    let store = AnalyzerStore::open_persistent(&store_path).expect("open publication store");
    store
        .write_parsed_blob(oid, lang, adapter, state)
        .expect("canonical publication succeeds");
    drop(store);

    let reopened = AnalyzerStore::open_persistent(&store_path).expect("reopen publication store");
    let generation = reopened
        .current_generation(lang)
        .expect("current language generation");
    assert_eq!(
        reopened
            .load_structural_facts_rows(oid, lang, generation, STRUCTURAL_FACTS_VERSION)
            .expect("read canonical structural rows"),
        Some(expected_structural),
        "structural consumers must read the source-owned publication"
    );

    let conn = reopened.read_conn().expect("read publication store");
    let blob_id: i64 = conn
        .query_row(
            "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2",
            rusqlite::params![oid.to_string(), lang],
            |row| row.get(0),
        )
        .expect("published blob id");

    let typed_imports = read_source_imports(&conn, blob_id, &|| true)
        .expect("typed source import read")
        .expect("typed source import publication");
    assert_eq!(typed_imports, expected_imports);
    assert_eq!(
        read_import_infos(&conn, &oid.to_string(), lang).expect("generic import read"),
        expected_generic_imports,
        "generic imports must remain a projection of canonical source imports"
    );

    let (generic_rows, linked_generic_rows, link_only_generic_rows): (i64, i64, i64) = conn
        .query_row(
            "SELECT count(*),
                    count(*) FILTER (WHERE source_import_id IS NOT NULL),
                    count(*) FILTER (WHERE source_import_id IS NOT NULL
                        AND statement IS NULL AND is_wildcard IS NULL AND is_global IS NULL
                        AND identifier IS NULL AND alias IS NULL AND path_kind IS NULL
                        AND declaration_start_byte IS NULL AND binder_start IS NULL
                        AND binder_end IS NULL AND declaration_occurrence_id IS NULL
                        AND binder_occurrence_id IS NULL)
             FROM import_statements WHERE blob_id = ?1",
            [blob_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("canonical generic projection rows");
    assert_eq!(generic_rows, expected_generic_imports.len() as i64);
    assert_eq!(linked_generic_rows, generic_rows);
    assert_eq!(link_only_generic_rows, generic_rows);
    let actual_bridge_pairs = conn
        .prepare(
            "SELECT declaration_id, unit_key FROM source_declaration_units
             WHERE blob_id = ?1 ORDER BY declaration_id, unit_key",
        )
        .expect("prepare declaration bridge query")
        .query_map([blob_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("read declaration bridges")
        .collect::<rusqlite::Result<Vec<(i64, i64)>>>()
        .expect("collect declaration bridges");
    let expected_bridge_pairs = expected_bridge_pairs
        .iter()
        .map(|(declaration, key)| (i64::from(declaration.get()), *key))
        .collect::<Vec<_>>();
    assert_eq!(actual_bridge_pairs, expected_bridge_pairs);

    let counts = conn
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM source_fact_manifests WHERE blob_id = ?1),
                 (SELECT COUNT(*) FROM source_occurrences WHERE blob_id = ?1),
                 (SELECT COUNT(*) FROM source_declarations WHERE blob_id = ?1),
                 (SELECT COALESCE(json_array_length(nodes), 0) FROM source_structural_facts WHERE blob_id = ?1),
                 (SELECT COUNT(*) FROM resolution_semantic_sites WHERE blob_id = ?1),
                 (SELECT COUNT(*) FROM resolution_semantic_sites
                    WHERE blob_id = ?1 AND semantic_role = 'reference'),
                 (SELECT COUNT(*) FROM source_declaration_units WHERE blob_id = ?1),
                 (SELECT COUNT(*) FROM source_declaration_units AS bridge
                    LEFT JOIN source_declarations AS declaration
                      ON declaration.blob_id = bridge.blob_id
                     AND declaration.declaration_id = bridge.declaration_id
                   WHERE bridge.blob_id = ?1 AND declaration.declaration_id IS NULL)",
            [blob_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .expect("canonical publication counts");
    assert_eq!(counts.0, 1, "one complete source-facts manifest");
    assert_eq!(counts.1, expected_occurrences);
    assert_eq!(counts.2, expected_declarations);
    assert_eq!(counts.3, expected_structural_nodes);
    assert!(counts.5 > 0, "fixture must publish native references");
    assert!(
        counts.5 <= counts.4,
        "every native reference site is a semantic site"
    );
    assert_eq!(counts.6, expected_bridge_rows);
    assert_eq!(
        counts.7, 0,
        "declaration bridges must stay in the source domain"
    );

    // The reference-site relation is interior detail now. What publication
    // still owns is the definition half, which must name a declaration of this
    // blob and nothing outside it. A Go named or blank import spec is a
    // file-scope binder without a source declaration; its own row family,
    // resolution_go_package_imports, bridges it to the import occurrence.
    let orphan_definition_sites: i64 = conn
        .query_row(
            "SELECT COUNT(*)
               FROM resolution_semantic_sites AS site
               LEFT JOIN source_native_declaration_bridges AS bridge
                 ON bridge.blob_id = site.blob_id AND bridge.source_site = site.source_site
              WHERE site.blob_id = ?1 AND site.semantic_role = 'definition'
                AND bridge.declaration_id IS NULL
                AND NOT EXISTS (
                    SELECT 1 FROM resolution_go_package_imports AS import
                     WHERE import.blob_id = site.blob_id
                       AND import.source_site = site.source_site
                )",
            [blob_id],
            |row| row.get(0),
        )
        .expect("validate native definition-site links");
    assert_eq!(orphan_definition_sites, 0);

    let hydrated = reopened
        .hydrate_file_state(oid, lang, adapter, &fixture.file(relative_path))
        .expect("hydrate published file")
        .expect("published file state");
    assert_eq!(hydrated.imports, expected_generic_imports);
}

#[test]
fn java_canonical_publication_reopens_imports_structural_rows_and_native_links() {
    let source = r#"import java.util.*;
import static java.lang.Math.max;
import java.lang.String;
import broken.;
class C {
    int field;
    void run() {
        int local = field;
        max(local);
    }
}
"#;
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("src/C.java", source)
        .build();
    let state = parse_state(&JavaAdapter, &fixture.file("src/C.java"));
    let facts = state.source_facts.as_ref().expect("Java source facts");
    assert_eq!(facts.imports.len(), 4);
    assert!(facts.imports[0].is_wildcard);
    assert_eq!(
        facts.imports[0].path.as_ref().and_then(|path| path.kind),
        Some(StructuredImportPathKind::Namespace)
    );
    assert!(
        facts.imports[3].path.is_none(),
        "malformed Java path is unavailable"
    );
    assert!(!facts.structural.nodes().is_empty());
    assert!(!facts.native_declaration_sources.is_empty());
    assert_published_canonical_source(&fixture, "src/C.java", "java", &JavaAdapter, &state);
}

#[test]
fn go_canonical_publication_reopens_import_aliases_structural_rows_and_native_links() {
    let source = r#"package p
import (
    alias "example.com/alias"
    . "example.com/dot"
    _ "example.com/blank"
)
type Thing struct { Field int }
func helper(value int) int { return value }
func use() { value := helper(1); _ = value; var thing Thing; _ = thing.Field }
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/test\n")
        .file("pkg/sample.go", source)
        .build();
    let state = parse_state(&GoAdapter, &fixture.file("pkg/sample.go"));
    let facts = state.source_facts.as_ref().expect("Go source facts");
    assert_eq!(facts.imports.len(), 3);
    assert_eq!(
        facts
            .imports
            .iter()
            .map(|import| import.alias.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("alias"), Some("."), Some("_")]
    );
    assert!(
        facts
            .imports
            .iter()
            .all(|import| import.alias_occurrence.is_some())
    );
    assert!(!facts.structural.nodes().is_empty());
    assert!(!facts.native_declaration_sources.is_empty());
    assert_published_canonical_source(&fixture, "pkg/sample.go", "go", &GoAdapter, &state);
}

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
fn prepared_java_publication_rejects_the_wrong_storage_capability() {
    prepare_empty_java_with_storage(GoAdapter.source_fact_storage());
}

#[test]
#[should_panic(expected = "canonical source facts contain an unhandled adapter family")]
fn prepared_java_publication_rejects_an_absent_storage_capability() {
    prepare_empty_java_with_storage(None);
}
