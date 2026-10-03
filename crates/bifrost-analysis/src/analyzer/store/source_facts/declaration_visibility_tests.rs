//! End-to-end acceptance tests for the Java source-declaration visibility family.
//!
//! These tests deliberately begin with a real Java parse.  The SQL assertions
//! then compare every persisted identity to the parse product, so a coherent
//! but independently reconstructed visibility table cannot satisfy the test.

use std::collections::HashMap;

use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use brokk_bifrost_core::analyzer::rust_facts::RustDeclarationKind;
use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_core::hash::HashMap as CoreHashMap;
use rusqlite::{Connection, params};

use crate::analyzer::Language;
use crate::analyzer::java::JavaAdapter;
use crate::analyzer::rust::RustAdapter;
use crate::analyzer::store::tests::{oid_for, parse_state};
use crate::analyzer::store::{AnalyzerStore, stored_unit_keys};
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::inline_project::InlineTestProject;

const JAVA_SOURCE: &str = r#"interface Contract {
    void implicitMethod();
    private void hidden() {}
    int implicitField = 1;
}

enum Choice { FIRST, SECOND; private Choice() {} }

record Pair(int left, int right) {
    public Pair {}
    private void privateRecord() {}
}

interface Alternative { default void run() {} }
class Alternative { private void run() {} }

class Container {
    private int privateField;
    protected void protectedMethod(int argument) {}
    void ordinary() {
        class Local { public void localMember() {} }
        Object value = new Object() { public void anonymousMember() {} };
    }
}
"#;

fn java_fixture() -> (
    crate::inline_project::BuiltInlineTestProject,
    crate::analyzer::ProjectFile,
    FileState,
) {
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("src/Container.java", JAVA_SOURCE)
        .build();
    let file = fixture.file("src/Container.java");
    let state = parse_state(&JavaAdapter, &file);
    (fixture, file, state)
}

fn declaration_name(
    facts: &ParsedSourceFacts,
    source: &str,
    id: SourceDeclarationId,
) -> Option<String> {
    let name = facts.occurrences.declaration(id).name?;
    let range = facts.occurrences.occurrence(name).range;
    Some(source.get(range.start_byte..range.end_byte)?.to_owned())
}

fn blob_id(conn: &Connection, oid: git2::Oid) -> i64 {
    conn.query_row(
        "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'",
        [oid.to_string()],
        |row| row.get(0),
    )
    .expect("published Java blob id")
}

fn rust_blob_id(conn: &Connection, oid: git2::Oid) -> i64 {
    conn.query_row(
        "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'",
        [oid.to_string()],
        |row| row.get(0),
    )
    .expect("published Rust blob id")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VisibilitySnapshot {
    marker: (i64, i64, i64, i64),
    visibilities: Vec<(i64, String)>,
    native_bridges: Vec<(i64, i64)>,
    metadata_bridges: Vec<(i64, i64, i64)>,
    native_visibility: Vec<(i64, String)>,
    metadata_values: Vec<(i64, i64, Option<String>, i64)>,
    legacy_rows: i64,
}

fn visibility_snapshot(conn: &Connection, id: i64) -> VisibilitySnapshot {
    let marker = conn
        .query_row(
            "SELECT facts_version, visibility_count, native_bridge_count,
                    metadata_bridge_count
               FROM source_declaration_visibility_manifests
              WHERE blob_id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("Java visibility marker");
    let visibilities = conn
        .prepare(
            "SELECT declaration_id, visibility
               FROM source_declaration_visibilities
              WHERE blob_id = ?1
              ORDER BY declaration_id",
        )
        .expect("prepare Java visibility rows")
        .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("read Java visibility rows")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect Java visibility rows");
    let native_bridges = conn
        .prepare(
            "SELECT source_site, declaration_id
               FROM source_native_declaration_bridges
              WHERE blob_id = ?1
              ORDER BY source_site",
        )
        .expect("prepare Java native bridges")
        .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("read Java native bridges")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect Java native bridges");
    let metadata_bridges = conn
        .prepare(
            "SELECT declaration_id, unit_key, metadata_ordinal
               FROM source_declaration_metadata_bridges
              WHERE blob_id = ?1
              ORDER BY declaration_id, unit_key, metadata_ordinal",
        )
        .expect("prepare Java metadata bridges")
        .query_map([id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("read Java metadata bridges")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect Java metadata bridges");
    let native_visibility = conn
        .prepare(
            "SELECT definition_semantic_key, visibility
               FROM resolution_declaration_visibility_properties
              WHERE blob_id = ?1
              ORDER BY definition_semantic_key",
        )
        .expect("prepare logical native visibility")
        .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("read logical native visibility")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect logical native visibility");
    let metadata_values = conn
        .prepare(
            "SELECT unit_key, ordinal, callable_declared_visibility,
                    metadata_available
               FROM unit_signature_metadata_values
              WHERE blob_id = ?1
              ORDER BY unit_key, ordinal",
        )
        .expect("prepare logical Java metadata")
        .query_map([id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .expect("read logical Java metadata")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect logical Java metadata");
    let legacy_rows = conn
        .query_row(
            "SELECT COUNT(*) FROM legacy_resolution_declaration_visibility_properties
              WHERE blob_id = ?1",
            [id],
            |row| row.get(0),
        )
        .expect("count legacy Java visibility rows");
    VisibilitySnapshot {
        marker,
        visibilities,
        native_bridges,
        metadata_bridges,
        native_visibility,
        metadata_values,
        legacy_rows,
    }
}

fn assert_source_visibility_properties(state: &FileState) {
    let facts = state
        .source_facts
        .as_ref()
        .expect("Java publishes canonical source facts");
    let visibilities = facts
        .declaration_visibilities
        .as_ref()
        .expect("Java publishes declaration visibility, including source-only rows");
    let by_id = visibilities
        .iter()
        .map(|fact| (fact.declaration, fact.visibility))
        .collect::<HashMap<_, _>>();
    assert_eq!(by_id.len(), visibilities.len(), "visibility IDs are unique");

    for (name, expected) in [
        ("Contract", DeclaredVisibility::PackagePrivate),
        ("implicitMethod", DeclaredVisibility::Public),
        ("hidden", DeclaredVisibility::Private),
        ("implicitField", DeclaredVisibility::Public),
        ("Choice", DeclaredVisibility::PackagePrivate),
        ("FIRST", DeclaredVisibility::Public),
        ("SECOND", DeclaredVisibility::Public),
        ("Pair", DeclaredVisibility::PackagePrivate),
        ("left", DeclaredVisibility::Private),
        ("right", DeclaredVisibility::Private),
        ("privateRecord", DeclaredVisibility::Private),
        ("Container", DeclaredVisibility::PackagePrivate),
        ("privateField", DeclaredVisibility::Private),
        ("protectedMethod", DeclaredVisibility::Protected),
        ("ordinary", DeclaredVisibility::PackagePrivate),
        ("localMember", DeclaredVisibility::Public),
        ("anonymousMember", DeclaredVisibility::Public),
    ] {
        assert!(
            visibilities.iter().any(|fact| {
                declaration_name(facts, JAVA_SOURCE, fact.declaration).as_deref() == Some(name)
                    && fact.visibility == expected
            }),
            "missing source visibility {name}={expected:?}"
        );
    }
    assert!(visibilities.iter().any(|fact| {
        declaration_name(facts, JAVA_SOURCE, fact.declaration).as_deref() == Some("run")
            && fact.visibility == DeclaredVisibility::Public
    }));
    assert!(visibilities.iter().any(|fact| {
        declaration_name(facts, JAVA_SOURCE, fact.declaration).as_deref() == Some("run")
            && fact.visibility == DeclaredVisibility::Private
    }));

    let native_declarations = facts
        .native_declaration_sources
        .iter()
        .map(|(_, declaration)| *declaration)
        .collect::<std::collections::HashSet<_>>();
    for source_only in ["left", "right"] {
        let ids = visibilities
            .iter()
            .filter(|fact| {
                declaration_name(facts, JAVA_SOURCE, fact.declaration).as_deref()
                    == Some(source_only)
            })
            .map(|fact| fact.declaration)
            .collect::<Vec<_>>();
        assert!(!ids.is_empty(), "source-only declaration {source_only}");
        assert!(
            ids.iter().all(|id| !native_declarations.contains(id)),
            "{source_only} must remain source-only"
        );
    }
    for native in ["FIRST", "SECOND"] {
        let ids = visibilities
            .iter()
            .filter(|fact| {
                declaration_name(facts, JAVA_SOURCE, fact.declaration).as_deref() == Some(native)
            })
            .map(|fact| fact.declaration)
            .collect::<Vec<_>>();
        assert!(!ids.is_empty(), "enum constant {native}");
        assert!(
            ids.iter().all(|id| native_declarations.contains(id)),
            "enum constant {native} must have a native source declaration"
        );
    }

    for link in &state.source_declaration_metadata {
        let metadata = &state.signature_metadata[&link.unit][link.metadata_ordinal];
        assert_eq!(
            metadata.callable_declared_visibility(),
            Some(by_id[&link.declaration]),
            "metadata link must carry the same construction-time visibility"
        );
    }
    assert!(
        state
            .signature_metadata
            .keys()
            .any(|unit| unit.is_synthetic()),
        "the fixture must retain an anonymous synthetic metadata unit"
    );
    assert!(
        state
            .source_declaration_metadata
            .iter()
            .all(|link| !link.unit.is_synthetic()),
        "synthetic metadata must not manufacture source declaration IDs"
    );
    assert!(
        state
            .source_declaration_metadata
            .iter()
            .all(|link| declaration_name(facts, JAVA_SOURCE, link.declaration).is_some())
    );
}

fn assert_persisted_rows_match_state(
    conn: &Connection,
    id: i64,
    state: &FileState,
) -> VisibilitySnapshot {
    let facts = state.source_facts.as_ref().expect("Java source facts");
    let visibilities = facts
        .declaration_visibilities
        .as_ref()
        .expect("Java visibility facts");
    let mut expected_visibilities = visibilities
        .iter()
        .map(|fact| {
            (
                i64::from(fact.declaration.get()),
                fact.visibility.label().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    expected_visibilities.sort_unstable();

    let mut expected_native = facts
        .native_declaration_sources
        .iter()
        .map(|(site, declaration)| (i64::from(site.get()), i64::from(declaration.get())))
        .collect::<Vec<_>>();
    expected_native.sort_unstable();

    let unit_keys = stored_unit_keys(&JavaAdapter, state);
    let mut expected_metadata = state
        .source_declaration_metadata
        .iter()
        .map(|link| {
            (
                i64::from(link.declaration.get()),
                unit_keys[&link.unit],
                i64::try_from(link.metadata_ordinal).expect("metadata ordinal fits SQLite"),
            )
        })
        .collect::<Vec<_>>();
    expected_metadata.sort_unstable();

    let snapshot = visibility_snapshot(conn, id);
    assert_eq!(
        snapshot.marker,
        (
            brokk_bifrost_core::analyzer::source_facts::SOURCE_DECLARATION_VISIBILITY_VERSION,
            i64::try_from(visibilities.len()).unwrap(),
            i64::try_from(facts.native_declaration_sources.len()).unwrap(),
            i64::try_from(state.source_declaration_metadata.len()).unwrap(),
        )
    );
    assert_eq!(snapshot.visibilities, expected_visibilities);
    assert_eq!(snapshot.native_bridges, expected_native);
    assert_eq!(snapshot.metadata_bridges, expected_metadata);
    assert_eq!(
        snapshot.legacy_rows, 0,
        "new Java must not write legacy visibility"
    );

    let expected_metadata_values = state
        .signature_metadata
        .iter()
        .flat_map(|(unit, entries)| {
            let unit_keys = &unit_keys;
            let unit_key = unit_keys[unit];
            entries.iter().enumerate().map(move |(ordinal, metadata)| {
                let coordinate = (unit_key, ordinal);
                let linked_visibilities = state
                    .source_declaration_metadata
                    .iter()
                    .filter(|link| {
                        unit_keys[&link.unit] == coordinate.0
                            && link.metadata_ordinal == coordinate.1
                    })
                    .map(|link| by_declaration_visibility(facts, link.declaration))
                    .collect::<Vec<_>>();
                let (value, available) = if unit.is_synthetic() {
                    (
                        metadata
                            .callable_declared_visibility()
                            .map(|visibility| visibility.label().to_owned()),
                        1,
                    )
                } else if linked_visibilities.is_empty() {
                    (None, 0)
                } else {
                    assert!(
                        linked_visibilities
                            .windows(2)
                            .all(|pair| pair[0] == pair[1]),
                        "one canonical metadata ordinal cannot have conflicting visibility"
                    );
                    (Some(linked_visibilities[0].label().to_owned()), 1)
                };
                (
                    coordinate.0,
                    i64::try_from(coordinate.1).unwrap(),
                    value,
                    available,
                )
            })
        })
        .collect::<Vec<_>>();
    let mut expected_metadata_values = expected_metadata_values;
    expected_metadata_values.sort_unstable_by_key(|row| (row.0, row.1));
    assert_eq!(snapshot.metadata_values, expected_metadata_values);

    let canonical_native_count: i64 = conn
        .query_row(
            "SELECT COUNT(*)
               FROM resolution_semantic_sites AS site
               JOIN source_native_declaration_bridges AS bridge
                 ON bridge.blob_id = site.blob_id
                AND bridge.source_site = site.source_site
               JOIN source_declaration_visibilities AS visibility
                 ON visibility.blob_id = bridge.blob_id
                AND visibility.declaration_id = bridge.declaration_id
              WHERE site.blob_id = ?1 AND site.semantic_role = 'definition'",
            [id],
            |row| row.get(0),
        )
        .expect("count canonical native visibility");
    let expected_native_visibility = conn
        .prepare(
            "SELECT site.semantic_key, visibility.visibility
               FROM resolution_semantic_sites AS site
               JOIN source_native_declaration_bridges AS bridge
                 ON bridge.blob_id = site.blob_id
                AND bridge.source_site = site.source_site
               JOIN source_declaration_visibilities AS visibility
                 ON visibility.blob_id = bridge.blob_id
                AND visibility.declaration_id = bridge.declaration_id
              WHERE site.blob_id = ?1 AND site.semantic_role = 'definition'
              ORDER BY site.semantic_key",
        )
        .expect("prepare expected canonical native visibility")
        .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("read expected canonical native visibility")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect expected canonical native visibility");
    assert_eq!(snapshot.native_visibility, expected_native_visibility);
    assert_eq!(
        snapshot.native_visibility.len() as i64,
        canonical_native_count,
        "the legacy logical name projects canonical native visibility"
    );
    snapshot
}

fn by_declaration_visibility(
    facts: &ParsedSourceFacts,
    declaration: SourceDeclarationId,
) -> DeclaredVisibility {
    facts
        .declaration_visibilities
        .as_ref()
        .expect("Java visibility facts")
        .iter()
        .find(|fact| fact.declaration == declaration)
        .map(|fact| fact.visibility)
        .expect("metadata bridge has a canonical visibility")
}

fn assert_reader_coherence(
    store: &AnalyzerStore,
    file: &crate::analyzer::ProjectFile,
    state: &FileState,
    oid: git2::Oid,
    generation: crate::analyzer::store::GenerationId,
) {
    let expected = &state.signature_metadata;
    let hydrated = store
        .hydrate_file_state_with_source(oid, "java", generation, &JavaAdapter, file, JAVA_SOURCE)
        .expect("full Java hydration")
        .expect("complete Java visibility publication");
    assert_eq!(hydrated.signature_metadata, *expected, "full reader");

    let bulk = store
        .hydrate_file_states(
            &[(file.clone(), oid)],
            "java",
            &JavaAdapter,
            &CoreHashMap::from_iter([(file.clone(), JAVA_SOURCE.to_owned())]),
        )
        .expect("bulk Java hydration");
    assert_eq!(bulk[file].signature_metadata, *expected, "bulk reader");

    let (target, target_metadata) = state
        .signature_metadata
        .iter()
        .find(|(_, metadata)| metadata.len() > 1)
        .map(|(unit, metadata)| (unit.clone(), metadata.clone()))
        .expect("fixture must retain divergent metadata alternatives");
    assert_eq!(
        store
            .signature_metadata_for_unit(oid, "java", generation, &target)
            .expect("unbounded metadata reader"),
        target_metadata,
        "unbounded reader preserves every canonical metadata alternative"
    );
    let bounded = store
        .signature_metadata_for_unit_limited(oid, "java", generation, &target, 1)
        .expect("bounded metadata reader");
    assert!(
        !bounded.complete,
        "one row cannot prove all alternatives exist"
    );
    assert_eq!(bounded.rows, target_metadata[..1].to_vec());

    let unit_keys = stored_unit_keys(&JavaAdapter, state);
    let target_key = unit_keys[&target];
    let usage = store
        .usage_fact_rows_by_lang("java")
        .expect("usage metadata reader")
        .into_iter()
        .find(|row| row.candidate.unit_key == target_key)
        .expect("usage row for divergent Java callable");
    let signature_ordinal = state.signature_metadata_signature_ordinals[&target]
        .iter()
        .position(|&ordinal| ordinal == 0)
        .expect("target has a metadata alternative paired with signature zero");
    assert_eq!(
        usage.signature_metadata,
        Some(target_metadata[signature_ordinal].clone())
    );
}

fn assert_metadata_read_plan(conn: &Connection, state: &FileState, oid: git2::Oid) {
    use crate::analyzer::store::{code_unit_kind_to_i64, signature_metadata_for_unit_sql};
    let unit = state
        .signature_metadata
        .keys()
        .find(|unit| unit.identifier() == "run")
        .expect("populated Java fixture has divergent callable metadata");
    let plan = conn
        .prepare(&format!(
            "EXPLAIN QUERY PLAN {}",
            signature_metadata_for_unit_sql()
        ))
        .unwrap()
        .query_map(
            params![
                oid.to_string(),
                "java",
                unit.fq_name(),
                code_unit_kind_to_i64(unit.kind()),
                unit.short_name(),
                unit.signature(),
                i64::from(unit.is_synthetic()),
                2_i64,
            ],
            |row| row.get::<_, String>(3),
        )
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        plan.iter().any(|detail| detail.contains(
            "SEARCH bridge USING COVERING INDEX source_declaration_metadata_bridges_metadata"
        )),
        "canonical metadata must seek exact bridge coordinates: {plan:#?}"
    );
    assert!(
        plan.iter().all(|detail| !detail.contains("SCAN bridge")
            && !detail.contains("SCAN metadata")
            && !detail.contains("SCAN visibility")),
        "one-unit metadata cannot scan property families: {plan:#?}"
    );
}

fn visibility_workspace(
    store: &AnalyzerStore,
    oid: git2::Oid,
) -> (
    crate::analyzer::store::WorkspaceId,
    crate::analyzer::store::WorkspaceSnapshots,
) {
    use crate::analyzer::store::{WorkspaceFileRow, WorkspaceId};
    let generation = store.current_generation("java").unwrap();
    store
        .ensure_resolution_producer_epoch("java", Language::Java)
        .unwrap();
    let workspace = WorkspaceId("64".repeat(32));
    let snapshot = store
        .sync_workspace_snapshot_for_workspace(
            &workspace,
            "java",
            generation,
            &[WorkspaceFileRow {
                rel_path: "src/Container.java".into(),
                blob_oid: oid,
            }],
            &[],
            &[],
            &[],
            &[],
            &[],
        )
        .unwrap();
    (
        workspace,
        CoreHashMap::from_iter([("java".to_owned(), snapshot)]),
    )
}

#[test]
fn java_visibility_publication_is_exact_across_reopen_reader_shapes_and_native_projection() {
    let (fixture, file, state) = java_fixture();
    assert_source_visibility_properties(&state);
    let oid = oid_for(JAVA_SOURCE.as_bytes());
    let path = fixture.root().join("java-declaration-visibility.db");
    let store = AnalyzerStore::open_persistent(&path).expect("open Java visibility store");
    let generation = store.current_generation("java").expect("Java generation");
    let mut stale_projection = state.clone();
    for (unit, alternatives) in &mut stale_projection.signature_metadata {
        if unit.is_synthetic() {
            continue;
        }
        for metadata in alternatives {
            let stale =
                if metadata.callable_declared_visibility() == Some(DeclaredVisibility::Private) {
                    DeclaredVisibility::Public
                } else {
                    DeclaredVisibility::Private
                };
            *metadata = metadata.clone().with_source_declared_visibility(stale);
        }
    }
    store
        .write_parsed_blob_at_generation(oid, "java", generation, &JavaAdapter, &stale_projection)
        .expect("publish complete Java visibility family");
    {
        let conn = store.read_conn().expect("read Java visibility publication");
        let id = blob_id(&conn, oid);
        let first = assert_persisted_rows_match_state(&conn, id, &state);
        assert_metadata_read_plan(&conn, &state, oid);
        assert_reader_coherence(&store, &file, &state, oid, generation);
        drop(conn);
        store
            .refresh_planner_statistics()
            .expect("refresh Java visibility planner statistics");
        let conn = store
            .read_conn()
            .expect("read Java visibility after ANALYZE");
        let id = blob_id(&conn, oid);
        let after_statistics = visibility_snapshot(&conn, id);
        assert_metadata_read_plan(&conn, &state, oid);
        assert_eq!(
            after_statistics, first,
            "ANALYZE preserves canonical visibility"
        );
        drop(conn);
    }
    drop(store);

    let reopened = AnalyzerStore::open_persistent(&path).expect("reopen Java visibility store");
    let generation = reopened
        .current_generation("java")
        .expect("reopened Java generation");
    let conn = reopened
        .read_conn()
        .expect("read reopened Java visibility publication");
    let id = blob_id(&conn, oid);
    let reopened_snapshot = assert_persisted_rows_match_state(&conn, id, &state);
    drop(conn);
    assert_reader_coherence(&reopened, &file, &state, oid, generation);
    let conn = reopened
        .read_conn()
        .expect("read final Java visibility publication");
    assert_eq!(visibility_snapshot(&conn, id), reopened_snapshot);
}

#[test]
fn empty_java_visibility_publication_is_present_and_distinct_from_legacy() {
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("Empty.java", "")
        .build();
    let file = fixture.file("Empty.java");
    let state = parse_state(&JavaAdapter, &file);
    let facts = state
        .source_facts
        .as_ref()
        .expect("empty Java source facts");
    assert!(matches!(
        facts.declaration_visibilities.as_deref(),
        Some(visibilities) if visibilities.is_empty()
    ));
    assert!(state.source_declaration_metadata.is_empty());
    assert!(facts.native_declaration_sources.is_empty());
    let oid = oid_for(b"empty-java-visibility");
    let store = AnalyzerStore::open_ephemeral().expect("empty Java visibility store");
    let generation = store.current_generation("java").expect("Java generation");
    store
        .write_parsed_blob_at_generation(oid, "java", generation, &JavaAdapter, &state)
        .expect("publish empty Java visibility family");
    let conn = store.read_conn().expect("read empty Java publication");
    let id = blob_id(&conn, oid);
    let marker: (i64, i64, i64, i64) = conn
        .query_row(
            "SELECT facts_version, visibility_count, native_bridge_count,
                    metadata_bridge_count
               FROM source_declaration_visibility_manifests
              WHERE blob_id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("empty marker");
    assert_eq!(marker, (1, 0, 0, 0));
    assert_eq!(
        conn.query_row(
            "SELECT declaration_visibility_version FROM blob_meta WHERE blob_id = ?1",
            [id],
            |row| row.get::<_, Option<i64>>(0),
        )
        .expect("empty visibility requirement"),
        Some(1)
    );
    assert_eq!(
        conn.query_row(
            "SELECT available FROM source_declaration_visibility_readiness WHERE blob_id = ?1",
            [id],
            |row| row.get::<_, i64>(0),
        )
        .expect("empty visibility readiness"),
        1
    );
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM legacy_resolution_declaration_visibility_properties
              WHERE blob_id = ?1",
            [id],
            |row| row.get::<_, i64>(0),
        )
        .expect("empty legacy visibility count"),
        0
    );
}

#[test]
fn incomplete_java_visibility_bridges_fail_atomically_without_legacy_fallback() {
    for missing in ["metadata", "native"] {
        let (_fixture, _file, mut state) = java_fixture();
        if missing == "metadata" {
            assert!(state.source_declaration_metadata.pop().is_some());
        } else {
            let facts = state.source_facts.as_mut().expect("Java facts");
            let visibility_declarations = facts
                .declaration_visibilities
                .as_ref()
                .expect("Java visibility facts")
                .iter()
                .map(|fact| fact.declaration)
                .collect::<std::collections::HashSet<_>>();
            let native_index = facts
                .native_declaration_sources
                .iter()
                .position(|(_, declaration)| visibility_declarations.contains(declaration))
                .expect("fixture has a native bridge with source visibility");
            facts.native_declaration_sources.remove(native_index);
        }
        let store = AnalyzerStore::open_ephemeral().expect("failed Java publication store");
        let oid = oid_for(format!("failed-{missing}-java-visibility").as_bytes());
        let generation = store.current_generation("java").expect("Java generation");
        let error = store
            .write_parsed_blob_at_generation(oid, "java", generation, &JavaAdapter, &state)
            .expect_err("missing canonical bridge must fail publication");
        assert!(
            error.to_string().contains("visibility")
                || error.to_string().contains("bridge")
                || error.to_string().contains("source"),
            "unexpected publication error: {error:?}"
        );
        assert_eq!(
            store
                .content_row_count(oid, "java")
                .expect("failed row count"),
            0
        );
        let conn = store.read_conn().expect("read failed Java publication");
        let canonical_rows: i64 = conn
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM source_declaration_visibility_manifests
                      WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))
                  + (SELECT COUNT(*) FROM source_declaration_visibilities
                      WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))
                  + (SELECT COUNT(*) FROM source_native_declaration_bridges
                      WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))
                  + (SELECT COUNT(*) FROM source_declaration_metadata_bridges
                      WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'))",
                [oid.to_string()],
                |row| row.get(0),
            )
            .expect("failed canonical row count");
        assert_eq!(
            canonical_rows, 0,
            "failed publication leaves no source family rows"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM legacy_resolution_declaration_visibility_properties
                  WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java')",
                [oid.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .expect("failed legacy row count"),
            0
        );
    }
}

#[test]
fn legacy_visibility_rows_cannot_override_a_canonical_java_publication() {
    let (_fixture, _file, state) = java_fixture();
    let store = AnalyzerStore::open_ephemeral().expect("legacy projection store");
    let oid = oid_for(b"legacy-does-not-win-java-visibility");
    let generation = store.current_generation("java").expect("Java generation");
    store
        .write_parsed_blob_at_generation(oid, "java", generation, &JavaAdapter, &state)
        .expect("publish Java visibility");
    let conn = store.read_conn().expect("read canonical Java visibility");
    let id = blob_id(&conn, oid);
    let before = visibility_snapshot(&conn, id);
    let (semantic_key, canonical): (i64, String) = conn
        .query_row(
            "SELECT definition_semantic_key, visibility
               FROM resolution_declaration_visibility_properties
              WHERE blob_id = ?1
              ORDER BY definition_semantic_key
              LIMIT 1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("canonical native visibility row");
    drop(conn);
    let stale = if canonical == "private" {
        "public"
    } else {
        "private"
    };
    store
        .conn
        .execute(move |conn| {
            conn.execute_batch(
            "DROP TRIGGER legacy_resolution_declaration_visibility_properties_no_canonical_insert;",
        )?;
            conn.execute(
                "INSERT INTO legacy_resolution_declaration_visibility_properties(
                 blob_id, definition_semantic_key, visibility
             ) VALUES(?1, ?2, ?3)",
                params![id, semantic_key, stale],
            )?;
            Ok::<(), crate::analyzer::store::StoreError>(())
        })
        .expect("inject controlled stale legacy row");
    let conn = store
        .read_conn()
        .expect("read canonical projection after legacy injection");
    let after = visibility_snapshot(&conn, id);
    assert_eq!(after.legacy_rows, 1);
    assert_eq!(after.native_visibility, before.native_visibility);
}

#[test]
fn damaged_java_visibility_publication_is_unavailable_not_legacy() {
    use crate::CancellationToken;
    use brokk_bifrost_core::analyzer::{
        DefinitionLanguageScope, RelationalDefinitionQuery, RelationalDefinitionRequest,
        RelationalName,
    };
    for corruption in ["marker", "source", "property", "version"] {
        let (fixture, file, state) = java_fixture();
        let store = AnalyzerStore::open_ephemeral().expect("corruption test store");
        let oid = oid_for(format!("corrupt-{corruption}-java-visibility").as_bytes());
        let generation = store.current_generation("java").expect("Java generation");
        store
            .write_parsed_blob_at_generation(oid, "java", generation, &JavaAdapter, &state)
            .expect("publish Java visibility");
        let (_, snapshots) = visibility_workspace(&store, oid);
        let conn = store.read_conn().expect("read Java corruption fixture");
        let id = blob_id(&conn, oid);
        let target_metadata: (i64, i64) = conn
            .query_row(
                "SELECT unit_key, metadata_ordinal
                   FROM source_declaration_metadata_bridges
                  WHERE blob_id = ?1
                  ORDER BY unit_key, metadata_ordinal
                  LIMIT 1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("fixture has a metadata bridge for targeted corruption");
        drop(conn);
        let target = stored_unit_keys(&JavaAdapter, &state)
            .into_iter()
            .find(|(_, key)| *key == target_metadata.0)
            .unwrap()
            .0;
        let requests = [RelationalDefinitionRequest {
            ordinal: 0,
            language_scope: DefinitionLanguageScope::Language(Language::Java),
            name: RelationalName::stable(target.fq().clone()),
            query: RelationalDefinitionQuery::CallableFacts,
        }];
        let generations = CoreHashMap::from_iter([("java".to_owned(), generation)]);
        let read_callable = || {
            store.relational_definition_values(
                &JavaAdapter,
                fixture.root(),
                &generations,
                &["java".to_owned()],
                &snapshots,
                &requests,
                &CancellationToken::default(),
                |_| {},
            )
        };
        assert!(
            matches!(read_callable().unwrap(),
            crate::analyzer::store::relational_query::RelationalStoreOutcome::Complete(values)
            if matches!(values.as_slice(), [brokk_bifrost_core::analyzer::RelationalDefinitionValue::CallableFacts(facts)]
                if !facts.is_empty())),
            "canonical callable is initially present and available"
        );
        let sql = match corruption {
            "marker" => format!(
                "DROP TRIGGER source_declaration_visibility_manifests_no_delete;
                 DELETE FROM source_declaration_visibility_manifests WHERE blob_id = {id};"
            ),
            "source" => format!(
                "PRAGMA foreign_keys = OFF;
                 DROP TRIGGER source_fact_manifests_no_direct_delete;
                 DELETE FROM source_fact_manifests WHERE blob_id = {id};
                 PRAGMA foreign_keys = ON;"
            ),
            "property" => format!(
                "DROP TRIGGER source_declaration_visibilities_no_delete_after_seal;
                 DELETE FROM source_declaration_visibilities
                  WHERE blob_id = {id}
                    AND declaration_id = (SELECT declaration_id
                                            FROM source_declaration_metadata_bridges
                                           WHERE blob_id = {id}
                                           ORDER BY unit_key, metadata_ordinal
                                           LIMIT 1);"
            ),
            "version" => format!(
                "DROP TRIGGER source_declaration_visibility_manifests_require_expected_update;
                 DROP TRIGGER source_declaration_visibility_manifests_no_update;
                 PRAGMA ignore_check_constraints = ON;
                 UPDATE source_declaration_visibility_manifests
                    SET facts_version = 0 WHERE blob_id = {id};
                 PRAGMA ignore_check_constraints = OFF;"
            ),
            _ => unreachable!("listed corruption case"),
        };
        store
            .conn
            .execute(move |conn| {
                conn.execute_batch(&sql)?;
                Ok::<(), crate::analyzer::store::StoreError>(())
            })
            .expect("apply controlled visibility corruption");
        assert!(
            read_callable().is_err(),
            "{corruption} must not become a complete empty callable answer"
        );
        assert!(
            store
                .signature_metadata_for_unit(oid, "java", generation, &target)
                .is_err(),
            "{corruption} must fail the known-unit metadata read"
        );
        let conn = store.read_conn().expect("read damaged Java visibility");
        if corruption == "property" {
            let metadata_available: i64 = conn
                .query_row(
                    "SELECT metadata_available
                       FROM unit_signature_metadata_values
                      WHERE blob_id = ?1 AND unit_key = ?2 AND ordinal = ?3",
                    rusqlite::params![id, target_metadata.0, target_metadata.1],
                    |row| row.get(0),
                )
                .expect("targeted metadata row after visibility corruption");
            assert_eq!(
                metadata_available, 0,
                "missing visibility is not non-private"
            );
        } else {
            assert_eq!(
                conn.query_row(
                    "SELECT COUNT(*) FROM live_parsed_blobs WHERE blob_id = ?1",
                    [id],
                    |row| row.get::<_, i64>(0),
                )
                .expect("damaged live membership"),
                0,
                "{corruption} corruption must not become legacy membership"
            );
            assert!(
                store
                    .hydrate_file_state_with_source(
                        oid,
                        "java",
                        generation,
                        &JavaAdapter,
                        &file,
                        JAVA_SOURCE,
                    )
                    .expect("damaged visibility hydration")
                    .is_none(),
                "{corruption} corruption must report unavailable hydration"
            );
        }
    }
}

#[test]
fn rust_native_declaration_sources_publish_exact_ids_and_visibility_facts() {
    const RUST_SOURCE: &str = r#"
mod first { fn repeated() {} }
mod second { fn repeated() {} }
"#;
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", RUST_SOURCE)
        .build();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let facts = state
        .source_facts
        .as_ref()
        .expect("Rust publishes canonical source facts");
    assert_eq!(
        facts.declaration_visibilities.as_ref().unwrap().len(),
        4,
        "Rust publishes the structured visibility of both modules and functions"
    );

    let repeated_declarations = facts
        .rust_declaration_properties
        .iter()
        .filter(|property| property.kind == RustDeclarationKind::Function)
        .map(|property| property.declaration)
        .collect::<Vec<_>>();
    assert_eq!(
        repeated_declarations.len(),
        2,
        "same-name module functions retain separate source declaration identities"
    );
    assert_ne!(repeated_declarations[0], repeated_declarations[1]);

    let mut expected_native = facts
        .native_declaration_sources
        .iter()
        .map(|(source_site, declaration)| {
            (i64::from(source_site.get()), i64::from(declaration.get()))
        })
        .collect::<Vec<_>>();
    expected_native.sort_unstable();
    assert_eq!(
        expected_native.len(),
        4,
        "both modules and their same-name functions have native declaration sites"
    );
    assert!(repeated_declarations.iter().all(|declaration| {
        expected_native
            .iter()
            .any(|(_, candidate)| *candidate == i64::from(declaration.get()))
    }));

    let oid = oid_for(RUST_SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().expect("Rust source publication store");
    store
        .conn
        .execute(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER test_delete_native_bridge_after_insert
                 AFTER INSERT ON source_native_declaration_bridges
                 BEGIN
                     DELETE FROM source_native_declaration_bridges
                      WHERE blob_id = NEW.blob_id
                        AND source_site = NEW.source_site
                        AND declaration_id = NEW.declaration_id;
                 END;",
            )?;
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .expect("install native bridge publication fault");
    let error = store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .expect_err("missing native bridge must fail publication");
    assert!(
        error
            .to_string()
            .contains("source native declaration bridge count is inconsistent"),
        "unexpected native bridge count error: {error:?}"
    );
    assert_eq!(
        store
            .content_row_count(oid, "rust")
            .expect("failed Rust publication row count"),
        0,
        "failed native bridge publication leaves no content rows"
    );
    store
        .conn
        .execute(|conn| {
            conn.execute_batch("DROP TRIGGER test_delete_native_bridge_after_insert;")?;
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .expect("remove native bridge publication fault");
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .expect("publish Rust native declaration bridges");
    let conn = store.read_conn().expect("read Rust source publication");
    let id = rust_blob_id(&conn, oid);

    let common_marker: (Option<i64>, String, bool, bool) = conn
        .query_row(
            "SELECT manifest.native_bridge_count, manifest.publication_state,
                    meta.native_bridges_required, readiness.available
               FROM source_fact_manifests AS manifest
               JOIN blob_meta AS meta ON meta.blob_id = manifest.blob_id
               JOIN source_fact_readiness AS readiness
                 ON readiness.blob_id = manifest.blob_id
              WHERE manifest.blob_id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("Rust common source-facts marker");
    assert_eq!(
        common_marker,
        (
            Some(i64::try_from(expected_native.len()).expect("bridge count fits SQLite")),
            "complete".to_owned(),
            true,
            true
        ),
        "new source publications declare exact bridges, require them, and become ready"
    );

    let actual_native = conn
        .prepare(
            "SELECT source_site, declaration_id
               FROM source_native_declaration_bridges
              WHERE blob_id = ?1
              ORDER BY source_site",
        )
        .expect("prepare Rust native bridge rows")
        .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("read Rust native bridge rows")
        .collect::<rusqlite::Result<Vec<(i64, i64)>>>()
        .expect("collect Rust native bridge rows");
    assert_eq!(actual_native, expected_native);

    let definition_native = conn
        .prepare(
            "SELECT bridge.source_site, bridge.declaration_id
               FROM source_native_declaration_bridges AS bridge
               JOIN resolution_semantic_sites AS site
                 ON site.blob_id = bridge.blob_id
                AND site.source_site = bridge.source_site
              WHERE bridge.blob_id = ?1
                AND site.semantic_role = 'definition'
              ORDER BY bridge.source_site",
        )
        .expect("prepare Rust native definition join")
        .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("read Rust native definition join")
        .collect::<rusqlite::Result<Vec<(i64, i64)>>>()
        .expect("collect Rust native definition join");
    assert_eq!(
        definition_native, expected_native,
        "native bridges join exact producer identities to definition-role sites"
    );
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM source_declaration_visibility_manifests
              WHERE blob_id = ?1",
            [id],
            |row| row.get::<_, i64>(0),
        )
        .expect("count Rust visibility family"),
        1,
        "Rust native bridge publication includes its source-owned visibility facts"
    );
}

#[test]
fn empty_rust_native_declaration_publication_is_ready_with_zero_count() {
    let fixture = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", "")
        .build();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let facts = state
        .source_facts
        .as_ref()
        .expect("empty Rust source facts");
    assert_eq!(
        facts.declaration_visibilities.as_deref(),
        Some([].as_slice())
    );
    assert!(facts.native_declaration_sources.is_empty());

    let oid = oid_for(b"");
    let store = AnalyzerStore::open_ephemeral().expect("empty Rust source publication store");
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .expect("publish empty Rust native declaration family");
    let conn = store
        .read_conn()
        .expect("read empty Rust source publication");
    let id = rust_blob_id(&conn, oid);
    let common_marker: (Option<i64>, String, bool, bool) = conn
        .query_row(
            "SELECT manifest.native_bridge_count, manifest.publication_state,
                    meta.native_bridges_required, readiness.available
               FROM source_fact_manifests AS manifest
               JOIN blob_meta AS meta ON meta.blob_id = manifest.blob_id
               JOIN source_fact_readiness AS readiness
                 ON readiness.blob_id = manifest.blob_id
              WHERE manifest.blob_id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("empty Rust common source-facts marker");
    assert_eq!(
        common_marker,
        (Some(0), "complete".to_owned(), true, true),
        "empty source publications declare zero bridges, require them, and become ready"
    );
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM source_native_declaration_bridges WHERE blob_id = ?1",
            [id],
            |row| row.get::<_, i64>(0),
        )
        .expect("empty Rust native bridge rows"),
        0
    );

    drop(conn);
    let oid_text = oid.to_string();
    store
        .conn
        .execute(move |conn| {
            conn.execute_batch("DROP TRIGGER source_fact_native_bridge_count_is_immutable;")?;
            conn.execute(
                "UPDATE source_fact_manifests
                    SET native_bridge_count = NULL
                  WHERE blob_id = (SELECT id FROM blobs
                                    WHERE blob_oid = ?1 AND lang = 'rust')",
                [&oid_text],
            )?;
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .expect("corrupt empty Rust native bridge count");
    let conn = store
        .read_conn()
        .expect("read corrupted empty Rust source publication");
    assert!(
        !conn
            .query_row(
                "SELECT available FROM source_fact_readiness
              WHERE blob_id = ?1",
                [id],
                |row| row.get::<_, bool>(0),
            )
            .expect("corrupted empty Rust source-fact readiness"),
        "missing zero native bridge count must make readiness unavailable"
    );
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM rust_published_fact_blobs
              WHERE blob_oid = ?1 AND lang = 'rust'",
            [oid.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .expect("corrupted empty Rust publication membership"),
        0,
        "unready empty Rust source must be excluded from published facts"
    );
}

#[test]
fn declaration_visibility_key_batches_seek_without_same_blob_fanout() {
    use crate::analyzer::store::planner_statistics::pinned_plans::pinned;
    use crate::analyzer::store::resolution_selection::tests::SelectionFixture;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use rusqlite::StatementStatus;

    let mut baseline_work = HashMap::new();
    for declarations in [256, 2048] {
        let methods = (0..declarations)
            .map(|index| format!("public void method{index}() {{}}"))
            .collect::<String>();
        let fixture = SelectionFixture::custom_source(1, &format!("class Example {{ {methods} }}"));
        let conn = fixture.store.conn.lock().unwrap();
        let blob: i64 = conn
            .query_row(
                "SELECT blob_id FROM resolution_fragment_interiors LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let all = conn
            .prepare("SELECT definition_semantic_key, visibility FROM resolution_declaration_visibility_properties WHERE blob_id=?1 ORDER BY definition_semantic_key")
            .unwrap()
            .query_map([blob], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            all.len() >= declarations,
            "real published declarations: {all:?}"
        );
        for statistics in PlannerStatisticsState::BOTH {
            statistics.install(&conn);
            let subject = pinned("resolution_declaration_visibilities_by_definition");
            for arity in [1, 16, 64, 256] {
                for (case, keys) in [
                    all.iter()
                        .take(arity)
                        .map(|(key, _)| *key)
                        .collect::<Vec<_>>(),
                    vec![i64::from(u32::MAX); arity],
                    vec![all[0].0; arity],
                ]
                .into_iter()
                .enumerate()
                {
                    let expected = all
                        .iter()
                        .filter(|(key, _)| keys.contains(key))
                        .cloned()
                        .collect::<Vec<_>>();
                    let payload = serde_json::to_string(&keys).unwrap();
                    let mut statement = conn.prepare(&subject.sql).unwrap();
                    let mut actual = statement
                        .query_map(params![blob, payload], |row| {
                            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                        })
                        .unwrap()
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .unwrap();
                    actual.sort_unstable();
                    assert_eq!(
                        actual, expected,
                        "{statistics:?}, declarations={declarations}, keys={keys:?}"
                    );
                    let vm = statement.get_status(StatementStatus::VmStep);
                    let plan = conn
                        .prepare(&format!("EXPLAIN QUERY PLAN {}", subject.sql))
                        .unwrap()
                        .query_map(params![blob, payload], |row| row.get::<_, String>(3))
                        .unwrap()
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .unwrap();
                    let work_key = (format!("{statistics:?}"), arity, case);
                    if let Some(baseline) = baseline_work.get(&work_key) {
                        assert_eq!(
                            vm, *baseline,
                            "same requested batch must not grow with unrelated declarations: {statistics:?}, declarations={declarations}, keys={keys:?}: {plan:?}"
                        );
                    } else {
                        baseline_work.insert(work_key, vm);
                    }
                    for required in [
                        "SEARCH site USING INDEX sqlite_autoindex_resolution_semantic_sites_2 (blob_id=? AND semantic_role=? AND semantic_key=?)",
                        "SEARCH legacy USING PRIMARY KEY (blob_id=? AND definition_semantic_key=?)",
                        "SEARCH native USING PRIMARY KEY (blob_id=? AND source_site=?)",
                        "SEARCH visibility USING PRIMARY KEY (blob_id=? AND declaration_id=?)",
                    ] {
                        assert!(
                            plan.iter().any(|step| step.contains(required)),
                            "{statistics:?}, keys={keys:?}: {required}: {plan:?}"
                        );
                    }
                    for forbidden in [
                        "SCAN site",
                        "SCAN legacy",
                        "SCAN native",
                        "SCAN visibility",
                        "AUTOMATIC",
                        "CO-ROUTINE",
                        "TEMP B-TREE",
                    ] {
                        assert!(
                            !plan.iter().any(|step| step.contains(forbidden)),
                            "{statistics:?}, keys={keys:?}: {forbidden}: {plan:?}"
                        );
                    }
                }
            }
        }
    }
}
