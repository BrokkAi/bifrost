//! End-to-end acceptance tests for the Java source-declaration visibility family.
//!
//! These tests deliberately begin with a real Java parse.  The SQL assertions
//! then compare every persisted identity to the parse product, so a coherent
//! but independently reconstructed visibility table cannot satisfy the test.

use std::collections::HashMap;

use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;

use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use brokk_bifrost_core::hash::HashMap as CoreHashMap;
use rusqlite::{Connection, params};

use crate::analyzer::Language;

use crate::analyzer::store::{AnalyzerStore, declaration_name};

use crate::analyzer::store::file_state::FileState;

#[doc(hidden)]
pub const JAVA_SOURCE: &str = r#"interface Contract {
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

#[doc(hidden)]
pub fn blob_id(conn: &Connection, oid: git2::Oid) -> i64 {
    conn.query_row(
        "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'",
        [oid.to_string()],
        |row| row.get(0),
    )
    .expect("published Java blob id")
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct VisibilitySnapshot {
    #[doc(hidden)]
    pub marker: (i64, i64, i64, i64),
    #[doc(hidden)]
    pub visibilities: Vec<(i64, String)>,
    #[doc(hidden)]
    pub native_bridges: Vec<(i64, i64)>,
    #[doc(hidden)]
    pub metadata_bridges: Vec<(i64, i64, i64)>,
    #[doc(hidden)]
    pub native_visibility: Vec<(i64, String)>,
    #[doc(hidden)]
    pub metadata_values: Vec<(i64, i64, Option<String>, i64)>,
    #[doc(hidden)]
    pub legacy_rows: i64,
}

#[doc(hidden)]
pub fn visibility_snapshot(conn: &Connection, id: i64) -> VisibilitySnapshot {
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

#[doc(hidden)]
pub fn assert_source_visibility_properties(state: &FileState) {
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
                declaration_name(facts, JAVA_SOURCE, fact.declaration) == name
                    && fact.visibility == expected
            }),
            "missing source visibility {name}={expected:?}"
        );
    }
    assert!(visibilities.iter().any(|fact| {
        declaration_name(facts, JAVA_SOURCE, fact.declaration) == "run"
            && fact.visibility == DeclaredVisibility::Public
    }));
    assert!(visibilities.iter().any(|fact| {
        declaration_name(facts, JAVA_SOURCE, fact.declaration) == "run"
            && fact.visibility == DeclaredVisibility::Private
    }));

    let native_declarations = facts
        .native_declaration_sources
        .iter()
        .map(|(_, declaration)| *declaration)
        .collect::<std::collections::HashSet<_>>();
    // #6291 / 406536ca0c: record components now bridge to native fields
    // and accessors as well as the canonical constructor formals.
    for native in ["FIRST", "SECOND", "left", "right"] {
        let ids = visibilities
            .iter()
            .filter(|fact| declaration_name(facts, JAVA_SOURCE, fact.declaration) == native)
            .map(|fact| fact.declaration)
            .collect::<Vec<_>>();
        assert!(!ids.is_empty(), "native declaration {native}");
        assert!(
            ids.iter().all(|id| native_declarations.contains(id)),
            "{native} must have a native source declaration"
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
            .all(|link| !declaration_name(facts, JAVA_SOURCE, link.declaration).is_empty())
    );
}

#[doc(hidden)]
pub fn by_declaration_visibility(
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

#[doc(hidden)]
pub fn assert_metadata_read_plan(conn: &Connection, state: &FileState, oid: git2::Oid) {
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
                brokk_bifrost_core::gitblob::ParseVariant::Empty,
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

#[doc(hidden)]
pub fn visibility_workspace(
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
