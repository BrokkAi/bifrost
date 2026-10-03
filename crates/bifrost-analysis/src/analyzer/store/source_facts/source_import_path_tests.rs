//! Canonical source-import path-presence round trips through the store.

use super::import_read::read_source_imports;
use crate::analyzer::rust::RustAdapter;
use crate::analyzer::store::tests::{oid_for, parse_state};
use crate::analyzer::store::{AnalyzerStore, read_import_infos};
use crate::inline_project::InlineTestProject;
use brokk_bifrost_core::analyzer::model::{ImportInfo, StructuredImportPathKind};
use brokk_bifrost_core::analyzer::parsed_file::{SourceImportFact, SourceImportPathFact};
use brokk_bifrost_core::analyzer::source_facts::SourceImportId;
use brokk_bifrost_core::analyzer::structural::facts::Span;

#[test]
fn canonical_import_path_presence_round_trips_through_typed_and_generic_reads() {
    let source = "fn main() {}\n";
    let fixture = InlineTestProject::new().file("src/lib.rs", source).build();
    let file = fixture.file("src/lib.rs");
    let mut state = parse_state(&RustAdapter, &file);
    let source_facts = state
        .source_facts
        .as_mut()
        .expect("Rust parsing publishes source facts");
    assert!(source_facts.occurrences.occurrence_count() > 0);

    let declaration = brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId::new(0);
    source_facts.imports = vec![
        SourceImportFact {
            declaration,
            target: Some(declaration),
            alias_occurrence: None,
            statement: "opaque import".to_owned(),
            is_wildcard: false,
            is_global: false,
            is_macro_use: false,
            identifier: Some("opaque".to_owned()),
            alias: None,
            path: None,
        },
        SourceImportFact {
            declaration,
            target: Some(declaration),
            alias_occurrence: None,
            statement: "empty structured import".to_owned(),
            is_wildcard: true,
            is_global: true,
            is_macro_use: false,
            identifier: None,
            alias: None,
            path: Some(SourceImportPathFact {
                kind: None,
                segments: Vec::new(),
                lexical_prefixes: Vec::new(),
                lexical_scopes: Vec::new(),
            }),
        },
    ];
    let expected_source_imports = source_facts.imports.clone();
    let expected_generic_imports = expected_source_imports
        .iter()
        .map(|import| import.import_info(&source_facts.occurrences))
        .collect::<Vec<_>>();
    source_facts.generic_imports = vec![SourceImportId::new(0), SourceImportId::new(1)];
    state.imports = vec![
        ImportInfo {
            raw_snippet: "stale opaque DTO".to_owned(),
            is_wildcard: true,
            is_global: true,
            identifier: Some("stale".to_owned()),
            alias: Some("stale_alias".to_owned()),
            path: Some(brokk_bifrost_core::analyzer::model::StructuredImportPath {
                segments: vec!["stale".to_owned()],
                kind: Some(StructuredImportPathKind::Namespace),
                lexical_prefixes: vec!["stale".to_owned()],
                lexical_scopes: Vec::new(),
                declaration_start_byte: usize::MAX,
            }),
            binder_span: Some(Span {
                start_byte: usize::MAX,
                end_byte: usize::MAX,
            }),
        },
        ImportInfo {
            raw_snippet: "stale empty DTO".to_owned(),
            is_wildcard: false,
            is_global: false,
            identifier: Some("stale_empty".to_owned()),
            alias: None,
            path: None,
            binder_span: None,
        },
    ];

    let oid = oid_for(source.as_bytes());
    let store_path = fixture.root().join("canonical-import-path-presence.db");
    let store = AnalyzerStore::open_persistent(&store_path).unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    drop(store);

    let reopened = AnalyzerStore::open_persistent(&store_path).unwrap();
    let typed = reopened
        .hydrate_file_state(oid, "rust", &RustAdapter, &file)
        .unwrap()
        .expect("canonical publication should hydrate");
    assert_eq!(typed.imports.len(), 2);
    assert_eq!(typed.imports[0].raw_snippet, "opaque import");
    assert!(!typed.imports[0].is_wildcard);
    assert!(!typed.imports[0].is_global);
    assert_eq!(typed.imports[0].identifier.as_deref(), Some("opaque"));
    assert_eq!(typed.imports[0].alias, None);
    assert_eq!(typed.imports[0].path, None);
    assert_eq!(typed.imports[1].raw_snippet, "empty structured import");
    assert!(typed.imports[1].is_wildcard);
    assert!(typed.imports[1].is_global);
    assert_eq!(typed.imports[1].identifier, None);
    assert_eq!(typed.imports[1].alias, None);
    let empty_path = typed.imports[1]
        .path
        .as_ref()
        .expect("empty structured path remains present");
    assert!(empty_path.segments.is_empty());
    assert_eq!(empty_path.kind, None);
    assert_eq!(typed.imports, expected_generic_imports);

    let conn = reopened.read_conn().unwrap();
    let blob_id: i64 = conn
        .query_row(
            "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'",
            [oid.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let keep_going = || true;
    let canonical = read_source_imports(&conn, blob_id, &keep_going)
        .unwrap()
        .expect("canonical source imports should be readable");
    assert_eq!(canonical, expected_source_imports);

    let generic = read_import_infos(&conn, &oid.to_string(), "rust").unwrap();
    assert_eq!(generic, expected_generic_imports);
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
        .unwrap();
    assert_eq!(generic_rows, expected_generic_imports.len() as i64);
    assert_eq!(linked_generic_rows, generic_rows);
    assert_eq!(link_only_generic_rows, generic_rows);
    let generic_source_ids = conn
        .prepare(
            "SELECT source_import_id FROM import_statements
             WHERE blob_id = ?1 ORDER BY ordinal",
        )
        .unwrap()
        .query_map([blob_id], |row| row.get::<_, i64>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(generic_source_ids, vec![0, 1]);
    let persisted_flags = conn
        .prepare(
            "SELECT has_structured_path FROM source_imports WHERE blob_id = ?1 ORDER BY import_id",
        )
        .unwrap()
        .query_map([blob_id], |row| row.get::<_, i64>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(persisted_flags, vec![0, 1]);
}
