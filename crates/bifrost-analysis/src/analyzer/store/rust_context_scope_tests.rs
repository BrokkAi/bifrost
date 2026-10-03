//! Canonical Rust context membership through the source occurrence spans.
//!
//! These tests exercise the source-owned context query after a real
//! publication and reopen.  Context identity comes from the context row and
//! its canonical occurrence foreign key; no source text or CodeUnit range is
//! consulted by the read.

use std::collections::HashSet;

use brokk_bifrost_core::analyzer::rust_facts::{RustSourceContextFact, RustSourceContextKind};
use brokk_bifrost_core::analyzer::source_facts::{SourceOccurrenceId, SourceOccurrenceProvenance};
use rusqlite::{Connection, params, params_from_iter, types::Value};

use crate::analyzer::rust::RustAdapter;
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};

use super::tests::{oid_for, parse_state};
use super::*;

const CONTEXT_SOURCE: &str = r#"
fn host(value: u8) {
    wrap! { struct Embedded; }
    let _first = value;
    {
        let _nested = value;
    }
}
"#;

fn context_ids_containing(
    facts: &brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts,
    reference_byte: usize,
    provenance: SourceOccurrenceProvenance,
) -> HashSet<SourceOccurrenceId> {
    facts
        .rust_items
        .contexts
        .iter()
        .filter_map(|context: &RustSourceContextFact| {
            let occurrence = facts.occurrences.occurrence(context.context);
            (occurrence.provenance == provenance
                && occurrence.range.start_byte <= reference_byte
                && reference_byte < occurrence.range.end_byte)
                .then_some(context.context)
        })
        .collect()
}

fn publish_context_fixture() -> (BuiltInlineTestProject, AnalyzerStore, git2::Oid) {
    let fixture = InlineTestProject::new()
        .file("src/lib.rs", CONTEXT_SOURCE)
        .build();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let source = state
        .source_facts
        .as_ref()
        .expect("context fixture has canonical Rust source facts");
    assert!(!source.rust_items.contexts.is_empty());
    assert!(
        source.rust_items.contexts.iter().any(|context| {
            source.occurrences.occurrence(context.context).provenance
                == SourceOccurrenceProvenance::PrimaryNode
        }),
        "context fixture has no primary source context"
    );
    assert!(
        source.rust_items.contexts.iter().any(|context| {
            source.occurrences.occurrence(context.context).provenance
                == SourceOccurrenceProvenance::Embedded
        }),
        "context fixture has no embedded source context to exercise provenance filtering"
    );

    let oid = oid_for(CONTEXT_SOURCE.as_bytes());
    let store = AnalyzerStore::open_persistent(&fixture.root().join("rust-contexts.db"))
        .expect("persistent context store");
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .expect("publish canonical context fixture");
    (fixture, store, oid)
}

#[test]
fn rust_primary_contexts_reopen_respect_half_open_spans_and_provenance() {
    let (fixture, store, oid) = publish_context_fixture();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let source = state.source_facts.as_ref().unwrap();
    let target = source
        .rust_items
        .contexts
        .iter()
        .rev()
        .find_map(|context| {
            let occurrence = source.occurrences.occurrence(context.context);
            (context.kind == RustSourceContextKind::Block
                && occurrence.provenance == SourceOccurrenceProvenance::PrimaryNode
                && occurrence.range.start_byte < occurrence.range.end_byte)
                .then_some(occurrence.range)
        })
        .expect("primary context with a nonempty span");
    let expected_at_start = context_ids_containing(
        source,
        target.start_byte,
        SourceOccurrenceProvenance::PrimaryNode,
    );
    let expected_at_end = context_ids_containing(
        source,
        target.end_byte,
        SourceOccurrenceProvenance::PrimaryNode,
    );
    let eof = source
        .occurrences
        .occurrences()
        .iter()
        .map(|occurrence| occurrence.range.end_byte)
        .max()
        .expect("canonical source occurrence end");
    let embedded_point = source
        .rust_items
        .contexts
        .iter()
        .find_map(|context| {
            let occurrence = source.occurrences.occurrence(context.context);
            (occurrence.provenance == SourceOccurrenceProvenance::Embedded)
                .then_some(occurrence.range.start_byte)
        })
        .expect("embedded context point");
    let expected_primary = context_ids_containing(
        source,
        embedded_point,
        SourceOccurrenceProvenance::PrimaryNode,
    );
    let excluded_embedded =
        context_ids_containing(source, embedded_point, SourceOccurrenceProvenance::Embedded);
    assert!(!expected_primary.is_empty() && !excluded_embedded.is_empty());

    let generation = store.current_generation("rust").unwrap();
    drop(state);
    drop(store);
    std::fs::remove_file(file.abs_path()).expect("remove source before persisted reopen");

    let reopened = AnalyzerStore::open_persistent(&fixture.root().join("rust-contexts.db"))
        .expect("reopen context store");
    let at_start = reopened
        .rust_primary_contexts_at(oid, generation, target.start_byte, &|| true)
        .unwrap()
        .unwrap()
        .into_iter()
        .collect::<HashSet<_>>();
    assert_eq!(at_start, expected_at_start);
    let at_end = reopened
        .rust_primary_contexts_at(oid, generation, target.end_byte, &|| true)
        .unwrap()
        .unwrap()
        .into_iter()
        .collect::<HashSet<_>>();
    assert_eq!(at_end, expected_at_end);
    assert_ne!(
        at_start, at_end,
        "the selected context must be end-exclusive"
    );
    let at_eof = reopened
        .rust_primary_contexts_at(oid, generation, eof, &|| true)
        .unwrap()
        .unwrap();
    assert!(
        at_eof.is_empty(),
        "EOF is outside every half-open span: {at_eof:?}"
    );
    let actual = reopened
        .rust_primary_contexts_at(oid, generation, embedded_point, &|| true)
        .unwrap()
        .unwrap()
        .into_iter()
        .collect::<HashSet<_>>();
    assert_eq!(actual, expected_primary);
    assert!(actual.is_disjoint(&excluded_embedded));

    let missing =
        reopened.rust_primary_contexts_at(oid_for(b"unpublished context"), generation, 0, &|| true);
    assert!(
        missing.is_err(),
        "an unpublished blob is not an empty context set"
    );
}

#[test]
fn rust_primary_contexts_require_fresh_item_publication_and_recover() {
    let (fixture, store, oid) = publish_context_fixture();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let generation = store.current_generation("rust").unwrap();
    let expected = store
        .rust_primary_contexts_at(oid, generation, 1, &|| true)
        .unwrap()
        .unwrap();
    assert!(!expected.is_empty());
    // Model an old sealed item publication without its current shape marker.
    // This temporary store alone has its reopen/shape guards disabled.
    store.conn.execute(|connection| {
        connection
            .execute_batch(
                "DROP TRIGGER source_fact_manifests_no_reopen;
             DROP TRIGGER source_fact_manifests_validate_rust_type_forms;
             UPDATE source_fact_manifests SET publication_state = 'building';
             UPDATE source_rust_item_manifests SET type_forms_version = NULL;
             UPDATE source_fact_manifests SET publication_state = 'complete';",
            )
            .unwrap();
    });
    assert!(
        store
            .rust_primary_contexts_at(oid, generation, 1, &|| true)
            .is_err()
    );
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    assert_eq!(
        store
            .rust_primary_contexts_at(oid, generation, 1, &|| true)
            .unwrap()
            .unwrap(),
        expected
    );
}

#[test]
fn rust_primary_contexts_cancel_before_and_during_rows_then_retry() {
    let (fixture, store, oid) = publish_context_fixture();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let source = state.source_facts.as_ref().unwrap();
    let point = source
        .rust_items
        .contexts
        .iter()
        .rev()
        .filter(|context| context.kind == RustSourceContextKind::Block)
        .map(|context| {
            source
                .occurrences
                .occurrence(context.context)
                .range
                .start_byte
        })
        .next()
        .expect("context start");
    let generation = store.current_generation("rust").unwrap();

    assert!(
        store
            .rust_primary_contexts_at(oid, generation, point, &|| false)
            .unwrap()
            .is_none(),
        "pre-cancelled context read must not open a result"
    );
    let checks = std::cell::Cell::new(0usize);
    let complete = store
        .rust_primary_contexts_at(oid, generation, point, &|| {
            checks.set(checks.get() + 1);
            true
        })
        .unwrap()
        .unwrap();
    assert!(!complete.is_empty());
    let total_checks = checks.get();
    assert!(
        total_checks >= 3,
        "context read has no row/final checkpoints"
    );
    for stop_at in 1..=total_checks {
        let checks = std::cell::Cell::new(0usize);
        assert!(
            store
                .rust_primary_contexts_at(oid, generation, point, &|| {
                    checks.set(checks.get() + 1);
                    checks.get() < stop_at
                })
                .unwrap()
                .is_none(),
            "cancelled context read returned partial rows at checkpoint {stop_at}"
        );
    }
    assert_eq!(
        store
            .rust_primary_contexts_at(oid, generation, point, &|| true)
            .unwrap()
            .unwrap(),
        complete,
        "a cancelled read must not poison retry"
    );
    drop(state);
    drop(fixture);
}

fn explain_context_query(
    connection: &Connection,
    blob_id: i64,
    reference_byte: i64,
) -> Vec<String> {
    let mut statement = connection
        .prepare(&format!(
            "EXPLAIN QUERY PLAN {}",
            super::source_facts::RUST_PRIMARY_CONTEXTS_AT_SQL
        ))
        .expect("context query explains");
    statement
        .query_map(
            params_from_iter([Value::Integer(blob_id), Value::Integer(reference_byte)]),
            |row| row.get(3),
        )
        .expect("context query plan rows")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("context query plan decodes")
}

fn explain_context_manifest(connection: &Connection, parameters: &[Value]) -> Vec<String> {
    let mut statement = connection
        .prepare(&format!(
            "EXPLAIN QUERY PLAN {}",
            super::source_facts::RUST_PRIMARY_CONTEXT_MANIFEST_SQL
        ))
        .expect("context manifest query explains");
    statement
        .query_map(params_from_iter(parameters), |row| row.get(3))
        .expect("context manifest query plan rows")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("context manifest query plan decodes")
}

fn assert_context_manifest_plan(plan: &[String]) {
    for alias in [
        "keys",
        "meta",
        "source",
        "module",
        "scope",
        "inventory",
        "manifest",
        "item",
    ] {
        assert!(
            plan.iter().any(|detail| {
                detail.contains(&format!("SEARCH {alias}"))
                    && detail.contains(if alias == "keys" {
                        "blob_oid"
                    } else {
                        "blob_id"
                    })
            }),
            "context manifest lacks bounded witness search for {alias}: {plan:?}"
        );
        assert!(
            plan.iter()
                .all(|detail| !detail.contains(&format!("SCAN {alias}"))),
            "context manifest scans witness alias {alias}: {plan:?}"
        );
    }
    assert!(
        plan.iter()
            .all(|detail| !detail.contains("AUTOMATIC") && !detail.contains("TEMP B-TREE")),
        "context manifest has an unexpected planner fallback: {plan:?}"
    );
}

fn assert_context_query_plan(plan: &[String]) {
    assert!(
        plan.iter()
            .any(|detail| detail.contains("SEARCH context") && detail.contains("blob_id=?")),
        "context query is not blob-first: {plan:?}"
    );
    assert!(
        plan.iter()
            .all(|detail| !detail.contains("SCAN context") && !detail.contains("SCAN occurrence")),
        "context query scans a source relation: {plan:?}"
    );
    assert!(
        plan.iter()
            .all(|detail| !detail.contains("AUTOMATIC") && !detail.contains("TEMP B-TREE")),
        "context query has an unbounded planner fallback: {plan:?}"
    );
}

#[test]
fn rust_primary_context_query_is_populated_blob_first_before_and_after_analyze() {
    let mut project = InlineTestProject::new();
    let mut sources = Vec::new();
    for index in 0..=16 {
        let source = format!("{CONTEXT_SOURCE}\n// context planner fixture {index}\n");
        project = project.file(format!("src/context_plan_{index}.rs"), source.clone());
        sources.push(source);
    }
    let fixture = project.build();
    let store = AnalyzerStore::open_ephemeral().expect("context query plan store");
    let mut oids = Vec::new();
    for (index, source) in sources.iter().enumerate() {
        let file = fixture.file(format!("src/context_plan_{index}.rs"));
        let state = parse_state(&RustAdapter, &file);
        let oid = oid_for(source.as_bytes());
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap_or_else(|error| panic!("populate context plan fixture {index}: {error}"));
        oids.push(oid);
    }
    let oid = oids[0];
    let blob_id: i64 = store.conn.execute(move |connection| {
        connection
            .query_row(
                "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'",
                [oid.to_string()],
                |row| row.get(0),
            )
            .expect("context plan blob id")
    });
    let generation = store.current_generation("rust").expect("Rust generation");
    let reference_byte: i64 = store
        .read_conn()
        .unwrap()
        .query_row(
            // The context's span and provenance are its own columns after lane
            // ST's stage B, so this reads the row rather than the arena.
            "SELECT context.start_byte
               FROM source_rust_item_contexts AS context
              WHERE context.blob_id = ?1
                AND context.provenance = 0
                AND context.start_byte < context.end_byte
              LIMIT 1",
            [blob_id],
            |row| row.get(0),
        )
        .expect("populated primary context point");

    store
        .conn
        .execute(|connection| {
            for table in ["sqlite_stat1", "sqlite_stat4"] {
                let exists: bool = connection.query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM sqlite_master
                          WHERE type = 'table' AND name = ?1
                     )",
                    [table],
                    |row| row.get(0),
                )?;
                if exists {
                    connection.execute(&format!("DELETE FROM {table}"), [])?;
                }
            }
            connection.execute_batch("ANALYZE sqlite_schema;")?;
            Ok::<_, rusqlite::Error>(())
        })
        .unwrap();
    store
        .reload_planner_statistics()
        .expect("reload cleared context planner statistics");
    let connection = store.read_conn().unwrap();
    let (item_version, macro_version, type_version, macro_context_version): (i64, i64, i64, i64) = connection.query_row(
        "SELECT facts_version, macro_facts_version, type_forms_version, macro_contexts_version FROM source_rust_item_manifests WHERE blob_id = ?1",
        [blob_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    ).unwrap();
    let manifest_parameters = [
        Value::Text(oid.to_string()),
        Value::Integer(generation.get()),
        Value::Integer(super::source_facts::SOURCE_FACTS_VERSION),
        Value::Integer(item_version),
        Value::Integer(macro_version),
        Value::Integer(type_version),
        Value::Integer(macro_context_version),
    ];
    let manifest_blob: i64 = connection
        .query_row(
            super::source_facts::RUST_PRIMARY_CONTEXT_MANIFEST_SQL,
            params_from_iter(&manifest_parameters),
            |row| row.get(0),
        )
        .expect("published context manifest witness");
    assert_eq!(manifest_blob, blob_id);
    assert_context_manifest_plan(&explain_context_manifest(&connection, &manifest_parameters));
    assert_context_query_plan(&explain_context_query(&connection, blob_id, reference_byte));
    assert!(
        connection
            .prepare(super::source_facts::RUST_PRIMARY_CONTEXTS_AT_SQL)
            .unwrap()
            .query(params![blob_id, reference_byte])
            .unwrap()
            .next()
            .unwrap()
            .is_some()
    );
    drop(connection);

    store
        .refresh_planner_statistics()
        .expect("populate context planner statistics");
    let connection = store.read_conn().unwrap();
    let manifest_blob: i64 = connection
        .query_row(
            super::source_facts::RUST_PRIMARY_CONTEXT_MANIFEST_SQL,
            params_from_iter(&manifest_parameters),
            |row| row.get(0),
        )
        .expect("published context manifest witness after ANALYZE");
    assert_eq!(manifest_blob, blob_id);
    assert_context_manifest_plan(&explain_context_manifest(&connection, &manifest_parameters));
    assert_context_query_plan(&explain_context_query(&connection, blob_id, reference_byte));
}
