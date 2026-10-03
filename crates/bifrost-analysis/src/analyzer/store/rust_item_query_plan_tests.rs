//! Query-plan pins for the normalized Rust item/type reader.
//!
//! These cases intentionally use the SQL text and parameter arity from
//! `analyzer::rust::source_storage`.  The reader is blob-first: every child
//! relation is selected by its leading `blob_id` key before its publication
//! rows are hydrated.

use rusqlite::{Connection, params_from_iter, types::Value};

use crate::analyzer::rust::RustAdapter;
use crate::inline_project::InlineTestProject;

use super::tests::{oid_for, parse_state};
use super::*;

const QUERY_FIXTURE: &str = r#"
use std::fmt::Debug;

macro_rules! declare { ($name:ident) => { struct $name; }; }

pub struct Item<T>(T);
pub struct Fields { value: Option<Item<u8>> }
pub trait Trait<T> {
    type Associated;
    fn method(&self, value: T);
}
impl<T: Debug> Trait<T> for Item<T> {
    type Associated = T;
    fn method(&self, value: T) {}
}
pub type Alias = Item<u8>;
pub type Wrapped = &[Item<u8>];
pub fn free(value: u8) -> Option<Item<u8>> { todo!() }
pub fn opaque() -> impl Debug + Send { todo!() }
pub fn dynamic() -> Box<dyn Debug + Send> { todo!() }

pub mod scoped_imports {
    use super::Item as NestedItem;

    pub fn consume(value: NestedItem<u8>) {
        let _ = value;
    }
}

wrap! { pub mod embedded { pub struct Embedded; } }
"#;

struct QueryPlanCase {
    name: &'static str,
    sql: &'static str,
    blob_relation: Option<&'static str>,
    parameters: Vec<Value>,
}

fn explain(connection: &Connection, case: &QueryPlanCase) -> Vec<String> {
    let mut statement = connection
        .prepare(&format!("EXPLAIN QUERY PLAN {}", case.sql))
        .unwrap_or_else(|error| panic!("{} SQL failed to prepare: {error}", case.name));
    statement
        .query_map(params_from_iter(case.parameters.iter()), |row| row.get(3))
        .unwrap_or_else(|error| panic!("{} SQL failed to explain: {error}", case.name))
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap_or_else(|error| panic!("{} query plan failed to decode: {error}", case.name))
}

fn reader_explain(store: &AnalyzerStore, case: &QueryPlanCase) -> Vec<String> {
    let connection = store
        .read_conn()
        .unwrap_or_else(|error| panic!("{} reader checkout failed: {error}", case.name));
    explain(&connection, case)
}

fn assert_blob_first(case: &QueryPlanCase, plan: &[String]) {
    let Some(relation) = case.blob_relation else {
        // The witness is a view, so SQLite reports the aliases from both the
        // view definition and the outer production query.  These are all
        // blob-scoped relations; only the tiny language/epoch metadata
        // relations are intentionally outside this bounded witness set.
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
                "{} lacks bounded witness search for {alias}: {plan:?}",
                case.name
            );
            assert!(
                plan.iter()
                    .all(|detail| !detail.contains(&format!("SCAN {alias}"))),
                "{} scans witness alias {alias}: {plan:?}",
                case.name
            );
        }
        assert!(
            plan.iter()
                .all(|detail| !detail.contains("AUTOMATIC") && !detail.contains("TEMP B-TREE")),
            "{} uses an unexpected witness planner fallback: {plan:?}",
            case.name
        );
        return;
    };

    let search = plan.iter().find(|detail| {
        detail.contains(&format!("SEARCH {relation}")) && detail.contains("blob_id")
    });
    assert!(
        search.is_some(),
        "{} lacks a blob-first seek for {relation}: {plan:?}",
        case.name
    );
    if relation == "owner" {
        assert!(
            plan.iter().any(|detail| {
                detail.contains("source_rust_item_contexts_owner")
                    && detail.contains("owner_declaration_id=?")
            }),
            "{} lacks an exact generic-owner seek: {plan:?}",
            case.name
        );
        assert!(
            plan.iter()
                .any(|detail| detail.contains("SEARCH parameter") && detail.contains("blob_id=?")),
            "{} lacks a blob-first generic parameter seek: {plan:?}",
            case.name
        );
    }
    assert!(
        plan.iter()
            .all(|detail| !detail.contains(&format!("SCAN {relation}"))),
        "{} scans {relation}: {plan:?}",
        case.name
    );
    assert!(
        plan.iter()
            .all(|detail| { !detail.contains("AUTOMATIC") && !detail.contains("TEMP B-TREE") }),
        "{} uses an unexpected planner fallback: {plan:?}",
        case.name
    );
}

fn assert_nonempty(connection: &Connection, case: &QueryPlanCase) {
    let mut statement = connection.prepare(case.sql).unwrap_or_else(|error| {
        panic!("{} SQL failed to prepare for execution: {error}", case.name)
    });
    let mut rows = statement
        .query(params_from_iter(case.parameters.iter()))
        .unwrap_or_else(|error| panic!("{} SQL failed to execute: {error}", case.name));
    assert!(
        rows.next()
            .unwrap_or_else(|error| panic!("{} SQL row iteration failed: {error}", case.name))
            .is_some(),
        "{} production SELECT returned no rows",
        case.name
    );
}

fn cases(oid: &str, blob_id: i64, generation: i64) -> Vec<QueryPlanCase> {
    let blob = || vec![Value::Integer(blob_id)];
    vec![
        QueryPlanCase {
            name: "publication witness",
            sql: "SELECT keys.blob_id, item.logical_rows, item.payload_bytes,
                         item.macro_facts_version, module.root_occurrence_id,
                         item.type_forms_version, item.macro_contexts_version
                    FROM rust_published_fact_blobs AS keys
                    JOIN source_fact_manifests AS manifest
                      ON manifest.blob_id = keys.blob_id
                    JOIN source_rust_item_manifests AS item
                      ON item.blob_id = keys.blob_id
                    JOIN source_rust_module_manifests AS module
                      ON module.blob_id = keys.blob_id
                   WHERE keys.blob_oid = ?1 AND keys.lang = 'rust'
                     AND keys.generation = ?2
                     AND manifest.publication_state = 'complete'
                     AND manifest.facts_version = ?3
                     AND item.facts_version = ?4",
            blob_relation: None,
            parameters: vec![
                Value::Text(oid.to_owned()),
                Value::Integer(generation),
                Value::Integer(super::source_facts::SOURCE_FACTS_VERSION),
                Value::Integer(1),
            ],
        },
        QueryPlanCase {
            name: "macro definitions",
            sql: "SELECT declaration_id, ordinal, is_macro_rules, context_occurrence_id
                    FROM source_rust_macro_definitions
                   WHERE blob_id = ?1 ORDER BY ordinal",
            blob_relation: Some("source_rust_macro_definitions"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "item syntax",
            sql: "SELECT occurrence_id, has_error
                     FROM source_rust_item_syntax
                    WHERE blob_id = ?1 ORDER BY occurrence_id",
            blob_relation: Some("source_rust_item_syntax"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "item contexts",
            sql: "SELECT occurrence_id, ordinal, parent_occurrence_id,
                          owner_declaration_id, context_kind
                     FROM source_rust_item_contexts
                    WHERE blob_id = ?1 ORDER BY ordinal",
            blob_relation: Some("source_rust_item_contexts"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "impl items",
            sql: "SELECT declaration_id, context_occurrence_id,
                          trait_type_occurrence_id, negation_occurrence_id,
                          target_type_occurrence_id, body_occurrence_id
                     FROM source_rust_impl_items
                    WHERE blob_id = ?1 ORDER BY declaration_id",
            blob_relation: Some("source_rust_impl_items"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "trait items",
            sql: "SELECT declaration_id, context_occurrence_id, body_occurrence_id
                     FROM source_rust_trait_items
                    WHERE blob_id = ?1 ORDER BY declaration_id",
            blob_relation: Some("source_rust_trait_items"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "alias items",
            sql: "SELECT declaration_id, context_occurrence_id,
                          target_type_occurrence_id
                     FROM source_rust_alias_items
                    WHERE blob_id = ?1 ORDER BY declaration_id",
            blob_relation: Some("source_rust_alias_items"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "callable items",
            sql: "SELECT declaration_id, context_occurrence_id,
                          parameters_occurrence_id, return_type_occurrence_id
                     FROM source_rust_callable_items
                    WHERE blob_id = ?1 ORDER BY declaration_id",
            blob_relation: Some("source_rust_callable_items"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "value items",
            sql: "SELECT declaration_id, context_occurrence_id, declared_type_occurrence_id
                     FROM source_rust_value_items
                    WHERE blob_id = ?1 ORDER BY declaration_id",
            blob_relation: Some("source_rust_value_items"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "generic parameters",
            sql: "SELECT declaration_id, ordinal, occurrence_id, syntax_kind,
                          name_occurrence_id, name
                     FROM source_rust_item_generic_parameters
                    WHERE blob_id = ?1 ORDER BY declaration_id, ordinal",
            blob_relation: Some("source_rust_item_generic_parameters"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "generic owner sealing",
            sql: "SELECT EXISTS (
                    SELECT 1 FROM source_rust_item_generic_parameters AS parameter
                    LEFT JOIN source_rust_item_contexts AS owner
                      ON owner.blob_id = parameter.blob_id
                     AND owner.owner_declaration_id = parameter.declaration_id
                     AND owner.context_kind IN (2, 3, 4, 7)
                    WHERE parameter.blob_id = ?1 AND owner.occurrence_id IS NULL
                  )",
            blob_relation: Some("owner"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "item body children",
            sql: "SELECT owner_declaration_id, ordinal, occurrence_id,
                          declaration_id, syntax_kind
                     FROM source_rust_item_body_children
                    WHERE blob_id = ?1 ORDER BY owner_declaration_id, ordinal",
            blob_relation: Some("source_rust_item_body_children"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "callable parameters",
            sql: "SELECT declaration_id, ordinal, occurrence_id, syntax_kind,
                          label_occurrence_id, label
                     FROM source_rust_callable_parameters
                    WHERE blob_id = ?1 ORDER BY declaration_id, ordinal",
            blob_relation: Some("source_rust_callable_parameters"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "item macro expansions",
            sql: "SELECT invocation_occurrence_id, context_occurrence_id,
                          expansion_kind, root_occurrence_id, source_position
                     FROM source_rust_item_macro_expansions
                    WHERE blob_id = ?1 ORDER BY invocation_occurrence_id",
            blob_relation: Some("source_rust_item_macro_expansions"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "item import contexts",
            sql: "SELECT declaration_occurrence_id, context_occurrence_id
                     FROM source_rust_item_import_contexts
                    WHERE blob_id = ?1 ORDER BY declaration_occurrence_id",
            blob_relation: Some("source_rust_item_import_contexts"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "source types",
            sql: "SELECT occurrence_id, path_kind, leading_absolute,
                          unsupported_occurrence_id, unsupported_syntax_kind,
                          compound_occurrence_id, type_parameters_occurrence_id
                     FROM source_rust_types
                    WHERE blob_id = ?1 ORDER BY occurrence_id",
            blob_relation: Some("source_rust_types"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "compound type children",
            sql: "SELECT type_occurrence_id, ordinal, occurrence_id
                     FROM source_rust_type_children
                    WHERE blob_id = ?1 ORDER BY type_occurrence_id, ordinal",
            blob_relation: Some("source_rust_type_children"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "type wrappers",
            sql: "SELECT type_occurrence_id, ordinal, occurrence_id, wrapper_kind
                     FROM source_rust_type_wrappers
                    WHERE blob_id = ?1 ORDER BY type_occurrence_id, ordinal",
            blob_relation: Some("source_rust_type_wrappers"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "type segments",
            sql: "SELECT type_occurrence_id, ordinal, occurrence_id, name
                     FROM source_rust_type_segments
                    WHERE blob_id = ?1 ORDER BY type_occurrence_id, ordinal",
            blob_relation: Some("source_rust_type_segments"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "type generic lists",
            sql: "SELECT type_occurrence_id, segment_ordinal, occurrence_id
                     FROM source_rust_type_generic_lists
                    WHERE blob_id = ?1 ORDER BY type_occurrence_id, segment_ordinal",
            blob_relation: Some("source_rust_type_generic_lists"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "type generic arguments",
            sql: "SELECT type_occurrence_id, segment_ordinal, ordinal, occurrence_id
                     FROM source_rust_type_generic_arguments
                    WHERE blob_id = ?1
                    ORDER BY type_occurrence_id, segment_ordinal, ordinal",
            blob_relation: Some("source_rust_type_generic_arguments"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "hierarchy manifest counts",
            sql: "SELECT declaration_count, declaration_unit_count
                     FROM source_fact_manifests
                    WHERE blob_id = ?1",
            blob_relation: Some("source_fact_manifests"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "hierarchy declarations",
            sql: "SELECT declaration_id, occurrence_id, name_occurrence_id
                     FROM source_declarations
                    WHERE blob_id = ?1 ORDER BY declaration_id",
            blob_relation: Some("source_declarations"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "hierarchy module names",
            sql: "SELECT declaration_id, module_name
                     FROM source_rust_module_declarations
                    WHERE blob_id = ?1 ORDER BY declaration_id",
            blob_relation: Some("source_rust_module_declarations"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "hierarchy declaration bridges",
            sql: super::source_facts::SOURCE_DECLARATION_UNITS_SQL,
            blob_relation: Some("source_declaration_units"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "source import manifest",
            sql: "SELECT publication_state, facts_version, import_count,
                          import_segment_count, import_scope_count, import_prefix_count
                     FROM source_fact_manifests
                    WHERE blob_id = ?1",
            blob_relation: Some("source_fact_manifests"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "source imports",
            sql: "SELECT import_id, statement, is_wildcard, is_global,
                          identifier, alias, path_kind, declaration_occurrence_id,
                          target_occurrence_id, alias_occurrence_id
                     FROM source_imports
                    WHERE blob_id = ?1 ORDER BY import_id",
            blob_relation: Some("source_imports"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "source import segments",
            sql: "SELECT import_id, ordinal, segment
                     FROM source_import_segments
                    WHERE blob_id = ?1 ORDER BY import_id, ordinal",
            blob_relation: Some("source_import_segments"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "source import scopes",
            sql: "SELECT import_id, ordinal, occurrence_id
                     FROM source_import_scopes
                    WHERE blob_id = ?1 ORDER BY import_id, ordinal",
            blob_relation: Some("source_import_scopes"),
            parameters: blob(),
        },
        QueryPlanCase {
            name: "source import prefixes",
            sql: "SELECT import_id, ordinal, prefix
                     FROM source_import_prefixes
                    WHERE blob_id = ?1 ORDER BY import_id, ordinal",
            blob_relation: Some("source_import_prefixes"),
            parameters: blob(),
        },
    ]
}

#[test]
fn rust_item_reader_queries_are_blob_first_before_and_after_analyze() {
    let sources = (0..=16)
        .map(|index| format!("{QUERY_FIXTURE}\n// planner fixture variant {index}\n"))
        .collect::<Vec<_>>();
    let mut project = InlineTestProject::new();
    for (index, source) in sources.iter().enumerate() {
        project = project.file(format!("src/plan_{index}.rs"), source.clone());
    }
    let fixture = project.build();
    let store = AnalyzerStore::open_ephemeral().expect("Rust item plan store");
    let mut oids = Vec::new();
    for (index, source) in sources.iter().enumerate() {
        let path = format!("src/plan_{index}.rs");
        let mut state = parse_state(&RustAdapter, &fixture.file(path));
        // Rust's current AST projection legitimately leaves lexical prefixes
        // empty.  Exercise the shared canonical import storage shape as well,
        // so the prefix reader has a populated blob-scoped row to pin.
        state
            .source_facts
            .as_mut()
            .expect("Rust planner fixture source facts")
            .imports
            .first_mut()
            .expect("Rust planner fixture import")
            .path
            .as_mut()
            .expect("Rust planner fixture structured import path")
            .lexical_prefixes
            .push("std".to_owned());
        let oid = oid_for(source.as_bytes());
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap_or_else(|error| panic!("populate Rust item plan fixture {index}: {error}"));
        oids.push(oid);
    }
    let oid = oids[0];
    let generation = store.current_generation("rust").expect("Rust generation");
    let hierarchy = store
        .rust_hierarchy_source_facts(
            oid,
            generation,
            &RustAdapter,
            &fixture.file("src/plan_0.rs"),
            &|| true,
        )
        .expect("read populated Rust item fixture")
        .expect("published Rust item fixture");
    assert!(
        !hierarchy.items.syntax.is_empty(),
        "fixture did not populate item facts"
    );
    assert!(
        !hierarchy.types.is_empty(),
        "fixture did not populate type facts"
    );

    let blob_id = store.conn.execute(move |connection| {
        connection
            .query_row(
                "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'",
                [oid.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .expect("published Rust fixture blob id")
    });
    // The "primary query location" case pinned the exact-range seek of
    // `source_occurrences_source_range`. That index had no production reader
    // and was dropped, and the statement it pinned is a test helper, so the
    // case pinned nothing production runs.
    let cases = cases(&oid.to_string(), blob_id, generation.get());

    // Remove existing statistics for the explicit pre-refresh measurement.
    // ANALYZE sqlite_schema reloads the connection without resampling; the
    // production refresh below then runs ANALYZE and recycles all reader
    // pools, so the second pass observes the refreshed state as readers do.
    store.conn.execute(|connection| {
        for table in ["sqlite_stat1", "sqlite_stat4"] {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM sqlite_master
                          WHERE type = 'table' AND name = ?1
                     )",
                    [table],
                    |row| row.get(0),
                )
                .expect("planner statistics table lookup");
            if exists {
                connection
                    .execute(&format!("DELETE FROM {table}"), [])
                    .expect("clear planner statistics");
            }
        }
    });
    store
        .reload_planner_statistics()
        .expect("reload empty planner statistics");

    let connection = store
        .read_conn()
        .expect("reader checkout before planner statistics refresh");
    for case in &cases {
        assert_nonempty(&connection, case);
        let plan = reader_explain(&store, case);
        assert_blob_first(case, &plan);
    }

    store
        .refresh_planner_statistics()
        .expect("refresh Rust item planner statistics");

    let connection = store
        .read_conn()
        .expect("reader checkout after planner statistics refresh");
    for case in &cases {
        assert_nonempty(&connection, case);
        let after = explain(&connection, case);
        assert_blob_first(case, &after);
    }
}
