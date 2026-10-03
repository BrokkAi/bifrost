use crate::analyzer::cpp::source_publication::cost;
use brokk_bifrost_core::analyzer::cpp_facts::{
    CppDeclarationSourceFact, CppDeclaredFieldTypeFact, CppSourceFacts,
};
use brokk_bifrost_core::analyzer::model::{CppTemplateExpression, CppTemplateTerm};
use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;

#[test]
fn cpp_cost_counts_relational_template_terms_and_payload() {
    let mut declaration = CppDeclarationSourceFact::new(SourceDeclarationId::new(0));
    declaration.field_type = Some(CppDeclaredFieldTypeFact {
        type_text: "vector".to_owned(),
        indirection: 0,
        binds_indirectly: false,
        template_arguments: Some(vec![CppTemplateExpression {
            text: "T::value".to_owned(),
            term: CppTemplateTerm::Node {
                kind: "qualified".to_owned(),
                children: vec![
                    CppTemplateTerm::Parameter("T".to_owned()),
                    CppTemplateTerm::Atom {
                        kind: "identifier".to_owned(),
                        text: "value".to_owned(),
                    },
                ],
            },
        }]),
    });
    declaration.lexical_path = vec!["Ns".to_owned(), "Value".to_owned()];
    let facts = CppSourceFacts {
        declarations: vec![declaration],
        ..CppSourceFacts::default()
    };

    let (rows, bytes) = cost(&facts);
    // The declaration's context is a separately sealed relational row.
    assert_eq!(rows, 1 + 1 + 2 + 1 + 3 + 1);
    assert_eq!(
        bytes,
        "vector".len()
            + "Ns".len()
            + "Value".len()
            + "T::value".len()
            + "qualified".len()
            + "T".len()
            + "identifier".len()
            + "value".len()
    );
}

use crate::analyzer::cpp::CppAdapter;
use crate::analyzer::cpp::CppAnalyzer;
use crate::analyzer::store::AnalyzerStore;
use crate::analyzer::store::tests::{oid_for, parse_state};
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnitIndex, Language, OverlayProject, Project, QueryScope,
};
use crate::inline_project::InlineTestProject;
use brokk_bifrost_cpp::graph_support::CppSource;
use std::collections::BTreeSet;
use std::sync::Arc;

const SOURCE: &str = r#"#include <vector>
namespace ns {
struct Base {};
template<class T = Base> struct Box {};
using RootAlias = Box<Base>;
struct Value : virtual Base {
  int value, *pointer;
  Box<Base> box;
  Box<> default_box;
  using Default = Box<>;
  using Alias = Box<Base>;
#if defined(USE_FAST_VALUE)
  using Conditional = Box<>;
#else
  using Conditional = Box<Base>;
#endif
  int run(const Base *value) const;
  void empty();
};
int Value::run(const Base *value) const { return 1; }
}
"#;

#[test]
fn cpp_source_facts_reopen_without_source_and_mount_exact_bridges() {
    let fixture = InlineTestProject::with_language(Language::Cpp)
        .file("first/types.cpp", SOURCE)
        .file("second/types.cpp", SOURCE)
        .build();
    let file = fixture.file("first/types.cpp");
    let second = fixture.file("second/types.cpp");
    let state = parse_state(&CppAdapter, &file);
    let expected = state.source_facts.as_ref().unwrap().cpp.as_ref().unwrap();
    assert!(
        expected
            .declarations
            .iter()
            .any(|fact| fact.callable_comparable_shapes == Some(Vec::new()))
    );
    let oid = oid_for(SOURCE.as_bytes());
    let path = fixture.root().join("cpp-source.db");
    {
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        store
            .write_parsed_blob(oid, "cpp", &CppAdapter, &state)
            .unwrap();
    }
    std::fs::remove_file(file.abs_path()).unwrap();
    let store = AnalyzerStore::open_persistent(&path).unwrap();
    let generation = store.current_generation("cpp").unwrap();
    let first = store
        .cpp_source_facts(oid, generation, "cpp", &CppAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    let mounted = store
        .cpp_source_facts(oid, generation, "cpp", &CppAdapter, &second, &|| true)
        .unwrap()
        .unwrap();
    assert_eq!(&first.facts, expected);
    assert_eq!(first.facts, mounted.facts);
    assert_eq!(
        first.source,
        state.source_facts.as_ref().unwrap().occurrences
    );
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
    assert!(
        store
            .cpp_source_facts(oid, generation, "cpp", &CppAdapter, &file, &|| false)
            .unwrap()
            .is_none()
    );
    store
        .conn
        .execute(|conn| {
            assert!(
                conn.execute(
                    "UPDATE source_cpp_declarations SET trailing_qualifiers='broken'",
                    []
                )
                .is_err()
            );
            assert!(
                conn.execute("UPDATE blob_meta SET cpp_source_version=NULL", [])
                    .is_err()
            );
            conn.execute("DELETE FROM blobs", [])?;
            for table in [
                "source_cpp_manifests",
                "source_cpp_declarations",
                "source_cpp_comparable_parameters",
                "source_cpp_comparable_nodes",
                "source_cpp_comparable_node_names",
                "source_cpp_comparable_node_arguments",
                "source_cpp_template_expressions",
                "source_cpp_template_terms",
                "source_cpp_includes",
                "source_cpp_declaration_contexts",
                "source_cpp_flattened_namespaces",
                "source_cpp_guard_sets",
                "source_cpp_guard_nodes",
                "source_cpp_guard_edges",
                "source_cpp_guard_roots",
            ] {
                let count: i64 =
                    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })?;
                assert_eq!(count, 0, "{table} must cascade with its owning blob");
            }
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
}

#[test]
fn cpp_source_publication_distinguishes_empty_missing_and_repaired() {
    let fixture = InlineTestProject::with_language(Language::Cpp)
        .file("empty.cpp", "\n")
        .build();
    let file = fixture.file("empty.cpp");
    let mut state = parse_state(&CppAdapter, &file);
    let oid = oid_for(state.source.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("cpp").unwrap();
    let facts = state.source_facts.as_mut().unwrap().cpp.take().unwrap();
    assert!(
        store
            .write_parsed_blob(oid, "cpp", &CppAdapter, &state)
            .is_err()
    );
    state.source_facts.as_mut().unwrap().cpp = Some(facts);
    store
        .write_parsed_blob(oid, "cpp", &CppAdapter, &state)
        .unwrap();
    let read = store
        .cpp_source_facts(oid, generation, "cpp", &CppAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    assert!(read.facts.declarations.is_empty());
    assert!(read.facts.includes.is_empty());
    store
        .conn
        .execute(|conn| {
            assert!(
                conn.execute(
                    "UPDATE source_cpp_manifests SET payload_bytes = payload_bytes",
                    []
                )
                .is_err()
            );
            conn.execute("UPDATE blob_meta SET is_complete = 0", [])?;
            assert!(
                conn.execute("UPDATE blob_meta SET cpp_source_version = NULL", [])
                    .is_err()
            );
            conn.execute("UPDATE blob_meta SET is_complete = 1", [])?;
            conn.execute_batch(
                "DROP TRIGGER source_cpp_manifests_no_delete_after_seal;
                 DELETE FROM source_cpp_manifests;",
            )?;
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
    assert!(
        store
            .cpp_source_facts(oid, generation, "cpp", &CppAdapter, &file, &|| true)
            .unwrap()
            .is_none()
    );
    store
        .write_parsed_blob(oid, "cpp", &CppAdapter, &state)
        .unwrap();
    assert!(
        store
            .cpp_source_facts(oid, generation, "cpp", &CppAdapter, &file, &|| true)
            .unwrap()
            .is_some()
    );
}

#[test]
fn cpp_dirty_overlay_source_facts_replace_stale_generation() {
    let fixture = InlineTestProject::with_language(Language::Cpp)
        .file("types.cpp", "struct Original {};")
        .build();
    let file = fixture.file("types.cpp");
    let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
    let analyzer = CppAnalyzer::from_project(fixture.project().clone())
        .clone_with_project(overlay.clone() as Arc<dyn Project>);

    let original_unit = {
        let scope = AnalyzerQueryScope::new(&analyzer);
        let source = CppSource::declaration_source_facts(&analyzer, scope.token(), &file)
            .expect("original C++ source facts");
        let unit = source
            .declaration_units
            .values()
            .flatten()
            .find(|unit| unit.identifier() == "Original")
            .cloned()
            .expect("original declaration unit");
        assert!(
            CppSource::declaration_source_properties(&analyzer, scope.token(), &unit)
                .is_some_and(|properties| !properties.is_empty()),
            "original declaration properties must come from canonical facts"
        );
        unit
    };

    assert!(overlay.set(file.abs_path(), "struct Updated {};".to_owned(),));
    let updated = analyzer.clone_with_project(Arc::new(overlay.snapshot()) as Arc<dyn Project>);
    assert!(overlay.clear(&file.abs_path()));

    let updated_units = updated.declarations(&file);
    let updated_unit = updated_units
        .iter()
        .find(|unit| unit.identifier() == "Updated")
        .cloned()
        .expect("updated declaration unit from the dirty overlay");
    assert!(
        updated_units
            .iter()
            .all(|unit| unit.identifier() != "Original"),
        "updated generation must retire stale declaration units: {updated_units:?}"
    );
    {
        let scope = AnalyzerQueryScope::new(&updated);
        let source = CppSource::declaration_source_facts(&updated, scope.token(), &file)
            .expect("updated C++ source facts must stay in memory after clearing overlay");
        let names: BTreeSet<_> = source
            .declaration_units
            .values()
            .flatten()
            .map(|unit| unit.identifier().to_owned())
            .collect();
        assert!(names.contains("Updated"), "updated source names: {names:?}");
        assert!(!names.contains("Original"), "stale source names: {names:?}");
        assert!(
            CppSource::declaration_source_properties(&updated, scope.token(), &updated_unit)
                .is_some_and(|properties| !properties.is_empty()),
            "updated declaration properties must use the in-memory canonical source"
        );
    }

    let scope = AnalyzerQueryScope::new(&analyzer);
    let original_source = CppSource::declaration_source_facts(&analyzer, scope.token(), &file)
        .expect("pre-update analyzer source facts");
    let names: BTreeSet<_> = original_source
        .declaration_units
        .values()
        .flatten()
        .map(|unit| unit.identifier().to_owned())
        .collect();
    assert!(
        names.contains("Original"),
        "pre-update source names: {names:?}"
    );
    assert!(
        !names.contains("Updated"),
        "stale overlay leaked into old generation: {names:?}"
    );
    assert!(
        CppSource::declaration_source_properties(&analyzer, scope.token(), &original_unit)
            .is_some_and(|properties| !properties.is_empty()),
        "pre-update declaration properties must retain their own generation"
    );
}

#[test]
fn cpp_source_reader_rejects_corrupt_cpp_accounting() {
    let fixture = InlineTestProject::with_language(Language::Cpp)
        .file("types.cpp", SOURCE)
        .build();
    let file = fixture.file("types.cpp");
    let state = parse_state(&CppAdapter, &file);
    let oid = oid_for(SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("cpp").unwrap();
    store
        .write_parsed_blob(oid, "cpp", &CppAdapter, &state)
        .unwrap();
    store
        .conn
        .execute(|conn| {
            assert!(
                conn.execute(
                    "UPDATE source_cpp_manifests SET payload_bytes = payload_bytes",
                    []
                )
                .is_err()
            );
            conn.execute_batch(
                "DROP TRIGGER source_cpp_manifests_no_update_after_seal;
                 UPDATE source_cpp_manifests
                 SET payload_bytes = payload_bytes + 1;",
            )?;
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
    assert!(
        store
            .cpp_source_facts(oid, generation, "cpp", &CppAdapter, &file, &|| true)
            .is_err()
    );
}

#[test]
fn cpp_source_reader_rejects_corrupt_global_accounting() {
    let fixture = InlineTestProject::with_language(Language::Cpp)
        .file("types.cpp", SOURCE)
        .build();
    let file = fixture.file("types.cpp");
    let state = parse_state(&CppAdapter, &file);
    let oid = oid_for(SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("cpp").unwrap();
    store
        .write_parsed_blob(oid, "cpp", &CppAdapter, &state)
        .unwrap();
    store
        .conn
        .execute(|conn| {
            assert!(
                conn.execute(
                    "UPDATE source_fact_manifests SET declaration_unit_count = declaration_unit_count",
                    []
                )
                .is_err()
            );
            conn.execute_batch(
                "DROP TRIGGER source_fact_manifests_declared_fields_are_immutable;
                 UPDATE source_fact_manifests
                 SET declaration_unit_count = declaration_unit_count + 1;",
            )?;
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
    assert!(
        store
            .cpp_source_facts(oid, generation, "cpp", &CppAdapter, &file, &|| true)
            .is_err()
    );
}

#[test]
fn cpp_source_lookup_seeks_populated_publications_before_and_after_statistics() {
    use rusqlite::params;

    let fixture = InlineTestProject::with_language(Language::Cpp)
        .file("types.cpp", SOURCE)
        .build();
    let file = fixture.file("types.cpp");
    let state = parse_state(&CppAdapter, &file);
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("cpp").unwrap();
    let oid = oid_for(SOURCE.as_bytes());
    store
        .write_parsed_blob(oid, "cpp", &CppAdapter, &state)
        .unwrap();
    for index in 0..32 {
        let other = oid_for(format!("planner publication {index}").as_bytes());
        store
            .write_parsed_blob(other, "cpp", &CppAdapter, &state)
            .unwrap();
    }
    for refreshed in [false, true] {
        if refreshed {
            store.refresh_planner_statistics().unwrap();
        }
        let conn = store.read_conn().unwrap();
        let plan = conn
            .prepare(&format!(
                "EXPLAIN QUERY PLAN {}",
                crate::analyzer::cpp::source_storage::CPP_SOURCE_HEADER_SQL
            ))
            .unwrap()
            .query_map(
                params![
                    oid.to_string(),
                    "cpp",
                    generation.get(),
                    brokk_bifrost_core::analyzer::cpp_facts::CPP_SOURCE_FACTS_VERSION,
                    super::SOURCE_FACTS_VERSION,
                ],
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            plan.iter()
                .any(|step| step.contains("SEARCH blob") && step.contains("INDEX")),
            "{plan:#?}"
        );
        assert!(
            plan.iter().all(|step| !step.starts_with("SCAN ")),
            "source publication lookup must seek its exact blob: {plan:#?}"
        );
        drop(conn);
        assert!(
            store
                .cpp_source_facts(oid, generation, "cpp", &CppAdapter, &file, &|| true)
                .unwrap()
                .is_some()
        );
    }
    store
        .conn
        .execute(|conn| {
            conn.execute("DELETE FROM blobs", [])?;
            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM source_cpp_manifests", [], |row| {
                    row.get(0)
                })?;
            assert_eq!(
                count, 0,
                "blob deletion must cascade sealed source publications"
            );
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
}
