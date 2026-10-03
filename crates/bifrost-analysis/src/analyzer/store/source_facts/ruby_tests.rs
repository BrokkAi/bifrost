use crate::analyzer::Language;
use crate::analyzer::ruby::RubyAdapter;
use crate::analyzer::store::AnalyzerStore;
use crate::analyzer::store::tests::{oid_for, parse_state};
use crate::inline_project::InlineTestProject;
use brokk_bifrost_core::analyzer::ruby_facts::{RubyLoadKind, RubyRuntimeBoundary};

const SOURCE: &str = r#"require_relative "support"
module Outer
  autoload :Visible, "visible"
  def later
    autoload :Inside, "inside"
    require "runtime"
  end
end
"#;

#[test]
fn ruby_source_facts_reopen_with_exact_loads_and_structural_identity() {
    let fixture = InlineTestProject::with_language(Language::Ruby)
        .file("main.rb", SOURCE)
        .build();
    let file = fixture.file("main.rb");
    let state = parse_state(&RubyAdapter, &file);
    let source = state.source_facts.as_ref().unwrap();
    assert_eq!(source.ruby.as_ref().unwrap().loads.len(), 4);
    assert_eq!(source.generic_imports.len(), 2);
    assert_eq!(state.source_declaration_metadata.len(), 1);
    let metadata = &state.source_declaration_metadata[0];
    assert_eq!(metadata.metadata_ordinal, 0);
    assert_eq!(metadata.unit.identifier(), "later");
    assert!(
        state
            .source_declaration_units
            .contains(&(metadata.declaration, metadata.unit.clone()))
    );

    for (declaration, unit) in &state.source_declaration_units {
        if unit.is_class() || unit.is_module() || unit.is_function() {
            let occurrence = source.occurrences.declaration(*declaration).occurrence;
            assert!(
                source
                    .structural
                    .nodes()
                    .iter()
                    .any(|node| node.occurrence == occurrence)
            );
        }
    }
    let oid = oid_for(SOURCE.as_bytes());
    let path = fixture.root().join("ruby-source.db");
    let store = AnalyzerStore::open_persistent(&path).unwrap();
    store
        .write_parsed_blob(oid, "ruby", &RubyAdapter, &state)
        .unwrap();
    drop(store);
    let store = AnalyzerStore::open_persistent(&path).unwrap();
    let generation = store.current_generation("ruby").unwrap();
    let metadata_links: usize = store
        .read_conn()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM source_declaration_metadata_bridges",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(metadata_links, 1);
    let expected_structural = crate::analyzer::structural::facts::FileFacts::from_source_and_rows(
        state.source.clone(),
        source.occurrences.clone(),
        source.structural.clone(),
    )
    .persisted_rows()
    .unwrap();
    assert_eq!(
        store
            .load_structural_facts_rows(
                oid,
                "ruby",
                generation,
                crate::analyzer::structural::facts::STRUCTURAL_FACTS_VERSION
            )
            .unwrap(),
        Some(expected_structural)
    );
    let facts = store.ruby_source_facts(oid, generation).unwrap();
    assert_eq!(facts.loads.len(), 4);
    assert_eq!(facts.loads[0].kind, RubyLoadKind::RequireRelative);
    assert!(facts.loads[0].generic);
    assert_eq!(
        facts.loads[1].autoload_constant,
        Some(vec!["Outer".to_owned(), "Visible".to_owned()])
    );
    assert_eq!(
        facts.loads[2].autoload_constant,
        Some(vec!["Outer".to_owned(), "Inside".to_owned()])
    );
    assert!(!facts.loads[2].generic);
    assert!(!facts.has_parse_errors);
    assert_eq!(facts.runtime_boundary, Some(RubyRuntimeBoundary::Autoload));
    assert_eq!(facts.source_bytes, SOURCE.len());
    for (info, load) in facts.loads.iter().zip(&source.ruby.as_ref().unwrap().loads) {
        assert_eq!(
            info.import,
            source.imports[load.import.index()].import_info(&source.occurrences)
        );
    }
}

#[test]
fn ruby_empty_and_malformed_publications_keep_explicit_availability() {
    let fixture = InlineTestProject::with_language(Language::Ruby)
        .file("empty.rb", "# empty\n")
        .file("broken.rb", "class Broken\n")
        .build();
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("ruby").unwrap();
    for (name, source, parse_error) in [
        ("empty.rb", "# empty\n", false),
        ("broken.rb", "class Broken\n", true),
    ] {
        let state = parse_state(&RubyAdapter, &fixture.file(name));
        let oid = oid_for(source.as_bytes());
        assert!(store.ruby_source_facts(oid, generation).is_err());
        store
            .write_parsed_blob(oid, "ruby", &RubyAdapter, &state)
            .unwrap();
        let facts = store.ruby_source_facts(oid, generation).unwrap();
        assert!(facts.loads.is_empty());
        assert_eq!(facts.has_parse_errors, parse_error);
    }
}

#[test]
fn ruby_source_rows_are_sealed_and_cold_corruption_is_unavailable() {
    let fixture = InlineTestProject::with_language(Language::Ruby)
        .file("main.rb", SOURCE)
        .build();
    let state = parse_state(&RubyAdapter, &fixture.file("main.rb"));
    let oid = oid_for(SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("ruby").unwrap();
    store
        .write_parsed_blob(oid, "ruby", &RubyAdapter, &state)
        .unwrap();
    store.conn.execute(|conn| {
        for sql in ["UPDATE source_ruby_loads SET kind=2", "DELETE FROM source_ruby_load_constants", "UPDATE source_ruby_manifests SET has_parse_errors=1", "UPDATE blob_meta SET ruby_source_version=NULL"] {
            assert!(conn.execute(sql, []).is_err(), "{sql}");
        }
        conn.execute_batch("DROP TRIGGER source_ruby_load_constants_no_delete_after_seal; DELETE FROM source_ruby_load_constants;")?;
        Ok::<_, crate::analyzer::store::StoreError>(())
    }).unwrap();
    assert!(store.ruby_source_facts(oid, generation).is_err());
    store
        .conn
        .execute(|conn| {
            conn.execute("DELETE FROM blobs", [])?;
            for table in [
                "source_ruby_loads",
                "source_ruby_load_constants",
                "source_ruby_manifests",
            ] {
                let count: i64 =
                    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })?;
                assert_eq!(count, 0);
            }
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
    store
        .write_parsed_blob(oid, "ruby", &RubyAdapter, &state)
        .unwrap();
    assert_eq!(
        store
            .ruby_source_facts(oid, generation)
            .unwrap()
            .loads
            .len(),
        4
    );
}

#[test]
fn ruby_source_publication_lookup_seeks_before_and_after_statistics() {
    use rusqlite::params;
    let fixture = InlineTestProject::with_language(Language::Ruby)
        .file("main.rb", SOURCE)
        .build();
    let state = parse_state(&RubyAdapter, &fixture.file("main.rb"));
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("ruby").unwrap();
    let oid = oid_for(SOURCE.as_bytes());
    for index in 0..33 {
        let current = if index == 0 {
            oid
        } else {
            oid_for(format!("Ruby planner {index}").as_bytes())
        };
        store
            .write_parsed_blob(current, "ruby", &RubyAdapter, &state)
            .unwrap();
    }
    for refresh in [false, true] {
        if refresh {
            store.refresh_planner_statistics().unwrap();
        }
        let conn = store.read_conn().unwrap();
        let blob: i64 = conn
            .query_row(
                "SELECT id FROM blobs WHERE blob_oid=?1 AND lang='ruby'",
                [oid.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        let header = conn
            .prepare(&format!(
                "EXPLAIN QUERY PLAN {}",
                crate::analyzer::ruby::source_storage::RUBY_SOURCE_HEADER_SQL
            ))
            .unwrap()
            .query_map(
                params![
                    oid.to_string(),
                    generation.get(),
                    1,
                    super::SOURCE_FACTS_VERSION
                ],
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let loads = conn
            .prepare(&format!(
                "EXPLAIN QUERY PLAN {}",
                crate::analyzer::ruby::source_storage::RUBY_LOADS_SQL
            ))
            .unwrap()
            .query_map([blob], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            header.iter().all(|step| !step.starts_with("SCAN ")),
            "{header:?}"
        );
        assert!(
            loads.iter().all(|step| !step.starts_with("SCAN ")),
            "{loads:?}"
        );
        assert!(
            loads
                .iter()
                .any(|step| step.contains("import_statements_by_source_import")),
            "{loads:?}"
        );
    }
}

#[test]
fn ruby_cancelled_and_failed_publications_rollback_family_rows_and_retry() {
    use crate::CancellationToken;
    use crate::analyzer::store::PersistBatchTargets;
    use std::sync::Arc;
    let fixture = InlineTestProject::with_language(Language::Ruby)
        .file("main.rb", SOURCE)
        .build();
    let state = Arc::new(parse_state(&RubyAdapter, &fixture.file("main.rb")));
    let oid = oid_for(SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("ruby").unwrap();
    let prepared = AnalyzerStore::prepare_parsed_blob(
        oid,
        "ruby",
        generation,
        &RubyAdapter,
        Arc::clone(&state),
    )
    .unwrap();
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let (outcomes, _) = store.persist_prepared_blobs_with_cancellation(
        vec![prepared],
        &cancellation,
        PersistBatchTargets::PRODUCTION,
    );
    assert!(outcomes[0].error.is_some());
    assert!(store.ruby_source_facts(oid, generation).is_err());
    assert_eq!(store.content_row_count(oid, "ruby").unwrap(), 0);
    store
        .conn
        .execute(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER reject_ruby_completion
            BEFORE UPDATE OF publication_state ON source_fact_manifests
            WHEN NEW.publication_state = 'complete'
            BEGIN SELECT RAISE(ABORT, 'injected Ruby completion failure'); END;",
            )?;
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
    assert!(
        store
            .write_parsed_blob(oid, "ruby", &RubyAdapter, &state)
            .is_err()
    );
    assert!(store.ruby_source_facts(oid, generation).is_err());
    assert_eq!(store.content_row_count(oid, "ruby").unwrap(), 0);
    store
        .conn
        .execute(|conn| {
            for table in [
                "source_fact_manifests",
                "source_ruby_manifests",
                "source_ruby_loads",
                "source_ruby_load_constants",
            ] {
                let count: i64 =
                    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })?;
                assert_eq!(count, 0, "partial publication in {table}");
            }
            conn.execute_batch("DROP TRIGGER reject_ruby_completion")?;
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
    store
        .write_parsed_blob(oid, "ruby", &RubyAdapter, &state)
        .unwrap();
    assert_eq!(
        store
            .ruby_source_facts(oid, generation)
            .unwrap()
            .loads
            .len(),
        4
    );
}

#[test]
fn ruby_dynamic_load_arguments_and_receivers_remain_explicit_boundaries_after_reopen() {
    let cases = [
        (
            "require \"#{name}\"\n",
            RubyRuntimeBoundary::DynamicRequire,
            0,
        ),
        (
            "require_relative \"#{name}\"\n",
            RubyRuntimeBoundary::DynamicRequireRelative,
            0,
        ),
        ("load \"#{name}\"\n", RubyRuntimeBoundary::DynamicLoad, 0),
        (
            "loader.require \"ready\"\n",
            RubyRuntimeBoundary::DynamicRequire,
            1,
        ),
    ];
    for (source, boundary, loads) in cases {
        let fixture = InlineTestProject::with_language(Language::Ruby)
            .file("main.rb", source)
            .build();
        let state = parse_state(&RubyAdapter, &fixture.file("main.rb"));
        let source_facts = state.source_facts.as_ref().unwrap().ruby.as_ref().unwrap();
        assert_eq!(
            source_facts.runtime_boundary.map(|(_, kind)| kind),
            Some(boundary)
        );
        assert_eq!(source_facts.loads.len(), loads);
        let path = fixture.root().join("ruby-dynamic.db");
        let oid = oid_for(source.as_bytes());
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        store
            .write_parsed_blob(oid, "ruby", &RubyAdapter, &state)
            .unwrap();
        drop(store);
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let facts = store
            .ruby_source_facts(oid, store.current_generation("ruby").unwrap())
            .unwrap();
        assert_eq!(facts.runtime_boundary, Some(boundary));
        assert_eq!(facts.loads.len(), loads);
        assert!(facts.loads.iter().all(|load| load.has_receiver));
    }
}
