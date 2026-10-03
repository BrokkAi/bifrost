use crate::analyzer::Language;
use crate::analyzer::python::PythonAdapter;
use crate::analyzer::store::AnalyzerStore;
use crate::analyzer::store::tests::{oid_for, parse_state};
use crate::inline_project::InlineTestProject;
use std::cell::Cell;

const SOURCE: &str = "class Widget: pass\nif outer_condition:\n    if inner_condition:\n        def hidden() -> Widget:\n            return Widget()\ndef outer():\n    return hidden()\ndef visible() -> Widget:\n    return Widget()\ndef unsupported() -> tuple[Widget, int]:\n    pass\ndef plain():\n    pass\ndef qualified() -> package.Widget:\n    pass\ndef forward() -> 'package.Widget':\n    pass\ndef unavailable() -> factory().Widget:\n    pass\ndef unicode_name() -> '\u{0394}.Widget':\n    pass\n";

#[test]
fn python_return_facts_reopen_source_free_at_two_mounts_and_cancel_hydration() {
    let fixture = InlineTestProject::with_language(Language::Python)
        .file("first/source.py", SOURCE)
        .file("second/source.py", SOURCE)
        .build();
    let file = fixture.file("first/source.py");
    let other = fixture.file("second/source.py");
    let state = parse_state(&PythonAdapter, &file);
    let expected = state.source_facts.as_ref().unwrap();
    let facts = expected.python.as_ref().unwrap();
    assert_eq!(facts.callable_returns.len(), 9);
    assert!(
        facts.callable_returns.iter().any(|fact| !state
            .source_declaration_units
            .iter()
            .any(|(id, _)| *id == fact.declaration)),
        "nested callable remains source-only"
    );
    assert!(
        facts
            .callable_returns
            .iter()
            .any(|fact| fact.return_annotation.is_some() && fact.runtime_type.is_none())
    );
    assert!(
        facts
            .callable_returns
            .iter()
            .any(|fact| fact.return_annotation.is_none())
    );
    let oid = oid_for(SOURCE.as_bytes());
    let path = fixture.root().join("python-source.db");
    {
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        store
            .write_parsed_blob(oid, "python", &PythonAdapter, &state)
            .unwrap();
    }
    std::fs::remove_file(file.abs_path()).unwrap();
    std::fs::remove_file(other.abs_path()).unwrap();
    let store = AnalyzerStore::open_persistent(&path).unwrap();
    let generation = store.current_generation("python").unwrap();
    for mount in [&file, &other] {
        let read = store
            .python_source_facts(oid, generation, mount, &|| true)
            .unwrap()
            .unwrap();
        assert_eq!(&read.facts, facts);
        assert_eq!(read.occurrences, expected.occurrences);
    }
    let visits = Cell::new(0);
    assert!(
        store
            .python_source_facts(oid, generation, &file, &|| {
                visits.set(visits.get() + 1);
                visits.get() < 5
            })
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .python_source_facts(oid, generation, &file, &|| true)
            .unwrap()
            .is_some()
    );
}

#[test]
fn python_return_publication_requires_empty_marker_and_seals_rows() {
    let fixture = InlineTestProject::with_language(Language::Python)
        .file("empty.py", "")
        .build();
    let file = fixture.file("empty.py");
    let mut state = parse_state(&PythonAdapter, &file);
    let oid = oid_for(b"");
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("python").unwrap();
    let facts = state.source_facts.as_mut().unwrap().python.take().unwrap();
    assert!(
        store
            .write_parsed_blob(oid, "python", &PythonAdapter, &state)
            .is_err()
    );
    state.source_facts.as_mut().unwrap().python = Some(facts);
    store
        .write_parsed_blob(oid, "python", &PythonAdapter, &state)
        .unwrap();
    assert!(
        store
            .python_source_facts(oid, generation, &file, &|| true)
            .unwrap()
            .unwrap()
            .facts
            .callable_returns
            .is_empty()
    );
    store.conn.execute(|conn| {
        assert!(conn.execute("UPDATE source_python_manifests SET logical_rows=logical_rows",[]).is_err());
        assert!(conn.execute("UPDATE blob_meta SET python_source_version=NULL",[]).is_err());
        conn.execute_batch("DROP TRIGGER source_python_manifests_no_delete_after_seal; DELETE FROM source_python_manifests;")?;
        Ok::<_,crate::analyzer::store::StoreError>(())
    }).unwrap();
    assert!(
        store
            .python_source_facts(oid, generation, &file, &|| true)
            .is_err()
    );
    store
        .write_parsed_blob(oid, "python", &PythonAdapter, &state)
        .unwrap();
    assert!(
        store
            .python_source_facts(oid, generation, &file, &|| true)
            .unwrap()
            .is_some()
    );
}

#[test]
fn python_return_rows_have_indexed_access_exact_accounting_and_immutable_links() {
    let fixture = InlineTestProject::with_language(Language::Python)
        .file("source.py", SOURCE)
        .build();
    let file = fixture.file("source.py");
    let state = parse_state(&PythonAdapter, &file);
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let oid = oid_for(SOURCE.as_bytes());
    let generation = store.current_generation("python").unwrap();
    store
        .write_parsed_blob(oid, "python", &PythonAdapter, &state)
        .unwrap();
    for index in 0..32 {
        store
            .write_parsed_blob(
                oid_for(format!("publication {index}").as_bytes()),
                "python",
                &PythonAdapter,
                &state,
            )
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
                crate::analyzer::python::source_storage::PYTHON_SOURCE_HEADER_SQL
            ))
            .unwrap()
            .query_map(
                rusqlite::params![
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
        assert!(
            plan.iter()
                .any(|step| step.contains("SEARCH blob") && step.contains("INDEX")),
            "{plan:?}"
        );
        assert!(
            plan.iter().all(|step| !step.starts_with("SCAN ")),
            "{plan:?}"
        );
        for table in [
            "source_python_callable_returns",
            "source_python_return_names",
        ] {
            let plan = conn
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN SELECT * FROM {table} WHERE blob_id=?1"
                ))
                .unwrap()
                .query_map([1_i64], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                plan.iter()
                    .any(|step| step.contains("SEARCH") && step.contains("PRIMARY KEY")),
                "{plan:?}"
            );
        }
    }
    store.conn.execute(|conn| {
        let costs=conn.prepare("SELECT marker.logical_rows,marker.payload_bytes,cost.logical_rows,cost.payload_bytes FROM source_python_manifests marker JOIN source_python_costs cost ON cost.blob_id=marker.blob_id").unwrap()
            .query_map([],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert!(costs.iter().all(|(a,b,c,d)|(a,b)==(c,d)),"{costs:?}");
        assert!(conn.execute("UPDATE source_python_return_names SET name='Other'",[]).is_err());
        assert!(conn.execute("DELETE FROM source_python_callable_returns",[]).is_err());
        conn.execute("DELETE FROM blobs",[])?;
        let count:i64=conn.query_row("SELECT COUNT(*) FROM source_python_manifests",[],|row|row.get(0))?;
        assert_eq!(count,0);
        Ok::<_,crate::analyzer::store::StoreError>(())
    }).unwrap();
}

#[test]
fn python_return_provider_selects_overlay_revisions_a_b_a() {
    use crate::analyzer::{
        AnalyzerQueryScope, IAnalyzer, OverlayProject, Project, PythonAnalyzer, QueryScope,
    };
    use brokk_bifrost_python::source_facts::PythonSourceFactProvider;
    use std::sync::Arc;
    let a = "class A: pass\nclass B: pass\ndef factory() -> A:\n    return A()\n";
    let b = "class A: pass\nclass B: pass\ndef factory() -> B:\n    return B()\n";
    let fixture = InlineTestProject::with_language(Language::Python)
        .file("source.py", a)
        .build();
    let file = fixture.file("source.py");
    let base = PythonAnalyzer::from_project(fixture.project().clone());
    let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
    for (source, expected) in [(a, "A"), (b, "B"), (a, "A")] {
        assert!(overlay.set(file.abs_path(), source.to_owned()));
        let request = base.clone_with_project(overlay.clone() as Arc<dyn Project>);
        if expected == "B" {
            let scope = AnalyzerQueryScope::new(&request);
            assert!(
                request
                    .python_source_facts(scope.token(), &file, &|| true)
                    .is_none(),
                "unprepared overlay cannot use disk declaration facts"
            );
        }
        let analyzer = request.update(&std::collections::BTreeSet::from([file.clone()]));
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert!(
            analyzer
                .python_source_facts(scope.token(), &file, &|| false)
                .is_none()
        );
        let facts = analyzer
            .python_source_facts(scope.token(), &file, &|| true)
            .unwrap();
        let ty = facts.facts.callable_returns[0]
            .runtime_type
            .as_ref()
            .unwrap()
            .nominal_name()
            .unwrap();
        assert_eq!(ty.path(), [expected]);
    }
    assert_eq!(std::fs::read_to_string(file.abs_path()).unwrap(), a);
}
