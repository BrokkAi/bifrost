use std::cell::Cell;

use crate::analyzer::Language;
use crate::analyzer::scala::ScalaAdapter;
use crate::analyzer::store::AnalyzerStore;
use crate::analyzer::store::tests::{oid_for, parse_state};
use crate::inline_project::InlineTestProject;
use brokk_bifrost_core::analyzer::scala_facts::{ScalaDeclarationKind, ScalaDeclarationVisibility};
use rusqlite::{Connection, params};

const SOURCE: &str = r#"package example

type Names = List[String]

enum Color {
  case Red
  case Green
}

case class Box[A](value: A)(using label: String)
case class Empty
class PublicClass
trait PublicTrait
object PublicObject
abstract class AbstractClass
sealed trait SealedTrait
final class FinalClass
class Surface {
  protected def inherited: Int = 1
  private def hidden: Int = 2
  def public: Int = 3
}

def render(value: List[Map[String, String]] = Nil)(using suffix: String): String = {
  val local: String = suffix
  value.mkString(local)
}
def transform(f: (String, Int) => List[String], values: List[String]): List[String] = values
def selected: Color.Red.type = Color.Red
"#;

#[test]
fn scala_declaration_source_facts_reopen_without_source_and_preserve_expression_shape() {
    let fixture = InlineTestProject::with_language(Language::Scala)
        .file("first/Source.scala", SOURCE)
        .file("second/Source.scala", SOURCE)
        .build();
    let file = fixture.file("first/Source.scala");
    let second = fixture.file("second/Source.scala");
    let state = parse_state(&ScalaAdapter, &file);
    let expected = state
        .source_facts
        .as_ref()
        .and_then(|facts| facts.scala.as_ref())
        .expect("Scala source facts");
    assert!(!expected.declarations.is_empty());
    assert!(expected.declarations.iter().any(|fact| fact.is_term_field));
    assert!(expected.declarations.iter().any(|fact| {
        fact.is_term_field
            && !state
                .source_declaration_units
                .iter()
                .any(|(declaration, _)| *declaration == fact.declaration)
    }));
    assert!(
        expected
            .declarations
            .iter()
            .filter_map(|fact| fact.callable.as_ref())
            .any(|callable| callable
                .parameter_function_type_paths
                .iter()
                .flatten()
                .flatten()
                .any(|paths| paths.len() == 2))
    );
    assert!(
        expected
            .declarations
            .iter()
            .any(|fact| fact.type_alias_path.is_some())
    );
    assert!(expected.declarations.iter().any(|fact| {
        fact.callable.as_ref().is_some_and(|callable| {
            callable
                .parameter_type_expressions
                .iter()
                .flatten()
                .flatten()
                .any(|expression| !expression.arguments.is_empty())
        })
    }));
    assert!(expected.declarations.iter().any(|fact| {
        fact.callable
            .as_ref()
            .is_some_and(|callable| callable.return_type_is_singleton)
    }));
    assert!(expected.declarations.iter().any(|fact| {
        fact.callable.as_ref().is_some_and(|callable| {
            callable.shape.len() == 1
                && callable.parameter_defaults.len() == 1
                && callable.parameter_type_paths.is_empty()
                && callable.parameter_type_expressions.is_empty()
                && callable.parameter_function_type_paths.is_empty()
        })
    }));
    for kind in [
        ScalaDeclarationKind::Other,
        ScalaDeclarationKind::Class,
        ScalaDeclarationKind::Trait,
        ScalaDeclarationKind::Object,
        ScalaDeclarationKind::Enum,
        ScalaDeclarationKind::EnumCase,
        ScalaDeclarationKind::TypeAlias,
    ] {
        assert!(
            expected.declarations.iter().any(|fact| fact.kind == kind),
            "missing Scala declaration kind {kind:?}"
        );
    }
    for visibility in [
        ScalaDeclarationVisibility::Public,
        ScalaDeclarationVisibility::Protected,
        ScalaDeclarationVisibility::NonApi,
    ] {
        assert!(
            expected
                .declarations
                .iter()
                .any(|fact| fact.visibility == visibility),
            "missing Scala declaration visibility {visibility:?}"
        );
    }
    assert!(
        expected
            .declarations
            .iter()
            .any(|fact| fact.is_explicitly_abstract)
    );
    assert!(expected.declarations.iter().any(|fact| fact.is_sealed));
    assert!(expected.declarations.iter().any(|fact| fact.is_final));

    let oid = oid_for(SOURCE.as_bytes());
    let path = fixture.root().join("scala-source.db");
    {
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        store
            .write_parsed_blob(oid, "scala", &ScalaAdapter, &state)
            .unwrap();
    }
    std::fs::remove_file(file.abs_path()).unwrap();
    let store = AnalyzerStore::open_persistent(&path).unwrap();
    let generation = store.current_generation("scala").unwrap();
    let first = store
        .scala_source_facts(oid, generation, &ScalaAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    let mounted = store
        .scala_source_facts(oid, generation, &ScalaAdapter, &second, &|| true)
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
            .all(|unit| { unit.source() == &file })
    );
    assert!(
        mounted
            .declaration_units
            .values()
            .flatten()
            .all(|unit| { unit.source() == &second })
    );

    let visits = Cell::new(0);
    assert!(
        store
            .scala_source_facts(oid, generation, &ScalaAdapter, &file, &|| {
                visits.set(visits.get() + 1);
                visits.get() < 5
            })
            .unwrap()
            .is_none()
    );
    store
        .conn
        .execute(|conn| {
            conn.execute("DELETE FROM blobs", [])?;
            let remaining: i64 = conn.query_row(
                "SELECT COUNT(*) FROM source_scala_declarations",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(
                remaining, 0,
                "sealed Scala rows must cascade with their blob"
            );
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
}

#[test]
fn scala_declaration_source_facts_distinguish_missing_marker_and_cascade_delete() {
    let fixture = InlineTestProject::with_language(Language::Scala)
        .file("Source.scala", "package example\n")
        .build();
    let file = fixture.file("Source.scala");
    let state = parse_state(&ScalaAdapter, &file);
    let oid = oid_for(state.source.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store.current_generation("scala").unwrap();
    store
        .write_parsed_blob(oid, "scala", &ScalaAdapter, &state)
        .unwrap();
    assert!(
        store
            .scala_source_facts(oid, generation, &ScalaAdapter, &file, &|| true)
            .unwrap()
            .is_some()
    );

    store
        .conn
        .execute(move |conn| {
            assert!(
                conn.execute(
                    "UPDATE source_scala_declaration_manifests SET payload_bytes = payload_bytes",
                    []
                )
                .is_err()
            );
            assert!(
                conn.execute("UPDATE blob_meta SET scala_source_version = NULL", [])
                    .is_err()
            );
            conn.execute_batch(
                "DROP TRIGGER source_scala_declaration_manifests_no_delete_after_seal;
                 DELETE FROM source_scala_declaration_manifests;",
            )?;
            let available: i64 = conn.query_row(
                "SELECT COALESCE((SELECT available FROM source_fact_readiness
                                  WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1)), 0)",
                [oid.to_string()],
                |row| row.get(0),
            )?;
            assert_eq!(available, 0, "missing Scala marker must not be ready");
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
    assert!(
        store
            .scala_source_facts(oid, generation, &ScalaAdapter, &file, &|| true)
            .is_err()
    );

    store
        .conn
        .execute(|conn| {
            conn.execute("DELETE FROM blobs", [])?;
            let remaining: i64 = conn.query_row(
                "SELECT COUNT(*) FROM source_scala_declarations",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(remaining, 0);
            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
}

fn assert_scala_reseal_rejects<F>(
    conn: &Connection,
    blob_id: i64,
    marker: (i64, i64, i64),
    label: &str,
    mutate: F,
) -> Result<(), crate::analyzer::store::StoreError>
where
    F: FnOnce(&Connection, i64) -> Result<(), crate::analyzer::store::StoreError>,
{
    conn.execute_batch(
        "SAVEPOINT scala_integrity_fault;
         DROP TRIGGER source_scala_declaration_manifests_no_delete_after_seal;",
    )?;
    let deleted = conn.execute(
        "DELETE FROM source_scala_declaration_manifests WHERE blob_id = ?1",
        [blob_id],
    )?;
    assert_eq!(deleted, 1, "{label}: Scala marker was not removed");
    mutate(conn, blob_id)?;
    let error = conn
        .execute(
            "INSERT INTO source_scala_declaration_manifests(
               blob_id, facts_version, logical_rows, payload_bytes
             ) VALUES(?1, ?2, ?3, ?4)",
            params![blob_id, marker.0, marker.1, marker.2],
        )
        .expect_err("corrupted Scala publication must not reseal");
    assert!(
        error.to_string().contains("Scala source publication"),
        "{label}: {error}"
    );
    conn.execute_batch(
        "ROLLBACK TO scala_integrity_fault;
         RELEASE scala_integrity_fault;",
    )?;
    Ok(())
}

#[test]
fn scala_sealed_children_are_immutable_and_corruptions_cannot_reseal() {
    let fixture = InlineTestProject::with_language(Language::Scala)
        .file("Source.scala", SOURCE)
        .build();
    let file = fixture.file("Source.scala");
    let state = parse_state(&ScalaAdapter, &file);
    let oid = oid_for(SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, "scala", &ScalaAdapter, &state)
        .unwrap();

    store
        .conn
        .execute(move |conn| {
            let blob_id: i64 = conn.query_row(
                "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'scala'",
                [oid.to_string()],
                |row| row.get(0),
            )?;
            let marker: (i64, i64, i64) = conn.query_row(
                "SELECT facts_version, logical_rows, payload_bytes
                 FROM source_scala_declaration_manifests WHERE blob_id = ?1",
                [blob_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;

            let error = conn
                .execute(
                    "UPDATE source_scala_declarations
                     SET stable_owner = stable_owner WHERE blob_id = ?1",
                    [blob_id],
                )
                .expect_err("sealed Scala child rows must be immutable");
            assert!(
                error.to_string().contains("sealed Scala source facts"),
                "{error}"
            );

            assert_scala_reseal_rejects(
                conn,
                blob_id,
                marker,
                "callable parameter count",
                |conn, blob_id| {
                    let (declaration_id, ordinal): (i64, i64) = conn.query_row(
                        "SELECT declaration_id, ordinal
                         FROM source_scala_callable_lists
                         WHERE blob_id = ?1 ORDER BY declaration_id, ordinal LIMIT 1",
                        [blob_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?;
                    let changed = conn.execute(
                        "UPDATE source_scala_callable_lists
                         SET total_arity = total_arity + 1
                         WHERE blob_id = ?1 AND declaration_id = ?2 AND ordinal = ?3",
                        params![blob_id, declaration_id, ordinal],
                    )?;
                    assert_eq!(changed, 1, "callable list fixture row is missing");
                    Ok(())
                },
            )?;

            assert_scala_reseal_rejects(
                conn,
                blob_id,
                marker,
                "singleton return expression",
                |conn, blob_id| {
                    let declaration_id: i64 = conn.query_row(
                        "SELECT declaration_id FROM source_scala_callables
                         WHERE blob_id = ?1 AND return_type_is_singleton = 1
                         ORDER BY declaration_id LIMIT 1",
                        [blob_id],
                        |row| row.get(0),
                    )?;
                    let changed = conn.execute(
                        "UPDATE source_scala_callables SET return_expression_id = NULL
                         WHERE blob_id = ?1 AND declaration_id = ?2",
                        params![blob_id, declaration_id],
                    )?;
                    assert_eq!(changed, 1, "singleton callable fixture row is missing");
                    Ok(())
                },
            )?;

            assert_scala_reseal_rejects(
                conn,
                blob_id,
                marker,
                "type expression ownership",
                |conn, blob_id| {
                    let (target_declaration, target_list, target_parameter, expression): (
                        i64,
                        i64,
                        i64,
                        i64,
                    ) = conn.query_row(
                        "SELECT target.declaration_id, target.list_ordinal,
                                target.ordinal, source.type_expression_id
                         FROM source_scala_callable_parameters AS target
                         JOIN source_scala_callable_parameters AS source
                           ON source.blob_id = target.blob_id
                          AND source.type_expression_id IS NOT NULL
                          AND source.type_expression_id <> target.type_expression_id
                          AND (source.declaration_id <> target.declaration_id
                               OR source.list_ordinal <> target.list_ordinal
                               OR source.ordinal <> target.ordinal)
                         WHERE target.blob_id = ?1
                           AND target.type_expression_id IS NOT NULL
                         ORDER BY target.declaration_id, target.list_ordinal,
                                  target.ordinal LIMIT 1",
                        [blob_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )?;
                    let changed = conn.execute(
                        "UPDATE source_scala_callable_parameters
                         SET type_expression_id = ?4
                         WHERE blob_id = ?1 AND declaration_id = ?2
                           AND list_ordinal = ?3 AND ordinal = ?5",
                        params![
                            blob_id,
                            target_declaration,
                            target_list,
                            expression,
                            target_parameter
                        ],
                    )?;
                    assert_eq!(changed, 1, "type-expression fixture row is missing");
                    Ok(())
                },
            )?;

            assert_scala_reseal_rejects(
                conn,
                blob_id,
                marker,
                "function path cell segments",
                |conn, blob_id| {
                    let (declaration_id, list_ordinal, parameter_ordinal, function_ordinal): (
                        i64,
                        i64,
                        i64,
                        i64,
                    ) = conn.query_row(
                        "SELECT declaration_id, list_ordinal, parameter_ordinal,
                                function_ordinal
                         FROM source_scala_callable_function_path_cells
                         WHERE blob_id = ?1 AND present = 1
                         ORDER BY declaration_id, list_ordinal, parameter_ordinal,
                                  function_ordinal LIMIT 1",
                        [blob_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )?;
                    let changed = conn.execute(
                        "UPDATE source_scala_callable_function_path_cells
                         SET present = 0
                         WHERE blob_id = ?1 AND declaration_id = ?2
                           AND list_ordinal = ?3 AND parameter_ordinal = ?4
                           AND function_ordinal = ?5",
                        params![
                            blob_id,
                            declaration_id,
                            list_ordinal,
                            parameter_ordinal,
                            function_ordinal
                        ],
                    )?;
                    assert_eq!(changed, 1, "function path cell fixture row is missing");
                    Ok(())
                },
            )?;

            Ok::<_, crate::analyzer::store::StoreError>(())
        })
        .unwrap();
}
