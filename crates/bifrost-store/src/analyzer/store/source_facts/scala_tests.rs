#[cfg(test)]
#[cfg(not(test))]
use std::cell::Cell;

#[cfg(test)]
#[cfg(not(test))]
use crate::analyzer::Language;

#[cfg(test)]
#[cfg(not(test))]
use crate::analyzer::store::AnalyzerStore;

#[cfg(test)]
#[cfg(not(test))]
use crate::analyzer::store::test_support::{oid_for, parse_state};

#[cfg(test)]
#[cfg(not(test))]
use crate::inline_project::InlineTestProject;

#[cfg(test)]
#[cfg(not(test))]
use brokk_bifrost_core::analyzer::scala_facts::{ScalaDeclarationKind, ScalaDeclarationVisibility};

use rusqlite::{Connection, params};

#[doc(hidden)]
pub const SOURCE: &str = r#"package example

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

#[doc(hidden)]
pub fn assert_scala_reseal_rejects<F>(
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
