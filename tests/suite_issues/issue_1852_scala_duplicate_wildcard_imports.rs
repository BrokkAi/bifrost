//! Issue #1852: repeating one wildcard import made a Scala name ambiguous.
//!
//! `scala_wildcard_imported_member_outcome` counted an import STATEMENT, not the
//! exporter the statement resolves to, and it bailed out before the dedup that
//! collapses the identical `CodeUnit`s the two statements produce. Writing
//! `import Encoding.*` in two sibling objects therefore flipped a resolved
//! member to `ambiguous_scala_wildcard_import` even though both statements name
//! the same object.
//!
//! Two wildcard imports of DIFFERENT objects that both export the name are a
//! real ambiguity and must stay one.

use crate::common::{InlineTestProject, definition_at};
use brokk_bifrost::Language;

#[test]
fn repeated_identical_wildcard_import_is_one_exporter() {
    let source = r#"package fx

object Outer {
  object Encoding {
    val table: Map[Int, String] = Map(1 -> "a")
  }

  object ReaderA {
    import Encoding.*
    def go(n: Int): String = table(n)
  }

  object ReaderB {
    import Encoding.*
    def go(m: Int): String = table(m)
  }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("fx/Fix.scala", source)
        .build();

    for needle in ["table(n)", "table(m)"] {
        let result = definition_at(&project, "fx/Fix.scala", source, needle);
        assert_eq!(
            result["status"], "resolved",
            "the same wildcard import repeated is one exporter, not two: {result:#}"
        );
        assert_eq!(
            result["definitions"][0]["fqn"], "fx.Outer$.Encoding$.table",
            "{result:#}"
        );
    }
}

#[test]
fn wildcard_imports_of_different_objects_stay_ambiguous() {
    let source = r#"package fx

object Left {
  val table: Map[Int, String] = Map(1 -> "a")
}

object Right {
  val table: Map[Int, String] = Map(2 -> "b")
}

object Reader {
  import Left.*
  import Right.*
  def go(n: Int): String = table(n)
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("fx/Fix.scala", source)
        .build();

    let result = definition_at(&project, "fx/Fix.scala", source, "table(n)");
    assert_eq!(
        result["status"], "no_definition",
        "two distinct exporters of the same name are a real ambiguity: {result:#}"
    );
    assert_eq!(
        result["diagnostics"][0]["kind"], "ambiguous_scala_wildcard_import",
        "{result:#}"
    );
}
