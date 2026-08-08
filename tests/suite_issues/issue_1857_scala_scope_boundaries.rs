//! Issue #1857: two Scala scope-boundary defects.
//!
//! 1. `new C(args) with T` does not parse like `new C(args)`. tree-sitter-scala
//!    wraps the first parent in an `applied_constructor_type` that owns the
//!    argument list and hangs it off a `compound_type`, so
//!    `call_site_shape_for_reference` saw no arguments at all and the scan
//!    recorded no reference for `C`. The forward direction still answered the
//!    class, so every such site was an inverse miss (7 corpus sites).
//!
//! 2. The "is this declaration a template member or a local?" walk treated
//!    neither `template_body` nor `instance_expression` as a boundary, so a
//!    member of an anonymous `new T { ... }` class was walked past into
//!    whatever block the *layout* wrapped the `new` in. A continuation-line
//!    `val x =\n  new T { ... }` gets an `indented_block`; the same code on one
//!    line does not. The anonymous member was therefore called "a local Scala
//!    value" on one layout and honestly missed on the other (3 corpus sites).
//!    Modelling anonymous-class members is issue #1860; this only makes the
//!    boundary - and so the diagnostic - honest.

use crate::common::{BuiltInlineTestProject, InlineTestProject, call_tool};
use brokk_bifrost::searchtools::{
    ScanUsagesByLocationParams, ScanUsagesTarget, scan_usages_by_location,
};
use brokk_bifrost::{Language, ScalaAnalyzer};
use serde_json::{Value, json};

/// The `get_definitions_by_location` result for the occurrence of `needle` in
/// `source` that follows `after`.
fn definition_at(
    project: &BuiltInlineTestProject,
    path: &str,
    source: &str,
    after: &str,
    needle: &str,
) -> Value {
    let anchor = source
        .find(after)
        .unwrap_or_else(|| panic!("`{after}` is not present in {path}"));
    let start = anchor
        + source[anchor..]
            .find(needle)
            .unwrap_or_else(|| panic!("`{needle}` is not present in {path} after `{after}`"));
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current_line)| current_line)
        .chars()
        .count()
        + 1;
    let args = json!({"references": [{"path": path, "line": line, "column": column}]}).to_string();
    call_tool(project, "get_definitions_by_location", &args)["results"][0].clone()
}

/// The diagnostic kinds a `get_definitions_by_location` result reports.
fn diagnostic_kinds(result: &Value) -> Vec<String> {
    result["diagnostics"]
        .as_array()
        .map(|diagnostics| {
            diagnostics
                .iter()
                .filter_map(|diagnostic| diagnostic["kind"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

const GLYPH: &str = "package app\nclass Glyph(val n: Int)\ntrait Assess\n";

/// Every `new` here names `Glyph`, and `probe` names it as a plain type, so the
/// inverse on the class must cover all four lines. No return type is annotated,
/// so a hit can only come from the reference under test.
const USE: &str = r#"package app
object Use {
  def plain() = new Glyph(1)
  def mixed() = new Glyph(2) with Assess
  def braced() = new Glyph(3) with Assess { def extra = 1 }
  def probe(g: Glyph): Int = g.n
}
"#;

/// The lines `app/Use.scala` reports for the declaration at
/// `app/Glyph.scala:line:column`.
fn inverse_lines(project: &BuiltInlineTestProject, line: usize, column: usize) -> Vec<usize> {
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());
    let mut scan = scan_usages_by_location(
        &analyzer,
        ScanUsagesByLocationParams {
            targets: vec![ScanUsagesTarget {
                path: "app/Glyph.scala".to_string(),
                line,
                column: Some(column),
                symbol: None,
            }],
            include_tests: true,
            paths: None,
            include_same_owner: false,
            max_duration_secs: None,
        },
    );
    let entry = scan.results.remove(0);
    let mut lines: Vec<usize> = entry
        .files
        .iter()
        .flat_map(|group| group.hits.iter().map(|hit| hit.line))
        .collect();
    lines.sort_unstable();
    lines.dedup();
    lines
}

fn glyph_project() -> BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Scala)
        .file("app/Glyph.scala", GLYPH)
        .file("app/Use.scala", USE)
        .build()
}

/// The corpus shape: `new C(args) with T` answers the class forward, so the
/// inverse on that class has to cover the site. Before #1857 it covered the
/// plain `new` and the plain type reference but neither mixin.
#[test]
fn inverse_on_the_class_covers_a_mixin_new() {
    let project = glyph_project();
    assert_eq!(
        inverse_lines(&project, 2, 7),
        vec![3, 4, 5, 6],
        "every `new Glyph(...)` and the plain `Glyph` type reference name the \
         class, mixin or not"
    );
}

/// The forward direction is unchanged, and is what makes the inverse above the
/// right expectation: a mixin `new` answers the class.
#[test]
fn forward_on_a_mixin_new_answers_the_class() {
    let project = glyph_project();
    for needle in ["Glyph(2)", "Glyph(3)"] {
        let result = definition_at(&project, "app/Use.scala", USE, needle, "Glyph");
        assert_eq!(
            result["definitions"][0]["fqn"], "app.Glyph",
            "the first parent of a mixin `new` is the class: {result:#}"
        );
    }
}

const TASK: &str = r#"package app

trait Task {
  def run(x: Int): String
}
"#;

/// A member of an anonymous `new T { ... }` class is not a local of whatever
/// block the layout wrapped the `new` in. Before #1857 the continuation-line
/// layout produced an `indented_block` that the boundary walk mistook for the
/// declaring scope, and the reference was reported as "a local Scala value".
#[test]
fn anonymous_class_member_is_not_reported_local() {
    const CONTINUATION: &str = r#"package app

object Holder {
  val task: Task =
    new Task {
      def run(x: Int): String = run("s")(x)
      private def run(s: String)(x: Int): String = s + x
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Task.scala", TASK)
        .file("app/Holder.scala", CONTINUATION)
        .build();
    let result = definition_at(&project, "app/Holder.scala", CONTINUATION, "= run", "run");
    assert_eq!(
        diagnostic_kinds(&result),
        vec!["no_indexed_definition".to_string()],
        "an anonymous-class member is a member of that class, not a local of \
         the enclosing block: {result:#}"
    );
}

/// The same code on one line has no wrapping `indented_block`, and always
/// reported the honest diagnostic. Both layouts must now agree - the defect was
/// layout-dependent, the miss underneath it is not.
#[test]
fn anonymous_class_member_diagnostic_does_not_depend_on_layout() {
    const SAME_LINE: &str = r#"package app

object Holder {
  val task: Task = new Task {
    def run(x: Int): String = run("s")(x)
    private def run(s: String)(x: Int): String = s + x
  }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Task.scala", TASK)
        .file("app/Holder.scala", SAME_LINE)
        .build();
    let result = definition_at(&project, "app/Holder.scala", SAME_LINE, "= run", "run");
    assert_eq!(
        diagnostic_kinds(&result),
        vec!["no_indexed_definition".to_string()],
        "the same-line layout answers the same diagnostic: {result:#}"
    );
}

/// Negative control: the identical overload pair in a *named* object still
/// resolves, so the boundary change did not turn members into non-members.
#[test]
fn named_object_member_still_resolves() {
    const NAMED: &str = r#"package app

object Named {
  def run(x: Int): String = run("s")(x)
  private def run(s: String)(x: Int): String = s + x
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Named.scala", NAMED)
        .build();
    let result = definition_at(&project, "app/Named.scala", NAMED, "= run", "run");
    assert_eq!(
        result["definitions"][0]["fqn"], "app.Named$.run",
        "a named object's member is still resolved: {result:#}"
    );
}

/// Negative control: a genuinely local `def` in a block is still reported as a
/// local, so enclosing-scope resolution is not corrupted the other way.
#[test]
fn genuine_local_definition_is_still_local() {
    const LOCAL: &str = r#"package app

object Local {
  def outer(x: Int): String = {
    def helper(s: String)(x: Int): String = s + x
    helper("s")(x)
  }
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Local.scala", LOCAL)
        .build();
    let result = definition_at(&project, "app/Local.scala", LOCAL, "    helper(", "helper");
    assert_eq!(
        diagnostic_kinds(&result),
        vec!["local_variable_reference".to_string()],
        "a nested `def` in a block is still a local: {result:#}"
    );
}
