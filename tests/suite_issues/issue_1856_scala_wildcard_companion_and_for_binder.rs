//! Issue #1856: a Scala `for` generator binder resolved forward to an instance
//! field of a case class that a wildcard import of the class's companion object
//! appeared to export (46 corpus sites, all `s3_website`).
//!
//! Two independent defects composed, and each is pinned here on its own.
//!
//! 1. `import Conf._` names a *term*, so it exports the companion object's
//!    members - indexed `Conf$.member`. The `$`-blind spelling in
//!    `scala_wildcard_imported_member_units` also read `Conf.member`, which is
//!    the *class*'s instance members, and handed the case class's constructor
//!    parameters out as bare names.
//! 2. A `for` enumerator binder was in scope only after its right-hand side
//!    ended, which is right for a *use* but wrong for the binder occurrence
//!    itself. `alpha` in `alpha <- xs` is a declaration site; it fell through to
//!    the enclosing scope and then to the file's wildcard imports.
//!
//! The negative controls hold the line that the first fix does not over-reach:
//! a wildcard import still exports an object's own members, a Scala 3 `enum`'s
//! cases (indexed under the undecorated name), and a package's top-level
//! declarations, and the class field is still reachable through an instance.

use crate::common::{BuiltInlineTestProject, InlineTestProject, call_tool};
use brokk_bifrost::Language;
use serde_json::{Value, json};

/// The `get_definitions_by_location` result for the occurrence of `needle` in
/// `source` that follows `after` (from the start of the file when empty).
fn definition_at(
    project: &BuiltInlineTestProject,
    path: &str,
    source: &str,
    after: &str,
    needle: &str,
) -> Value {
    let anchor = if after.is_empty() {
        0
    } else {
        source
            .find(after)
            .unwrap_or_else(|| panic!("`{after}` is not present in {path}"))
    };
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

/// Every fully-qualified name a `get_definitions_by_location` result reports.
/// A local binding carries no fq name, so an empty list also states "local".
fn definition_fq_names(result: &Value) -> Vec<String> {
    result["definitions"]
        .as_array()
        .map(|definitions| {
            definitions
                .iter()
                .filter_map(|definition| definition["fqn"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The `kind` each answered definition reports.
fn definition_kinds(result: &Value) -> Vec<String> {
    result["definitions"]
        .as_array()
        .map(|definitions| {
            definitions
                .iter()
                .filter_map(|definition| definition["kind"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

const CONF: &str = r#"package model

case class Conf(alpha: String, beta: Int)

object Conf {
  val gamma: Int = 7
  def parse(text: String): Conf = Conf(text, 0)
}
"#;

const LOAD: &str = r#"package app

import model.Conf._

object Load {
  def loadStr(key: String): Either[String, String] = Right(key)
  def loadInt(key: String): Either[String, Int] = Right(0)

  def viaFor: Either[String, Conf] =
    for {
      alpha <- loadStr("a")
      beta <- loadInt("b")
      both = alpha + beta.toString
    } yield Conf(alpha, both.length)
}
"#;

fn conf_project() -> BuiltInlineTestProject {
    InlineTestProject::with_language(Language::Scala)
        .file("model/Conf.scala", CONF)
        .file("app/Load.scala", LOAD)
        .build()
}

/// Defect 2, the corpus shape: the binder occurrence `alpha <- loadStr("a")`
/// is a declaration site, so it must answer the generator and never the case
/// class's constructor parameter `model.Conf.alpha`.
#[test]
fn for_generator_binder_answers_the_binder_not_a_case_class_field() {
    let project = conf_project();
    let result = definition_at(&project, "app/Load.scala", LOAD, "for {", "alpha");
    assert!(
        definition_fq_names(&result).is_empty(),
        "a `for` generator binder is a local binding, not a `Conf` member: {result:#}"
    );
    assert_eq!(
        definition_kinds(&result),
        vec!["local_variable".to_string()],
        "the generator binder answers itself: {result:#}"
    );
}

/// The same for the `=` enumerator, which tree-sitter-scala also spells
/// `enumerator`. `both` shadows nothing here, but the binder occurrence must
/// still answer the binding rather than falling through to the imports.
#[test]
fn for_comprehension_val_binder_answers_the_binder() {
    let project = conf_project();
    let result = definition_at(&project, "app/Load.scala", LOAD, "beta <- loadInt", "both");
    assert_eq!(
        definition_kinds(&result),
        vec!["local_variable".to_string()],
        "a for-comprehension `=` binder is a local binding: {result:#}"
    );
}

/// A later *use* of a binder already resolved locally before #1856; it is
/// pinned so the binder-occurrence fix cannot regress the use.
#[test]
fn use_of_a_for_binder_stays_local() {
    let project = conf_project();
    let result = definition_at(&project, "app/Load.scala", LOAD, "} yield Conf(", "alpha");
    assert!(
        definition_fq_names(&result).is_empty(),
        "a use of a `for` binder resolves to the binder, not a `Conf` member: {result:#}"
    );
}

/// A binder is in scope only after its right-hand side ends, so an occurrence
/// *inside* that right-hand side still reads the enclosing binding.
#[test]
fn generator_right_hand_side_reads_the_enclosing_binding() {
    const OUTER: &str = r#"package app

object Outer {
  def loadStr(key: String): Either[String, String] = Right(key)

  def run(alpha: String): Either[String, Int] =
    for {
      alpha <- loadStr(alpha)
    } yield alpha.length
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Outer.scala", OUTER)
        .build();
    let result = definition_at(&project, "app/Outer.scala", OUTER, "loadStr(", "alpha");
    let signatures: Vec<_> = result["definitions"]
        .as_array()
        .map(|definitions| {
            definitions
                .iter()
                .filter_map(|definition| definition["signature"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        signatures.iter().all(|signature| !signature.contains("<-")),
        "an occurrence inside the generator's right-hand side reads the method \
         parameter, not the binder it is defining: {result:#}"
    );
}

/// Defect 1 on its own, with no binder in the picture: a wildcard import of the
/// companion object must not export the class's constructor parameters.
#[test]
fn wildcard_companion_import_does_not_export_class_fields() {
    const BARE: &str = r#"package app

import model.Conf._

object BareRead {
  def value: String = alpha
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("model/Conf.scala", CONF)
        .file("app/BareRead.scala", BARE)
        .build();
    let result = definition_at(&project, "app/BareRead.scala", BARE, "def value", "alpha");
    assert!(
        definition_fq_names(&result).is_empty(),
        "`import model.Conf._` names the companion object, which does not \
         declare `alpha`; the class's constructor parameter is not exported: \
         {result:#}"
    );
}

/// Negative control: the companion object's own members are still exported.
#[test]
fn wildcard_companion_import_still_exports_object_members() {
    const BARE_GAMMA: &str = r#"package app

import model.Conf._

object BareGamma {
  def value: Int = gamma
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("model/Conf.scala", CONF)
        .file("app/BareGamma.scala", BARE_GAMMA)
        .build();
    let result = definition_at(
        &project,
        "app/BareGamma.scala",
        BARE_GAMMA,
        "def value",
        "gamma",
    );
    assert_eq!(
        definition_fq_names(&result),
        vec!["model.Conf$.gamma".to_string()],
        "`gamma` is declared by the companion object itself: {result:#}"
    );
}

/// Negative control: a Scala 3 `enum` is an importable term whose cases are
/// indexed under the *undecorated* name, so the wildcard import still finds
/// them. This is the case a blanket "no members under the plain fq name" rule
/// would have broken.
#[test]
fn wildcard_enum_import_still_exports_cases() {
    const COLOR: &str = r#"package model

enum Color:
  case Red, Green
"#;
    const PICK: &str = r#"package app

import model.Color._

object Pick {
  def pick: Color = Red
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("model/Color.scala", COLOR)
        .file("app/Pick.scala", PICK)
        .build();
    let result = definition_at(&project, "app/Pick.scala", PICK, "def pick", "Red");
    assert_eq!(
        definition_fq_names(&result),
        vec!["model.Color.Red".to_string()],
        "an enum case is exported by a wildcard import of the enum: {result:#}"
    );
}

/// Negative control: a package wildcard import still exports the package's
/// top-level declarations, which also live under the undecorated name.
#[test]
fn wildcard_package_import_still_exports_top_level_declarations() {
    const HELPER: &str = r#"package model.util

object Helper {
  def help: Int = 1
}
"#;
    const GO: &str = r#"package app

import model.util._

object Go {
  def go: Int = Helper.help
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("model/util/Helper.scala", HELPER)
        .file("app/Go.scala", GO)
        .build();
    let result = definition_at(&project, "app/Go.scala", GO, "def go", "Helper");
    assert_eq!(
        definition_fq_names(&result),
        vec!["model.util.Helper$".to_string()],
        "a package wildcard import still exports its top-level declarations: \
         {result:#}"
    );
}

/// Negative control: the class field is still reachable through an instance.
#[test]
fn class_field_still_resolves_through_an_instance() {
    const VIA_INSTANCE: &str = r#"package app

import model.Conf

object ViaInstance {
  def read(conf: Conf): String = conf.alpha
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("model/Conf.scala", CONF)
        .file("app/ViaInstance.scala", VIA_INSTANCE)
        .build();
    let result = definition_at(
        &project,
        "app/ViaInstance.scala",
        VIA_INSTANCE,
        "conf.",
        "alpha",
    );
    assert_eq!(
        definition_fq_names(&result),
        vec!["model.Conf.alpha".to_string()],
        "an instance receiver still reaches the case-class field: {result:#}"
    );
}

/// Negative control: a `for` binder with nothing to shadow, and no wildcard
/// import at all, still binds locally.
#[test]
fn for_binder_that_shadows_nothing_stays_local() {
    const SOLO: &str = r#"package app

object Solo {
  def loadStr(key: String): Either[String, String] = Right(key)

  def run: Either[String, Int] =
    for {
      delta <- loadStr("d")
    } yield delta.length
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Solo.scala", SOLO)
        .build();
    for (after, needle) in [("for {", "delta"), ("} yield ", "delta")] {
        let result = definition_at(&project, "app/Solo.scala", SOLO, after, needle);
        assert_eq!(
            definition_kinds(&result),
            vec!["local_variable".to_string()],
            "`delta` is a local binding at `{after}`: {result:#}"
        );
    }
}
