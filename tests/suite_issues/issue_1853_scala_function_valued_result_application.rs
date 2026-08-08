//! Issue #1853: the Scala call-shape relation failed closed on legal shapes.
//!
//! `scala_call_shape_relation` walked the site's application lists against the
//! declared parameter lists and answered `Incompatible` the moment the site
//! supplied one more list than the declaration has. In Scala that shape is
//! legal whenever the declared RESULT is function-valued: `def transform:
//! Int => Int` is applied once, `def transform(flag: Boolean): Int => Int`
//! twice. The same relation rejected the mirror shape - fewer lists than
//! declared, i.e. partial application / eta-expansion - whenever the enclosing
//! context could not prove the expected method-value arity.
//!
//! A shape may be rejected only when no result type could make it legal.

use crate::common::{InlineTestProject, definition_at};
use brokk_bifrost::Language;

fn scala_definition(source: &str, needle: &str) -> serde_json::Value {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("fx/Fix.scala", source)
        .build();
    definition_at(&project, "fx/Fix.scala", source, needle)
}

/// `def transform(flag: Boolean): Int => Int` applied twice: one declared
/// parameter list, two application lists, the second consumed by the result.
#[test]
fn extra_application_list_on_a_function_valued_member_resolves() {
    let source = r#"package fx

class Marker {
  def transform(flag: Boolean): Int => Int = (x: Int) => if (flag) x else -x

  def use(x: Int): Int = transform(true)(x)
}
"#;
    let result = scala_definition(source, "transform(true)(x)");
    assert_eq!(
        result["status"], "resolved",
        "applying a function-valued result is a legal shape: {result:#}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "fx.Marker.transform",
        "{result:#}"
    );
}

/// `def transform: Int => Int` applied once: no declared parameter list at all,
/// so the single application list belongs entirely to the result.
#[test]
fn application_of_a_parameterless_function_valued_member_resolves() {
    let source = r#"package fx

class Marker {
  def transform: Int => Int = (x: Int) => x

  def use(x: Int): Int = transform(x)
}
"#;
    let result = scala_definition(source, "transform(x)");
    assert_eq!(
        result["status"], "resolved",
        "a parameterless function-valued member is applied, not called: {result:#}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "fx.Marker.transform",
        "{result:#}"
    );
}

/// A named result type can alias a function type, so it cannot rule the extra
/// application list out - this is the production shape (`def transform:
/// TlaExTransformation`).
#[test]
fn application_of_a_named_result_type_resolves() {
    let source = r#"package fx

class Marker {
  type Transformation = Int => Int

  def transform: Transformation = (x: Int) => x

  def use(x: Int): Int = transform(x)
}
"#;
    let result = scala_definition(source, "transform(x)");
    assert_eq!(
        result["status"], "resolved",
        "a named result type can alias a function type: {result:#}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "fx.Marker.transform",
        "{result:#}"
    );
}

/// Partial application: the site supplies fewer lists than declared and passes
/// the result where a function value is expected. The expected arity is not
/// provable here, and an unprovable arity is not a mismatch.
#[test]
fn partial_application_of_a_curried_member_resolves() {
    let source = r#"package fx

class Marker {
  def render(base: String)(x: Int): String = base + x

  def use(xs: List[Int]): List[String] = xs.map(render("p"))
}
"#;
    let result = scala_definition(source, "render(\"p\")");
    assert_eq!(
        result["status"], "resolved",
        "partial application of the only callable is a legal shape: {result:#}"
    );
    assert_eq!(
        result["definitions"][0]["fqn"], "fx.Marker.render",
        "{result:#}"
    );
}

/// Negative control: a value-typed result cannot consume a further application
/// list under any result type, so the shape stays incompatible.
#[test]
fn extra_application_list_on_a_value_typed_result_stays_incompatible() {
    let source = r#"package fx

class Marker {
  def size(flag: Boolean): Int = if (flag) 1 else 0

  def use(x: Int): Int = size(true)(x)
}
"#;
    let result = scala_definition(source, "size(true)(x)");
    assert_ne!(
        result["status"], "resolved",
        "no result type makes `Int` applicable: {result:#}"
    );
}

/// Negative control: `Int => Int` supplies exactly one application list, and
/// what it leaves is a value type, so a second list has nothing left to apply.
#[test]
fn more_application_lists_than_the_function_type_supplies_stays_incompatible() {
    let source = r#"package fx

class Marker {
  def transform: Int => Int = (x: Int) => x

  def use(x: Int): Int = transform(x)(x)
}
"#;
    let result = scala_definition(source, "transform(x)(x)");
    assert_ne!(
        result["status"], "resolved",
        "`Int => Int` supplies one application list, not two: {result:#}"
    );
}

/// Negative control: an ordinary complete call keeps selecting the overload
/// whose parameter lists it fills.
#[test]
fn complete_calls_still_select_the_matching_overload() {
    let source = r#"package fx

class Marker {
  def pick(a: Int): String = "one"

  def pick(a: Int, b: Int): String = "two"

  def use(x: Int): String = pick(x, x)
}
"#;
    let result = scala_definition(source, "pick(x, x)");
    assert_eq!(result["status"], "resolved", "{result:#}");
    assert_eq!(
        result["definitions"].as_array().map(Vec::len),
        Some(1),
        "a complete call must still pick exactly one overload: {result:#}"
    );
}
