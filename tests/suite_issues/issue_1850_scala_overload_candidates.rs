//! Issue #1850: a genuine Scala overload set that the typed selector cannot
//! discriminate answered `no_definition` with ZERO targets.
//!
//! `scala_exact_owner_typed_overload_resolution` selects an overload from exact
//! argument type identity, which it can only construct from a literal or a
//! `new T(...)`. Every other argument shape - a parameter, a local val, a
//! method result - makes the selection impossible, and the caller turned that
//! into an empty `no_definition`: the collected overloads were discarded.
//!
//! This is the #1811/#1812 answer-shape rule. An ambiguity that shows nothing
//! gives the caller nothing to choose between, so the overloads themselves are
//! the answer. Widening the argument typing is separate work; it is not needed
//! to stop losing the candidates.

use crate::common::{InlineTestProject, definition_at};
use brokk_bifrost::Language;

fn scala_definition(source: &str, needle: &str) -> serde_json::Value {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("Fix.scala", source)
        .build();
    definition_at(&project, "Fix.scala", source, needle)
}

fn definition_names(result: &serde_json::Value) -> Vec<String> {
    let mut names = result["definitions"]
        .as_array()
        .map(|definitions| {
            definitions
                .iter()
                .filter_map(|definition| {
                    definition["fqName"]
                        .as_str()
                        .or(definition["fq_name"].as_str())
                        .or(definition["symbol"].as_str())
                })
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// M6: two real overloads, a parameter argument, a fully indexed hierarchy.
/// The selector genuinely cannot choose - and must say so WITH the overloads.
#[test]
fn undecidable_overload_set_reports_its_candidates() {
    let source = r#"package m

class M6 {
  def bar(x: Int): Int = x
  def bar(x: String): Int = 0
  def call(v: Int): Int = bar(v)
}
"#;
    let result = scala_definition(source, "bar(v)");
    assert_eq!(
        result["status"], "ambiguous",
        "an undecidable overload set is ambiguous, not absent: {result:#}"
    );
    assert_eq!(
        result["definitions"].as_array().map(Vec::len),
        Some(2),
        "both overloads must be offered: {result:#} names={:?}",
        definition_names(&result)
    );
}

/// The same set inside a class whose supertype is not indexed. #1849 stopped
/// the ancestor short-circuit; the argument stage is now actually reached, and
/// it must give the same answer.
#[test]
fn undecidable_overload_set_under_unindexed_supertype_reports_its_candidates() {
    let source = r#"package m

class M6 extends UnknownExternalTrait {
  def bar(x: Int): Int = x
  def bar(x: String): Int = 0
  def call(v: Int): Int = bar(v)
}
"#;
    let result = scala_definition(source, "bar(v)");
    assert_eq!(
        result["status"], "ambiguous",
        "an undecidable overload set is ambiguous, not absent: {result:#}"
    );
    assert_eq!(
        result["definitions"].as_array().map(Vec::len),
        Some(2),
        "both overloads must be offered: {result:#}"
    );
}

/// An overload set inherited from an indexed supertype is collected at a deeper
/// level, and must be reported the same way.
#[test]
fn undecidable_inherited_overload_set_reports_its_candidates() {
    let source = r#"package m

trait Base {
  def bar(x: Int): Int = x
  def bar(x: String): Int = 0
}

class Derived extends Base {
  def call(v: Int): Int = bar(v)
}
"#;
    let result = scala_definition(source, "bar(v)");
    assert_eq!(
        result["status"], "ambiguous",
        "an inherited undecidable overload set is ambiguous, not absent: {result:#}"
    );
    assert_eq!(
        result["definitions"].as_array().map(Vec::len),
        Some(2),
        "both inherited overloads must be offered: {result:#}"
    );
}

/// M7 and M5 controls: one candidate always resolves whatever the argument
/// shape, and a literal argument still selects exactly one of two overloads.
/// Neither may become an ambiguity.
#[test]
fn decidable_calls_stay_resolved() {
    let single = r#"package m

class M7 {
  def bar(x: Int): Int = x
  def call(v: Int): Int = bar(v)
}
"#;
    let single_result = scala_definition(single, "bar(v)");
    assert_eq!(
        single_result["status"], "resolved",
        "one candidate is never ambiguous: {single_result:#}"
    );

    let literal = r#"package m

class M5 {
  def bar(x: Int): Int = x
  def bar(x: String): Int = 0
  def call(): Int = bar(1)
}
"#;
    let literal_result = scala_definition(literal, "bar(1)");
    assert_eq!(
        literal_result["status"], "resolved",
        "a literal argument still selects one overload: {literal_result:#}"
    );
    assert_eq!(
        literal_result["definitions"].as_array().map(Vec::len),
        Some(1),
        "literal selection must report exactly the selected overload: {literal_result:#}"
    );
}
