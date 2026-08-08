//! #1855: the Scala-site-to-Java-declaration scan misses four shapes.
//!
//! `crates/bifrost-jvm/src/java/graph/jvm_scala.rs` is the only place a Scala
//! file is read for a reference to a Java declaration. Four mechanical gaps
//! kept whole shapes out of the inverse result while forward resolution stated
//! them:
//!
//! * a Java constructor was an early return plus an empty `match` arm, so no
//!   Scala file was ever scanned for `new JavaClass(..)`;
//! * a nested-type qualifier such as the `Stats` of `Stats.Type` was only
//!   accepted under a `field_expression` parent, which is the expression form;
//!   the type form (`stable_type_identifier`) and the pattern form
//!   (`stable_identifier`) both failed;
//! * a paren-less Scala call of a Java static method failed a
//!   `lists.len() == 1` gate, because Scala writes `Stats.origin` with no
//!   argument list at all;
//! * a Scala annotation `@JMark` was not a type-like reference position.
//!
//! Every positive below is paired with a near miss in a package that neither
//! declares nor imports the Java target, so filling the gaps cannot be passed
//! by matching the spelling alone.

use crate::common::{InlineTestProject, line_of};
use brokk_bifrost::usages::{FuzzyResult, UsageFinder, UsageHit};
use brokk_bifrost::{
    AnalyzerDelegate, CodeUnit, CodeUnitIndex, JavaAnalyzer, Language, MultiAnalyzer, ScalaAnalyzer,
};
use std::collections::BTreeMap;

const STATS_JAVA: &str = r#"package lib;

public class Stats {
    public static final int LIMIT = 5;

    public Stats() {}

    public Stats(int seed) {}

    public static int origin() { return 1; }

    public enum Type { NEWADDR }
}
"#;

const MARK_JAVA: &str = r#"package lib;

public @interface JMark {
    String name() default "";
}
"#;

const USE_SCALA: &str = r#"package app

import lib.JMark
import lib.Stats

@JMark(name = "x")
class Use {
  @JMark def marked: Int = 1
  def zeroArg: Stats = new Stats()
  def oneArg: Stats = new Stats(3)
  def qualified: Stats = new lib.Stats()
  def plainType(s: Stats): Int = 0
  def parenLess: Int = Stats.origin
  def typeQualifier(t: Stats.Type): Int = 0
  def patternQualifier(t: Stats.Type): Int = t match {
    case Stats.Type.NEWADDR => 1
  }
}
"#;

/// The near miss: same spellings, no import of `lib`, and its own declarations
/// of every name. Nothing here may be attributed to the Java declarations.
const OTHER_SCALA: &str = r#"package other

class JMark extends scala.annotation.StaticAnnotation
class Stats(seed: Int) {
  def this() = this(0)
}
object Stats {
  def origin: Int = 1
  object Type { val NEWADDR = 1 }
}

@JMark
class Near {
  def zeroArg: Stats = new Stats()
  def parenLess: Int = Stats.origin
  def patternQualifier(t: Int): Int = t match {
    case Stats.Type.NEWADDR => 1
    case _ => 0
  }
}
"#;

struct Workspace {
    _project: crate::common::BuiltInlineTestProject,
    java: JavaAnalyzer,
    multi: MultiAnalyzer,
}

fn workspace() -> Workspace {
    let project = InlineTestProject::new()
        .file("lib/Stats.java", STATS_JAVA)
        .file("lib/JMark.java", MARK_JAVA)
        .file("app/Use.scala", USE_SCALA)
        .file("other/Near.scala", OTHER_SCALA)
        .build();
    let java = JavaAnalyzer::from_project(project.project().clone());
    let scala = ScalaAnalyzer::from_project(project.project().clone());
    let multi = MultiAnalyzer::new(BTreeMap::from([
        (Language::Java, AnalyzerDelegate::Java(java.clone())),
        (Language::Scala, AnalyzerDelegate::Scala(scala.clone())),
    ]));
    Workspace {
        _project: project,
        java,
        multi,
    }
}

fn definitions(java: &JavaAnalyzer, fq_name: &str) -> Vec<CodeUnit> {
    let units = java.get_definitions(fq_name);
    assert!(!units.is_empty(), "missing Java definition for {fq_name}");
    units
}

fn hits(result: FuzzyResult) -> Vec<UsageHit> {
    result
        .into_either()
        .expect("expected usage graph success")
        .into_iter()
        .collect()
}

fn usages(workspace: &Workspace, fq_name: &str) -> Vec<UsageHit> {
    let targets = definitions(&workspace.java, fq_name);
    hits(UsageFinder::new().find_usages_default(&workspace.multi, &targets))
}

fn rel_path(hit: &UsageHit) -> String {
    hit.file.rel_path().to_string_lossy().replace('\\', "/")
}

fn assert_scala_hit(hits: &[UsageHit], path: &str, source: &str, needle: &str) {
    let line = line_of(source, needle);
    assert!(
        hits.iter()
            .any(|hit| rel_path(hit) == path && hit.line == line),
        "expected a hit at {path}:{line} ({needle:?}), got {:#?}",
        hits.iter()
            .map(|hit| (rel_path(hit), hit.line, hit.snippet.clone()))
            .collect::<Vec<_>>()
    );
}

fn assert_no_hit_in(hits: &[UsageHit], path: &str) {
    assert!(
        hits.iter().all(|hit| rel_path(hit) != path),
        "expected no hit in {path}, got {:#?}",
        hits.iter()
            .map(|hit| (rel_path(hit), hit.line, hit.snippet.clone()))
            .collect::<Vec<_>>()
    );
}

/// A Java constructor referenced by `new` from Scala, in the bare, arity-one
/// and package-qualified forms.
#[test]
fn scala_new_expressions_record_the_java_constructor() {
    let workspace = workspace();
    let hits = usages(&workspace, "lib.Stats.Stats");
    assert_scala_hit(&hits, "app/Use.scala", USE_SCALA, "def zeroArg");
    assert_scala_hit(&hits, "app/Use.scala", USE_SCALA, "def oneArg");
    assert_scala_hit(&hits, "app/Use.scala", USE_SCALA, "def qualified");
    assert_no_hit_in(&hits, "other/Near.scala");
}

/// A plain type reference is a use of the class, not of its constructor. The
/// constructor scan must not collapse the two.
#[test]
fn a_plain_scala_type_reference_is_not_a_java_constructor_usage() {
    let workspace = workspace();
    let hits = usages(&workspace, "lib.Stats.Stats");
    let line = line_of(USE_SCALA, "def plainType");
    assert!(
        hits.iter()
            .all(|hit| !(rel_path(hit) == "app/Use.scala" && hit.line == line)),
        "a parameter type is not a constructor call, got {:#?}",
        hits.iter()
            .map(|hit| (rel_path(hit), hit.line, hit.snippet.clone()))
            .collect::<Vec<_>>()
    );
}

/// The `Stats` of `Stats.Type` names the Java class in a type position and in a
/// `case` pattern, neither of which is a `field_expression`.
#[test]
fn scala_nested_type_qualifiers_record_the_java_owner() {
    let workspace = workspace();
    let hits = usages(&workspace, "lib.Stats");
    assert_scala_hit(&hits, "app/Use.scala", USE_SCALA, "def typeQualifier");
    assert_scala_hit(&hits, "app/Use.scala", USE_SCALA, "case Stats.Type.NEWADDR");
    assert_no_hit_in(&hits, "other/Near.scala");
}

/// Scala calls a Java zero-argument static method without an argument list.
#[test]
fn a_paren_less_scala_call_records_the_java_static_method() {
    let workspace = workspace();
    let hits = usages(&workspace, "lib.Stats.origin");
    assert_scala_hit(&hits, "app/Use.scala", USE_SCALA, "def parenLess");
    assert_no_hit_in(&hits, "other/Near.scala");
}

/// A Java annotation type applied from Scala, on a class and on a method.
#[test]
fn scala_annotations_record_the_java_annotation_type() {
    let workspace = workspace();
    let hits = usages(&workspace, "lib.JMark");
    assert_scala_hit(&hits, "app/Use.scala", USE_SCALA, "@JMark(name = \"x\")");
    assert_scala_hit(&hits, "app/Use.scala", USE_SCALA, "def marked");
    assert_no_hit_in(&hits, "other/Near.scala");
}
