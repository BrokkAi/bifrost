//! Issue #1851: an unresolvable supertype poisoned the whole Scala lexical type
//! namespace.
//!
//! `resolve_exact_lexical_type_namespace` walks the enclosing owners nearest
//! first, and for each one consults its ancestor closure. It returned
//! `Ambiguous` for the entire lookup as soon as an owner's supertypes could not
//! be resolved to indexed declarations - before considering any outer owner,
//! and with no candidate to show. Callers report that as
//! "`X` resolves to multiple exact Scala type declarations", which is false:
//! there is exactly one `X`, and the unresolvable name is an unrelated
//! ancestor.
//!
//! Same discipline as #1849. An ancestor this workspace cannot see contributes
//! no type member, so it cannot make a name ambiguous. Resolve from the levels
//! that ARE known; the unresolved remainder only matters when nothing known
//! answers, and then the honest answer names the incomplete hierarchy.

use crate::common::{InlineTestProject, definition_at};
use brokk_bifrost::Language;

fn scala_definition(source: &str, needle: &str) -> serde_json::Value {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("Fix.scala", source)
        .build();
    definition_at(&project, "Fix.scala", source, needle)
}

/// The airframe `ServerAddress` shape: a companion object whose supertype is
/// not indexed, calling its own case class's apply. `anc_none` (no `extends`)
/// already resolved; only the ancestor clause differed.
#[test]
fn companion_apply_resolves_under_an_unindexed_supertype() {
    let clean = r#"package fx

case class ServerAddress(host: String, port: Int)

object ServerAddress {
  val empty: ServerAddress = ServerAddress("", -1)
}
"#;
    let clean_result = scala_definition(clean, "ServerAddress(\"\", -1)");
    assert_eq!(
        clean_result["status"], "resolved",
        "no-supertype control regressed: {clean_result:#}"
    );

    let source = r#"package fx

case class ServerAddress(host: String, port: Int)

object ServerAddress extends Foo {
  val empty: ServerAddress = ServerAddress("", -1)
}
"#;
    let result = scala_definition(source, "ServerAddress(\"\", -1)");
    assert_eq!(
        result["status"], "resolved",
        "an unindexed supertype must not hide the companion's own class: {result:#}"
    );
}

/// `anc_transitive`, the production airframe shape: the direct supertype IS
/// indexed, and ITS supertypes are not.
#[test]
fn companion_apply_resolves_under_a_transitively_unindexed_supertype() {
    let log = r#"package wvlet.log

trait LogSupport extends LoggingMethods with LazyLogger
"#;
    let source = r#"package fx

import wvlet.log.LogSupport

case class ServerAddress(host: String, port: Int)

object ServerAddress extends LogSupport {
  val empty: ServerAddress = ServerAddress("", -1)
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("Log.scala", log)
        .file("Fix.scala", source)
        .build();
    let result = definition_at(&project, "Fix.scala", source, "ServerAddress(\"\", -1)");
    assert_eq!(
        result["status"], "resolved",
        "an unindexed grandparent must not poison the type namespace: {result:#}"
    );
}

/// Negative control, and the line this fix must not cross. A supertype name
/// with more than one INDEXED declaration is a different state from one with
/// none: the workspace holds the supertype, so it may well declare the name
/// being looked up, and skipping the level would silently answer with an outer
/// scope Scala says is shadowed. That case must keep failing closed.
#[test]
fn duplicated_supertype_still_fails_closed() {
    let duplicate_a = "package dup\n\ntrait Marker {\n  def marker(): Int = 0\n}\n";
    let duplicate_b = "package dup\n\ntrait Marker {\n  def marker(): Int = 1\n}\n";
    let source = r#"package dup

case class ServerAddress(host: String, port: Int)

object ServerAddress extends Marker {
  val empty: ServerAddress = ServerAddress("", -1)
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("a/Marker.scala", duplicate_a)
        .file("b/Marker.scala", duplicate_b)
        .file("Fix.scala", source)
        .build();
    let result = definition_at(&project, "Fix.scala", source, "ServerAddress(\"\", -1)");
    assert_eq!(
        result["diagnostics"][0]["kind"], "ambiguous_scala_type",
        "a supertype the workspace holds twice must still fail closed: {result:#}"
    );
}

/// Control for the qualified-path branch, which resolves the path ROOT through
/// a different walk (`scala_exact_owner_namespace_children`). That walk has the
/// same unresolvable-ancestor bail, but no probe reached it: this shape - the
/// root declared by an OUTER owner, the inner owner's supertype unindexed -
/// already resolved before this change and must keep resolving.
#[test]
fn qualified_type_path_resolves_under_an_unindexed_supertype() {
    let clean = r#"package fx

class Outer {
  object Holder {
    case class Inner(v: Int)
  }
  class User {
    def make(): Holder.Inner = Holder.Inner(1)
  }
}
"#;
    let clean_result = scala_definition(clean, "Holder.Inner =");
    assert_eq!(
        clean_result["status"], "resolved",
        "no-supertype control regressed: {clean_result:#}"
    );

    let source = r#"package fx

class Outer {
  object Holder {
    case class Inner(v: Int)
  }
  class User extends UnknownExternal {
    def make(): Holder.Inner = Holder.Inner(1)
  }
}
"#;
    let result = scala_definition(source, "Holder.Inner =");
    assert_eq!(
        result["status"], "resolved",
        "an unindexed supertype must not poison a qualified type path: {result:#}"
    );
}

/// A genuine conflict must still be reported: two indexed traits mixed into one
/// owner, each declaring the same nested type, is a real ambiguity at one
/// inheritance level.
#[test]
fn two_indexed_ancestors_declaring_the_same_type_stay_ambiguous() {
    let source = r#"package amb

trait Left {
  class Shared(val v: Int)
}

trait Right {
  class Shared(val v: Int)
}

class Both extends Left with Right {
  def make(): Shared = new Shared(1)
}
"#;
    let result = scala_definition(source, "Shared =");
    assert_ne!(
        result["status"], "resolved",
        "two inherited declarations of the same name are a real conflict: {result:#}"
    );
}

/// N6/N7 from the #1849 fixture matrix: apply sugar on a local object, with
/// zero candidates in the enclosing class. The bare-call fast path asks the
/// lexical type namespace first, so the enclosing class's unindexed supertype
/// hid a plain workspace object.
#[test]
fn apply_sugar_on_local_object_matches_its_clean_ancestor_twin() {
    let clean = r#"package n

trait Plain
object Comp { def apply(x: Int): Int = x }

class N6 extends Plain {
  def call(): Int = Comp(1)
}
"#;
    let clean_result = scala_definition(clean, "Comp(1)");
    assert_eq!(
        clean_result["status"], "resolved",
        "clean-ancestor apply-sugar control regressed: {clean_result:#}"
    );

    let source = r#"package n

object Comp { def apply(x: Int): Int = x }

class N7 extends UnknownExternal {
  def call(): Int = Comp(1)
}
"#;
    let result = scala_definition(source, "Comp(1)");
    assert_eq!(
        result["status"], "resolved",
        "an unindexed supertype must not hide a local object's apply: {result:#}"
    );
}

/// The #1849 external-ancestor leak probe: the SAME `Left("boom")` call
/// answered a false ambiguity only when the ENCLOSING class had an unindexed
/// supertype. The callee is external either way, so the answer may only differ
/// in how much of the hierarchy the workspace can see - never in claiming an
/// ambiguity.
#[test]
fn external_callee_answer_is_never_an_ambiguity() {
    let with_external_parent = r#"package p

class WithExternalParent extends UnknownExternalTrait {
  def use(): Either[String, Int] = Left("boom")
}
"#;
    let with_local_parent = r#"package p

trait Local {
  def hello(): Int = 1
}

class WithLocalParent extends Local {
  def use(): Either[String, Int] = Left("boom")
}
"#;
    let external = scala_definition(with_external_parent, "Left(\"boom\")");
    let local = scala_definition(with_local_parent, "Left(\"boom\")");
    assert_eq!(
        local["diagnostics"][0]["kind"], "no_indexed_definition",
        "local-parent control regressed: {local:#}"
    );
    assert_eq!(
        external["status"], "unresolvable_import_boundary",
        "an unindexed enclosing parent leaves an honest boundary, not a verdict: {external:#}"
    );
}

/// A member only the unindexed supertype could declare. Every workspace tier
/// fails, so the last answer names the incomplete hierarchy - the #1849
/// boundary, observable only once this namespace stops pre-empting it.
#[test]
fn member_only_reachable_through_the_unindexed_supertype_answers_a_boundary() {
    let source = r#"package m

class Reporter extends UnknownExternalTrait {
  def call(v: Int): Int = inheritedOnly(v)
}
"#;
    let result = scala_definition(source, "inheritedOnly(v)");
    assert_eq!(
        result["status"], "unresolvable_import_boundary",
        "an unindexed supertype leaves a boundary, not a verdict: {result:#}"
    );

    let clean = r#"package m

class Reporter {
  def call(v: Int): Int = inheritedOnly(v)
}
"#;
    let clean_result = scala_definition(clean, "inheritedOnly(v)");
    assert_eq!(
        clean_result["diagnostics"][0]["kind"], "no_indexed_definition",
        "a fully indexed hierarchy still proves the name absent: {clean_result:#}"
    );
}
