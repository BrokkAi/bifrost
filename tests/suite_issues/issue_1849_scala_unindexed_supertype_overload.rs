//! Issue #1849: an unresolvable supertype short-circuited Scala typed-overload
//! resolution into an empty `no_definition`.
//!
//! `scala_exact_owner_typed_overload_resolution` walked the enclosing class's
//! ancestor closure and returned `Ambiguous` on the first supertype it could
//! not resolve to exactly one indexed declaration - before the
//! `callable_count < 2 => NotNeeded` guard, and discarding every candidate the
//! walk had already collected. `extends Actor`, `extends Serializable` and
//! `extends AnyVal` all produce that verdict, so every bare one-argument-list
//! call inside such a class answered `ambiguous_scala_typed_overload` with zero
//! targets, even with exactly one candidate declared a few lines above.
//!
//! An unresolvable ancestor is INCOMPLETE information, not ambiguity: the
//! levels that did resolve still answer the call, and the unresolved remainder
//! only matters when nothing else in the workspace does.

use crate::common::{InlineTestProject, definition_at};
use brokk_bifrost::Language;

fn scala_definition(source: &str, needle: &str) -> serde_json::Value {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("Fix.scala", source)
        .build();
    definition_at(&project, "Fix.scala", source, needle)
}

/// M1: exactly one same-class candidate under an unindexed supertype. The one
/// candidate must win; there is no overload set to be ambiguous about.
#[test]
fn single_candidate_under_unindexed_supertype_resolves() {
    let source = r#"package m

class M1 extends UnknownExternalTrait {
  def foo(x: Int): Int = x
  def call(v: Int): Int = foo(v)
}
"#;
    let result = scala_definition(source, "foo(v)");
    assert_eq!(
        result["status"], "resolved",
        "one candidate under an unindexed supertype must resolve: {result:#}"
    );
}

/// M2/M3 controls: the same shape with a resolvable supertype and with no
/// supertype at all already resolved and must keep resolving.
#[test]
fn single_candidate_supertype_controls_stay_resolved() {
    let local = r#"package m

trait LocalParent {
  def marker(): Int = 0
}

class M2 extends LocalParent {
  def foo(x: Int): Int = x
  def call(v: Int): Int = foo(v)
}
"#;
    let local_result = scala_definition(local, "foo(v)");
    assert_eq!(
        local_result["status"], "resolved",
        "local-supertype control regressed: {local_result:#}"
    );

    let none = r#"package m

class M3 {
  def foo(x: Int): Int = x
  def call(v: Int): Int = foo(v)
}
"#;
    let none_result = scala_definition(none, "foo(v)");
    assert_eq!(
        none_result["status"], "resolved",
        "no-supertype control regressed: {none_result:#}"
    );
}

/// N5: the unindexed supertype is two levels up. The transitive closure is what
/// the walk consults, so an unindexed grandparent broke the same calls.
#[test]
fn transitively_unindexed_supertype_resolves() {
    let source = r#"package n

trait Mid extends UnknownExternal

class N5 extends Mid {
  def foo(x: Int): Int = x
  def call(v: Int): Int = foo(v)
}
"#;
    let result = scala_definition(source, "foo(v)");
    assert_eq!(
        result["status"], "resolved",
        "an unindexed grandparent must not block a same-class candidate: {result:#}"
    );
}

/// P1: a supertype declared twice in the workspace (the cross-build source-set
/// shape) is equally unusable as a member source, and equally irrelevant to a
/// same-class candidate.
#[test]
fn duplicated_supertype_declaration_resolves() {
    let duplicate_a = "package q\n\ntrait Dup {\n  def marker(): Int = 0\n}\n";
    let duplicate_b = "package q\n\ntrait Dup {\n  def marker(): Int = 1\n}\n";
    let source = r#"package q

class P1 extends Dup {
  def foo(x: Int): Int = x
  def call(v: Int): Int = foo(v)
}
"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("a/Dup.scala", duplicate_a)
        .file("b/Dup.scala", duplicate_b)
        .file("Fix.scala", source)
        .build();
    let result = definition_at(&project, "Fix.scala", source, "foo(v)");
    assert_eq!(
        result["status"], "resolved",
        "a duplicated supertype must not block a same-class candidate: {result:#}"
    );
}

/// N4: an empty ordinary argument list is still one ordinary list, so it took
/// the same short-circuit.
#[test]
fn empty_argument_list_under_unindexed_supertype_resolves() {
    let source = r#"package n

class N4 extends UnknownExternal {
  def foo(): Int = 1
  def call(): Int = foo()
}
"#;
    let result = scala_definition(source, "foo()\n");
    assert_eq!(
        result["status"], "resolved",
        "an empty argument list must resolve like any other: {result:#}"
    );
}

/// P2: `array(i) = null` update sugar is only affected through the same leak -
/// it resolves on its own (M8) and must resolve under an unindexed supertype.
#[test]
fn update_sugar_under_unindexed_supertype_resolves() {
    let clean = r#"package q

class M8 {
  val array = new Array[String](4)
  def call(i: Int): Unit = {
    array(i) = null
  }
}
"#;
    let clean_result = scala_definition(clean, "array(i)");
    assert_eq!(
        clean_result["status"], "resolved",
        "update-sugar control regressed: {clean_result:#}"
    );

    let source = r#"package q

class P2 extends UnknownExternal {
  val array = new Array[String](4)
  def call(i: Int): Unit = {
    array(i) = null
  }
}
"#;
    let result = scala_definition(source, "array(i)");
    assert_eq!(
        result["status"], "resolved",
        "update sugar must resolve under an unindexed supertype: {result:#}"
    );
}

/// N1/N2/N3: call shapes that never entered the selector must stay on their
/// fast path.
#[test]
fn call_shape_escapes_stay_resolved() {
    let curried = r#"package n

class N1 extends UnknownExternal {
  def cur(a: Int)(b: Int): Int = a + b
  def call(): Int = cur(1)(2)
}
"#;
    let curried_result = scala_definition(curried, "cur(1)(2)");
    assert_eq!(
        curried_result["status"], "resolved",
        "curried control regressed: {curried_result:#}"
    );

    let no_list = r#"package n

class N2 extends UnknownExternal {
  def prop: Int = 1
  def call(): Int = prop
}
"#;
    let no_list_result = scala_definition(no_list, "prop\n");
    assert_eq!(
        no_list_result["status"], "resolved",
        "no-argument-list control regressed: {no_list_result:#}"
    );

    let qualified = r#"package n

class N3 extends UnknownExternal {
  def foo(): Int = 1
  def call(): Int = this.foo()
}
"#;
    let qualified_result = scala_definition(qualified, "foo()\n");
    assert_eq!(
        qualified_result["status"], "resolved",
        "this-qualified control regressed: {qualified_result:#}"
    );
}

/// M4/M5: a genuine two-overload set with a literal argument selects by exact
/// argument type identity. That must keep working, with and without an
/// unindexed supertype.
#[test]
fn literal_argument_still_selects_one_overload() {
    let clean = r#"package m

class M5 {
  def bar(x: Int): Int = x
  def bar(x: String): Int = 0
  def call(): Int = bar(1)
}
"#;
    let clean_result = scala_definition(clean, "bar(1)");
    assert_eq!(
        clean_result["status"], "resolved",
        "literal-argument overload selection regressed: {clean_result:#}"
    );

    let source = r#"package m

class M4 extends UnknownExternalTrait {
  def bar(x: Int): Int = x
  def bar(x: String): Int = 0
  def call(): Int = bar(1)
}
"#;
    let result = scala_definition(source, "bar(1)");
    assert_eq!(
        result["status"], "resolved",
        "an unindexed supertype must not block literal-argument selection: {result:#}"
    );
}
