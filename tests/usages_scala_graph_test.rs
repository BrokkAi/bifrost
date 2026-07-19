mod common;

use brokk_bifrost::usages::{
    ExplicitCandidateProvider, FuzzyResult, ScalaUsageGraphStrategy, UsageAnalyzer, UsageFinder,
    UsageHit, UsageHitKind,
};
use brokk_bifrost::{
    CodeUnit, CodeUnitType, IAnalyzer, ImportAnalysisProvider, Language, ScalaAnalyzer,
};
use common::{InlineTestProject, call_search_tool_json, line_of};
use serde_json::json;
use std::collections::BTreeSet;
use std::sync::Arc;

fn scala_analyzer_with_files(
    files: &[(&str, &str)],
) -> (common::BuiltInlineTestProject, ScalaAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Scala);
    for (path, contents) in files {
        builder = builder.file(path, *contents);
    }
    let project = builder.build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

#[test]
fn scala_explicit_package_singleton_collision_fails_closed() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "collision/Api.scala",
            "package collision\nobject Api { class ActorContext }\n",
        ),
        (
            "collision/Api/Types.scala",
            "package collision.Api\nclass ActorContext\n",
        ),
        (
            "app/Use.scala",
            r#"package app
import collision.{Api => mixed}
object Use {
  val context: mixed.ActorContext = null // negative-same-tier-package-singleton
}
"#,
        ),
    ]);
    let provider = ExplicitCandidateProvider::new(Arc::new(
        analyzer.get_analyzed_files().into_iter().collect(),
    ));

    for target in ["collision.Api$.ActorContext", "collision.Api.ActorContext"] {
        let target = definition(&analyzer, target);
        let target_hits = hits(
            UsageFinder::new()
                .with_authoritative_scope(true)
                .query_with_provider(
                    &analyzer,
                    std::slice::from_ref(&target),
                    Some(&provider),
                    100,
                    100,
                )
                .result,
        );
        assert_no_hit_contains(&target_hits, "negative-same-tier-package-singleton");
    }
}

#[test]
fn scala_imported_bare_helper_return_seeds_local_receiver_type() {
    let (project, analyzer) = scala_analyzer_with_files(&[
        (
            "model/matchers/MatchResult.scala",
            r#"package model
package matchers
class MatchResult(val matches: Boolean)
"#,
        ),
        (
            "model/matchers/MatchersHelper.scala",
            r#"package model
package matchers
class OtherResult(val matches: Boolean)
private[model] object MatchersHelper {
  def fullyMatchRegexWithGroups(left: String, regex: String, groups: Seq[String]): MatchResult =
    new MatchResult(true)
}
object OtherHelper {
  def fullyMatchRegexWithGroups(left: String): OtherResult = new OtherResult(false)
}
"#,
        ),
        (
            "app/Use.scala",
            r#"package app
import model.matchers.MatchersHelper.fullyMatchRegexWithGroups
object Use {
  def positive = {
    val result = fullyMatchRegexWithGroups("", "", Seq.empty)
    result.matches // positive-imported-helper-return
  }
  def shadowed = {
    def fullyMatchRegexWithGroups(left: String): model.matchers.OtherResult =
      model.matchers.OtherHelper.fullyMatchRegexWithGroups(left)
    val result = fullyMatchRegexWithGroups("")
    result.matches // negative-local-helper-shadow
  }
}
"#,
        ),
        (
            "other/Use.scala",
            r#"package app
object Use {
  def unrelated = 1
}
"#,
        ),
    ]);
    let target = definition(&analyzer, "model.matchers.MatchResult.matches");
    let provider = ExplicitCandidateProvider::new(Arc::new(
        std::iter::once(project.file("app/Use.scala")).collect(),
    ));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            100,
        );
    let target_hits = hits(query.result);
    assert_hit_contains(&target_hits, "positive-imported-helper-return");
    assert_no_hit_contains(&target_hits, "negative-local-helper-shadow");
}

#[test]
fn scala_nested_constructor_role_preserves_exact_duplicate_source_identity() {
    let (project, analyzer) = scala_analyzer_with_files(&[
        (
            "scala-3/ByteString.scala",
            r#"package akka.util
object ByteString {
  object ByteString1 {
    def apply(value: Int): ByteString1 = new ByteString1(value)
  }
  final class ByteString1 private (val value: Int) {
    def copy = ByteString1(value) // positive-exact-nested-constructor
  }
}
"#,
        ),
        (
            "scala-2.13/ByteString.scala",
            r#"package akka.util
object ByteString {
  object ByteString1 {
    def apply(value: Int): ByteString1 = new ByteString1(value)
  }
  final class ByteString1 private (val value: Int)
}
"#,
        ),
    ]);
    let target = analyzer
        .get_definitions("akka.util.ByteString$.ByteString1.ByteString1")
        .into_iter()
        .find(|unit| unit.source() == &project.file("scala-3/ByteString.scala"))
        .expect("Scala 3 synthetic constructor");
    let provider = ExplicitCandidateProvider::new(Arc::new(
        std::iter::once(project.file("scala-3/ByteString.scala")).collect(),
    ));
    let target_hits = hits(
        UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                &analyzer,
                std::slice::from_ref(&target),
                Some(&provider),
                1,
                100,
            )
            .result,
    );
    assert_hit_contains(&target_hits, "positive-exact-nested-constructor");
    assert!(
        target_hits
            .iter()
            .all(|hit| hit.file == project.file("scala-3/ByteString.scala")),
        "duplicate physical constructor leaked: {target_hits:#?}"
    );
}

fn definition(analyzer: &ScalaAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn hit_snippets(result: FuzzyResult) -> Vec<String> {
    result
        .into_either()
        .expect("expected usage graph success")
        .into_iter()
        .map(|hit| hit.snippet)
        .collect()
}

#[test]
fn authoritative_scala_object_reference_in_direct_method_body_is_exact() {
    let consumer_source = r#"package app

object Consumer {
  def token: AnyRef = Token // positive-rhs
  def parameter(Token: AnyRef): AnyRef = Token // negative-parameter-shadow
  def local: AnyRef = {
    val Token: AnyRef = other.Token
    Token // negative-local-shadow
  }
  def otherPackage: AnyRef = other.Token // negative-other-package
}
"#;
    let (project, analyzer) = scala_analyzer_with_files(&[
        ("app/Token.scala", "package app\nobject Token\n"),
        ("other/Token.scala", "package other\nobject Token\n"),
        ("app/Consumer.scala", consumer_source),
    ]);
    let target = definition(&analyzer, "app.Token$");
    let consumer = project.file("app/Consumer.scala");
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(consumer.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            &analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            1,
            100,
        );
    assert_eq!(
        query.candidate_files,
        std::iter::once(consumer.clone()).collect(),
        "authoritative query must scan only the explicit consumer"
    );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_total_by_overload,
        ..
    } = query.result
    else {
        panic!("expected authoritative Scala usage success");
    };
    let actual = hits_by_overload
        .get(&target)
        .into_iter()
        .flatten()
        .map(|hit| {
            assert_eq!(hit.file, consumer);
            (hit.start_offset, hit.end_offset)
        })
        .collect::<BTreeSet<_>>();
    let line = "  def token: AnyRef = Token // positive-rhs";
    let line_start = consumer_source.find(line).expect("positive fixture line");
    let token_start = line.find("Token").expect("positive Token");
    let expected = BTreeSet::from([(
        line_start + token_start,
        line_start + token_start + "Token".len(),
    )]);
    assert_eq!(actual, expected, "only the direct method RHS is exact");
    assert_eq!(
        unproven_total_by_overload
            .get(&target)
            .copied()
            .unwrap_or_default(),
        0,
        "parameter/local shadows and the other-package object are proven negatives"
    );
}

#[test]
fn scala_lexical_nested_singletons_and_typed_patterns_preserve_exact_identity() {
    let (project, analyzer) = scala_analyzer_with_files(&[
        (
            "model/Outer.scala",
            r#"package model
object Outer {
  object Token
  class UseRef
  object internal { object PathToken }
  object Factory { def apply(value: Int): UseRef = new UseRef }
  object Pattern { def unapply(value: Any): Option[Int] = None }

  def singleton: Any = Token // positive-lexical-singleton
  def stablePath(value: Any): Int = value match {
    case internal.PathToken => 1 // positive-lexical-stable-path
    case _ => 0
  }
  def made = Factory(1) // positive-lexical-object-apply
  def extracted(value: Any): Int = value match {
    case Pattern(number) => number // positive-lexical-object-extractor
    case _ => 0
  }
  def shadowedSingleton(Token: Any): Any = Token // negative-term-shadow
  def typedWithTerm(UseRef: Int, tree: Any): Any = tree match {
    case value: UseRef => value // positive-typed-pattern-term-namespace
    case _ => tree
  }
  def UseRef(tree: Any): Any = tree match {
    case value: UseRef => value // positive-typed-pattern-method-name
    case _ => tree
  }
}

object Other {
  object Token
  class UseRef
  def singleton: Any = Token // negative-other-owner-singleton
  def typed(tree: Any): Any = tree match {
    case value: UseRef => value // negative-other-owner-type
    case _ => tree
  }
}
"#,
        ),
        (
            "duplicate/First.scala",
            r#"package duplicate
object Outer {
  object Token
  def singleton: Any = Token // negative-ambiguous-first
}
class PackageType
object PackageToken
"#,
        ),
        (
            "duplicate/Second.scala",
            r#"package duplicate
object Outer {
  object Token
  def singleton: Any = Token // negative-ambiguous-second
}
class PackageType
object PackageToken
"#,
        ),
        (
            "consumer/Ambiguous.scala",
            r#"package consumer
object Ambiguous {
  def typed: duplicate.PackageType = null // negative-package-type-ambiguity
  def token(value: Any): Int = value match {
    case duplicate.PackageToken => 1 // negative-package-object-ambiguity
    case _ => 0
  }
}
"#,
        ),
    ]);

    let outer = project.file("model/Outer.scala");
    let outer_provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(outer.clone()).collect()));
    let outer_hits = |target: &CodeUnit| {
        hits(
            UsageFinder::new()
                .with_authoritative_scope(true)
                .query_with_provider(
                    &analyzer,
                    std::slice::from_ref(target),
                    Some(&outer_provider),
                    1,
                    100,
                )
                .result,
        )
    };

    let token = definition(&analyzer, "model.Outer$.Token$");
    let token_hits = outer_hits(&token);
    assert_hit_contains(&token_hits, "positive-lexical-singleton");
    assert_no_hit_contains(&token_hits, "negative-term-shadow");
    assert_no_hit_contains(&token_hits, "negative-other-owner-singleton");

    for (target_fqn, marker) in [
        (
            "model.Outer$.internal$.PathToken$",
            "positive-lexical-stable-path",
        ),
        (
            "model.Outer$.Factory$.apply",
            "positive-lexical-object-apply",
        ),
        (
            "model.Outer$.Pattern$.unapply",
            "positive-lexical-object-extractor",
        ),
    ] {
        let target = definition(&analyzer, target_fqn);
        let target_hits = outer_hits(&target);
        assert_hit_contains(&target_hits, marker);
    }

    let use_ref = analyzer
        .get_definitions("model.Outer$.UseRef")
        .into_iter()
        .find(CodeUnit::is_class)
        .expect("nested UseRef class");
    let use_ref_hits = outer_hits(&use_ref);
    assert_hit_contains(&use_ref_hits, "positive-typed-pattern-term-namespace");
    assert_hit_contains(&use_ref_hits, "positive-typed-pattern-method-name");
    assert_no_hit_contains(&use_ref_hits, "negative-other-owner-type");

    let first = project.file("duplicate/First.scala");
    let ambiguous_token = analyzer
        .get_definitions("duplicate.Outer$.Token$")
        .into_iter()
        .find(|unit| unit.is_class() && unit.source() == &first)
        .expect("first ambiguous nested Token object");
    let ambiguous_provider = ExplicitCandidateProvider::new(Arc::new(
        [
            project.file("duplicate/First.scala"),
            project.file("duplicate/Second.scala"),
        ]
        .into_iter()
        .collect(),
    ));
    let ambiguous_hits = hits(
        UsageFinder::new()
            .with_authoritative_scope(true)
            .query_with_provider(
                &analyzer,
                std::slice::from_ref(&ambiguous_token),
                Some(&ambiguous_provider),
                1,
                100,
            )
            .result,
    );
    assert_no_hit_contains(&ambiguous_hits, "negative-ambiguous-first");
    assert_no_hit_contains(&ambiguous_hits, "negative-ambiguous-second");

    let consumer_provider = ExplicitCandidateProvider::new(Arc::new(
        std::iter::once(project.file("consumer/Ambiguous.scala")).collect(),
    ));
    for (target_fqn, marker) in [
        ("duplicate.PackageType", "negative-package-type-ambiguity"),
        (
            "duplicate.PackageToken$",
            "negative-package-object-ambiguity",
        ),
    ] {
        let target = analyzer
            .get_definitions(target_fqn)
            .into_iter()
            .find(|unit| unit.is_class() && unit.source() == &first)
            .unwrap_or_else(|| panic!("first ambiguous declaration for {target_fqn}"));
        let target_hits = hits(
            UsageFinder::new()
                .with_authoritative_scope(true)
                .query_with_provider(
                    &analyzer,
                    std::slice::from_ref(&target),
                    Some(&consumer_provider),
                    1,
                    100,
                )
                .result,
        );
        assert_no_hit_contains(&target_hits, marker);
    }
}

#[test]
fn scala_usage_finder_distinguishes_class_and_object_identity_roles() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "app/Token.scala",
            r#"
package app

class Token

object Token {
  class Nested
  def unapply(value: String): Option[String] = Some(value)
}
"#,
        ),
        (
            "app/Use.scala",
            r#"
package app

object Use {
  val bareObject = Token
  val singleton: Token.type = Token
  val nestedType: Token.Nested = new Token.Nested
  val classType: Token = new Token

  def extracted(value: String): String = value match {
    case Token(found) => found
    case _ => value
  }
}
"#,
        ),
        (
            "other/Token.scala",
            r#"
package other

class Token
object Token {
  class Nested
  def unapply(value: String): Option[String] = Some(value)
}

object Use {
  val bareObject = Token
  val singleton: Token.type = Token
  val nestedType: Token.Nested = new Token.Nested
  val classType: Token = new Token
  def extracted(value: String): String = value match { case Token(found) => found }
}
"#,
        ),
    ]);

    let object = definition(&analyzer, "app.Token$");
    let object_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&object)));
    for expected in [
        "val bareObject = Token",
        "val singleton: Token.type = Token",
        "val nestedType: Token.Nested",
        "new Token.Nested",
        "case Token(found)",
    ] {
        assert_hit_contains(&object_hits, expected);
    }
    assert_no_hit_contains(&object_hits, "val classType: Token = new Token");
    assert!(
        object_hits
            .iter()
            .all(|hit| hit.file.rel_path() != "other/Token.scala"),
        "unrelated companion object leaked: {object_hits:#?}"
    );

    let class = definition(&analyzer, "app.Token");
    let class_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&class)));
    assert_hit_contains(&class_hits, "val classType: Token = new Token");
    assert_no_hit_contains(&class_hits, "val bareObject = Token");
    assert_no_hit_contains(&class_hits, "Token.type");
    assert_no_hit_contains(&class_hits, "Token.Nested");
    assert_hit_contains(&class_hits, "case Token(found)");
    assert!(
        class_hits
            .iter()
            .all(|hit| hit.file.rel_path() != "other/Token.scala"),
        "unrelated class leaked: {class_hits:#?}"
    );
}

#[test]
fn scala_type_roles_cover_anonymous_mixins_and_infix_type_operators() {
    let use_source = r#"package app

import model.{Base, First, InHandler, OutHandler, CanEqual}

object Use {
  def mixinRole(): Base =
    new Base with First with InHandler with OutHandler {} // positive-mixin

  def infixTypeRole[A, B](evidence: A CanEqual B): Unit = () // positive-infix-type

  def termObjectRole: Any = InHandler // negative-term-object
  def ordinaryInfix(left: String, right: String): String = left CanEqual right // negative-term-infix
}
"#;
    let (project, analyzer) = scala_analyzer_with_files(&[
        (
            "model/Roles.scala",
            r#"package model

class Base
trait First
trait InHandler
trait OutHandler
object InHandler

infix abstract class CanEqual[A, B]
object CanEqual
"#,
        ),
        (
            "other/Roles.scala",
            r#"package other
trait InHandler
infix abstract class CanEqual[A, B]
"#,
        ),
        ("app/Use.scala", use_source),
    ]);

    for (symbol, positive_marker, negative_marker) in [
        ("model.InHandler", "positive-mixin", "negative-term-object"),
        (
            "model.CanEqual",
            "positive-infix-type",
            "negative-term-infix",
        ),
    ] {
        let target = definition(&analyzer, symbol);
        let target_hits =
            hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));
        assert_hit_line(&target_hits, line_of(use_source, positive_marker));
        assert_no_hit_line(&target_hits, line_of(use_source, negative_marker));
        assert!(
            target_hits
                .iter()
                .all(|hit| hit.file.rel_path() != "other/Roles.scala"),
            "unrelated type identity leaked for {symbol}: {target_hits:#?}"
        );

        let mcp = call_search_tool_json(
            project.root(),
            "scan_usages_by_reference",
            &json!({
                "symbols": [symbol],
                "include_tests": true,
            })
            .to_string(),
        );
        let result = &mcp["results"][0];
        assert_eq!(result["status"], "found", "{mcp}");
        let mcp_lines = result["files"]
            .as_array()
            .expect("MCP usage files")
            .iter()
            .flat_map(|file| file["hits"].as_array().into_iter().flatten())
            .filter_map(|hit| hit["line"].as_u64())
            .collect::<BTreeSet<_>>();
        assert!(
            mcp_lines.contains(&(line_of(use_source, positive_marker) as u64)),
            "MCP result omitted {positive_marker}: {mcp}"
        );
        assert!(
            !mcp_lines.contains(&(line_of(use_source, negative_marker) as u64)),
            "MCP result included {negative_marker}: {mcp}"
        );
    }
}

#[test]
fn scala_usage_finder_preserves_exact_companion_nested_and_ambiguous_object_roles() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "app/Owners.scala",
            r#"package app
class Token { def make(): Token = this }
object Token { def make(): Token = new Token }
object Outer {
  def make(): Int = 1
  object Inner { def make(): Int = 2 }
}
object Shared
class Holder { val Shared: Int = 1 }
object Use {
  val made = Token.make()
  val nested = Outer.Inner
  val nestedCall = Outer.Inner.make()
  val unqualifiedNested = Inner
  def instanceField(holder: Holder): Int = holder.Shared
}
"#,
        ),
        (
            "left/Shared.scala",
            "package left\nobject Shared { def make(): Int = 1 }\n",
        ),
        (
            "right/Shared.scala",
            "package right\nobject Shared { def make(): Int = 2 }\n",
        ),
        (
            "app/Ambiguous.scala",
            "package app\nimport left._\nimport right._\nobject Ambiguous {\n  val value = Shared\n  val call = Shared.make()\n}\n",
        ),
        (
            "app/Explicit.scala",
            "package app\nimport left.Shared\nimport right._\nobject Explicit { val call = Shared.make() }\n",
        ),
    ]);
    let object_make = definition(&analyzer, "app.Token$.make");
    let object_make_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&object_make)));
    assert_hit_contains(&object_make_hits, "Token.make()");
    let class_make = definition(&analyzer, "app.Token.make");
    let class_make_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&class_make)));
    assert_no_hit_contains(&class_make_hits, "val made = Token.make()");
    let inner = definition(&analyzer, "app.Outer$.Inner$");
    let inner_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&inner)));
    assert_hit_contains(&inner_hits, "val nested = Outer.Inner");
    assert_no_hit_contains(&inner_hits, "val unqualifiedNested = Inner");
    let inner_make = definition(&analyzer, "app.Outer$.Inner$.make");
    let inner_make_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&inner_make)));
    assert_hit_contains(&inner_make_hits, "Outer.Inner.make()");
    let outer_make = definition(&analyzer, "app.Outer$.make");
    let outer_make_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&outer_make)));
    assert_no_hit_contains(&outer_make_hits, "Outer.Inner.make()");
    let shared = definition(&analyzer, "app.Shared$");
    let shared_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&shared)));
    assert_no_hit_contains(&shared_hits, "holder.Shared");
    let left = definition(&analyzer, "left.Shared$");
    let left_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&left)));
    assert!(
        left_hits
            .iter()
            .all(|hit| hit.file.rel_path() != "app/Ambiguous.scala"),
        "ambiguous wildcard object leaked: {left_hits:#?}"
    );
    assert_hit_contains(&left_hits, "object Explicit { val call = Shared.make() }");
}

#[test]
fn scala_usage_finder_resolves_qualified_stable_type_paths_exactly() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "model/Structure.scala",
            r#"package model
object Structure {
  case class Value(value: Int)
  object Value
  class Plain
  object Plain { def apply(value: Int): Plain = new Plain }
  class Box[T](value: T)
  object Deep { class Leaf }
}
"#,
        ),
        (
            "decoy/Structure.scala",
            r#"package decoy
object Structure {
  case class Value(value: Int)
  object Value
  class Plain
  object Plain { def apply(value: Int): Plain = new Plain }
  class Box[T](value: T)
  object Deep { class Leaf }
}
"#,
        ),
        (
            "app/Direct.scala",
            r#"package app
import model.Structure
object Direct {
  val decoded = Option.empty[Structure.Value]
  val created = new Structure.Value(1)
  val wrongConstructor = new Structure.Value(1, 2)
  val applied = Structure.Value(2)
  val wrongApply = Structure.Value(2, 3)
  def extracted(value: Structure.Value): Int = value match {
    case Structure.Value(number) => number
  }
  def notExtractor(value: Structure.Plain): Int = value match {
    case Structure.Plain() => 0
    case _ => 1
  }
  val generic = new Structure.Box[Int](1)
  val wrongGeneric = new Structure.Box[Int](1, 2)
  val deep = Option.empty[Structure.Deep.Leaf]
}
"#,
        ),
        (
            "app/Alias.scala",
            r#"package app
import model.{Structure as Schema}
object Alias {
  val decoded = Option.empty[Schema.Value]
  val deep = Option.empty[Schema.Deep.Leaf]
}
"#,
        ),
        (
            "model/PackageRoot.scala",
            r#"package app
object PackageRoot {
  val decoded = Option.empty[model.Structure.Value]
  val deep = Option.empty[model.Structure.Deep.Leaf]
}
"#,
        ),
        (
            "app/Shadowed.scala",
            r#"package app
import model.Structure
object Shadowed {
  val Structure = decoy.Structure
  val decoded = Option.empty[Structure.Value]
}
"#,
        ),
        (
            "decoy/Use.scala",
            r#"package decoy
object Use {
  val decoded = Option.empty[Structure.Value]
  val created = new Structure.Value(3)
  val applied = Structure.Value(4)
}
"#,
        ),
    ]);

    let value = definition(&analyzer, "model.Structure$.Value");
    let value_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&value)));
    for expected in [
        "Option.empty[Structure.Value]",
        "new Structure.Value(1)",
        "Structure.Value(2)",
        "case Structure.Value(number)",
        "Option.empty[Schema.Value]",
        "Option.empty[model.Structure.Value]",
    ] {
        assert_hit_contains(&value_hits, expected);
    }
    assert!(
        value_hits.iter().all(|hit| !matches!(
            hit.file.rel_path().to_str(),
            Some("decoy/Use.scala" | "app/Shadowed.scala")
        )),
        "same-name qualified type leaked: {value_hits:#?}"
    );
    assert_no_hit_contains(&value_hits, "new Structure.Value(1, 2)");
    assert_no_hit_contains(&value_hits, "Structure.Value(2, 3)");

    let companion = definition(&analyzer, "model.Structure$.Value$");
    let companion_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&companion)));
    assert_hit_contains(&companion_hits, "Structure.Value(2)");
    assert_hit_contains(&companion_hits, "case Structure.Value(number)");
    assert_no_hit_contains(&companion_hits, "Option.empty[Structure.Value]");

    let plain = definition(&analyzer, "model.Structure$.Plain");
    let plain_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&plain)));
    assert_no_hit_contains(&plain_hits, "case Structure.Plain()");

    let box_constructor = definition(&analyzer, "model.Structure$.Box.Box");
    let box_constructor_hits = hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&box_constructor)),
    );
    assert_hit_contains(&box_constructor_hits, "new Structure.Box[Int](1)");
    assert_no_hit_contains(&box_constructor_hits, "new Structure.Box[Int](1, 2)");

    let leaf = definition(&analyzer, "model.Structure$.Deep$.Leaf");
    let leaf_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&leaf)));
    for expected in [
        "Option.empty[Structure.Deep.Leaf]",
        "Option.empty[Schema.Deep.Leaf]",
        "Option.empty[model.Structure.Deep.Leaf]",
    ] {
        assert_hit_contains(&leaf_hits, expected);
    }
    assert!(
        leaf_hits
            .iter()
            .all(|hit| hit.file.rel_path() != "decoy/Use.scala"),
        "multi-level stable type leaked to decoy: {leaf_hits:#?}"
    );
}

#[test]
fn scala_usage_finder_applies_compilation_unit_import_precedence() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "app/Shared.scala",
            "package app\nobject Shared { def make(): Int = 0 }\n",
        ),
        (
            "left/Shared.scala",
            "package left\nobject Shared { def make(): Int = 1 }\n",
        ),
        (
            "app/WildcardWins.scala",
            "package app\nimport left._\nobject WildcardWins { val call = Shared.make() }\n",
        ),
    ]);
    let left = definition(&analyzer, "left.Shared$.make");
    let left_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&left)));
    assert!(
        left_hits
            .iter()
            .any(|hit| hit.file.rel_path() == "app/WildcardWins.scala"),
        "wildcard import should beat another file in the same package: {left_hits:#?}"
    );
    let package = definition(&analyzer, "app.Shared$.make");
    let package_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&package)));
    assert!(
        package_hits
            .iter()
            .all(|hit| hit.file.rel_path() != "app/WildcardWins.scala"),
        "same-package declaration from another file must lose to wildcard import: {package_hits:#?}"
    );

    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "left/Shared.scala",
            "package left\nobject Shared { def make(): Int = 1 }\n",
        ),
        (
            "app/LocalWins.scala",
            "package app\nimport left.Shared\nobject Shared { def make(): Int = 2 }\nobject LocalWins { val call = Shared.make() }\n",
        ),
    ]);
    let local = definition(&analyzer, "app.Shared$.make");
    let local_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&local)));
    assert_hit_contains(&local_hits, "object LocalWins { val call = Shared.make() }");
    let imported = definition(&analyzer, "left.Shared$.make");
    let imported_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&imported)));
    assert_no_hit_contains(
        &imported_hits,
        "object LocalWins { val call = Shared.make() }",
    );
}

#[test]
fn scala_usage_finder_keeps_companion_bare_field_owners_exact() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "app/CompanionFields.scala",
        r#"package app
class Obj {
  val field: Int = 1
  def classRead: Int = field
}
object Obj {
  val field: Int = 2
  def objectRead: Int = field
}
object Sibling {
  val field: Int = 3
  def siblingRead: Int = field
}
"#,
    )]);
    let object_field = definition(&analyzer, "app.Obj$.field");
    let object_hits = hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&object_field)),
    );
    assert!(
        object_hits
            .iter()
            .any(|hit| hit.enclosing.fq_name() == "app.Obj$.objectRead"),
        "object bare read should resolve to the exact object field: {object_hits:#?}"
    );
    for enclosing in ["app.Obj.classRead", "app.Sibling$.siblingRead"] {
        assert_no_hit_in_enclosing(&object_hits, enclosing);
    }

    let class_field = definition(&analyzer, "app.Obj.field");
    let class_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&class_field)));
    assert!(
        class_hits
            .iter()
            .any(|hit| hit.enclosing.fq_name() == "app.Obj.classRead"),
        "class bare read should resolve to the exact class field: {class_hits:#?}"
    );
    assert_no_hit_in_enclosing(&class_hits, "app.Obj$.objectRead");
}

#[test]
fn scala_usage_finder_resolves_outer_stable_fields_in_nested_and_anonymous_scopes() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "app/Container.scala",
        r#"
package app

class Service { def run(): Int = 1 }
class OtherService { def run(): Int = 2 }

class Container(val service: Service) {
  class Nested {
    val nestedRead = service.run()
    val explicitOuterRead = Container.this.service.run()
  }

  val anonymous = new Runnable {
    def run(): Unit = {
      val anonymousRead = service.run()
    }
  }

  def shadowed(service: OtherService): Int = service.run()
  def localShadow(): Int = {
    val service = new OtherService
    service.run()
  }
}
"#,
    )]);

    let service = definition(&analyzer, "app.Container.service");
    let service_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&service)));
    assert_hit_contains(&service_hits, "val nestedRead = service.run()");
    assert_hit_contains(&service_hits, "Container.this.service.run()");
    assert_hit_contains(&service_hits, "val anonymousRead = service.run()");
    assert_no_hit_contains(&service_hits, "def shadowed(service: OtherService)");
    assert_no_hit_contains(&service_hits, "val service = new OtherService");
}

#[test]
fn scala_usage_finder_resolves_exact_structured_field_chains() {
    let consumer = r#"package app

import model.{AliasOnly, Child, Middle, Owners, Stable}

object Use {
  def typed(middle: Middle): Int = middle.leaf.token // positive-typed-chain
  def inherited(child: Child): Int = child.inherited.leaf.token // positive-inherited-selection
  def stable: Int = Stable.middle.leaf.token // positive-stable-chain
  def nested: Int = {
    val state = new Owners.State(1)
    state.maximumHeapSize // positive-qualified-nested-constructor
  }
  def localShadow(middle: other.Middle): Int = middle.leaf.token // negative-local-shadow
  def unrelated(middle: other.Middle): Int = middle.leaf.token // negative-unrelated-owner
  def ambiguous(owner: dup.Owner): Int = owner.value // negative-ambiguous-owner
  def aliasIsNotATerm: Any = AliasOnly.Value // negative-type-alias-term
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "model/Fields.scala",
            r#"package model

class Leaf(val token: Int)
class Middle(val leaf: Leaf)
class Base(val inherited: Middle)
class Child extends Base(new Middle(new Leaf(1))) {
  def bare: Int = inherited.leaf.token // positive-inherited-bare
  def shadow(inherited: other.Middle): Int = inherited.leaf.token // negative-inherited-shadow
}
object Stable { val middle: Middle = new Middle(new Leaf(2)) }
object Owners { final class State(var maximumHeapSize: Int) }
object AliasOnly { type Value = Int }
"#,
        ),
        (
            "other/Fields.scala",
            r#"package other
class Leaf(val token: Int)
class Middle(val leaf: Leaf)
"#,
        ),
        (
            "dup/First.scala",
            "package dup\nclass Owner(val value: Int)\n",
        ),
        (
            "dup/Second.scala",
            "package dup\nclass Owner(val value: Int)\n",
        ),
        ("app/Use.scala", consumer),
    ]);

    let leaf = definition(&analyzer, "model.Middle.leaf");
    let leaf_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&leaf)));
    for expected in [
        "positive-typed-chain",
        "positive-inherited-selection",
        "positive-stable-chain",
        "positive-inherited-bare",
    ] {
        assert_hit_contains(&leaf_hits, expected);
    }
    for rejected in [
        "negative-local-shadow",
        "negative-unrelated-owner",
        "negative-inherited-shadow",
    ] {
        assert_no_hit_contains(&leaf_hits, rejected);
    }

    let token = definition(&analyzer, "model.Leaf.token");
    let token_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&token)));
    for expected in [
        "positive-typed-chain",
        "positive-inherited-selection",
        "positive-stable-chain",
        "positive-inherited-bare",
    ] {
        assert_hit_contains(&token_hits, expected);
    }
    assert_no_hit_contains(&token_hits, "negative-local-shadow");

    let inherited = definition(&analyzer, "model.Base.inherited");
    let inherited_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&inherited)));
    assert_hit_contains(&inherited_hits, "positive-inherited-selection");
    assert_hit_contains(&inherited_hits, "positive-inherited-bare");
    assert_no_hit_contains(&inherited_hits, "negative-inherited-shadow");

    let maximum_heap_size = definition(&analyzer, "model.Owners$.State.maximumHeapSize");
    let state_hits = hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&maximum_heap_size)),
    );
    assert_hit_contains(&state_hits, "positive-qualified-nested-constructor");

    let ambiguous = definition(&analyzer, "dup.Owner.value");
    let ambiguous_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&ambiguous)));
    assert_no_hit_contains(&ambiguous_hits, "negative-ambiguous-owner");

    let alias = definition(&analyzer, "model.AliasOnly$.Value");
    let alias_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&alias)));
    assert_no_hit_contains(&alias_hits, "negative-type-alias-term");
}

#[test]
fn scala_usage_finder_resolves_lexical_nested_state_field_in_local_function() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "app/ClusterReceptionist.scala",
            r#"package app
class Registry { def read: Int = 1 }
class State(val registry: other.Registry)
object ClusterReceptionist {
  final case class State(registry: Registry)
  def behavior(state: State): Int = {
    def onCommand(): Int = state.registry.read // positive-nested-state-field
    onCommand()
  }
  def decoy(state: app.State): Int = state.registry.read // negative-package-state
}
"#,
        ),
        (
            "other/Registry.scala",
            "package other\nclass Registry { def read: Int = 2 }\n",
        ),
    ]);

    let registry = definition(&analyzer, "app.ClusterReceptionist$.State.registry");
    assert_eq!(
        analyzer.parent_of(&registry).map(|owner| owner.fq_name()),
        Some("app.ClusterReceptionist$.State".to_string())
    );
    let registry_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&registry)));
    assert_hit_contains(&registry_hits, "positive-nested-state-field");
    assert_no_hit_contains(&registry_hits, "negative-package-state");
}

#[test]
fn scala_usage_finder_resolves_inherited_field_through_sequential_package_parent() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "impl/IndexedStepperBase.scala",
            r#"package scala.collection.convert
package impl
abstract class IndexedStepperBase[Sub, Semi <: Sub](protected var i0: Int)
"#,
        ),
        (
            "impl/ArrayStepper.scala",
            r#"package scala.collection.convert
package impl
trait AnyStepper[A]
class ObjectArrayStepper[A](start: Int)
  extends IndexedStepperBase[AnyStepper[A], ObjectArrayStepper[A]](start)
    with AnyStepper[A] {
  def nextStep(): Int = { val j = i0; i0 += 1; j } // positive-inherited-i0
  def shadow(i0: Int): Int = i0 // negative-local-i0
}
class Unrelated(protected var i0: Int) {
  def read: Int = i0 // negative-unrelated-i0
}
"#,
        ),
    ]);

    let i0 = definition(
        &analyzer,
        "scala.collection.convert.impl.IndexedStepperBase.i0",
    );
    assert_eq!(
        analyzer.parent_of(&i0).map(|owner| owner.fq_name()),
        Some("scala.collection.convert.impl.IndexedStepperBase".to_string())
    );
    let i0_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&i0)));
    assert_hit_contains(&i0_hits, "positive-inherited-i0");
    assert_no_hit_contains(&i0_hits, "negative-local-i0");
    assert_no_hit_contains(&i0_hits, "negative-unrelated-i0");
}

#[test]
fn scala_usage_finder_uses_parser_active_enclosing_package_for_constructor() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "scala/collection/ArrayOps.scala",
            "package scala.collection\nclass ArrayOps(value: Int)\n",
        ),
        (
            "scala/collection/immutable/ArraySeq.scala",
            r#"package scala.collection
package immutable
object ArraySeq {
  val tail = new ArrayOps(1) // positive-enclosing-package
}
"#,
        ),
        (
            "scala/collection/immutable/Shadow.scala",
            r#"package scala.collection
package immutable
object Shadow {
  class ArrayOps(value: Int)
  val value = new ArrayOps(2) // negative-inner-package
}
"#,
        ),
        (
            "other/ArrayOps.scala",
            "package other\nclass ArrayOps(value: Int)\n",
        ),
        (
            "scala/collection/immutable/Imported.scala",
            r#"package scala.collection
package immutable
import other.ArrayOps
object Imported { val value = new ArrayOps(3) } // negative-explicit-import
"#,
        ),
        (
            "dotted/Use.scala",
            r#"package scala.collection.immutable
object Dotted { val value = new ArrayOps(4) } // negative-dotted-parent
"#,
        ),
        (
            "braced/Use.scala",
            r#"package scala.collection {
  package hidden { object Hidden { val value = new ArrayOps(5) } } // positive-braced-child
}
package sibling { object Sibling { val value = new ArrayOps(6) } } // negative-braced-sibling
"#,
        ),
    ]);

    let constructor = definition(&analyzer, "scala.collection.ArrayOps.ArrayOps");
    let constructor_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&constructor)));
    assert_hit_contains(&constructor_hits, "positive-enclosing-package");
    assert_hit_contains(&constructor_hits, "positive-braced-child");
    for marker in [
        "negative-inner-package",
        "negative-explicit-import",
        "negative-dotted-parent",
        "negative-braced-sibling",
    ] {
        assert_no_hit_contains(&constructor_hits, marker);
    }

    let (_project, ambiguous) = scala_analyzer_with_files(&[
        (
            "left/ArrayOps.scala",
            "package scala.collection\nclass ArrayOps(value: Int)\n",
        ),
        (
            "right/ArrayOps.scala",
            "package scala.collection\nclass ArrayOps(value: Int)\n",
        ),
        (
            "use/Use.scala",
            r#"package scala.collection
package immutable
object Use { val value = new ArrayOps(1) } // negative-ambiguous-package
"#,
        ),
    ]);
    let ambiguous_constructor = definition(&ambiguous, "scala.collection.ArrayOps.ArrayOps");
    let ambiguous_hits = hits(
        UsageFinder::new()
            .find_usages_default(&ambiguous, std::slice::from_ref(&ambiguous_constructor)),
    );
    assert_no_hit_contains(&ambiguous_hits, "negative-ambiguous-package");
}

#[test]
fn scala_usage_finder_resolves_unique_unapplied_companion_apply_values() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "model/Token.scala",
            r#"package model
case class Token(value: Int)
class Manual(value: Int)
object Manual {
  def apply(value: Int): Manual = new Manual(value)
  def apply(value: String): Manual = new Manual(value.length)
}
"#,
        ),
        (
            "other/Token.scala",
            "package other\ncase class Token(value: Int)\n",
        ),
        (
            "app/Use.scala",
            r#"package app
import model.{Manual, Token}
object Use {
  private def accept(value: Int, function: Int => Token): Token = function(value)
  private def wrong(function: (Int, Int) => Token): Token = function(1, 2)
  private def keep(value: Any): Any = value
  val contextual = accept(1, Token) // positive-contextual-method-value
  val unavailable = Option(1).map(Token) // positive-unique-method-value
  val wrongArity = wrong(Token) // negative-wrong-context-arity
  val nonFunction = keep(Token) // negative-known-non-function-parameter
  val overloaded = Option(1).map(Manual) // negative-overloaded-apply
  def local(Token: Int => model.Token): model.Token = Option(1).map(Token).get
    // negative-local-term
}
"#,
        ),
        (
            "app/Imported.scala",
            r#"package app
import other.Token
object Imported { val value = Option(1).map(Token) } // negative-unrelated-import
"#,
        ),
    ]);

    let token = definition(&analyzer, "model.Token");
    let token_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&token)));
    assert_hit_contains(&token_hits, "positive-contextual-method-value");
    assert_hit_contains(&token_hits, "positive-unique-method-value");
    for marker in [
        "negative-wrong-context-arity",
        "negative-known-non-function-parameter",
        "negative-overloaded-apply",
        "negative-local-term",
        "negative-unrelated-import",
    ] {
        assert_no_hit_contains(&token_hits, marker);
    }
}

#[test]
fn scala_usage_finder_resolves_same_file_companion_wildcard_nested_type() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        ("kyo/Chunk.scala", "package kyo\nclass Chunk[+A]\n"),
        (
            "p/Clean.scala",
            "package p\nclass A\n  class B // clean-indented-top-level\n",
        ),
        (
            "kyo/Batch.scala",
            r#"package kyo
object Batch:
    import internal.*
    def run[A, S](v: A): A =
        type Item = A | Int
        def expand(items: List[Item]) =
            Kyo.foreach(items) {
                case ToExpand[A @unchecked, S @unchecked](seq: Seq[Any], cont) =>
                    Kyo.foreach(seq)(v => v)
                case item => item
            }
        expand(Nil)
    end run
    object internal:
        case class Call[A](v: A) // negative-nested-package-wildcard
    end internal
end Batch
"#,
        ),
        (
            "kyo/ai/Context.scala",
            r#"package kyo.ai
import Context.*
import kyo.*
case class Context(calls: Chunk[Call]):
    def assistantMessage(calls: Chunk[Call]): Context = this // positive-context-call
end Context
object Context:
    case class Call(id: String)
end Context
"#,
        ),
    ]);

    assert!(
        analyzer
            .top_level_declarations(&_project.file("kyo/Batch.scala"))
            .iter()
            .all(|unit| unit.fq_name() != "kyo.Call"),
        "structurally nested Batch.internal.Call must not be collected as package-level kyo.Call"
    );
    assert!(
        analyzer
            .get_definitions("kyo.Batch$.internal$.Call")
            .iter()
            .any(|unit| unit.source().rel_path() == _project.file("kyo/Batch.scala").rel_path()),
        "recovered nested Call must retain its exact Batch.internal owner"
    );
    assert!(
        analyzer
            .top_level_declarations(&_project.file("p/Clean.scala"))
            .iter()
            .any(|unit| unit.fq_name() == "p.B"),
        "indentation alone must not invent recovery ownership"
    );
    assert!(
        analyzer.get_definitions("p.A.B").is_empty(),
        "clean root declarations must not be nested without structured recovery evidence"
    );

    let call = definition(&analyzer, "kyo.ai.Context$.Call");
    let call_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&call)));
    assert_hit_contains(&call_hits, "positive-context-call");
    assert_no_hit_contains(&call_hits, "negative-nested-package-wildcard");
}

#[test]
fn scala_usage_finder_resolves_infix_extractor_object_identity() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "app/Extractors.scala",
            r#"
package app

object Pair {
  def unapply(value: (String, String)): Option[(String, String)] = Some(value)
}

object Use {
  def extract(value: (String, String)): String = value match {
    case left Pair right => left + right
    case _ => ""
  }
}
"#,
        ),
        (
            "other/Extractors.scala",
            r#"
package other

object Pair {
  def unapply(value: (String, String)): Option[(String, String)] = Some(value)
}

object Use {
  def extract(value: (String, String)): String = value match {
    case left Pair right => left + right
    case _ => ""
  }
}
"#,
        ),
    ]);

    let pair = definition(&analyzer, "app.Pair$");
    let pair_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&pair)));
    assert_hit_contains(&pair_hits, "case left Pair right");
    assert!(
        pair_hits
            .iter()
            .all(|hit| hit.file.rel_path() != "other/Extractors.scala"),
        "unrelated infix extractor leaked: {pair_hits:#?}"
    );
}

#[test]
fn scala_usage_finder_resolves_modified_constructor_parameter_as_inherited_member() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "app/Services.scala",
            r#"
package app

class Service { def run(): Int = 1 }

class Base(protected val service: Service)

class Child(provided: Service) extends Base(provided) {
  val inheritedRead = this.service.run()
  class Nested {
    val nestedInheritedRead = service.run()
  }
}
"#,
        ),
        (
            "other/Services.scala",
            r#"
package other

class Service { def run(): Int = 1 }
class Base(protected val service: Service)
class Child(service: Service) extends Base(service) {
  val inheritedRead = this.service.run()
}
"#,
        ),
    ]);

    let service = definition(&analyzer, "app.Base.service");
    let service_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&service)));
    assert_hit_contains(&service_hits, "val inheritedRead = this.service.run()");
    assert_hit_contains(&service_hits, "val nestedInheritedRead = service.run()");
    assert!(
        service_hits
            .iter()
            .all(|hit| hit.file.rel_path() != "other/Services.scala"),
        "unrelated inherited constructor parameter leaked: {service_hits:#?}"
    );
}

#[test]
fn scala_usage_finder_applies_compound_callable_shapes_conservatively() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "app/Unary.scala",
            r#"
package app

def dispatch(value: Int): Int = value
"#,
        ),
        (
            "app/Binary.scala",
            r#"
package app

def dispatch(value: Int, enabled: Boolean): Int = value
"#,
        ),
        (
            "app/Api.scala",
            r#"
package app

class Api {
  def defaulted(value: Int, label: String = "default"): Int = value
  def gather(values: Int*): Int = values.size
  def curried(value: Int)(label: String): Int = value
  def later(value: Int): Int = value
}

object Use {
  def exercise(api: Api): Unit = {
    dispatch(1)
    dispatch(1, true)
    dispatch()
    dispatch(1, true, false)

    api.defaulted(1)
    api.defaulted(1, "named")
    api.defaulted()
    api.defaulted(1, "named", "extra")

    api.gather()
    api.gather(1, 2, 3)

    api.curried(1)("named")
    api.curried()("missing")
    api.curried(1)("too", "many")

    val unapplied: Int => Int = api.later
    api.later(1)
    api.later()
    api.later(1, 2)
  }
}
"#,
        ),
        (
            "other/Unary.scala",
            r#"
package other

def dispatch(value: Int): Int = value
"#,
        ),
        (
            "other/Binary.scala",
            r#"
package other

def dispatch(value: Int, enabled: Boolean): Int = value
"#,
        ),
        (
            "other/Api.scala",
            r#"
package other

class Api {
  def defaulted(value: Int, label: String = "default"): Int = value
  def gather(values: Int*): Int = values.size
  def curried(value: Int)(label: String): Int = value
  def later(value: Int): Int = value
}

object Use {
  def exercise(api: Api): Unit = {
    dispatch(1)
    api.defaulted(1)
    api.gather(1)
    api.curried(1)("other")
    val unapplied: Int => Int = api.later
  }
}
"#,
        ),
    ]);

    let mut dispatches = analyzer.get_definitions("app.dispatch");
    dispatches.sort_by_key(|unit| analyzer.signatures(unit).join("\n"));
    assert_eq!(dispatches.len(), 2, "expected both dispatch overloads");
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = UsageFinder::new().find_usages_default(&analyzer, &dispatches)
    else {
        panic!("expected dispatch usage success");
    };
    for dispatch in &dispatches {
        let signature = analyzer.signatures(dispatch).join("\n");
        let bucket = hits_by_overload
            .get(dispatch)
            .unwrap_or_else(|| panic!("missing dispatch bucket for {signature}"));
        let bucket = bucket.iter().cloned().collect::<Vec<_>>();
        if signature.contains("enabled: Boolean") {
            assert_hit_contains(&bucket, "dispatch(1, true)");
            assert_no_hit_contains(&bucket, "dispatch(1)");
        } else {
            assert_hit_contains(&bucket, "dispatch(1)");
            assert_no_hit_contains(&bucket, "dispatch(1, true)");
        }
        assert_no_hit_contains(&bucket, "dispatch()");
        assert_no_hit_contains(&bucket, "dispatch(1, true, false)");
        assert!(
            bucket
                .iter()
                .all(|hit| !hit.file.rel_path().starts_with("other/")),
            "unrelated overload owner leaked: {bucket:#?}"
        );
    }

    for (target, expected_hits, rejected_hits) in [
        (
            "app.Api.defaulted",
            vec!["api.defaulted(1)", "api.defaulted(1, \"named\")"],
            vec!["api.defaulted()", "api.defaulted(1, \"named\", \"extra\")"],
        ),
        (
            "app.Api.gather",
            vec!["api.gather()", "api.gather(1, 2, 3)"],
            vec![],
        ),
        (
            "app.Api.curried",
            vec!["api.curried(1)(\"named\")"],
            vec![
                "api.curried()(\"missing\")",
                "api.curried(1)(\"too\", \"many\")",
            ],
        ),
        (
            "app.Api.later",
            vec!["api.later", "api.later(1)"],
            vec!["api.later()", "api.later(1, 2)"],
        ),
    ] {
        let target = definition(&analyzer, target);
        let target_hits =
            hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));
        for expected in expected_hits {
            assert_hit_contains(&target_hits, expected);
        }
        for rejected in rejected_hits {
            assert_no_hit_contains(&target_hits, rejected);
        }
        assert!(
            target_hits
                .iter()
                .all(|hit| hit.file.rel_path() != "other/Api.scala"),
            "unrelated callable owner leaked for {target:?}: {target_hits:#?}"
        );
    }
}

#[test]
fn scala_usage_finder_resolves_generic_lexical_constructors_and_stable_paths() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "model/Flags.scala",
            r#"package model
object Flags {
  val Enabled: Int = 1
  case object Nested
}
"#,
        ),
        (
            "decoy/Flags.scala",
            r#"package decoy
object Flags {
  val Enabled: Int = 2
  case object Nested
}
"#,
        ),
        (
            "app/Use.scala",
            r#"package app

import model.Flags

object Use {
  class Generic[A](value: A)

  def validGeneric = new Generic[Int](1)
  def wrongGenericArity = new Generic[Int]()
  def localConstructorRoot(Generic: LocalFactory) = new Generic[Int](1)
  def directField: Int = Flags.Enabled
  def stableField(value: Any): Int = value match {
    case Flags.Enabled => 1
    case model.Flags.Enabled => 2
    case _ => 0
  }
  def stableObject(value: Any): Int = value match {
    case Flags.Nested => 1
    case model.Flags.Nested => 2
    case _ => 0
  }
  def localRootIsNotImported(Flags: LocalFlags): Int = Flags.Enabled
  def decoyField(value: Any): Int = value match {
    case decoy.Flags.Enabled => 1
    case _ => 0
  }
  def decoyObject(value: Any): Int = value match {
    case decoy.Flags.Nested => 1
    case _ => 0
  }
}

class LocalFlags { val Enabled: Int = 2 }
class LocalFactory
"#,
        ),
    ]);

    let constructor = definition(&analyzer, "app.Use$.Generic.Generic");
    let constructor_hits = hits(UsageFinder::new().find_usages_default(&analyzer, &[constructor]));
    assert_hit_contains(&constructor_hits, "new Generic[Int](1)");
    assert_hit_contains(&constructor_hits, "Generic: LocalFactory");
    assert_no_hit_contains(&constructor_hits, "new Generic[Int]()");

    let enabled = definition(&analyzer, "model.Flags$.Enabled");
    let enabled_hits = hits(UsageFinder::new().find_usages_default(&analyzer, &[enabled]));
    for expected in [
        "def directField: Int = Flags.Enabled",
        "case Flags.Enabled => 1",
        "case model.Flags.Enabled => 2",
    ] {
        assert_hit_contains(&enabled_hits, expected);
    }
    assert_no_hit_contains(&enabled_hits, "Flags: LocalFlags");
    assert_no_hit_contains(&enabled_hits, "case decoy.Flags.Enabled");

    let nested = definition(&analyzer, "model.Flags$.Nested$");
    let nested_hits = hits(UsageFinder::new().find_usages_default(&analyzer, &[nested]));
    assert_hit_contains(&nested_hits, "case Flags.Nested => 1");
    assert_hit_contains(&nested_hits, "case model.Flags.Nested => 2");
    assert_no_hit_contains(&nested_hits, "case decoy.Flags.Nested");
}

#[test]
fn scala_usage_finder_matches_all_same_file_overloads_and_curried_constructor_lists() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "app/Calls.scala",
        r#"package app
class Api {
  def route(value: Int, label: String): Int = value
  def route(value: Int): Int = value
  def flip(value: Int): Int = value
  def flip(value: Int, label: String): Int = value
}
class Curried(value: Int)(label: String = "default")
object Use {
  def calls(api: Api): Unit = {
    api.route(1)
    api.route(1, "two")
    api.route()
    api.route(1, "two", "three")
    val routePartial: Int => Int = api.route
    api.flip(1)
    api.flip(1, "two")
    api.flip()
    api.flip(1, "two", "three")
    val flipPartial: Int => Int = api.flip
    new Curried(1)()
    new Curried()("missing")
    new Curried(1)("too", "many")
  }
}
"#,
    )]);
    for method in ["route", "flip"] {
        let target = definition(&analyzer, &format!("app.Api.{method}"));
        let method_hits =
            hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));
        assert_hit_contains(&method_hits, &format!("api.{method}(1)"));
        assert_hit_contains(&method_hits, &format!("api.{method}(1, \"two\")"));
        assert_no_hit_contains(&method_hits, &format!("api.{method}()"));
        assert_no_hit_contains(
            &method_hits,
            &format!("api.{method}(1, \"two\", \"three\")"),
        );
        assert_no_hit_contains(&method_hits, &format!("val {method}Partial"));
    }
    let constructor = definition(&analyzer, "app.Curried.Curried");
    let constructor_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&constructor)));
    assert_hit_contains(&constructor_hits, "new Curried(1)()");
    assert_no_hit_contains(&constructor_hits, "new Curried()(\"missing\")");
    assert_no_hit_contains(&constructor_hits, "new Curried(1)(\"too\", \"many\")");
}

#[test]
fn scala_usage_finder_omits_only_trailing_contextual_parameter_lists() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "app/Calls.scala",
        r#"package app
trait Context
object Scope {
  def run[A](value: A)(using Context): A = value
  def run[A](parallelism: Int)(value: A)(using Context): A = value
}
object Required {
  def run(parallelism: Int)(value: Int)(using Context): Int = value
}
object Use {
  given Context = new Context {}
  val contextual = Scope.run { 1 }
  val contextualAfterTwoExplicitLists = Scope.run(2) { 1 }
  val ambiguousEta = Scope.run
  val missingRequiredExplicitList = Required.run(2)
  val completeRequiredExplicitList = Required.run(2)(1)
}
"#,
    )]);

    let scope_run = definition(&analyzer, "app.Scope$.run");
    let scope_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&scope_run)));
    assert_hit_contains(&scope_hits, "Scope.run { 1 }");
    assert_hit_contains(&scope_hits, "Scope.run(2) { 1 }");
    assert_no_hit_contains(&scope_hits, "val ambiguousEta = Scope.run");

    let required_run = definition(&analyzer, "app.Required$.run");
    let required_hits = hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&required_run)),
    );
    assert_no_hit_in_enclosing(&required_hits, "app.Use.missingRequiredExplicitList");
    assert_hit_contains(&required_hits, "Required.run(2)(1)");
}

#[test]
fn scala_usage_finder_routes_chained_wildcard_contextual_apply() {
    let consumer_source = r#"package dotty.tools.dotc.typer
import dotty.tools.dotc.core.*
import Annotations.*

object Typer {
  given Context = new Context {}
  val annotation = Annotation(1, 2, 3)
  val wrongArity = Annotation(1, 2)
}
"#;
    let (project, analyzer) = scala_analyzer_with_files(&[
        (
            "dotty/tools/dotc/core/Annotations.scala",
            r#"package dotty.tools.dotc.core
trait Context
object Annotations {
  object Annotation {
    def apply(cls: Int, arg: Int, span: Int)(using Context): Int = cls
    def apply(cls: String, arg: Int, span: Int)(using Context): Int = arg
  }
}
"#,
        ),
        ("dotty/tools/dotc/typer/Typer.scala", consumer_source),
    ]);
    let target = definition(
        &analyzer,
        "dotty.tools.dotc.core.Annotations$.Annotation$.apply",
    );
    let result = UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target));
    let hits = hits(result);

    assert_hit_line(&hits, line_of(consumer_source, "Annotation(1, 2, 3)"));
    assert_no_hit_line(&hits, line_of(consumer_source, "Annotation(1, 2)"));
    assert!(
        hits.iter()
            .any(|hit| { hit.file == project.file("dotty/tools/dotc/typer/Typer.scala") }),
        "default candidate discovery must route the chained wildcard consumer"
    );
}

#[test]
fn scala_usage_finder_keeps_sibling_wildcard_import_scopes_exact() {
    let consumer_source = r#"package app

object LeftConsumer {
  import api.LeftFactories.*
  val value = Factory(1)
}

object RightConsumer {
  import api.RightFactories.*
  val value = Factory(2)
}
"#;
    let (project, analyzer) = scala_analyzer_with_files(&[
        (
            "api/Factories.scala",
            r#"package api
object LeftFactories {
  object Factory { def apply(value: Int): Int = value }
}
object RightFactories {
  object Factory { def apply(value: Int): Int = value }
}
"#,
        ),
        ("app/Consumers.scala", consumer_source),
    ]);
    let consumer = project.file("app/Consumers.scala");

    for (target_fqn, expected_line, rejected_line) in [
        (
            "api.LeftFactories$.Factory$.apply",
            "val value = Factory(1)",
            "val value = Factory(2)",
        ),
        (
            "api.RightFactories$.Factory$.apply",
            "val value = Factory(2)",
            "val value = Factory(1)",
        ),
    ] {
        let target = definition(&analyzer, target_fqn);
        let query = UsageFinder::new().query(&analyzer, std::slice::from_ref(&target), 100, 100);
        assert!(
            query.candidate_files.contains(&consumer),
            "default candidate discovery must route {target_fqn} to the consumer"
        );
        let target_hits = hits(query.result);
        assert_hit_line(&target_hits, line_of(consumer_source, expected_line));
        assert_no_hit_line(&target_hits, line_of(consumer_source, rejected_line));
    }
}

#[test]
fn scala_usage_finder_merges_case_class_and_explicit_companion_apply_shapes() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "akka/util/Timeout.scala",
        r#"package akka.util
case class Timeout(duration: Long)
object Timeout {
  def apply(length: Long, unit: String): Timeout = new Timeout(length)
}
object Use {
  val generated = Timeout(1)
  val explicit = Timeout(1, "second")
  val tooFew = Timeout()
  val tooMany = Timeout(1, "second", "extra")
}
"#,
    )]);
    let target = definition(&analyzer, "akka.util.Timeout$.apply");
    let target_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));

    assert_hit_contains(&target_hits, "Timeout(1)");
    assert_hit_contains(&target_hits, "Timeout(1, \"second\")");
    assert_no_hit_contains(&target_hits, "Timeout()");
    assert_no_hit_contains(&target_hits, "Timeout(1, \"second\", \"extra\")");
}

#[test]
fn scala_usage_finder_keeps_overload_shape_receiver_and_return_facts_aligned() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "app/Aligned.scala",
        r#"package app
class A { def run(): Int = 1 }
class B { def run(): Int = 2 }
object Factory {
  def make(value: Int): A = new A
  def make(value: Int, label: String): B = new B
}
object Extensions {
  extension (value: A) def tag(number: Int): Int = number
  extension (value: B) def tag(number: Int, label: String): Int = number
}
object Use {
  import Extensions._
  def returnA(): Int = Factory.make(1).run()
  def returnB(): Int = Factory.make(1, "b").run()
  def extensionA(value: A): Int = value.tag(1)
  def extensionB(value: B): Int = value.tag(1, "b")
  def wrongShapeA(value: A): Int = value.tag(1, "bad")
  def wrongShapeB(value: B): Int = value.tag(1)
  def unappliedA(value: A) = value.tag
}
"#,
    )]);
    let a_run = definition(&analyzer, "app.A.run");
    let a_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&a_run)));
    assert_hit_contains(&a_hits, "def returnA(): Int = Factory.make(1).run()");
    assert_no_hit_contains(&a_hits, "def returnB(): Int = Factory.make(1, \"b\").run()");
    let b_run = definition(&analyzer, "app.B.run");
    let b_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&b_run)));
    assert_hit_contains(&b_hits, "def returnB(): Int = Factory.make(1, \"b\").run()");
    assert_no_hit_contains(&b_hits, "def returnA(): Int = Factory.make(1).run()");

    let tag = definition(&analyzer, "app.Extensions$.tag");
    let tag_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&tag)));
    assert_hit_contains(&tag_hits, "def extensionA(value: A): Int = value.tag(1)");
    assert_hit_contains(
        &tag_hits,
        "def extensionB(value: B): Int = value.tag(1, \"b\")",
    );
    assert_no_hit_contains(&tag_hits, "def wrongShapeA");
    assert_no_hit_contains(&tag_hits, "def wrongShapeB");
    assert_no_hit_contains(&tag_hits, "def unappliedA");
}

#[test]
fn scala_usage_finder_fails_closed_for_ambiguous_declaration_type_paths() {
    let consumer_source = r#"package app
import left._
import right._

object Factory {
  def make(): A = ???
  def makeNested(): A.Nested = ???
  def makeProven(): proven.Service = ???
}

object Use {
  def call(): Int = Factory.make().run()
  def nestedCall(): Int = Factory.makeNested().run()
  def provenCall(): Int = Factory.makeProven().run()
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "A.scala",
            "class A { def run(): Int = 0; class Nested { def run(): Int = 0 } }\n",
        ),
        (
            "left/A.scala",
            "package left\nclass A { def run(): Int = 1; class Nested { def run(): Int = 1 } }\n",
        ),
        (
            "right/A.scala",
            "package right\nclass A { def run(): Int = 2; class Nested { def run(): Int = 2 } }\n",
        ),
        (
            "proven/Service.scala",
            "package proven\nclass Service { def run(): Int = 3 }\n",
        ),
        ("app/AmbiguousReturn.scala", consumer_source),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = ScalaUsageGraphStrategy::new();

    for run_fqn in ["A.run", "left.A.run", "right.A.run"] {
        let run = definition(&analyzer, run_fqn);
        let run_hits =
            hits(strategy.find_usages(&analyzer, std::slice::from_ref(&run), &candidates, 1000));
        assert_no_hit_contains(&run_hits, "Factory.make().run()");
    }
    for run_fqn in ["A.Nested.run", "left.A.Nested.run", "right.A.Nested.run"] {
        let run = definition(&analyzer, run_fqn);
        let run_hits =
            hits(strategy.find_usages(&analyzer, std::slice::from_ref(&run), &candidates, 1000));
        assert_no_hit_contains(&run_hits, "Factory.makeNested().run()");
    }
    let proven_run = definition(&analyzer, "proven.Service.run");
    let proven_hits = hits(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&proven_run),
        &candidates,
        1000,
    ));
    assert_hit_contains(&proven_hits, "Factory.makeProven().run()");
}

#[test]
fn scala_overload_query_preserves_exact_hit_buckets() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "app/Unary.scala",
            r#"
package app

def compute(value: Int): Int = value
"#,
        ),
        (
            "app/Binary.scala",
            r#"
package app

def compute(left: Int, right: Int): Int = left + right
"#,
        ),
        (
            "app/Caller.scala",
            r#"
package app

object Caller {
  val unary = compute(1)
  val binary = compute(1, 2)
  val unrelated = other.compute("no")
}
"#,
        ),
        (
            "other/Other.scala",
            r#"
package other

def compute(value: String): String = value
"#,
        ),
    ]);
    let mut overloads = analyzer.get_definitions("app.compute");
    overloads.sort_by_key(|unit| analyzer.signatures(unit).join("\n"));
    assert_eq!(overloads.len(), 2, "expected both compute overloads");

    let result = UsageFinder::new().find_usages_default(&analyzer, &overloads);
    let FuzzyResult::Success {
        hits_by_overload, ..
    } = result
    else {
        panic!("expected overload usage success");
    };
    assert_eq!(hits_by_overload.len(), 2, "one bucket per overload");
    for overload in &overloads {
        let signature = analyzer.signatures(overload).join("\n");
        let bucket = hits_by_overload
            .get(overload)
            .unwrap_or_else(|| panic!("missing bucket for {signature}"));
        assert_eq!(bucket.len(), 1, "wrong arity leaked into {signature}");
        let expected = if signature.contains("left: Int, right: Int") {
            "compute(1, 2)"
        } else {
            "compute(1)"
        };
        assert_hit_contains(&bucket.iter().cloned().collect::<Vec<_>>(), expected);
        assert!(
            bucket
                .iter()
                .all(|hit| !hit.snippet.contains("other.compute")),
            "unrelated same-name method leaked into {signature}: {bucket:#?}"
        );
    }

    let limited = UsageFinder::new().query(&analyzer, &overloads, 100, 1);
    assert!(
        matches!(
            limited.result,
            FuzzyResult::TooManyCallsites { limit: 1, .. }
        ),
        "multi-overload query must preserve the query-wide usage cap"
    );
}

#[test]
fn scala_inherited_class_method_usages_preserve_target_buckets_and_cap() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "app/Services.scala",
        r#"
package app

class UnaryBase {
  def execute(value: Int): Int = value
}

class BinaryBase {
  def execute(left: Int, right: Int): Int = left + right
}

class UnaryChild extends UnaryBase {
  val unary = execute(1)
}

class BinaryChild extends BinaryBase {
  val binary = execute(1, 2)
}
"#,
    )]);
    let targets = [
        definition(&analyzer, "app.UnaryBase.execute"),
        definition(&analyzer, "app.BinaryBase.execute"),
    ];

    let FuzzyResult::Success {
        hits_by_overload, ..
    } = UsageFinder::new().find_usages_default(&analyzer, &targets)
    else {
        panic!("expected inherited usage success");
    };
    for target in &targets {
        let signature = analyzer.signatures(target).join("\n");
        let bucket = hits_by_overload
            .get(target)
            .unwrap_or_else(|| panic!("missing bucket for {signature}"));
        assert_eq!(bucket.len(), 1, "same-name base leaked into {signature}");
        let expected = if signature.contains("left: Int, right: Int") {
            "execute(1, 2)"
        } else {
            "execute(1)"
        };
        assert_hit_contains(&bucket.iter().cloned().collect::<Vec<_>>(), expected);
    }

    let limited = UsageFinder::new().query(&analyzer, &targets, 100, 1);
    assert!(
        matches!(
            limited.result,
            FuzzyResult::TooManyCallsites { limit: 1, .. }
        ),
        "inherited multi-target query must preserve the query-wide usage cap"
    );
}

#[test]
fn scala_inherited_bare_members_use_exact_hierarchy_and_contextual_callable_shape() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "app/Bases.scala",
            r#"package app

trait ActorBase {
  def sender(): String = "base"
}

trait CallbackBase {
  def transform(value: Int): String = value.toString
  def transform(value: Int, suffix: String): String = value.toString + suffix
}

trait ConflictingActor {
  def sender(): String = "conflict"
}

trait ConflictingCallbacks {
  def transform(value: Int): String = "conflict"
}

trait OtherCallbacks {
  def transform(value: Int): String = "other"
}
"#,
        ),
        (
            "app/Consumers.scala",
            r#"package app

class GoodConsumer extends ActorBase with CallbackBase {
  def consume(seed: Int)(callback: Int => String): String = callback(seed)

  val inheritedCall = sender() // positive-inherited-call
  val inheritedMethodValue = consume(1)(transform) // positive-method-value
  val inheritedBinaryCall = transform(1, "!") // positive-binary-call
}

class TraitConflict extends ActorBase with ConflictingActor {
  val conflicted = sender() // negative-trait-conflict
}

class CallbackConflict extends CallbackBase with ConflictingCallbacks {
  def consume(callback: Int => String): String = callback(1)
  val conflicted = consume(transform) // negative-callback-conflict
}

class LocalShadow extends ActorBase with CallbackBase {
  def run(): String = {
    def sender(): String = "local"
    sender() // negative-local-shadow
  }

  def consume(callback: Int => String): String = callback(1)
  def callback(): String = {
    def transform(value: Int): String = "local"
    consume(transform) // negative-method-value-shadow
  }
}

class UnrelatedActor {
  def sender(): String = "unrelated"
  val value = sender() // negative-unrelated
}

class OtherOverride extends OtherCallbacks {
  override def transform(value: Int): String = "override"
  def consume(callback: Int => String): String = callback(1)
  val value = consume(transform) // negative-unrelated-override
}

class SenderOverride extends ActorBase {
  override def sender(): String = "override"
  val value = sender() // positive-related-override
}
"#,
        ),
    ]);

    let sender = definition(&analyzer, "app.ActorBase.sender");
    let sender_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&sender)));
    assert_hit_contains(&sender_hits, "sender() // positive-inherited-call");
    assert_hit_contains(&sender_hits, "sender() // positive-related-override");
    assert_no_hit_contains(&sender_hits, "negative-trait-conflict");
    assert_no_hit_contains(&sender_hits, "negative-local-shadow");
    assert_no_hit_contains(&sender_hits, "negative-unrelated");

    let sender_override = definition(&analyzer, "app.SenderOverride.sender");
    let override_hits = hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&sender_override)),
    );
    assert_hit_contains(&override_hits, "sender() // positive-related-override");
    assert_no_hit_contains(&override_hits, "positive-inherited-call");

    let transform = definition(&analyzer, "app.CallbackBase.transform");
    let transform_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&transform)));
    assert_hit_contains(
        &transform_hits,
        "consume(1)(transform) // positive-method-value",
    );
    assert_hit_contains(
        &transform_hits,
        "transform(1, \"!\") // positive-binary-call",
    );
    assert_no_hit_contains(&transform_hits, "negative-callback-conflict");
    assert_no_hit_contains(&transform_hits, "negative-method-value-shadow");
    assert_no_hit_contains(&transform_hits, "negative-unrelated-override");

    let limited = UsageFinder::new().query(&analyzer, &[transform], 100, 1);
    assert!(
        matches!(
            limited.result,
            FuzzyResult::TooManyCallsites { limit: 1, .. }
        ),
        "inherited bare-member overloads must preserve the query-wide cap"
    );
}

#[test]
fn scala_usage_scan_is_stack_safe_for_deep_lexical_scopes() {
    std::thread::Builder::new()
        .name("scala-deep-usage-scan".to_string())
        .stack_size(256 * 1024)
        .spawn(|| {
            let depth = 1_024;
            let mut source = String::from(
                "package app\n\nclass Deep {\n  def ping(): Unit = ()\n  def run(): Unit = ",
            );
            for _ in 0..depth {
                source.push_str("{\n");
            }
            source.push_str("ping() // positive-deep-scope\n");
            for _ in 0..depth {
                source.push_str("}\n");
            }
            source.push_str("}\n");

            let (_project, analyzer) =
                scala_analyzer_with_files(&[("app/Deep.scala", source.as_str())]);
            let target = definition(&analyzer, "app.Deep.ping");
            let hits = hits(
                UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
            );
            assert_hit_contains(&hits, "ping() // positive-deep-scope");
        })
        .expect("spawn deep Scala usage scan")
        .join()
        .expect("deep Scala usage scan must not overflow its small stack");
}

#[test]
fn scala_callable_arity_accepts_defaults_and_repeated_parameters() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "app/Api.scala",
            r#"
package app

class Base {
  def doTest(text: String, result: String, settings: String = "default"): Unit = ()
  def collect(head: String, rest: String*): Unit = ()
}

class Child extends Base {
  doTest("text", "result")
  doTest()
  doTest("one", "two", "three", "four")
  collect("one")
  collect("one", "two", "three")
}

object SbtScalaSdkData {
  def apply(version: Option[String], language: String = "Scala", jars: Int = 0, docs: Int = 0, sources: Int = 0): String = "sdk"
}

object Use {
  val sdk = SbtScalaSdkData(Some("3.3"))
  val missing = SbtScalaSdkData()
  val excessive = SbtScalaSdkData(Some("3.3"), "Scala", 1, 2, 3, 4)
}
"#,
        ),
        (
            "other/Api.scala",
            r#"
package other

class Base {
  def doTest(text: String, result: String): Unit = ()
  def collect(head: String, rest: String*): Unit = ()
}
class Child extends Base {
  doTest("other", "result")
  collect("other")
}
object SbtScalaSdkData {
  def apply(version: Option[String], language: String = "Other"): String = "sdk"
}
object Use { val sdk = SbtScalaSdkData(Some("other")) }
"#,
        ),
    ]);

    for (target, expected_hits) in [
        ("app.Base.doTest", vec!["doTest(\"text\", \"result\")"]),
        (
            "app.Base.collect",
            vec!["collect(\"one\")", "collect(\"one\", \"two\", \"three\")"],
        ),
        (
            "app.SbtScalaSdkData$.apply",
            vec!["SbtScalaSdkData(Some(\"3.3\"))"],
        ),
    ] {
        let target = definition(&analyzer, target);
        let hits =
            hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));
        for expected in expected_hits {
            assert_hit_contains(&hits, expected);
        }
        assert_no_hit_contains(&hits, "doTest()");
        assert_no_hit_contains(&hits, "doTest(\"one\", \"two\", \"three\", \"four\")");
        assert_no_hit_contains(&hits, "SbtScalaSdkData()");
        assert_no_hit_contains(
            &hits,
            "SbtScalaSdkData(Some(\"3.3\"), \"Scala\", 1, 2, 3, 4)",
        );
        assert!(
            hits.iter()
                .all(|hit| hit.file.rel_path() != "other/Api.scala"),
            "unrelated callable owner leaked for {target:?}: {hits:#?}"
        );
    }
}

#[test]
fn scala_companion_apply_and_infix_usages_preserve_exact_targets() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "scala/Int.scala",
            r#"
package scala

class Int {
  def -(other: Int): Int = this
  def <(other: Int): Boolean = false
}
"#,
        ),
        (
            "app/Factories.scala",
            r#"
package app

case class Box private (value: Int)

object Box {
  def apply(value: Int): Box = new Box(value)
}

object Factory {
  def apply(value: Int): Box = ???
}
"#,
        ),
        (
            "app/Use.scala",
            r#"
package app

object Use {
  val factory = Factory(1)
  val box = Box(2)
  val difference = 3 - 1
  val comparison = 3 < 4
}
"#,
        ),
        (
            "other/Factories.scala",
            r#"
package other

case class Box private (value: Int)

object Box {
  def apply(value: Int): Box = new Box(value)
}

object Factory {
  def apply(value: Int): Box = ???
}

object Use {
  val factory = Factory(1)
  val box = Box(2)
}
"#,
        ),
        (
            "other/Numbers.scala",
            r#"
package other

class Number {
  def -(other: Number): Number = this
  def <(other: Number): Boolean = false
}

object NumberUse {
  def difference(left: Number, right: Number): Number = left - right
  def comparison(left: Number, right: Number): Boolean = left < right
}
"#,
        ),
    ]);

    for (target, expected) in [
        ("app.Factory$.apply", "Factory(1)"),
        ("app.Box$.apply", "Box(2)"),
        ("scala.Int.-", "3 - 1"),
        ("scala.Int.<", "3 < 4"),
    ] {
        let target = definition(&analyzer, target);
        let hits =
            hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));
        assert_eq!(
            hits.len(),
            1,
            "wrong same-name target leaked for {target:?}"
        );
        assert_hit_contains(&hits, expected);
        assert_eq!(hits[0].file.rel_path(), "app/Use.scala");
    }

    let targets = [
        definition(&analyzer, "app.Factory$.apply"),
        definition(&analyzer, "app.Box$.apply"),
        definition(&analyzer, "scala.Int.-"),
        definition(&analyzer, "scala.Int.<"),
    ];
    let limited = UsageFinder::new().query(&analyzer, &targets, 100, 3);
    assert!(
        matches!(
            limited.result,
            FuzzyResult::TooManyCallsites { limit: 3, .. }
        ),
        "lowered Scala calls must preserve the query-wide usage cap"
    );
}

#[test]
fn scala_selection_label_stable_and_type_usages_preserve_exact_targets() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "app/Model.scala",
            r#"
package app

case class Config(name: String)
case class GenericConfig[T](name: String, value: T)

object Marks {
  val START = "<"
}

class Base {
  val marker = "base"
}

class Child extends Base {
  val inherited = marker
}

trait Api {
  def value: Int
  def run(): Int
}

class Impl extends Api {
  override def value: Int = 1
  override def run(): Int = 2
}

enum Mode {
  case Active
}

object Extractor {
  def unapply(value: String): Option[String] = Some(value)
}
"#,
        ),
        (
            "app/Use.scala",
            r#"
package app

object Use {
  val config = Config(name = "main")
  val generic = GenericConfig[Int](name = "generic", value = 1)
  val created = new GenericConfig[Int](name = "created", value = 2)
  val typed: Config = config
  val marked = s"${Marks.START}value"
  val mode = Mode.Active

  def selected(api: Api): Int = api.run() + api.value
  def extracted(value: String): String = value match {
    case Extractor(found) => found
    case _ => value
  }
}
"#,
        ),
        (
            "other/Model.scala",
            r#"
package other

case class Config(name: String)
case class GenericConfig[T](name: String, value: T)
object Marks { val START = "other" }
class Base { val marker = "other" }
trait Api { def value: Int; def run(): Int }
enum Mode { case Active }
object Extractor { def unapply(value: String): Option[String] = Some(value) }

object Use {
  val config = Config(name = "other")
  val generic = GenericConfig[Int](name = "other", value = 1)
  val marked = s"${Marks.START}value"
  val mode = Mode.Active
  def selected(api: Api): Int = api.run() + api.value
  def extracted(value: String): String = value match { case Extractor(found) => found }
}
"#,
        ),
    ]);

    for (target, expected) in [
        ("app.Config.name", "Config(name = \"main\")"),
        ("app.GenericConfig.name", "name = \"created\""),
        ("app.Base.marker", "val inherited = marker"),
        ("app.Marks$.START", "Marks.START"),
        ("app.Api.run", "api.run()"),
        ("app.Api.value", "api.value"),
        ("app.Config", "val typed: Config"),
        ("app.Mode", "Mode.Active"),
        ("app.Extractor$", "case Extractor(found)"),
    ] {
        let target = definition(&analyzer, target);
        let hits =
            hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));
        assert_hit_contains(&hits, expected);
        assert!(
            hits.iter()
                .all(|hit| hit.file.rel_path() != "other/Model.scala"),
            "unrelated same-name owner leaked for {target:?}: {hits:#?}"
        );
    }
}

#[test]
fn scala_class_targets_follow_only_exact_companion_apply_and_extractor_roles() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "model/Model.scala",
            r#"package model
case class Event(value: Int)
final class Settings private (val value: Int)
object Settings {
  def apply(value: Int): Settings = new Settings(value)
  def unapply(settings: Settings): Option[Int] = Some(settings.value)
}
final class Plain(val value: Int)
object Plain { def apply(value: Int): Event = Event(value) }
"#,
        ),
        (
            "other/Model.scala",
            r#"package other
case class Event(value: Int)
final class Settings(val value: Int)
object Settings {
  def apply(value: Int): Settings = new Settings(value)
  def unapply(settings: Settings): Option[Int] = Some(settings.value)
}
"#,
        ),
        (
            "app/Use.scala",
            r#"package app
import model.{Event => ModelEvent, Settings => ModelSettings, Plain}
object Use {
  val event = ModelEvent(1)
  val wrongEventArity = ModelEvent(1, 2)
  val settings = ModelSettings(2)
  val wrongSettingsArity = ModelSettings()
  val plainReturnsEvent = Plain(3)
  def extract(value: Any): Int = value match {
    case ModelEvent(number) => number
    case ModelSettings(number) => number
    case Plain(number) => number
    case _ => 0
  }
}
"#,
        ),
        (
            "other/Use.scala",
            r#"package other
object Use {
  val event = Event(1)
  val settings = Settings(2)
  def extract(value: Any): Int = value match {
    case Event(number) => number
    case Settings(number) => number
    case _ => 0
  }
}
"#,
        ),
    ]);

    let event = definition(&analyzer, "model.Event");
    let event_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&event)));
    assert_hit_contains(&event_hits, "val event = ModelEvent(1)");
    assert_hit_contains(&event_hits, "case ModelEvent(number)");
    assert_no_hit_contains(&event_hits, "ModelEvent(1, 2)");
    assert!(
        event_hits
            .iter()
            .all(|hit| hit.file.rel_path() != "other/Use.scala"),
        "same-name package companion leaked: {event_hits:#?}"
    );

    let settings = definition(&analyzer, "model.Settings");
    let settings_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&settings)));
    assert_hit_contains(&settings_hits, "val settings = ModelSettings(2)");
    assert_hit_contains(&settings_hits, "case ModelSettings(number)");
    assert_no_hit_contains(&settings_hits, "ModelSettings()");

    let plain = definition(&analyzer, "model.Plain");
    let plain_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&plain)));
    assert_no_hit_contains(&plain_hits, "Plain(3)");
    assert_no_hit_contains(&plain_hits, "case Plain(number)");
}

#[test]
fn scala_unqualified_type_roles_follow_exact_callable_precedence() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "model/Model.scala",
            r#"package model
class Extracted(val value: Int)
object Extracted {
  def unapply(value: Any): Option[Int] = None
}
class Built(val value: Int)
abstract class Zero
final class Projected private (val value: Int)
object Projected {
  def apply(value: Int): Projected = new Projected(value)
}
class Other
class Plain(val value: Int)
object Plain {
  def apply(value: Int): Other = new Other
}
object LexicalCollision {
  def apply(value: Int): Other = new Other
}
object NestedFactory {
  final class Settings private (val value: Int)
  object Settings {
    def apply(value: Int): Settings = new Settings(value)
  }
  val nested = Settings(8) // positive-nested-apply
}
trait Growable {
  def +=(value: Int): Unit
}
"#,
        ),
        (
            "app/Use.scala",
            r#"package app
import model.*
object Use {
  def extract(value: Any): Int = value match {
    case Extracted(found) => found // positive-extractor
    case _ => 0
  }
  val built = Built(1) // positive-universal
  val projected = Projected(2) // positive-projected-apply
  val plain = Plain(3) // positive-other-return-apply
  val explicitlyPlain = new Plain(4) // positive-explicit-constructor
  val zero = new Zero: // positive-zero-arity
    override def toString = "zero"
  def grow(target: Growable): Unit = target += 1 // positive-infix
}
class LocalWins {
  def Projected(value: Int): Int = value
  val value = Projected(9) // negative-same-name-member
}
class NestedWins {
  class LexicalCollision(val value: Int)
  val value = LexicalCollision(7) // positive-lexical-collision
}
"#,
        ),
    ]);

    for (target, expected) in [
        ("model.Extracted", "positive-extractor"),
        ("model.Built", "positive-universal"),
        ("model.Built.Built", "positive-universal"),
        ("model.Projected", "positive-projected-apply"),
        ("model.Projected$.apply", "positive-projected-apply"),
        ("model.Zero", "positive-zero-arity"),
        ("model.Growable.+=", "positive-infix"),
        ("model.Plain$.apply", "positive-other-return-apply"),
        ("model.NestedFactory$.Settings", "positive-nested-apply"),
        (
            "model.NestedFactory$.Settings$.apply",
            "positive-nested-apply",
        ),
        (
            "app.NestedWins.LexicalCollision",
            "positive-lexical-collision",
        ),
        (
            "app.NestedWins.LexicalCollision.LexicalCollision",
            "positive-lexical-collision",
        ),
    ] {
        let target = definition(&analyzer, target);
        let target_hits =
            hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));
        assert!(
            target_hits.iter().any(|hit| hit.snippet.contains(expected)),
            "{target:?} missing {expected:?}: {target_hits:#?}"
        );
        assert_no_hit_contains(&target_hits, "negative-same-name-member");
    }

    let plain = definition(&analyzer, "model.Plain");
    let plain_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&plain)));
    assert_no_hit_contains(&plain_hits, "positive-other-return-apply");

    let plain_constructor = definition(&analyzer, "model.Plain.Plain");
    let constructor_hits = hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&plain_constructor)),
    );
    assert_hit_contains(&constructor_hits, "positive-explicit-constructor");
    assert_no_hit_contains(&constructor_hits, "positive-other-return-apply");

    let projected_constructor = definition(&analyzer, "model.Projected.Projected");
    let projected_constructor_hits = hits(
        UsageFinder::new()
            .find_usages_default(&analyzer, std::slice::from_ref(&projected_constructor)),
    );
    assert_no_hit_contains(&projected_constructor_hits, "positive-projected-apply");

    let imported_collision = definition(&analyzer, "model.LexicalCollision$.apply");
    let imported_collision_hits = hits(
        UsageFinder::new()
            .find_usages_default(&analyzer, std::slice::from_ref(&imported_collision)),
    );
    assert_no_hit_contains(&imported_collision_hits, "positive-lexical-collision");
}

#[test]
fn scala_nested_type_visibility_honors_lexical_alias_wildcard_and_ambiguity() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "model/Nested.scala",
            r#"package model
object Outer {
  case class Inner(value: Int)
  val lexicalType: Inner = Inner(1)
  val lexicalCall = Inner(2)
  def lexicalExtract(value: Any): Int = value match {
    case Inner(number) => number
    case _ => 0
  }
}
object Sibling { case class Inner(value: Int) }
"#,
        ),
        (
            "app/Wildcard.scala",
            r#"package app
import model.Outer._
object Wildcard {
  val typed: Inner = Inner(3)
  def extract(value: Any): Int = value match {
    case Inner(number) => number
    case _ => 0
  }
}
"#,
        ),
        (
            "app/Alias.scala",
            r#"package app
import model.Outer.Inner as Renamed
object Alias {
  val typed: Renamed = Renamed(4)
  def extract(value: Any): Int = value match {
    case Renamed(number) => number
    case _ => 0
  }
}
"#,
        ),
        (
            "app/Ambiguous.scala",
            r#"package app
import model.Outer._
import model.Sibling._
object Ambiguous {
  val typed: Inner = Inner(5)
  def extract(value: Any): Int = value match {
    case Inner(number) => number
    case _ => 0
  }
}
"#,
        ),
    ]);

    let inner = definition(&analyzer, "model.Outer$.Inner");
    let query = UsageFinder::new().query(&analyzer, std::slice::from_ref(&inner), 100, 100);
    for expected in [
        "app/Wildcard.scala",
        "app/Alias.scala",
        "app/Ambiguous.scala",
    ] {
        assert!(
            query
                .candidate_files
                .iter()
                .any(|file| file.rel_path() == expected),
            "default Scala candidate routing omitted {expected}: {:#?}",
            query.candidate_files
        );
    }
    let inner_hits = hits(query.result);
    for expected in [
        "val lexicalType: Inner = Inner(1)",
        "val lexicalCall = Inner(2)",
        "case Inner(number)",
        "val typed: Inner = Inner(3)",
        "val typed: Renamed = Renamed(4)",
        "case Renamed(number)",
    ] {
        assert_hit_contains(&inner_hits, expected);
    }
    assert!(
        inner_hits
            .iter()
            .all(|hit| hit.file.rel_path() != "app/Ambiguous.scala"),
        "ambiguous sibling wildcard imports must not select a nested target: {inner_hits:#?}"
    );
}

#[test]
fn scala_method_local_imports_preserve_scope_order_shadowing_and_object_identity() {
    let consumer_source = r#"package app
class Consumer {
  def methodLocal: Any = {
    import Owner._
    accept(RetryTick) // positive-method
  }
  def anonymous: Any = new Runnable {
    import Owner._
    def run(): Unit = accept(RetryTick) // positive-anonymous
  }
  def aliased: Any = {
    import Owner.{RetryTick => AliasTick}
    accept(AliasTick) // positive-alias
  }
  def beforeImport: Any = {
    accept(RetryTick) // negative-before
    import Owner._
  }
  def siblingScope: Any = {
    { import Owner._; accept(RetryTick) } // positive-sibling-inner
    accept(RetryTick) // negative-sibling-outer
  }
  def shadowed: Any = {
    import Owner._
    val RetryTick = other.RetryTick
    accept(RetryTick) // negative-shadow
  }
  def ambiguous: Any = {
    import Owner._
    import other._
    accept(RetryTick) // negative-ambiguous
  }
  def absent: Any = accept(RetryTick) // negative-absent
  private def accept(value: Any): Any = value
}
"#;
    let (project, analyzer) = scala_analyzer_with_files(&[
        (
            "app/Owner.scala",
            r#"package app
object Owner {
  private class RetryTick
  private object RetryTick
}
"#,
        ),
        ("other/RetryTick.scala", "package other\nobject RetryTick\n"),
        ("app/Consumer.scala", consumer_source),
    ]);

    let target = definition(&analyzer, "app.Owner$.RetryTick$");
    let target_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));
    for marker in [
        "positive-method",
        "positive-anonymous",
        "positive-alias",
        "positive-sibling-inner",
    ] {
        assert_hit_line(&target_hits, line_of(consumer_source, marker));
    }
    for marker in [
        "negative-before",
        "negative-sibling-outer",
        "negative-shadow",
        "negative-ambiguous",
        "negative-absent",
    ] {
        assert_no_hit_line(&target_hits, line_of(consumer_source, marker));
    }

    let class = definition(&analyzer, "app.Owner$.RetryTick");
    let class_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&class)));
    for marker in [
        "positive-method",
        "positive-anonymous",
        "positive-alias",
        "positive-sibling-inner",
    ] {
        assert_no_hit_line(&class_hits, line_of(consumer_source, marker));
    }

    let imports = analyzer.import_info_of(definition(&analyzer, "app.Consumer").source());
    assert_eq!(
        8,
        imports.len(),
        "each source import is collected exactly once"
    );
    assert!(imports.iter().all(|info| {
        info.path
            .as_ref()
            .is_some_and(|path| path.declaration_start_byte > 0 && !path.lexical_scopes.is_empty())
    }));

    let mcp = call_search_tool_json(
        project.root(),
        "scan_usages_by_reference",
        &json!({
            "symbols": ["app.Owner$.RetryTick$"],
            "include_tests": true,
        })
        .to_string(),
    );
    let result = &mcp["results"][0];
    assert_eq!(result["status"], "found", "{mcp}");
    let mcp_hits = result["files"]
        .as_array()
        .expect("MCP usage files")
        .iter()
        .flat_map(|file| file["hits"].as_array().into_iter().flatten())
        .filter_map(|hit| hit["line"].as_u64())
        .collect::<BTreeSet<_>>();
    for marker in [
        "positive-method",
        "positive-anonymous",
        "positive-alias",
        "positive-sibling-inner",
    ] {
        assert!(
            mcp_hits.contains(&(line_of(consumer_source, marker) as u64)),
            "MCP result omitted {marker}: {mcp}"
        );
    }
}

#[test]
fn scala_case_class_wildcard_exposes_only_stable_companion_children() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "model/Container.scala",
            r#"package model
case class Container(value: Int) {
  class InstanceNested
}
object Container {
  class CompanionNested
}
"#,
        ),
        (
            "app/Use.scala",
            r#"package app
import model.Container.*
object Use {
  val companion: CompanionNested = new CompanionNested
  val invalidInstanceLeak: InstanceNested = new InstanceNested
}
"#,
        ),
    ]);

    let companion = definition(&analyzer, "model.Container$.CompanionNested");
    let companion_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&companion)));
    assert_hit_contains(
        &companion_hits,
        "val companion: CompanionNested = new CompanionNested",
    );

    let instance = definition(&analyzer, "model.Container.InstanceNested");
    let instance_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&instance)));
    assert!(
        instance_hits
            .iter()
            .all(|hit| hit.file.rel_path() != "app/Use.scala"),
        "case-class instance children leaked through companion wildcard import: {instance_hits:#?}"
    );
}

#[test]
fn scala_qualified_call_initializer_seeds_local_receiver_type() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "app/Console.scala",
        r#"
package app

class Editor
class ScalaLanguageConsole { def textSent(value: String): Unit = () }
class OtherConsole { def textSent(value: String): Unit = () }

object ScalaConsoleInfo {
  def getConsole(editor: Editor): ScalaLanguageConsole = new ScalaLanguageConsole
}
object OtherInfo {
  def getConsole(editor: Editor): OtherConsole = new OtherConsole
}

object Action {
  def run(editor: Editor): Unit = {
    val console = ScalaConsoleInfo.getConsole(editor)
    console.textSent("expected")
    val decoy = OtherInfo.getConsole(editor)
    decoy.textSent("other")
  }
}
"#,
    )]);
    let target = definition(&analyzer, "app.ScalaLanguageConsole.textSent");
    let hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));

    assert_hit_contains(&hits, "console.textSent(\"expected\")");
    assert_no_hit_contains(&hits, "decoy.textSent");
}

#[test]
fn scala_unqualified_call_initializer_uses_exact_owner_and_hierarchy_return_types() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "model/Messages.scala",
            r#"package model

class Messages { def tail: Int = 1 }
class OtherMessages { def tail: Int = 2 }
"#,
        ),
        (
            "helpers/ImportedFactories.scala",
            r#"package helpers

import model.{Messages, OtherMessages}

object ImportedFactories {
  def systemDrain(seed: Int): OtherMessages = new OtherMessages
  def importedDrain(seed: Int): Messages = new Messages
}
"#,
        ),
        (
            "app/Factories.scala",
            r#"package app

import helpers.ImportedFactories.{importedDrain, systemDrain}
import model.{Messages, OtherMessages}

trait InheritedFactory {
  def inheritedDrain(seed: Int): Messages = new Messages
}

class SameOwnerFactory {
  def systemDrain(seed: Int): Messages = new Messages
  def sameOwner(): Int = {
    val messages = systemDrain(1)
    messages.tail // positive-same-owner
  }

  def overloaded(seed: Int): Messages = new Messages
  def overloaded(seed: String): OtherMessages = new OtherMessages
  def ambiguousOverload(): Int = {
    val messages = overloaded(1)
    messages.tail // negative-overload
  }

  def otherDrain(seed: Int): OtherMessages = new OtherMessages
  def wrongReturn(): Int = {
    val messages = otherDrain(1)
    messages.tail // negative-return
  }

  def localShadow(): Int = {
    def systemDrain(seed: Int): OtherMessages = new OtherMessages
    val messages = systemDrain(1)
    messages.tail // negative-local-shadow
  }
}

class InheritedConsumer extends InheritedFactory {
  def run(): Int = {
    val messages = inheritedDrain(1)
    messages.tail // positive-inherited
  }
}

class ImportedConsumer {
  def run(): Int = {
    val messages = importedDrain(1)
    messages.tail // positive-imported
  }
}

class UnrelatedFactory {
  def systemDrain(seed: Int): OtherMessages = new OtherMessages
  def run(): Int = {
    val messages = systemDrain(1)
    messages.tail // negative-unrelated
  }
}
"#,
        ),
    ]);
    let target = definition(&analyzer, "model.Messages.tail");
    let hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));

    assert_hit_contains(&hits, "messages.tail // positive-same-owner");
    assert_hit_contains(&hits, "messages.tail // positive-inherited");
    assert_hit_contains(&hits, "messages.tail // positive-imported");
    assert_no_hit_contains(&hits, "negative-overload");
    assert_no_hit_contains(&hits, "negative-return");
    assert_no_hit_contains(&hits, "negative-local-shadow");
    assert_no_hit_contains(&hits, "negative-unrelated");
}

#[test]
fn scala_nested_mixin_factory_receiver_survives_while_reassignment() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "queue/Messages.scala",
            r#"package queue

class LatestMessages
class Messages {
  def nonEmpty: Boolean = true
  def tail: Messages = new Messages
}

trait SystemQueue { self: Mailbox =>
  def systemDrain(seed: LatestMessages): Messages = new Messages
}

class Mailbox
"#,
        ),
        (
            "app/Dispatcher.scala",
            r#"package app

import queue.{LatestMessages, Mailbox, SystemQueue}

class Dispatcher {
  private class SharingMailbox extends Mailbox with SystemQueue {
    def cleanUp(): Unit = {
      var messages = systemDrain(new LatestMessages)
      while (messages.nonEmpty) {
        messages = messages.tail // positive-nested-mixin-reassignment
      }
    }
  }
}
"#,
        ),
    ]);

    let tail = definition(&analyzer, "queue.Messages.tail");
    let tail_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&tail)));
    assert_hit_contains(
        &tail_hits,
        "messages = messages.tail // positive-nested-mixin-reassignment",
    );

    let drain = definition(&analyzer, "queue.SystemQueue.systemDrain");
    let drain_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&drain)));
    assert_hit_contains(&drain_hits, "systemDrain(new LatestMessages)");

    let non_empty = definition(&analyzer, "queue.Messages.nonEmpty");
    let non_empty_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&non_empty)));
    assert_hit_contains(&non_empty_hits, "while (messages.nonEmpty)");
}

#[test]
fn scala_inherited_companion_apply_fallback_preserves_exact_owner_identity() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "app/Factories.scala",
            r#"package app

trait KnownFactory {
  def apply(value: Int): Int
}

class ExternalBacked {
  def apply(index: Int): Int = index
}
object ExternalBacked extends external.Factory[ExternalBacked]

class Plain {
  def apply(index: Int): Int = index
}
object Plain

class Known {
  def apply(index: Int): Int = index
}
object Known extends KnownFactory

class Duplicate {
  def apply(index: Int): Int = index
}
object Duplicate extends external.Factory[Duplicate]

object Use {
  val external = ExternalBacked(1)
  val plain = Plain(2)
  val known = Known(3)
  val duplicate = Duplicate(4)
}
"#,
        ),
        (
            "app/Duplicate.scala",
            r#"package app
object Duplicate extends external.Factory[Duplicate]
"#,
        ),
        (
            "other/Factories.scala",
            r#"package other
class ExternalBacked {
  def apply(index: Int): Int = index
}
object ExternalBacked extends external.Factory[ExternalBacked]
object Use {
  val external = ExternalBacked(5)
}
"#,
        ),
    ]);

    let external = definition(&analyzer, "app.ExternalBacked.apply");
    let external_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&external)));
    assert_hit_contains(&external_hits, "val external = ExternalBacked(1)");
    assert_no_hit_contains(&external_hits, "val external = ExternalBacked(5)");

    for (target_fqn, rejected_call) in [
        ("app.Plain.apply", "val plain = Plain(2)"),
        ("app.Known.apply", "val known = Known(3)"),
        ("app.Duplicate.apply", "val duplicate = Duplicate(4)"),
    ] {
        let target = definition(&analyzer, target_fqn);
        let target_hits =
            hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));
        assert_no_hit_contains(&target_hits, rejected_call);
    }
}

#[test]
fn scala_union_receiver_requires_every_structured_alternative_to_share_member_family() {
    let consumer_source = r#"package app

import model.CompletionValue.Workspace
import model.CompletionValue.Extension
import model.Unrelated
import model.Duplicate

object Use {
  def imported(v: Workspace | Extension): Option[String] = v.insertText
  def nested(v: model.CompletionValue.Workspace | model.CompletionValue.Extension |
      model.CompletionValue.Interpolator | model.CompletionValue.ImplicitClass): Option[String] =
    v.insertText
  def concrete(v: model.CompletionValue.Interpolator): Option[String] = v.insertText
  def unsupported(v: Workspace | Unrelated): Option[String] = v.insertText
  def duplicate(v: Duplicate | Extension): Option[String] = v.insertText
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "model/CompletionValue.scala",
            r#"package model

sealed trait CompletionValue {
  def insertText: Option[String] = None
}
object CompletionValue {
  sealed trait Symbolic extends CompletionValue
  object Symbolic
  class Workspace extends Symbolic
  class Extension extends Symbolic
  class Interpolator extends Symbolic {
    override val insertText: Option[String] = Some("interpolated")
  }
  class ImplicitClass extends CompletionValue
}
class Unrelated
"#,
        ),
        (
            "model/InheritedDuplicate.scala",
            "package model\nclass Duplicate extends CompletionValue\n",
        ),
        (
            "model/PlainDuplicate.scala",
            "package model\nclass Duplicate\n",
        ),
        ("app/Use.scala", consumer_source),
    ]);

    let insert_text = definition(&analyzer, "model.CompletionValue.insertText");
    let hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&insert_text)));
    let lines = hits.iter().map(|hit| hit.line).collect::<BTreeSet<_>>();
    assert_eq!(
        lines,
        BTreeSet::from([
            line_of(consumer_source, "def imported"),
            line_of(consumer_source, "    v.insertText"),
        ]),
        "only unions whose alternatives all inherit the member may resolve: {hits:#?}"
    );
}

#[test]
fn scala_nested_structural_owners_cover_field_apply_and_inherited_call_families() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "left/Owners.scala",
            r#"package left
object Outer {
  class Base {
    val marker: Int = 1
    def run(value: Int): Int = value
    def apply(value: Int): Int = value
  }
  class Child extends Base {
    val inheritedField = marker
    val inheritedCall = run(1)
  }
  object Factory { def apply(value: Int): Child = new Child }
  val made = Factory(1)
  val notAnInstanceApply = Base(1)
}
"#,
        ),
        (
            "right/Owners.scala",
            r#"package right
object Outer {
  class Base {
    val marker: Int = 2
    def run(value: Int): Int = value + 1
  }
  class Child extends Base {
    val inheritedField = marker
    val inheritedCall = run(2)
  }
  object Factory { def apply(value: Int): Child = new Child }
  val made = Factory(2)
}
"#,
        ),
    ]);

    for (target_fqn, expected) in [
        ("left.Outer$.Base.marker", "val inheritedField = marker"),
        ("left.Outer$.Base.run", "val inheritedCall = run(1)"),
        ("left.Outer$.Factory$.apply", "val made = Factory(1)"),
    ] {
        let target = definition(&analyzer, target_fqn);
        let parent = analyzer
            .parent_of(&target)
            .unwrap_or_else(|| panic!("missing structural parent for {target_fqn}"));
        assert_eq!(
            parent.source(),
            target.source(),
            "member ownership must preserve exact source identity"
        );
        let hits =
            hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));
        assert_hit_contains(&hits, expected);
        assert!(
            hits.iter()
                .all(|hit| hit.file.rel_path() != "right/Owners.scala"),
            "unrelated nested owner leaked for {target_fqn}: {hits:#?}"
        );
    }

    let instance_apply = definition(&analyzer, "left.Outer$.Base.apply");
    let instance_hits = hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&instance_apply)),
    );
    assert_no_hit_contains(&instance_hits, "Base(1)");
}

#[test]
fn scala_unqualified_calls_resolve_through_lexical_owner_tiers() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "app/Owners.scala",
        r#"package app

object Outer {
  def catalog(value: Int): Int = value

  class Inner {
    val inheritedLexically = catalog(1) // positive-lexical-outer
  }

  class Nearer {
    def catalog(value: Int): Int = value + 1
    val nearer = catalog(2) // negative-nearer-owner
  }

  class Shadowed {
    def run(catalog: Int => Int): Int =
      catalog(3) // negative-local-shadow
  }
}

object Unrelated {
  def catalog(value: Int): Int = value + 2
  val call = catalog(4) // negative-unrelated-owner
}
"#,
    )]);

    let target = definition(&analyzer, "app.Outer$.catalog");
    let target_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));
    assert_hit_contains(&target_hits, "catalog(1) // positive-lexical-outer");
    assert_no_hit_contains(&target_hits, "negative-nearer-owner");
    assert_no_hit_contains(&target_hits, "negative-local-shadow");
    assert_no_hit_contains(&target_hits, "negative-unrelated-owner");
}

#[test]
fn scala_fresh_instance_receivers_require_a_valid_structured_constructor() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "app/Fresh.scala",
        r#"package app

class Worker(seed: Int) {
  def run(): Int = seed
}

object Use {
  val good = new Worker(1).run() // positive-fresh-instance
  val wrongConstructor = new Worker().run() // negative-wrong-constructor
}
"#,
    )]);

    let target = definition(&analyzer, "app.Worker.run");
    let target_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));
    assert_hit_contains(
        &target_hits,
        "new Worker(1).run() // positive-fresh-instance",
    );
    assert_no_hit_contains(&target_hits, "negative-wrong-constructor");
}

#[test]
fn scala_import_hits_ignore_unrelated_aliased_import_path() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        ("Target.scala", "package app\n\nclass Target\n"),
        ("OtherTarget.scala", "package other\n\nclass Target\n"),
        (
            "Consumer.scala",
            r#"
package app.feature

import app.Target
import other.Target as OtherTarget

class Consumer(value: Target, other: OtherTarget)
"#,
        ),
    ]);

    let target = definition(&analyzer, "app.Target");
    let result = UsageFinder::new().find_usages_default(&analyzer, &[target]);
    let editor_hits = result.all_hits_including_imports();

    assert!(
        editor_hits
            .iter()
            .any(|hit| hit.snippet.contains("import app.Target")),
        "expected target import hit: {editor_hits:#?}"
    );
    assert!(
        editor_hits
            .iter()
            .all(|hit| !hit.snippet.contains("import other.Target as OtherTarget")),
        "unrelated aliased import must not be reported as target hit: {editor_hits:#?}"
    );
}

fn hits(result: FuzzyResult) -> Vec<UsageHit> {
    result
        .into_either()
        .expect("expected usage graph success")
        .into_iter()
        .collect()
}

fn assert_hit_contains(hits: &[UsageHit], needle: &str) {
    assert!(
        hits.iter().any(|hit| hit.snippet.contains(needle)),
        "expected hit containing {needle:?}, got {hits:#?}"
    );
}

fn assert_hit_line(hits: &[UsageHit], line: usize) {
    assert!(
        hits.iter().any(|hit| hit.line == line),
        "expected hit on line {line}, got {hits:#?}"
    );
}

fn assert_no_hit_line(hits: &[UsageHit], line: usize) {
    assert!(
        hits.iter().all(|hit| hit.line != line),
        "expected no hit on line {line}, got {hits:#?}"
    );
}

fn assert_no_hit_in_enclosing(hits: &[UsageHit], enclosing_fq_name: &str) {
    assert!(
        hits.iter()
            .all(|hit| hit.enclosing.fq_name() != enclosing_fq_name),
        "expected no hit in {enclosing_fq_name}, got {hits:#?}"
    );
}

fn assert_hit_count_by_snippet(hits: &[UsageHit], needle: &str, expected: usize) {
    let actual = hits
        .iter()
        .filter(|hit| hit.snippet.contains(needle))
        .count();
    assert_eq!(
        expected, actual,
        "expected {expected} hits containing {needle:?}, got {hits:#?}"
    );
}

fn assert_no_hit_contains(hits: &[UsageHit], needle: &str) {
    assert!(
        hits.iter().all(|hit| !hit.snippet.contains(needle)),
        "expected no hit containing {needle:?}, got {hits:#?}"
    );
}

fn rel_path_string(file: &brokk_bifrost::ProjectFile) -> String {
    file.rel_path().to_string_lossy().replace('\\', "/")
}

fn scala_hits(analyzer: &ScalaAnalyzer, target: &CodeUnit, candidates: &[&str]) -> Vec<UsageHit> {
    let candidate_files = analyzer
        .get_analyzed_files()
        .into_iter()
        .filter(|file| {
            let rel_path = rel_path_string(file);
            candidates.iter().any(|candidate| rel_path == *candidate)
        })
        .collect();
    hits(ScalaUsageGraphStrategy::new().find_usages(
        analyzer,
        std::slice::from_ref(target),
        &candidate_files,
        1000,
    ))
}

#[test]
fn usage_finder_routes_scala_targets_through_graph_strategy() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Target.scala",
            r#"
package pkg

class Target {
  def run(): Int = 1
}
"#,
        ),
        (
            "pkg/Consumer.scala",
            r#"
package pkg

class Consumer {
  def call(target: Target): Int = target.run()
  def unrelated(): Int = run()
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "pkg.Target.run");
    let hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));

    assert_eq!(1, hits.len());
    assert_hit_contains(&hits, "target.run()");
    assert_eq!(5, hits[0].line);
}

#[test]
fn scala_graph_finds_imported_types_constructors_and_members() {
    let consumer_source = r#"
package app

import pkg.{Target as AliasTarget, Contract}
import pkg.Utility

class Consumer extends Contract {
  val target: AliasTarget = new AliasTarget(1)

  def call(): Int = {
    if (Utility.flag) {
      target.field = 2
      Utility.help() + target.run()
      val copy = target.field
      copy
    } else {
      0
    }
  }
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Target.scala",
            r#"
package pkg

class Target(val value: Int) {
  val field: Int = value
  def run(): Int = value
}
"#,
        ),
        (
            "pkg/Contract.scala",
            r#"
package pkg

trait Contract
"#,
        ),
        (
            "pkg/Utility.scala",
            r#"
package pkg

object Utility {
  val flag: Boolean = true
  def help(): Int = 1
}
"#,
        ),
        ("app/Consumer.scala", consumer_source),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = ScalaUsageGraphStrategy::new();

    let contract = definition(&analyzer, "pkg.Contract");
    let contract_hits = hit_snippets(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&contract),
        &candidates,
        1000,
    ));
    assert!(
        contract_hits
            .iter()
            .any(|hit| hit.contains("extends Contract"))
    );

    let target = definition(&analyzer, "pkg.Target");
    let target_hits = hit_snippets(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    ));
    assert!(
        target_hits
            .iter()
            .any(|hit| hit.contains("new AliasTarget"))
    );

    let run = definition(&analyzer, "pkg.Target.run");
    let run_hits = hit_snippets(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&run),
        &candidates,
        1000,
    ));
    assert!(run_hits.iter().any(|hit| hit.contains("target.run()")));

    let field = definition(&analyzer, "pkg.Target.field");
    let field_hits = hit_snippets(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&field),
        &candidates,
        1000,
    ));
    assert!(
        field_hits
            .iter()
            .any(|hit| hit.contains("target.field = 2"))
    );
    assert!(
        field_hits
            .iter()
            .any(|hit| hit.contains("val copy = target.field"))
    );

    let help = definition(&analyzer, "pkg.Utility$.help");
    let help_hits = hit_snippets(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&help),
        &candidates,
        1000,
    ));
    assert!(help_hits.iter().any(|hit| hit.contains("Utility.help()")));

    let flag = definition(&analyzer, "pkg.Utility$.flag");
    let flag_hits = hit_snippets(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&flag),
        &candidates,
        1000,
    ));
    assert!(flag_hits.iter().any(|hit| hit.contains("Utility.flag")));
}

#[test]
fn scala_graph_counts_static_qualifier_references_for_object_targets() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Utility.scala",
            r#"
package pkg

object Utility {
  val value: Int = 7
  def build(): String = "ok"
}

class Other {
  def touch(): Unit = ()
}
"#,
        ),
        (
            "app/Consumer.scala",
            r#"
package app

import pkg.{Other, Utility}

class Consumer {
  def run(): Unit = {
    Utility.build()
    val value = Utility.value
    val Utility = new Other()
    Utility.touch()
  }
}
"#,
        ),
    ]);

    let target = definition(&analyzer, "pkg.Utility$");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    ));

    assert_hit_contains(&hits, "Utility.build()");
    assert_hit_contains(&hits, "Utility.value");
    assert_no_hit_contains(&hits, "Utility.touch()");
}

#[test]
fn scala_graph_handles_wildcard_member_imports_and_ignores_unrelated_same_names() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Utility.scala",
            r#"
package pkg

object Utility {
  def help(): Int = 1
}
"#,
        ),
        (
            "other/Utility.scala",
            r#"
package other

object Utility {
  def help(): Int = 2
}
"#,
        ),
        (
            "app/Consumer.scala",
            r#"
package app

import pkg.Utility.*

class Consumer {
  def call(): Int = help()
  def unrelated(other: other.Utility.type): Int = other.help()
}
"#,
        ),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let target = definition(&analyzer, "pkg.Utility$.help");
    let hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    ));

    assert_eq!(1, hits.len());
    assert!(hits[0].snippet.contains("help()"));
    assert!(hits[0].line < 10, "unexpected hit: {hits:#?}");
}

#[test]
fn scala_graph_resolves_transitive_export_selectors_and_routes_original_files() {
    let (project, analyzer) = scala_analyzer_with_files(&[
        (
            "dotty/tools/tasty/TastyFormat.scala",
            r#"package dotty.tools.tasty
object TastyFormat {
  def astTagToString(tag: Int): String = tag.toString
  def isModifierTag(tag: Int): Boolean = tag > 0
  def original(): Int = 1
}
"#,
        ),
        (
            "dotty/tools/tasty/besteffort/BestEffortTastyFormat.scala",
            r#"package dotty.tools.tasty.besteffort
import dotty.tools.tasty.TastyFormat
object BestEffortTastyFormat {
  export TastyFormat.{*, astTagToString as _, original as selected}
}
"#,
        ),
        (
            "dotty/tools/dotc/core/tasty/TastyPrinter.scala",
            r#"package dotty.tools.dotc.core.tasty
import dotty.tools.tasty.besteffort.BestEffortTastyFormat.*
object TastyPrinter {
  def selectedCall(): Int = selected() // positive-renamed-export
  def print(nextByte: Int): Boolean =
    while nextByte > 0 && !isModifierTag(nextByte) do () // positive-tasty-export
    true
}
"#,
        ),
    ]);

    let tasty_format = project.file("dotty/tools/tasty/TastyFormat.scala");
    let tasty_printer = project.file("dotty/tools/dotc/core/tasty/TastyPrinter.scala");
    assert!(
        analyzer
            .referencing_files_of(&tasty_format)
            .contains(&tasty_printer),
        "transitive export target must participate in import candidate routing"
    );

    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let modifier = definition(&analyzer, "dotty.tools.tasty.TastyFormat$.isModifierTag");
    let modifier_hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&modifier),
        &candidates,
        1000,
    ));
    assert_hit_contains(&modifier_hits, "positive-tasty-export");

    let original = definition(&analyzer, "dotty.tools.tasty.TastyFormat$.original");
    let original_hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&original),
        &candidates,
        1000,
    ));
    assert_hit_contains(&original_hits, "positive-renamed-export");

    let excluded = definition(&analyzer, "dotty.tools.tasty.TastyFormat$.astTagToString");
    let excluded_hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&excluded),
        &candidates,
        1000,
    ));
    assert_no_hit_contains(&excluded_hits, "positive-tasty-export");
}

#[test]
fn scala_graph_export_cycles_terminate_and_ambiguous_exports_fail_closed() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Exports.scala",
            r#"package pkg
object Left { def help(): Int = 1 }
object Right { def help(): Int = 2 }
object Ambiguous {
  export Left.*
  export Right.*
}
object CycleA {
  def leaf(): Int = 3
  export CycleB.*
}
object CycleB { export CycleA.* }
"#,
        ),
        (
            "app/Consumer.scala",
            r#"package app
object AmbiguousConsumer {
  import pkg.Ambiguous.*
  def call(): Int = help() // negative-ambiguous-export
}
object CycleConsumer {
  import pkg.CycleB.*
  def call(): Int = leaf() // positive-cycle-export
}
"#,
        ),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    for target in ["pkg.Left$.help", "pkg.Right$.help"] {
        let target = definition(&analyzer, target);
        let target_hits = hits(ScalaUsageGraphStrategy::new().find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &candidates,
            1000,
        ));
        assert_no_hit_contains(&target_hits, "negative-ambiguous-export");
    }

    let leaf = definition(&analyzer, "pkg.CycleA$.leaf");
    let leaf_hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&leaf),
        &candidates,
        1000,
    ));
    assert_hit_contains(&leaf_hits, "positive-cycle-export");
}

#[test]
fn scala_graph_covers_enums_cases_and_with_inheritance() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Types.scala",
            r#"
package pkg

trait Base
trait Contract
enum Mode {
  case Ready
  case Done
}
enum OtherMode {
  case Ready
}
"#,
        ),
        (
            "app/Consumer.scala",
            r#"
package app

import pkg.{Base, Contract, Mode}

class Impl extends Base with Contract {
  val mode: Mode = Mode.Ready
  def current(): Mode = Mode.Ready
  def unrelated(other: pkg.OtherMode): pkg.OtherMode = pkg.OtherMode.Ready
}
"#,
        ),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = ScalaUsageGraphStrategy::new();

    let mode = definition(&analyzer, "pkg.Mode");
    let mode_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&mode), &candidates, 1000));
    assert_hit_contains(&mode_hits, "val mode: Mode");
    assert_hit_contains(&mode_hits, "def current(): Mode");

    let contract = definition(&analyzer, "pkg.Contract");
    let contract_hits = hits(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&contract),
        &candidates,
        1000,
    ));
    assert_hit_contains(&contract_hits, "with Contract");

    let ready = definition(&analyzer, "pkg.Mode.Ready");
    let ready_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&ready), &candidates, 1000));
    assert_hit_contains(&ready_hits, "Mode.Ready");
    assert_no_hit_in_enclosing(&ready_hits, "app.Consumer.unrelated");
}

#[test]
fn scala_graph_covers_top_level_functions_and_values() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Api.scala",
            r#"
package pkg

def helper(): Int = 1
val answer: Int = 42
var counter: Int = 0
"#,
        ),
        (
            "other/Api.scala",
            r#"
package other

def helper(): Int = 2
val answer: Int = 99
"#,
        ),
        (
            "pkg/LocalConsumer.scala",
            r#"
package pkg

class LocalConsumer {
  def call(): Int = helper() + answer
}
"#,
        ),
        (
            "app/ImportedConsumer.scala",
            r#"
package app

import pkg.{helper, answer, counter}

class ImportedConsumer {
  def call(): Int = {
    counter = counter + 1
    helper() + pkg.helper() + answer + counter
  }
  def unrelated(): Int = other.helper() + other.answer
}
"#,
        ),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = ScalaUsageGraphStrategy::new();

    let helper = definition(&analyzer, "pkg.helper");
    let helper_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&helper), &candidates, 1000));
    assert_hit_contains(&helper_hits, "helper() + answer");
    assert_hit_contains(&helper_hits, "helper() + pkg.helper()");
    assert_no_hit_in_enclosing(&helper_hits, "app.ImportedConsumer.unrelated");

    let answer = definition(&analyzer, "pkg.answer");
    let answer_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&answer), &candidates, 1000));
    assert_hit_contains(&answer_hits, "helper() + answer");
    assert_hit_contains(&answer_hits, "answer + counter");
    assert_no_hit_in_enclosing(&answer_hits, "app.ImportedConsumer.unrelated");

    let counter = definition(&analyzer, "pkg.counter");
    let counter_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&counter), &candidates, 1000));
    assert_hit_contains(&counter_hits, "counter = counter + 1");
    assert_hit_contains(&counter_hits, "answer + counter");
}

#[test]
fn scala_graph_distinguishes_field_reads_and_writes() {
    let consumer_source = r#"
package app

import pkg.Target

class Consumer {
  val target = new Target(1)

  def call(): Int = {
    target.field = 2
    val copy = target.field
    copy
  }
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Target.scala",
            r#"
package pkg

class Target(initial: Int) {
  var field: Int = initial
}
"#,
        ),
        ("app/Consumer.scala", consumer_source),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let field = definition(&analyzer, "pkg.Target.field");
    let field_hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&field),
        &candidates,
        1000,
    ));

    assert_hit_line(&field_hits, line_of(consumer_source, "target.field = 2"));
    assert_hit_line(
        &field_hits,
        line_of(consumer_source, "val copy = target.field"),
    );
    assert_hit_count_by_snippet(&field_hits, "target.field", 2);
}

#[test]
fn scala_graph_resolves_this_members_only_in_owner_context() {
    let target_source = r#"
package pkg

class Target {
  var field: Int = 1
  def run(): Int = field
  def call(): Int = {
    field = 2
    this.field = 2
    this.run()
    field + run()
  }
  class Inner {
    def callOuter(): Int = Target.this.run()
  }
}

class Other {
  var field: Int = 3
  def run(): Int = field
  def call(): Int = {
    this.field = 4
    this.run()
    field + run()
  }
  class Inner {
    def callOuter(): Int = Other.this.run()
  }
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[("pkg/Target.scala", target_source)]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = ScalaUsageGraphStrategy::new();

    let field = definition(&analyzer, "pkg.Target.field");
    let field_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&field), &candidates, 1000));
    assert_hit_line(
        &field_hits,
        line_of(target_source, "def run(): Int = field"),
    );
    assert_hit_line(&field_hits, line_of(target_source, "this.field = 2"));
    assert_hit_line(&field_hits, line_of(target_source, "field = 2"));
    assert_hit_line(&field_hits, line_of(target_source, "field + run()"));
    assert_no_hit_line(&field_hits, line_of(target_source, "this.field = 4"));
    assert_no_hit_in_enclosing(&field_hits, "pkg.Other.call");

    let run = definition(&analyzer, "pkg.Target.run");
    let run_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&run), &candidates, 1000));
    assert_hit_line(&run_hits, line_of(target_source, "this.run()"));
    assert_hit_line(&run_hits, line_of(target_source, "Target.this.run()"));
    assert_no_hit_line(&run_hits, line_of(target_source, "Other.this.run()"));
    assert_no_hit_in_enclosing(&run_hits, "pkg.Other.call");
}

#[test]
fn scala_graph_resolves_constructor_inferred_receivers() {
    let consumer_source = r#"
package app

import pkg.{Other, Target}

class Consumer {
  def call(): Int = {
    val target = new Target(1)
    target.run() + target.field
  }
  def unrelated(): Int = {
    val other = new Other()
    other.run()
  }
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Target.scala",
            r#"
package pkg

class Target(initial: Int) {
  val field: Int = initial
  def run(): Int = field
}
"#,
        ),
        (
            "pkg/Other.scala",
            r#"
package pkg

class Other {
  def run(): Int = 0
}
"#,
        ),
        ("app/Consumer.scala", consumer_source),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = ScalaUsageGraphStrategy::new();

    let run = definition(&analyzer, "pkg.Target.run");
    let run_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&run), &candidates, 1000));
    assert_hit_line(&run_hits, line_of(consumer_source, "target.run()"));
    assert_no_hit_in_enclosing(&run_hits, "app.Consumer.unrelated");

    let field = definition(&analyzer, "pkg.Target.field");
    let field_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&field), &candidates, 1000));
    assert_hit_line(
        &field_hits,
        line_of(consumer_source, "target.run() + target.field"),
    );
    assert_no_hit_in_enclosing(&field_hits, "app.Consumer.unrelated");
}

#[test]
fn scala_graph_respects_local_shadowing() {
    let consumer_source = r#"
package app

import pkg.{Utility, answer, helper}

class Consumer {
  def helperShadow(helper: Int): Int = helper + 1

  def answerShadow(): Int = {
    val answer = 0
    answer
  }

  def receiverShadow(): Int = {
    val target = new other.Other()
    target.run()
  }

  def utilityShadow(Utility: other.Utility.type): Int = Utility.help()
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Api.scala",
            r#"
package pkg

def helper(): Int = 1
val answer: Int = 42

object Utility {
  def help(): Int = 1
}

class Target {
  def run(): Int = 1
}
"#,
        ),
        (
            "other/Api.scala",
            r#"
package other

object Utility {
  def help(): Int = 2
}

class Other {
  def run(): Int = 2
}
"#,
        ),
        ("app/Consumer.scala", consumer_source),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = ScalaUsageGraphStrategy::new();

    let helper = definition(&analyzer, "pkg.helper");
    let helper_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&helper), &candidates, 1000));
    assert_no_hit_in_enclosing(&helper_hits, "app.Consumer.helperShadow");

    let answer = definition(&analyzer, "pkg.answer");
    let answer_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&answer), &candidates, 1000));
    assert_no_hit_in_enclosing(&answer_hits, "app.Consumer.answerShadow");

    let run = definition(&analyzer, "pkg.Target.run");
    let run_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&run), &candidates, 1000));
    assert_no_hit_in_enclosing(&run_hits, "app.Consumer.receiverShadow");

    let help = definition(&analyzer, "pkg.Utility$.help");
    let help_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&help), &candidates, 1000));
    assert_no_hit_in_enclosing(&help_hits, "app.Consumer.utilityShadow");
}

#[test]
fn scala_graph_handles_alias_and_wildcard_import_edges() {
    let alias_source = r#"
package app

import pkg.{Utility as U}
import pkg.{helper as h}

class AliasConsumer {
  def call(): Int = U.help() + h()
}
"#;
    let wildcard_source = r#"
package app

import pkg.*

class WildcardConsumer {
  def call(): Int = helper() + answer
}
"#;
    let ambiguous_source = r#"
package app

import pkg.*
import other.*

class AmbiguousConsumer {
  def call(): Int = helper()
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Api.scala",
            r#"
package pkg

def helper(): Int = 1
val answer: Int = 42

object Utility {
  def help(): Int = 1
}
"#,
        ),
        (
            "other/Api.scala",
            r#"
package other

def helper(): Int = 2
"#,
        ),
        ("app/AliasConsumer.scala", alias_source),
        ("app/WildcardConsumer.scala", wildcard_source),
        ("app/AmbiguousConsumer.scala", ambiguous_source),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = ScalaUsageGraphStrategy::new();

    let help = definition(&analyzer, "pkg.Utility$.help");
    let help_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&help), &candidates, 1000));
    assert_hit_line(&help_hits, line_of(alias_source, "U.help()"));

    let helper = definition(&analyzer, "pkg.helper");
    let helper_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&helper), &candidates, 1000));
    assert_hit_line(&helper_hits, line_of(alias_source, "h()"));
    assert_hit_line(&helper_hits, line_of(wildcard_source, "helper() + answer"));
    assert_no_hit_in_enclosing(&helper_hits, "app.AmbiguousConsumer.call");

    let answer = definition(&analyzer, "pkg.answer");
    let answer_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&answer), &candidates, 1000));
    assert_hit_line(&answer_hits, line_of(wildcard_source, "helper() + answer"));
}

#[test]
fn scala_graph_resolves_renamed_member_import_usages_without_external_import_hit() {
    let consumer_source = r#"
package app

import app.ConsoleRenderer.{default => renderer}

object App {
  val direct = renderer.render("ok")
  val workflow = new Workflow(renderer)
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "app/ConsoleRenderer.scala",
            r#"
package app

class ConsoleRenderer {
  def render(value: String): String = value
}

object ConsoleRenderer {
  def default: ConsoleRenderer = new ConsoleRenderer
}

class Workflow(renderer: ConsoleRenderer)
"#,
        ),
        ("app/App.scala", consumer_source),
    ]);
    let target = definition(&analyzer, "app.ConsoleRenderer$.default");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let result = ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    );
    let editor_hits = result.all_hits_including_imports();
    let external_hits = result.all_hits();

    assert_hit_line(
        &external_hits.iter().cloned().collect::<Vec<_>>(),
        line_of(consumer_source, "renderer.render"),
    );
    assert_hit_line(
        &external_hits.iter().cloned().collect::<Vec<_>>(),
        line_of(consumer_source, "new Workflow(renderer)"),
    );
    assert_no_hit_line(
        &external_hits.iter().cloned().collect::<Vec<_>>(),
        line_of(consumer_source, "import app.ConsoleRenderer"),
    );
    assert!(
        editor_hits.iter().any(|hit| {
            hit.kind == UsageHitKind::Import && hit.snippet.contains("default => renderer")
        }),
        "expected renamed member import hit classified as Import: {editor_hits:#?}"
    );
}

#[test]
fn scala_graph_resolves_same_package_scala3_renamed_companion_import_usages() {
    let workflow_source = r#"
package example

trait Renderer:
  def render(value: String): String

class ConsoleRenderer extends Renderer:
  override def render(value: String): String =
    value.trim

object ConsoleRenderer:
  def default: ConsoleRenderer =
    new ConsoleRenderer

class Workflow(renderer: Renderer):
  def run(value: String): String =
    renderer.render(value)

object App:
  import ConsoleRenderer.{default => renderer}

  val workflow = new Workflow(renderer)
  val direct = renderer.render("  ok ")
"#;
    let (_project, analyzer) =
        scala_analyzer_with_files(&[("example/Workflow.scala", workflow_source)]);
    let target = definition(&analyzer, "example.ConsoleRenderer$.default");
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1000,
    ));

    assert_hit_line(&hits, line_of(workflow_source, "new Workflow(renderer)"));
    assert_hit_line(&hits, line_of(workflow_source, "val direct"));
    assert_no_hit_line(&hits, line_of(workflow_source, "import ConsoleRenderer"));
}

#[test]
fn scala_graph_resolves_visible_extension_method_usage() {
    let app_source = r#"
package app

object App {
  import app.Syntax.*
  val slugged = "Hello World".slug
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "app/Syntax.scala",
            r#"
package app

object Syntax:
  extension (value: String)
    def slug: String = value.toLowerCase
"#,
        ),
        ("app/App.scala", app_source),
    ]);
    let target = definition(&analyzer, "app.Syntax$.slug");
    let hits = scala_hits(&analyzer, &target, &["app/App.scala"]);

    assert_hit_line(&hits, line_of(app_source, "\"Hello World\".slug"));
}

#[test]
fn scala_graph_resolves_relative_wildcard_extension_method_usage() {
    let workflow_source = r#"
package example

object Syntax:
  extension (value: String)
    def slug: String =
      value.toLowerCase.replace(" ", "-")

object App:
  import Syntax.*
  val slugged = "Hello World".slug
"#;
    let (_project, analyzer) =
        scala_analyzer_with_files(&[("src/main/scala/example/Workflow.scala", workflow_source)]);
    let target = definition(&analyzer, "example.Syntax$.slug");
    let hits = scala_hits(
        &analyzer,
        &target,
        &["src/main/scala/example/Workflow.scala"],
    );

    assert_hit_line(&hits, line_of(workflow_source, "\"Hello World\".slug"));
}

#[test]
fn scala_graph_extension_usage_excludes_direct_member_call() {
    let workflow_source = r#"
package app

final case class User(slug: String)

object Syntax:
  extension (u: User)
    def slug: String = "extension"

object Workflow:
  import Syntax.*
  def run(u: User): String = u.slug
"#;
    let (_project, analyzer) =
        scala_analyzer_with_files(&[("app/Workflow.scala", workflow_source)]);
    let target = definition(&analyzer, "app.Syntax$.slug");
    let hits = scala_hits(&analyzer, &target, &["app/Workflow.scala"]);

    assert_no_hit_line(&hits, line_of(workflow_source, "u.slug"));
}

#[test]
fn scala_graph_extension_usage_requires_matching_receiver_type() {
    let workflow_source = r#"
package app

object Syntax:
  extension (s: String)
    def slug: String = s.toLowerCase

object Workflow:
  import Syntax.*
  def run(i: Int): String = i.slug
"#;
    let (_project, analyzer) =
        scala_analyzer_with_files(&[("app/Workflow.scala", workflow_source)]);
    let target = definition(&analyzer, "app.Syntax$.slug");
    let hits = scala_hits(&analyzer, &target, &["app/Workflow.scala"]);

    assert_no_hit_line(&hits, line_of(workflow_source, "i.slug"));
}

#[test]
fn scala_graph_extension_receiver_type_uses_declaration_context() {
    let syntax_source = r#"
package ext

final case class User(name: String)

object Syntax:
  extension (u: User)
    def slug: String = u.name.toLowerCase
"#;
    let app_source = r#"
package app

final case class User(name: String)

object Workflow:
  import ext.Syntax.*
  def run(u: User): String = u.slug
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        ("ext/Syntax.scala", syntax_source),
        ("app/Workflow.scala", app_source),
    ]);
    let target = definition(&analyzer, "ext.Syntax$.slug");
    let hits = scala_hits(&analyzer, &target, &["app/Workflow.scala"]);

    assert_no_hit_line(&hits, line_of(app_source, "u.slug"));
}

#[test]
fn scala_graph_extension_usage_survives_inapplicable_direct_member() {
    let workflow_source = r#"
package app

final case class User(name: String):
  def slug(): String = name

object Syntax:
  extension (u: User)
    def slug(i: Int): String = u.name + i.toString

object Workflow:
  import Syntax.*
  def run(u: User): String = u.slug(1)
"#;
    let (_project, analyzer) =
        scala_analyzer_with_files(&[("app/Workflow.scala", workflow_source)]);
    let target = definition(&analyzer, "app.Syntax$.slug");
    let hits = scala_hits(&analyzer, &target, &["app/Workflow.scala"]);

    assert_hit_line(&hits, line_of(workflow_source, "u.slug(1)"));
}

#[test]
fn scala_graph_returns_all_matching_ambiguous_extension_methods() {
    let app_source = r#"
package app

object App {
  import app.SyntaxA.*
  import app.SyntaxB.*
  val slugged = "Hello World".slug
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "app/SyntaxA.scala",
            r#"
package app

object SyntaxA:
  extension (value: String)
    def slug: String = value.toLowerCase
"#,
        ),
        (
            "app/SyntaxB.scala",
            r#"
package app

object SyntaxB:
  extension (value: String)
    def slug: String = value.reverse
"#,
        ),
        ("app/App.scala", app_source),
    ]);
    let target_a = definition(&analyzer, "app.SyntaxA$.slug");
    let hits_a = scala_hits(&analyzer, &target_a, &["app/App.scala"]);
    let target_b = definition(&analyzer, "app.SyntaxB$.slug");
    let hits_b = scala_hits(&analyzer, &target_b, &["app/App.scala"]);

    assert_hit_line(&hits_a, line_of(app_source, "\"Hello World\".slug"));
    assert_hit_line(&hits_b, line_of(app_source, "\"Hello World\".slug"));
}

#[test]
fn scala_graph_guardrails_cover_failure_fallback_zero_hits_and_candidate_boundaries() {
    let zero_fallback_source = r#"
package app

class ZeroFallback {
  def call(): Int = run()
}
"#;
    let included_source = r#"
package app

import pkg.Target

class Included {
  def call(target: Target): Int = target.run()
}
"#;
    let excluded_source = r#"
package app

import pkg.Target

class Excluded {
  def call(target: Target): Int = target.run()
}
"#;
    let fallback_source = r#"
package app

class FallbackConsumer {
  def call(): Unit = Ghost()
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Target.scala",
            r#"
package pkg

class Target {
  def run(): Int = 1
}
"#,
        ),
        ("app/ZeroFallback.scala", zero_fallback_source),
        ("app/Included.scala", included_source),
        ("app/Excluded.scala", excluded_source),
        ("app/FallbackConsumer.scala", fallback_source),
    ]);

    let run = definition(&analyzer, "pkg.Target.run");
    let zero_hits = hits(
        UsageFinder::new()
            .with_file_filter(|file| rel_path_string(file) == "app/ZeroFallback.scala")
            .find_usages_default(&analyzer, std::slice::from_ref(&run)),
    );
    assert!(
        zero_hits.is_empty(),
        "successful zero-hit graph result should not fall back to regex: {zero_hits:#?}"
    );

    let boundary_hits = scala_hits(&analyzer, &run, &["app/Included.scala"]);
    assert_hit_line(&boundary_hits, line_of(included_source, "target.run()"));
    assert_no_hit_in_enclosing(&boundary_hits, "app.Excluded.call");

    let fallback_target = CodeUnit::with_signature(
        analyzer
            .get_analyzed_files()
            .into_iter()
            .find(|file| rel_path_string(file) == "app/FallbackConsumer.scala")
            .expect("fallback source file"),
        CodeUnitType::Function,
        "pkg",
        "Ghost",
        None,
        true,
    );
    let direct = ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&fallback_target),
        &analyzer.get_analyzed_files().into_iter().collect(),
        1000,
    );
    assert!(
        matches!(direct, FuzzyResult::Failure { .. }),
        "unsupported synthetic constructor shape should fail graph seeding, got {direct:?}"
    );
    let fallback_query = UsageFinder::new().query(&analyzer, &[fallback_target], 1000, 1000);
    assert!(
        fallback_query.graph_failure.is_some(),
        "UsageFinder should surface graph failure diagnostics"
    );
    assert!(
        matches!(fallback_query.result, FuzzyResult::Failure { .. }),
        "UsageFinder should not use regex fallback for graph failure cases"
    );
}

#[test]
fn scala_graph_keeps_shadowing_lexical_and_method_local() {
    let consumer_source = r#"
package app

import pkg.{Utility, helper}

class Consumer {
  def nestedBlock(): Int = {
    val before = helper()
    {
      val helper = 0
      helper
    }
    val after = helper()
    before + after
  }

  def localFunctionShadow(): Int = {
    def helper(): Int = 0
    helper()
  }

  def patternShadow(value: Int): Int = value match {
    case helper => helper
  }

  def sibling(): Int = helper()

  def localQualifierShadow(): Int = {
    val Utility = other.Utility
    Utility.help()
  }

  def parameterQualifierShadow(Utility: other.Utility.type): Int = Utility.help()
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Api.scala",
            r#"
package pkg

def helper(): Int = 1

object Utility {
  def help(): Int = 1
}
"#,
        ),
        (
            "other/Utility.scala",
            r#"
package other

object Utility {
  def help(): Int = 2
}
"#,
        ),
        ("app/Consumer.scala", consumer_source),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = ScalaUsageGraphStrategy::new();

    let helper = definition(&analyzer, "pkg.helper");
    let helper_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&helper), &candidates, 1000));
    assert_hit_line(
        &helper_hits,
        line_of(consumer_source, "val before = helper()"),
    );
    assert_hit_line(
        &helper_hits,
        line_of(consumer_source, "val after = helper()"),
    );
    assert_hit_line(
        &helper_hits,
        line_of(consumer_source, "def sibling(): Int = helper()"),
    );
    assert_no_hit_in_enclosing(&helper_hits, "app.Consumer.localFunctionShadow");
    assert_no_hit_in_enclosing(&helper_hits, "app.Consumer.patternShadow");

    let help = definition(&analyzer, "pkg.Utility$.help");
    let help_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&help), &candidates, 1000));
    assert_no_hit_in_enclosing(&help_hits, "app.Consumer.localQualifierShadow");
    assert_no_hit_in_enclosing(&help_hits, "app.Consumer.parameterQualifierShadow");
}

#[test]
fn scala_template_field_initializers_preserve_member_identity_without_leaking_local_decoys() {
    let source = r#"
package app

class ORSet {
  protected val elementsMap: Map[String, Int] = Map.empty
  private val copiedBefore = elementsMap // positive-before
  private val localBlock = { val elementsMap = Map("local" -> 1); elementsMap } // negative-local-block
  private val copiedAfter = elementsMap // positive-after

  def methodLocal: Map[String, Int] = {
    val elementsMap = Map("method" -> 1)
    elementsMap // negative-method-local
  }

  final class Nested {
    private val elementsMap = Map("nested" -> 1)
    private val nestedCopy = elementsMap // negative-nested-owner
  }
}

final class InheritedORSet extends ORSet {
  private val inheritedCopy = elementsMap // positive-inherited
}

final class ShadowingORSet extends ORSet {
  protected val elementsMap: Map[String, Int] = Map("shadow" -> 1)
  private val shadowCopy = elementsMap // negative-subclass-shadow
}

final class Unrelated {
  private val elementsMap = Map("unrelated" -> 1)
  private val copied = elementsMap // negative-unrelated-owner
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[("app/ORSet.scala", source)]);
    let elements_map = definition(&analyzer, "app.ORSet.elementsMap");

    let hits = hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&elements_map)),
    );

    assert_hit_contains(&hits, "positive-before");
    assert_hit_contains(&hits, "positive-after");
    assert_hit_contains(&hits, "positive-inherited");
    assert_no_hit_contains(&hits, "negative-local-block");
    assert_no_hit_contains(&hits, "negative-method-local");
    assert_no_hit_contains(&hits, "negative-nested-owner");
    assert_no_hit_contains(&hits, "negative-subclass-shadow");
    assert_no_hit_contains(&hits, "negative-unrelated-owner");
}

#[test]
fn scala_graph_keeps_receiver_inference_scoped_and_conservative() {
    let consumer_source = r#"
package app

import pkg.{Other, Target}

class Consumer {
  def typedParam(target: Target): Int = target.run()

  def typedLocal(): Int = {
    val target: Target = new Target()
    target.run()
  }

  def constructorLocal(): Int = {
    val target = new Target()
    target.run()
  }

  def reassigned(): Int = {
    var target: Target = new Target()
    target = new Other()
    target.run()
  }

  def tupleDestructuring(pair: (Target, Int)): Int = {
    val (target, _) = pair
    target.run()
  }

  def aliasChain(): Int = {
    val target = new Target()
    val alias = target
    alias.run()
  }

  def leakedName(): Int = target.run()
}

class OtherConsumer {
  def leakedClass(): Int = target.run()
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Target.scala",
            r#"
package pkg

class Target {
  def run(): Int = 1
}
"#,
        ),
        (
            "pkg/Other.scala",
            r#"
package pkg

class Other {
  def run(): Int = 2
}
"#,
        ),
        ("app/Consumer.scala", consumer_source),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let run = definition(&analyzer, "pkg.Target.run");
    let run_hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&run),
        &candidates,
        1000,
    ));

    assert_hit_line(&run_hits, line_of(consumer_source, "def typedParam"));
    assert_hit_line(&run_hits, line_of(consumer_source, "target.run()"));
    assert_no_hit_in_enclosing(&run_hits, "app.Consumer.reassigned");
    assert_no_hit_in_enclosing(&run_hits, "app.Consumer.tupleDestructuring");
    assert_no_hit_in_enclosing(&run_hits, "app.Consumer.aliasChain");
    assert_no_hit_in_enclosing(&run_hits, "app.Consumer.leakedName");
    assert_no_hit_in_enclosing(&run_hits, "app.OtherConsumer.leakedClass");
}

#[test]
fn scala_graph_documents_inheritance_member_limits() {
    let consumer_source = r#"
package app

import pkg.{Base, Contract, Impl, Target}

class Concrete extends Base with Contract

class Consumer {
  def typeRefs(): Unit = {
    val concrete: Contract = new Concrete()
  }

  def inheritedMember(impl: Impl): Int = impl.run()

  def overriddenMember(target: Target): Int = target.run(1)

  def extensionMember(target: Target): Int = target.extra()

  def pathDependent(box: Box): Int = {
    val item: box.Item = box.item
    item.run()
  }
}

class Box {
  class Item {
    def run(): Int = 1
  }
  val item: Item = new Item()
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Types.scala",
            r#"
package pkg

trait Base
trait Contract

class Impl extends Contract {
  def run(): Int = 1
}

class Target {
  def run(): Int = 1
  def run(value: Int): Int = value
}

extension (target: Target) {
  def extra(): Int = 1
}
"#,
        ),
        ("app/Consumer.scala", consumer_source),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = ScalaUsageGraphStrategy::new();

    let contract = definition(&analyzer, "pkg.Contract");
    let contract_hits = hits(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&contract),
        &candidates,
        1000,
    ));
    assert_hit_line(&contract_hits, line_of(consumer_source, "with Contract"));
    assert_hit_line(
        &contract_hits,
        line_of(consumer_source, "val concrete: Contract"),
    );

    let run = definition(&analyzer, "pkg.Impl.run");
    let run_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&run), &candidates, 1000));
    assert_hit_line(&run_hits, line_of(consumer_source, "impl.run()"));

    let target_run = definition(&analyzer, "pkg.Target.run");
    let target_run_hits = hits(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&target_run),
        &candidates,
        1000,
    ));
    assert_hit_line(&target_run_hits, line_of(consumer_source, "target.run(1)"));
    assert_no_hit_in_enclosing(&target_run_hits, "app.Consumer.extensionMember");
    assert_no_hit_contains(&target_run_hits, "item.run()");
}

#[test]
fn scala_graph_connects_trait_methods_to_overrides_and_receiver_calls() {
    let workflow_source = r#"
package example

trait Renderer {
  def render(value: String): String
}

class ConsoleRenderer extends Renderer {
  override def render(value: String): String = value.trim
  def render(): String = "empty"
}

class OtherRenderer {
  def render(value: String): String = value
}

class Workflow(renderer: Renderer, console: ConsoleRenderer, other: OtherRenderer) {
  def viaTrait(value: String): String = renderer.render(value)
  def viaConcrete(value: String): String = console.render(value)
  def overload(): String = console.render()
  def unrelated(value: String): String = other.render(value)
}

object ConsoleRenderer {
  def default: ConsoleRenderer = new ConsoleRenderer()
}

object App {
  import ConsoleRenderer.{default => renderer}

  val direct = renderer.render("  ok ")
}
"#;
    let (_project, analyzer) =
        scala_analyzer_with_files(&[("example/Workflow.scala", workflow_source)]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let render = definition(&analyzer, "example.Renderer.render");
    let hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&render),
        &candidates,
        1000,
    ));

    assert_hit_line(&hits, line_of(workflow_source, "override def render"));
    assert_hit_line(&hits, line_of(workflow_source, "renderer.render(value)"));
    assert_hit_line(&hits, line_of(workflow_source, "console.render(value)"));
    assert_hit_line(&hits, line_of(workflow_source, "val direct"));
    assert_no_hit_in_enclosing(&hits, "example.Workflow.overload");
    assert_no_hit_in_enclosing(&hits, "example.Workflow.unrelated");
}

#[test]
fn scala_graph_trait_default_method_matches_inherited_receiver() {
    let workflow_source = r#"
package example

trait Logging {
  def info(msg: String): Unit = ()
}

class Service extends Logging

class OtherService {
  def info(msg: String): Unit = ()
}

class Workflow {
  def inherited(service: Service): Unit = service.info("started")
  def unrelated(other: OtherService): Unit = other.info("ignored")
}
"#;
    let (_project, analyzer) =
        scala_analyzer_with_files(&[("example/Workflow.scala", workflow_source)]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let info = definition(&analyzer, "example.Logging.info");
    let hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&info),
        &candidates,
        1000,
    ));

    assert_hit_line(&hits, line_of(workflow_source, "service.info"));
    assert_no_hit_in_enclosing(&hits, "example.Workflow.unrelated");
}

#[test]
fn scala_graph_trait_val_matches_inherited_receiver() {
    let workflow_source = r#"
package example

trait Identified {
  val id: String = "x"
}

class Service extends Identified

class OtherService {
  val id: String = "other"
}

class Workflow {
  def inherited(service: Service): String = service.id
  def unrelated(other: OtherService): String = other.id
}
"#;
    let (_project, analyzer) =
        scala_analyzer_with_files(&[("example/Workflow.scala", workflow_source)]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let id = definition(&analyzer, "example.Identified.id");
    let hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&id),
        &candidates,
        1000,
    ));

    assert_hit_line(&hits, line_of(workflow_source, "service.id"));
    assert_no_hit_in_enclosing(&hits, "example.Workflow.unrelated");
}

#[test]
fn scala_graph_trait_method_does_not_claim_receiver_overridden_by_val() {
    let workflow_source = r#"
package example

trait Identified {
  def id: String = "base"
}

class Service extends Identified {
  override val id: String = "service"
}

class Workflow {
  def concrete(service: Service): String = service.id
}
"#;
    let (_project, analyzer) =
        scala_analyzer_with_files(&[("example/Workflow.scala", workflow_source)]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let trait_id = definition(&analyzer, "example.Identified.id");
    let service_id = definition(&analyzer, "example.Service.id");

    let trait_hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&trait_id),
        &candidates,
        1000,
    ));
    let service_hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&service_id),
        &candidates,
        1000,
    ));

    assert_no_hit_in_enclosing(&trait_hits, "example.Workflow.concrete");
    assert_hit_line(&service_hits, line_of(workflow_source, "service.id"));
}

#[test]
fn scala_graph_trait_member_conflict_does_not_guess_inherited_receiver() {
    let workflow_source = r#"
package example

trait Primary {
  def id: String = "primary"
}

trait Secondary {
  def id: String = "secondary"
}

class Service extends Primary with Secondary

class Workflow {
  def ambiguous(service: Service): String = service.id
}
"#;
    let (_project, analyzer) =
        scala_analyzer_with_files(&[("example/Workflow.scala", workflow_source)]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let primary_id = definition(&analyzer, "example.Primary.id");
    let secondary_id = definition(&analyzer, "example.Secondary.id");

    let primary_hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&primary_id),
        &candidates,
        1000,
    ));
    let secondary_hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&secondary_id),
        &candidates,
        1000,
    ));

    assert_no_hit_in_enclosing(&primary_hits, "example.Workflow.ambiguous");
    assert_no_hit_in_enclosing(&secondary_hits, "example.Workflow.ambiguous");
}

#[test]
fn scala_unqualified_inherited_call_resolves_package_relative_mixin() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "akka/actor/dungeon/ReceiveTimeout.scala",
            r#"package akka.actor.dungeon

object ReceiveTimeout

trait ReceiveTimeout {
  protected def checkReceiveTimeoutIfNeeded(message: Any, beforeReceive: Any): Unit = ()
}
"#,
        ),
        (
            "akka/actor/other/OtherTimeout.scala",
            r#"package akka.actor.other

trait OtherTimeout {
  protected def checkReceiveTimeoutIfNeeded(message: Any, beforeReceive: Any): Unit = ()
}
"#,
        ),
        (
            "dungeon/ReceiveTimeout.scala",
            r#"package dungeon

trait ReceiveTimeout {
  protected def checkReceiveTimeoutIfNeeded(message: Any, beforeReceive: Any): Unit = ()
}
"#,
        ),
        (
            "akka/actor/ActorCell.scala",
            r#"package akka.actor

class ActorCell extends dungeon.ReceiveTimeout {
  def invoke(message: Any, beforeReceive: Any): Unit = {
    checkReceiveTimeoutIfNeeded(message, beforeReceive)
  }
}

class ConflictedCell extends dungeon.ReceiveTimeout with other.OtherTimeout {
  def invoke(message: Any, beforeReceive: Any): Unit = {
    checkReceiveTimeoutIfNeeded(message, beforeReceive)
  }
}

class DuplicateCell extends duplicate.SharedTimeout {
  def invoke(message: Any, beforeReceive: Any): Unit = {
    checkReceiveTimeoutIfNeeded(message, beforeReceive)
  }
}
"#,
        ),
        (
            "akka/actor/duplicate/First.scala",
            r#"package akka.actor.duplicate
trait SharedTimeout {
  protected def checkReceiveTimeoutIfNeeded(message: Any, beforeReceive: Any): Unit = ()
}
"#,
        ),
        (
            "akka/actor/duplicate/Second.scala",
            r#"package akka.actor.duplicate
trait SharedTimeout {
  protected def checkReceiveTimeoutIfNeeded(message: Any, beforeReceive: Any): Unit = ()
}
"#,
        ),
        (
            "unrelated/Cell.scala",
            r#"package unrelated
class Cell {
  def checkReceiveTimeoutIfNeeded(message: Any, beforeReceive: Any): Unit = ()
  def invoke(message: Any, beforeReceive: Any): Unit =
    checkReceiveTimeoutIfNeeded(message, beforeReceive)
}
"#,
        ),
    ]);

    let target = definition(
        &analyzer,
        "akka.actor.dungeon.ReceiveTimeout.checkReceiveTimeoutIfNeeded",
    );
    let target_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)));
    assert_hit_contains(
        &target_hits,
        "checkReceiveTimeoutIfNeeded(message, beforeReceive)",
    );
    assert_no_hit_in_enclosing(&target_hits, "akka.actor.ConflictedCell.invoke");
    assert_no_hit_in_enclosing(&target_hits, "unrelated.Cell.invoke");

    let root_package_decoy = definition(
        &analyzer,
        "dungeon.ReceiveTimeout.checkReceiveTimeoutIfNeeded",
    );
    let root_package_hits = hits(
        UsageFinder::new()
            .find_usages_default(&analyzer, std::slice::from_ref(&root_package_decoy)),
    );
    assert_no_hit_in_enclosing(&root_package_hits, "akka.actor.ActorCell.invoke");

    let duplicate = definition(
        &analyzer,
        "akka.actor.duplicate.SharedTimeout.checkReceiveTimeoutIfNeeded",
    );
    let duplicate_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&duplicate)));
    assert_no_hit_in_enclosing(&duplicate_hits, "akka.actor.DuplicateCell.invoke");
}

#[test]
fn scala_graph_connects_class_methods_to_overrides_and_child_receivers() {
    let source = r#"
package exact

class Base {
  def run(value: String): String = value
}

class Child extends Base {
  override def run(value: String): String = value.trim
}

class Workflow(base: Base, child: Child) {
  def viaBase(value: String): String = base.run(value)
  def viaChild(value: String): String = child.run(value)
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[("exact/Workflow.scala", source)]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let run = definition(&analyzer, "exact.Base.run");
    let hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&run),
        &candidates,
        1000,
    ));

    assert_hit_line(&hits, line_of(source, "base.run(value)"));
    assert_hit_line(&hits, line_of(source, "override def run"));
    assert_hit_line(&hits, line_of(source, "child.run(value)"));
}

#[test]
fn scala_graph_rejects_unrelated_factory_return_types() {
    let api_source = r#"
package api

trait Renderer {
  def render(value: String): String
}

object Factory {
  def default: Renderer = ???
}
"#;
    let app_source = r#"
package app

class Renderer {
  def render(value: String): String = value
}

object Factory {
  def default: Renderer = new Renderer()
}

object Consumer {
  import Factory.{default => renderer}

  val direct = renderer.render("ok")
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        ("api/Renderer.scala", api_source),
        ("app/Consumer.scala", app_source),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let render = definition(&analyzer, "api.Renderer.render");
    let hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&render),
        &candidates,
        1000,
    ));

    assert_no_hit_contains(&hits, "renderer.render");
}

#[test]
fn scala_usage_finder_finds_imported_top_level_members_by_default() {
    let consumer_source = r#"
package app

import pkg.{answer, helper}

class Consumer {
  def call(): Int = helper() + answer
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Api.scala",
            r#"
package pkg

def helper(): Int = 1
val answer: Int = 42
"#,
        ),
        ("app/Consumer.scala", consumer_source),
    ]);

    let helper = definition(&analyzer, "pkg.helper");
    let helper_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&helper)));
    assert_hit_line(&helper_hits, line_of(consumer_source, "helper() + answer"));

    let answer = definition(&analyzer, "pkg.answer");
    let answer_hits =
        hits(UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&answer)));
    assert_hit_line(&answer_hits, line_of(consumer_source, "helper() + answer"));
}

#[test]
fn scala_graph_resolves_imported_constructor_targets() {
    let consumer_source = r#"
package app

import pkg.Target

class Consumer {
  val target = new Target(1)
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Target.scala",
            r#"
package pkg

class Target(value: Int)
"#,
        ),
        ("app/Consumer.scala", consumer_source),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let constructor = definition(&analyzer, "pkg.Target.Target");
    let constructor_hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&constructor),
        &candidates,
        1000,
    ));

    assert_hit_line(&constructor_hits, line_of(consumer_source, "new Target(1)"));
}

#[test]
fn scala_graph_resolves_non_first_typed_parameter_receiver() {
    let consumer_source = r#"
package app

import pkg.{Other, Target}

class Consumer {
  def call(other: Other, target: Target): Int = target.run()
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Target.scala",
            r#"
package pkg

class Target {
  def run(): Int = 1
}
"#,
        ),
        (
            "pkg/Other.scala",
            r#"
package pkg

class Other
"#,
        ),
        ("app/Consumer.scala", consumer_source),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let run = definition(&analyzer, "pkg.Target.run");
    let run_hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&run),
        &candidates,
        1000,
    ));

    assert_hit_line(&run_hits, line_of(consumer_source, "target.run()"));
}

#[test]
fn scala_graph_resolves_commented_typed_parameter_receiver() {
    let consumer_source = r#"
package app

import pkg.Target

class Consumer {
  def call(target: /* receiver type */ Target): Int = target.run()
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Target.scala",
            r#"
package pkg

class Target {
  def run(): Int = 1
}
"#,
        ),
        ("app/Consumer.scala", consumer_source),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let run = definition(&analyzer, "pkg.Target.run");
    let run_hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&run),
        &candidates,
        1000,
    ));

    assert_hit_line(&run_hits, line_of(consumer_source, "target.run()"));
}

#[test]
fn scala_graph_uses_tree_sitter_for_member_qualifiers_and_call_arity() {
    let consumer_source = r#"
package app

import pkg.Target

class Consumer {
  def calls(target: Target): Int = {
    target.zero() +
      target.zero(1) +
      target.one(1) +
      target.one(nested(1, 2)) +
      target.one() +
      target.one(1, 2) +
      pkg.helper(target.one(2))
  }

  def nested(left: Int, right: Int): Int = left + right
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Target.scala",
            r#"
package pkg

class Target {
  def zero(): Int = 0
  def one(value: Int): Int = value
}

def helper(value: Int): Int = value
"#,
        ),
        ("app/Consumer.scala", consumer_source),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = ScalaUsageGraphStrategy::new();

    let zero_arg_run = definition(&analyzer, "pkg.Target.zero");
    let zero_arg_hits = hits(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&zero_arg_run),
        &candidates,
        1000,
    ));
    assert_hit_line(&zero_arg_hits, line_of(consumer_source, "target.zero() +"));
    assert_no_hit_line(&zero_arg_hits, line_of(consumer_source, "target.zero(1) +"));

    let one_arg_run = definition(&analyzer, "pkg.Target.one");
    let one_arg_hits = hits(strategy.find_usages(
        &analyzer,
        std::slice::from_ref(&one_arg_run),
        &candidates,
        1000,
    ));
    assert_hit_line(&one_arg_hits, line_of(consumer_source, "target.one(1) +"));
    assert_hit_line(
        &one_arg_hits,
        line_of(consumer_source, "target.one(nested(1, 2))"),
    );
    assert_hit_line(&one_arg_hits, line_of(consumer_source, "pkg.helper"));
    assert_no_hit_line(&one_arg_hits, line_of(consumer_source, "target.one() +"));
    assert_no_hit_line(&one_arg_hits, line_of(consumer_source, "target.one(1, 2)"));

    let helper = definition(&analyzer, "pkg.helper");
    let helper_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&helper), &candidates, 1000));
    assert_hit_line(&helper_hits, line_of(consumer_source, "pkg.helper"));
}

#[test]
fn scala_graph_uses_assignment_expression_for_receiver_shadowing() {
    let consumer_source = r#"
package app

import pkg.{Other, Target}

class Consumer {
  var field: Int = 0

  def qualifiedAssignment(target: Target): Int = {
    this.field = 2
    target.run()
  }

  def reassigned(): Int = {
    var target: Target = new Target()
    target = new Other()
    target.run()
  }
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Target.scala",
            r#"
package pkg

class Target {
  def run(): Int = 1
}
"#,
        ),
        (
            "pkg/Other.scala",
            r#"
package pkg

class Other {
  def run(): Int = 2
}
"#,
        ),
        ("app/Consumer.scala", consumer_source),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let run = definition(&analyzer, "pkg.Target.run");
    let run_hits = hits(ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&run),
        &candidates,
        1000,
    ));

    assert_hit_line(&run_hits, line_of(consumer_source, "target.run()"));
    assert_no_hit_in_enclosing(&run_hits, "app.Consumer.reassigned");
}

#[test]
fn scala_graph_enforces_max_usages_limit() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "pkg/Target.scala",
            r#"
package pkg

class Target
"#,
        ),
        (
            "pkg/Consumer.scala",
            r#"
package pkg

class Consumer {
  val one: Target = new Target()
  val two: Target = new Target()
}
"#,
        ),
    ]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let target = definition(&analyzer, "pkg.Target");
    let result = ScalaUsageGraphStrategy::new().find_usages(
        &analyzer,
        std::slice::from_ref(&target),
        &candidates,
        1,
    );

    match result {
        FuzzyResult::TooManyCallsites { limit, .. } => assert_eq!(1, limit),
        other => panic!("expected TooManyCallsites, got {other:?}"),
    }
}

#[test]
fn scala_usage_finder_resolves_package_lexical_field_and_application_projections() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "root/api/Types.scala",
            "package root.api\nclass ActorContext\n",
        ),
        (
            "root/consumer/sibling/Local.scala",
            "package root.consumer.sibling\nclass Local\n",
        ),
        (
            "root/model/Model.scala",
            r#"package root.model

object Result {
  opaque type Success[A] = A
  object Success
}
class Context { val system: Int = 1 }
trait Actor { val context: Context = new Context }
trait Generator[A]
trait GeneratorMarker[A]
object Generator {
  def anonymous[A] = new Generator[List[A]] with GeneratorMarker[List[A]] {} // positive-top-level-generic-trait-new
}
case class Good[A](value: A)
object Good { class GoodType[A] }

object Outer {
  object internal { class BranchData }
  class Holder { val branch: internal.BranchData = null } // positive-lexical-object-root
}

object Constructors {
  object ByteString1 {
    def apply(value: Int): ByteString1 = new ByteString1(value)
  }
  final class ByteString1 private (val value: Int) {
    def copy = ByteString1(value) // positive-nested-self-constructor
  }
  trait Generator[A]
  trait Marker[A]
  abstract class FlowVisitorCollect[A](empty: A, combine: (A, A) => A)
  class Inside { val bytes = ByteString1(1) } // positive-universal-constructor
}

object Qualified {
  final class Applied(val value: Int)
  object Applied { def apply(value: Int): Applied = new Applied(value) }
  final class Extracted(val value: Int)
  object Extracted { def unapply(value: Any): Option[Int] = None }
  object Factory { def apply(value: Int): Int = value }
  object Pattern { def unapply(value: Any): Option[Int] = None }
}
"#,
        ),
        (
            "root/model/PatternUse.scala",
            r#"package root.model
object PatternUse {
  val constructed = Good(1) // positive-synthetic-constructor-apply
  def extract(value: Any): Any = value match {
    case (Good(found), Good(_)) => found // positive-synthetic-constructor-extractor
    case _ => value
  }
}
"#,
        ),
        (
            "root/consumer/Use.scala",
            r#"package root.consumer

import root.{api => classic}
import root.api
import root.model.*
import root.model.Constructors.*

class Child extends Actor {
  val inherited = context // positive-inherited-field
}

object Use {
  val aliased: classic.ActorContext = null // positive-package-alias
  val directlyImported: api.ActorContext = null // positive-direct-package
  val relative: sibling.Local = null // positive-relative-package
  val stable: Result.Success[Int] = 1 // positive-stable-type-member
  val term = Result.Success // negative-term-for-type-member
  val explicit = new Constructors.FlowVisitorCollect[Int](0, _ + _) {} // positive-generic-new
  val anonymous = new Constructors.Generator[Int] with Constructors.Marker[Int] {} // positive-generic-trait-new
  val qualifiedApply = Qualified.Applied(2) // positive-qualified-apply
  def qualifiedExtract(value: Any): Int = value match {
    case Qualified.Extracted(found) => found // positive-qualified-extractor
    case _ => 0
  }
  val objectApply = Qualified.Factory(3) // positive-qualified-object-apply
  def objectExtract(value: Any): Int = value match {
    case Qualified.Pattern(found) => found // positive-qualified-object-extractor
    case _ => 0
  }
}
"#,
        ),
        (
            "decoy/api/Types.scala",
            "package decoy.api\nclass ActorContext\n",
        ),
        (
            "decoy/Objects.scala",
            "package decoy\nobject Api { class ActorContext }\n",
        ),
        (
            "collision/Api.scala",
            "package collision\nobject Api { class ActorContext }\n",
        ),
        (
            "root/consumer/collision/Api.scala",
            "package root.consumer.collision\nobject Api { class ActorContext }\n",
        ),
        (
            "root/consumer/Ambiguous.scala",
            r#"package root.consumer
import root.{api => clash}
import decoy.{api => clash}
object Ambiguous {
  val wrong: clash.ActorContext = null // negative-conflicting-package-alias
}
"#,
        ),
        (
            "root/consumer/CrossNamespace.scala",
            r#"package root.consumer
import root.{api => mixed}
import decoy.{Api => mixed}
object CrossNamespace {
  val wrong: mixed.ActorContext = null // negative-package-object-alias
}
"#,
        ),
        (
            "root/consumer/CandidateCollision.scala",
            r#"package root.consumer
import collision.{Api => overlap}
object CandidateCollision {
  val selected: overlap.ActorContext = null // positive-relative-object-import
}
"#,
        ),
    ]);

    let provider = ExplicitCandidateProvider::new(Arc::new(
        analyzer.get_analyzed_files().into_iter().collect(),
    ));
    for (target, marker) in [
        ("root.api.ActorContext", "positive-package-alias"),
        ("root.api.ActorContext", "positive-direct-package"),
        ("root.consumer.sibling.Local", "positive-relative-package"),
        ("root.model.Result$.Success", "positive-stable-type-member"),
        (
            "root.model.Outer$.internal$.BranchData",
            "positive-lexical-object-root",
        ),
        ("root.model.Actor.context", "positive-inherited-field"),
        (
            "root.model.Constructors$.FlowVisitorCollect.FlowVisitorCollect",
            "positive-generic-new",
        ),
        (
            "root.model.Constructors$.Generator",
            "positive-generic-trait-new",
        ),
        (
            "root.model.Generator",
            "positive-top-level-generic-trait-new",
        ),
        // A nested same-name class/object call cannot encode whether forward
        // selected the companion apply or Scala 3 universal constructor. Keep
        // both exact callable identities discoverable when their shapes agree.
        (
            "root.model.Constructors$.ByteString1.ByteString1",
            "positive-nested-self-constructor",
        ),
        (
            "root.model.Good.Good",
            "positive-synthetic-constructor-extractor",
        ),
        (
            "root.model.Good.Good",
            "positive-synthetic-constructor-apply",
        ),
        (
            "root.model.Qualified$.Applied$.apply",
            "positive-qualified-apply",
        ),
        (
            "root.model.Qualified$.Extracted$.unapply",
            "positive-qualified-extractor",
        ),
        (
            "root.model.Qualified$.Factory$.apply",
            "positive-qualified-object-apply",
        ),
        (
            "root.model.Qualified$.Pattern$.unapply",
            "positive-qualified-object-extractor",
        ),
        (
            "root.consumer.collision.Api$.ActorContext",
            "positive-relative-object-import",
        ),
    ] {
        let target = definition(&analyzer, target);
        let target_hits = hits(
            UsageFinder::new()
                .with_authoritative_scope(true)
                .query_with_provider(
                    &analyzer,
                    std::slice::from_ref(&target),
                    Some(&provider),
                    100,
                    100,
                )
                .result,
        );
        assert_hit_contains(&target_hits, marker);
        assert_no_hit_contains(&target_hits, "negative-conflicting-package-alias");
        assert_no_hit_contains(&target_hits, "negative-package-object-alias");
        assert_no_hit_contains(&target_hits, "negative-term-for-type-member");
    }

    for target in ["decoy.Api$.ActorContext", "collision.Api$.ActorContext"] {
        let target = definition(&analyzer, target);
        let target_hits = hits(
            UsageFinder::new()
                .with_authoritative_scope(true)
                .query_with_provider(
                    &analyzer,
                    std::slice::from_ref(&target),
                    Some(&provider),
                    100,
                    100,
                )
                .result,
        );
        assert_no_hit_contains(&target_hits, "negative-package-object-alias");
        assert_no_hit_contains(&target_hits, "positive-relative-object-import");
    }
}
