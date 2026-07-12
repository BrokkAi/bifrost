mod common;

use brokk_bifrost::usages::{
    FuzzyResult, ScalaUsageGraphStrategy, UsageAnalyzer, UsageFinder, UsageHit, UsageHitKind,
};
use brokk_bifrost::{CodeUnit, CodeUnitType, IAnalyzer, Language, ScalaAnalyzer};
use common::InlineTestProject;

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

fn line_of(source: &str, needle: &str) -> usize {
    source
        .lines()
        .position(|line| line.contains(needle))
        .map(|line| line + 1)
        .unwrap_or_else(|| panic!("missing line containing {needle:?}"))
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
    assert_no_hit_in_enclosing(&target_run_hits, "app.Consumer.overriddenMember");
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
fn scala_graph_keeps_class_methods_exact_owner() {
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
    assert_no_hit_contains(&hits, "override def run");
    assert_no_hit_in_enclosing(&hits, "exact.Workflow.viaChild");
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
