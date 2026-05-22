mod common;

use brokk_bifrost::usages::{
    FuzzyResult, ScalaUsageGraphStrategy, UsageAnalyzer, UsageFinder, UsageHit,
};
use brokk_bifrost::{CodeUnit, IAnalyzer, Language, ScalaAnalyzer};
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

fn line_of(source: &str, needle: &str) -> usize {
    source
        .lines()
        .position(|line| line.contains(needle))
        .map(|line| line + 1)
        .unwrap_or_else(|| panic!("missing line containing {needle:?}"))
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
    this.field = 2
    this.run()
    field + run()
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
}
"#;
    let (_project, analyzer) = scala_analyzer_with_files(&[("pkg/Target.scala", target_source)]);
    let candidates = analyzer.get_analyzed_files().into_iter().collect();
    let strategy = ScalaUsageGraphStrategy::new();

    let field = definition(&analyzer, "pkg.Target.field");
    let field_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&field), &candidates, 1000));
    assert_hit_line(&field_hits, line_of(target_source, "this.field = 2"));
    assert_hit_line(&field_hits, line_of(target_source, "field + run()"));
    assert_no_hit_line(&field_hits, line_of(target_source, "this.field = 4"));
    assert_no_hit_in_enclosing(&field_hits, "pkg.Other.call");

    let run = definition(&analyzer, "pkg.Target.run");
    let run_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&run), &candidates, 1000));
    assert_hit_line(&run_hits, line_of(target_source, "this.run()"));
    assert_hit_line(&run_hits, line_of(target_source, "field + run()"));
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
