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
        (
            "app/Consumer.scala",
            r#"
package app

import pkg.{Target as AliasTarget, Contract}
import pkg.Utility

class Consumer extends Contract {
  val target: AliasTarget = new AliasTarget(1)

  def call(): Int = {
    if (Utility.flag) {
      target.field = 2
      Utility.help() + target.run() + target.field
    } else {
      0
    }
  }
}
"#,
        ),
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
    assert!(field_hits.iter().any(|hit| hit.contains("target.field")));

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
    assert!(
        ready_hits.iter().all(|hit| hit.line != 9),
        "OtherMode.Ready should not be reported: {ready_hits:#?}"
    );
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
    assert!(
        helper_hits.iter().all(|hit| hit.line != 11),
        "other.helper() should not be reported: {helper_hits:#?}"
    );

    let answer = definition(&analyzer, "pkg.answer");
    let answer_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&answer), &candidates, 1000));
    assert_hit_contains(&answer_hits, "helper() + answer");
    assert_hit_contains(&answer_hits, "answer + counter");
    assert!(
        answer_hits.iter().all(|hit| hit.line != 11),
        "other.answer should not be reported: {answer_hits:#?}"
    );

    let counter = definition(&analyzer, "pkg.counter");
    let counter_hits =
        hits(strategy.find_usages(&analyzer, std::slice::from_ref(&counter), &candidates, 1000));
    assert_hit_contains(&counter_hits, "counter = counter + 1");
    assert_hit_contains(&counter_hits, "answer + counter");
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
