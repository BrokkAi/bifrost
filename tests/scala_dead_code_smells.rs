mod common;

use brokk_bifrost::code_quality::{
    ReportDeadCodeAndUnusedAbstractionSmellsParams, report_dead_code_and_unused_abstraction_smells,
};
use brokk_bifrost::{CodeUnit, IAnalyzer, Language, ScalaAnalyzer};
use common::InlineTestProject;

fn scala_analyzer_with_files(
    files: &[(&str, &str)],
) -> (common::BuiltInlineTestProject, ScalaAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Scala);
    for (path, contents) in files {
        builder = builder.file(*path, *contents);
    }
    let project = builder.build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn scala_definition(analyzer: &ScalaAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing Scala definition for {fq_name}"))
}

fn report(
    analyzer: &dyn IAnalyzer,
    params: ReportDeadCodeAndUnusedAbstractionSmellsParams,
) -> String {
    report_dead_code_and_unused_abstraction_smells(analyzer, params).report
}

#[test]
fn scala_dead_code_smell_reports_unused_private_method() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "example/Service.scala",
        r#"
package example

class Service {
  private def helper(): Int = 1

  def entry(): Int = 2
}
"#,
    )]);
    let helper = scala_definition(&analyzer, "example.Service.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["example/Service.scala".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("example.Service.helper"), "{report}");
    assert!(report.contains("no non-self usages found"), "{report}");
    assert!(
        report.contains("symbol has no workspace inbound usage evidence in Scala"),
        "{report}"
    );
    assert!(report.contains("| 0 | 0 |"), "{report}");
}

#[test]
fn scala_dead_code_smell_reports_one_call_method() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "example/Service.scala",
        r#"
package example

class Service {
  def wrapper(): Int = leaf()

  private def leaf(): Int = 1
}
"#,
    )]);
    let leaf = scala_definition(&analyzer, "example.Service.leaf");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["example/Service.scala".to_string()],
            fq_names: vec![leaf.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("example.Service.leaf"), "{report}");
    assert!(
        report.contains("one workspace inbound edge from example.Service.wrapper"),
        "{report}"
    );
    assert!(report.contains("| 1 | 0 |"), "{report}");
}

#[test]
fn scala_type_usage_prevents_false_dead_code_finding() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "example/Target.scala",
        r#"
package example

class Target

class Consumer {
  def make(): Target = new Target()
}

class OtherConsumer {
  def make(): Target = new Target()
}
"#,
    )]);

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["example/Target.scala".to_string()],
            fq_names: vec!["example.Target".to_string()],
            ..Default::default()
        },
    );

    assert!(report.contains("No dead code"), "{report}");
    assert!(!report.contains("| `class` | `example.Target`"), "{report}");
}

#[test]
fn scala_dead_code_smell_does_not_flag_symbol_with_multiple_inbound_edges() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "example/Service.scala",
        r#"
package example

class Service {
  def firstCaller(): Int = helper()

  def secondCaller(): Int = helper()

  private def helper(): Int = 1
}
"#,
    )]);
    let helper = scala_definition(&analyzer, "example.Service.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["example/Service.scala".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("No dead code"), "{report}");
    assert!(
        !report.contains("| `function` | `example.Service.helper`"),
        "{report}"
    );
}

#[test]
fn scala_dead_code_smell_honors_usage_candidate_file_cap() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "example/Service.scala",
            "package example\nclass Service { private def helper(): Int = 1 }\n",
        ),
        ("example/Other.scala", "package example\nclass Other\n"),
    ]);
    let helper = scala_definition(&analyzer, "example.Service.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec![
                "example/Service.scala".to_string(),
                "example/Other.scala".to_string(),
            ],
            fq_names: vec![helper.fq_name()],
            max_usage_candidate_files: 1,
            ..Default::default()
        },
    );

    assert!(
        report.contains("Scala usage graph candidate files exceeded cap 1"),
        "{report}"
    );
    assert!(
        !report.contains("| `function` | `example.Service.helper`"),
        "{report}"
    );
}

#[test]
fn scala_dead_code_smell_honors_usage_cap() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "example/Service.scala",
        r#"
package example

class Service {
  def firstCaller(): Int = helper()

  def secondCaller(): Int = helper()

  private def helper(): Int = 1
}
"#,
    )]);
    let helper = scala_definition(&analyzer, "example.Service.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["example/Service.scala".to_string()],
            fq_names: vec![helper.fq_name()],
            max_usages_per_symbol: 1,
            ..Default::default()
        },
    );

    assert!(
        report.contains("too many workspace inbound call sites (2, limit 1)"),
        "{report}"
    );
    assert!(
        !report.contains("| `function` | `example.Service.helper`"),
        "{report}"
    );
}

#[test]
fn scala_field_candidate_stays_on_precise_path_for_bare_identifier_reads() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "example/Service.scala",
        r#"
package example

class Service {
  private val cached: Int = 1

  def read(): Int = cached
}
"#,
    )]);
    let cached = scala_definition(&analyzer, "example.Service.cached");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["example/Service.scala".to_string()],
            fq_names: vec![cached.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        report.contains("Scala field usage evidence was inconclusive"),
        "{report}"
    );
    assert!(
        !report.contains("| `field` | `example.Service.cached`"),
        "{report}"
    );
}

#[test]
fn scala_constructor_candidate_stays_on_precise_path() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "example/Target.scala",
        r#"
package example

class Target(value: Int)

object Maker {
  def make(): Target = new Target(1)
}
"#,
    )]);
    let constructor = scala_definition(&analyzer, "example.Target.Target");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["example/Target.scala".to_string()],
            fq_names: vec![constructor.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("example.Target.Target"), "{report}");
    assert!(
        report.contains("only usage: example/Target.scala"),
        "{report}"
    );
    assert!(!report.contains("no non-self usages found"), "{report}");
}

#[test]
fn scala_overloaded_methods_stay_on_precise_path() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "example/Service.scala",
        r#"
package example

class Service {
  def call(): Int = overloaded(1)

  def overloaded(): Int = 1

  def overloaded(value: Int): Int = value
}
"#,
    )]);
    let overload = scala_definition(&analyzer, "example.Service.overloaded");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["example/Service.scala".to_string()],
            fq_names: vec![overload.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("example.Service.overloaded"), "{report}");
    assert!(
        !report.contains("one workspace inbound edge from example.Service.call"),
        "{report}"
    );
}

#[test]
fn scala_direct_member_import_candidate_stays_on_precise_path() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "example/Target.scala",
            r#"
package example

object Target {
  def run(): Int = 1
}
"#,
        ),
        (
            "example/Consumer.scala",
            r#"
package example

import example.Target.run

class Consumer {
  def call(): Int = run()
}
"#,
        ),
    ]);
    let run = scala_definition(&analyzer, "example.Target$.run");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec![
                "example/Target.scala".to_string(),
                "example/Consumer.scala".to_string(),
            ],
            fq_names: vec![run.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("example.Target$.run"), "{report}");
    assert!(
        report.contains("only usage: example/Consumer.scala"),
        "{report}"
    );
    assert!(!report.contains("no non-self usages found"), "{report}");
}

#[test]
fn scala_wildcard_import_candidate_stays_on_precise_path() {
    let (_project, analyzer) = scala_analyzer_with_files(&[
        (
            "example/Target.scala",
            r#"
package example

object Target {
  def run(): Int = 1
}
"#,
        ),
        (
            "example/Consumer.scala",
            r#"
package example

import example.Target._

class Consumer {
  def call(): Int = run()
}
"#,
        ),
    ]);
    let run = scala_definition(&analyzer, "example.Target$.run");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec![
                "example/Target.scala".to_string(),
                "example/Consumer.scala".to_string(),
            ],
            fq_names: vec![run.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("example.Target$.run"), "{report}");
    assert!(
        report.contains("only usage: example/Consumer.scala"),
        "{report}"
    );
    assert!(!report.contains("no non-self usages found"), "{report}");
}

#[test]
fn scala_public_api_uses_conservative_wording_and_score() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "example/PublicApi.scala",
        r#"
package example

class PublicApi {
  def extensionPoint(): Unit = ()
}
"#,
    )]);
    let extension_point = scala_definition(&analyzer, "example.PublicApi.extensionPoint");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["example/PublicApi.scala".to_string()],
            fq_names: vec![extension_point.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        report.contains("example.PublicApi.extensionPoint"),
        "{report}"
    );
    assert!(
        report.contains("public Scala symbol is unreferenced in workspace"),
        "{report}"
    );
    assert!(report.contains("0.55"), "{report}");
    assert!(!report.contains("generated residue"), "{report}");
}

#[test]
fn scala_private_method_keeps_strong_wording() {
    let (_project, analyzer) = scala_analyzer_with_files(&[(
        "example/Service.scala",
        r#"
package example

class Service {
  private def helper(): Int = 1
}
"#,
    )]);
    let helper = scala_definition(&analyzer, "example.Service.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["example/Service.scala".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("example.Service.helper"), "{report}");
    assert!(
        report.contains("symbol has no workspace inbound usage evidence in Scala"),
        "{report}"
    );
    assert!(report.contains("0.90"), "{report}");
    assert!(!report.contains("public Scala symbol"), "{report}");
}
