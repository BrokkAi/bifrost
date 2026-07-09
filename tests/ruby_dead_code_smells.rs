mod common;

use brokk_bifrost::code_quality::{
    ReportDeadCodeAndUnusedAbstractionSmellsParams, report_dead_code_and_unused_abstraction_smells,
};
use brokk_bifrost::{CodeUnit, IAnalyzer, Language, RubyAnalyzer};
use common::InlineTestProject;

fn ruby_analyzer_with_files(
    files: &[(&str, &str)],
) -> (common::BuiltInlineTestProject, RubyAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Ruby);
    for (path, contents) in files {
        builder = builder.file(*path, *contents);
    }
    let project = builder.build();
    let analyzer = RubyAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definition(analyzer: &RubyAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing Ruby definition for {fq_name}"))
}

fn report(
    analyzer: &dyn IAnalyzer,
    params: ReportDeadCodeAndUnusedAbstractionSmellsParams,
) -> String {
    report_dead_code_and_unused_abstraction_smells(analyzer, params).report
}

#[test]
fn ruby_dead_code_smell_reports_unused_method() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "service.rb",
        r#"
class Service
  def unused
    1
  end
end
"#,
    )]);
    let unused = definition(&analyzer, "Service.unused");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.rb".to_string()],
            fq_names: vec![unused.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("Service.unused"), "{report}");
    assert!(report.contains("no non-self usages found"), "{report}");
    assert!(
        report.contains("public Ruby symbol is unreferenced in workspace"),
        "{report}"
    );
}

#[test]
fn ruby_method_called_through_proven_receiver_is_not_flagged() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "service.rb",
        r#"
class Service
  def used
    1
  end
end

class Consumer
  def call
    service = Service.new
    service.used
  end

  def call_again
    service = Service.new
    service.used
  end
end
"#,
    )]);
    let used = definition(&analyzer, "Service.used");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.rb".to_string()],
            fq_names: vec![used.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("Service.used |"), "{report}");
    assert!(
        report.contains("No dead code or unused abstraction smells"),
        "{report}"
    );
}

#[test]
fn ruby_module_function_called_module_side_is_not_flagged() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "helpers.rb",
        r#"
module Helpers
  def normalize
    "ok"
  end
  module_function :normalize
end

class Consumer
  def call
    Helpers.normalize
  end

  def call_again
    Helpers.normalize
  end
end
"#,
    )]);
    let normalize = definition(&analyzer, "Helpers.normalize");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["helpers.rb".to_string()],
            fq_names: vec![normalize.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("Helpers.normalize |"), "{report}");
    assert!(
        report.contains("No dead code or unused abstraction smells"),
        "{report}"
    );
}

#[test]
fn ruby_dead_code_smell_unproven_receiver_usage_is_inconclusive_not_dead() {
    let (_project, analyzer) = ruby_analyzer_with_files(&[(
        "service.rb",
        r#"
class Service
  def target
    1
  end

  def unused
    2
  end

  def used
    3
  end

  def dispatched
    4
  end
end

class Consumer
  def use_unknown(service)
    service.target
  end

  def use_dynamic(service)
    service.public_send(:dispatched)
  end

  def use_proven
    service = Service.new
    service.used
  end
end
"#,
    )]);
    let target = definition(&analyzer, "Service.target");
    let unused = definition(&analyzer, "Service.unused");
    let used = definition(&analyzer, "Service.used");
    let dispatched = definition(&analyzer, "Service.dispatched");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.rb".to_string()],
            fq_names: vec![
                target.fq_name(),
                unused.fq_name(),
                used.fq_name(),
                dispatched.fq_name(),
            ],
            ..Default::default()
        },
    );

    assert!(
        report.contains("Service.target`: 1 structurally matching usage site(s)"),
        "{report}"
    );
    assert!(!report.contains("Service.target |"), "{report}");
    assert!(
        report.contains("Service.dispatched`: 1 structurally matching usage site(s)"),
        "{report}"
    );
    assert!(!report.contains("Service.dispatched |"), "{report}");
    assert!(
        report.contains("Service.unused") && report.contains("no non-self usages found"),
        "{report}"
    );
    assert!(!report.contains("Service.used |"), "{report}");
}
