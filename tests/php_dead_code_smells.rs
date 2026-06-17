mod common;

use brokk_bifrost::code_quality::{
    ReportDeadCodeAndUnusedAbstractionSmellsParams, report_dead_code_and_unused_abstraction_smells,
};
use brokk_bifrost::{CodeUnit, CodeUnitType, IAnalyzer, Language, PhpAnalyzer};
use common::InlineTestProject;

fn php_analyzer_with_files(
    files: &[(&str, &str)],
) -> (common::BuiltInlineTestProject, PhpAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Php);
    for (path, contents) in files {
        builder = builder.file(*path, *contents);
    }
    let project = builder.build();
    let analyzer = PhpAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definition(analyzer: &PhpAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing PHP definition for {fq_name}"))
}

fn declaration_by<F>(analyzer: &PhpAnalyzer, mut predicate: F) -> CodeUnit
where
    F: FnMut(&CodeUnit) -> bool,
{
    let declarations = analyzer.get_all_declarations();
    declarations
        .iter()
        .find(|unit| predicate(unit))
        .cloned()
        .unwrap_or_else(|| panic!("missing matching PHP declaration in {declarations:#?}"))
}

fn member_field(analyzer: &PhpAnalyzer, owner: &str, name: &str) -> CodeUnit {
    declaration_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Field
            && unit.identifier() == name
            && analyzer
                .parent_of(unit)
                .is_some_and(|parent| parent.fq_name() == owner)
    })
}

fn report(
    analyzer: &dyn IAnalyzer,
    params: ReportDeadCodeAndUnusedAbstractionSmellsParams,
) -> String {
    report_dead_code_and_unused_abstraction_smells(analyzer, params).report
}

#[test]
fn php_dead_code_smell_reports_unused_function_with_public_wording() {
    let (_project, analyzer) = php_analyzer_with_files(&[(
        "Service.php",
        r#"<?php
namespace App;
function helper(): void {}
"#,
    )]);
    let helper = definition(&analyzer, "App.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Service.php".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("App.helper"), "{report}");
    assert!(report.contains("no non-self usages found"), "{report}");
    assert!(
        report.contains("public PHP symbol is unreferenced in workspace"),
        "{report}"
    );
    assert!(report.contains("0.55"), "{report}");
}

#[test]
fn php_dead_code_smell_reports_one_call_function() {
    let (_project, analyzer) = php_analyzer_with_files(&[(
        "Service.php",
        r#"<?php
namespace App;
function leaf(): int { return 1; }
function wrapper(): int { return leaf(); }
"#,
    )]);
    let leaf = definition(&analyzer, "App.leaf");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Service.php".to_string()],
            fq_names: vec![leaf.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("App.leaf"), "{report}");
    assert!(
        report.contains("one workspace inbound edge from App.wrapper"),
        "{report}"
    );
    assert!(report.contains("| 1 | 1 |"), "{report}");
}

#[test]
fn php_type_usage_from_another_file_prevents_finding() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Target.php",
            r#"<?php
namespace App;
class Target {}
"#,
        ),
        (
            "Consumer.php",
            r#"<?php
namespace App;
function first(Target $target): Target { return new Target(); }
function second(Target $target): Target { return new Target(); }
"#,
        ),
    ]);
    let target = definition(&analyzer, "App.Target");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Target.php".to_string()],
            fq_names: vec![target.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("App.Target |"), "{report}");
    assert!(
        report.contains("No dead code or unused abstraction smells"),
        "{report}"
    );
}

#[test]
fn php_symbol_with_two_distinct_inbound_callers_is_not_flagged() {
    let (_project, analyzer) = php_analyzer_with_files(&[(
        "Service.php",
        r#"<?php
namespace App;
function helper(): int { return 1; }
function first(): int { return helper(); }
function second(): int { return helper(); }
"#,
    )]);
    let helper = definition(&analyzer, "App.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Service.php".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("App.helper |"), "{report}");
    assert!(
        report.contains("No dead code or unused abstraction smells"),
        "{report}"
    );
}

#[test]
fn php_dead_code_smell_honors_usage_candidate_file_cap() {
    let (_project, analyzer) = php_analyzer_with_files(&[
        (
            "Service.php",
            r#"<?php
namespace App;
function helper(): void {}
"#,
        ),
        (
            "Other.php",
            r#"<?php
namespace App;
class Other {}
"#,
        ),
    ]);
    let helper = definition(&analyzer, "App.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Service.php".to_string()],
            fq_names: vec![helper.fq_name()],
            max_usage_candidate_files: 1,
            ..Default::default()
        },
    );

    assert!(
        report.contains("PHP usage graph candidate files exceeded cap 1"),
        "{report}"
    );
    assert!(!report.contains("App.helper |"), "{report}");
}

#[test]
fn php_dead_code_smell_honors_usage_cap() {
    let (_project, analyzer) = php_analyzer_with_files(&[(
        "Service.php",
        r#"<?php
namespace App;
function helper(): int { return 1; }
function first(): int { return helper(); }
function second(): int { return helper(); }
"#,
    )]);
    let helper = definition(&analyzer, "App.helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Service.php".to_string()],
            fq_names: vec![helper.fq_name()],
            max_usages_per_symbol: 1,
            ..Default::default()
        },
    );

    assert!(
        report.contains("too many workspace inbound call sites (2, limit 1)"),
        "{report}"
    );
    assert!(!report.contains("App.helper |"), "{report}");
}

#[test]
fn php_public_class_uses_conservative_wording_and_score() {
    let (_project, analyzer) = php_analyzer_with_files(&[(
        "Api.php",
        r#"<?php
namespace App;
class Api {}
"#,
    )]);
    let api = definition(&analyzer, "App.Api");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Api.php".to_string()],
            fq_names: vec![api.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("App.Api"), "{report}");
    assert!(
        report.contains("public PHP symbol is unreferenced in workspace"),
        "{report}"
    );
    assert!(report.contains("0.55"), "{report}");
}

#[test]
fn php_constructor_candidate_stays_on_precise_path() {
    let (_project, analyzer) = php_analyzer_with_files(&[(
        "Target.php",
        r#"<?php
namespace App;
class Target {
    public function __construct() {}
}
function build(): Target { return new Target(); }
"#,
    )]);
    let constructor = definition(&analyzer, "App.Target.__construct");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Target.php".to_string()],
            fq_names: vec![constructor.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("no non-self usages found"), "{report}");
    assert!(!report.contains("one workspace inbound edge"), "{report}");
}

#[test]
fn php_method_candidate_stays_on_precise_path() {
    let (_project, analyzer) = php_analyzer_with_files(&[(
        "Target.php",
        r#"<?php
namespace App;
class Target {
    public function run(): void {}
}
function use_target(Target $target): void { $target->run(); }
"#,
    )]);
    let run = definition(&analyzer, "App.Target.run");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Target.php".to_string()],
            fq_names: vec![run.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("no non-self usages found"), "{report}");
    assert!(!report.contains("one workspace inbound edge"), "{report}");
}

#[test]
fn php_property_candidate_stays_on_precise_path() {
    let (_project, analyzer) = php_analyzer_with_files(&[(
        "Target.php",
        r#"<?php
namespace App;
class Target {
    public int $value;
}
function read(Target $target): int { return $target->value; }
"#,
    )]);
    let value = member_field(&analyzer, "App.Target", "value");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Target.php".to_string()],
            fq_names: vec![value.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("no non-self usages found"), "{report}");
    assert!(!report.contains("one workspace inbound edge"), "{report}");
}
