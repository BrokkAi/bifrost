mod common;

use brokk_bifrost::code_quality::{
    ReportDeadCodeAndUnusedAbstractionSmellsParams, report_dead_code_and_unused_abstraction_smells,
};
use brokk_bifrost::{
    CodeUnit, IAnalyzer, JavascriptAnalyzer, Language, PythonAnalyzer, TypescriptAnalyzer,
};
use common::InlineTestProject;

fn python_definition(analyzer: &PythonAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn js_definition(analyzer: &JavascriptAnalyzer, predicate: impl Fn(&CodeUnit) -> bool) -> CodeUnit {
    analyzer
        .get_all_declarations()
        .into_iter()
        .find(predicate)
        .expect("missing JS definition")
}

fn ts_definition(analyzer: &TypescriptAnalyzer, predicate: impl Fn(&CodeUnit) -> bool) -> CodeUnit {
    analyzer
        .get_all_declarations()
        .into_iter()
        .find(predicate)
        .expect("missing TS definition")
}

#[test]
fn python_dead_code_smell_reports_unused_helper() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
def helper():
    return 1

def used():
    return 2
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import used

def run():
    return used()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let helper = python_definition(&analyzer, "service.helper");

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.py".to_string(), "consumer.py".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        result.report.contains("service.helper"),
        "{}",
        result.report
    );
    assert!(
        result.report.contains("no non-self usages found"),
        "{}",
        result.report
    );
}

#[test]
fn python_dead_code_smell_reports_one_call_wrapper() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
def wrapper():
    return 1
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import wrapper

def run():
    return wrapper()
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let wrapper = python_definition(&analyzer, "service.wrapper");

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.py".to_string(), "consumer.py".to_string()],
            fq_names: vec![wrapper.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        result.report.contains("service.wrapper"),
        "{}",
        result.report
    );
    assert!(
        result.report.contains("only usage: consumer.py"),
        "{}",
        result.report
    );
}

#[test]
fn python_dead_code_smell_does_not_flag_used_symbol() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
def worker():
    return 1
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import worker

def run():
    first = worker()
    second = worker()
    return first + second
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let worker = python_definition(&analyzer, "service.worker");

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.py".to_string(), "consumer.py".to_string()],
            fq_names: vec![worker.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("No dead code or unused abstraction smells met minScore 8."),
        "{}",
        result.report
    );
}

#[test]
fn js_dead_code_smell_reports_unused_export() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "service.js",
            r#"
export function helper() {
  return 1;
}
"#,
        )
        .file("consumer.js", "export function run() { return 2; }\n")
        .build();
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());
    let target_file = project.file("service.js");
    let helper = js_definition(&analyzer, |cu| {
        cu.is_function() && cu.identifier() == "helper" && cu.source() == &target_file
    });

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.js".to_string(), "consumer.js".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(result.report.contains("helper"), "{}", result.report);
    assert!(
        result.report.contains("no non-self usages found"),
        "{}",
        result.report
    );
}

#[test]
fn ts_dead_code_smell_reports_one_call_adapter() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            r#"
export function adapter(): number {
  return 1;
}
"#,
        )
        .file(
            "consumer.ts",
            r#"
import { adapter } from "./service";

export function run(): number {
  return adapter();
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let target_file = project.file("service.ts");
    let adapter = ts_definition(&analyzer, |cu| {
        cu.is_function() && cu.identifier() == "adapter" && cu.source() == &target_file
    });

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.ts".to_string(), "consumer.ts".to_string()],
            fq_names: vec![adapter.fq_name()],
            ..Default::default()
        },
    );

    assert!(result.report.contains("adapter"), "{}", result.report);
    assert!(
        result.report.contains("only usage: consumer.ts"),
        "{}",
        result.report
    );
}

#[test]
fn ts_dead_code_smell_reexport_counts_as_usage() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            "export function adapter(): number { return 1; }\n",
        )
        .file("barrel.ts", "export { adapter } from \"./service\";\n")
        .file(
            "consumer.ts",
            r#"
import { adapter } from "./barrel";

export function run(): number {
  const first = adapter();
  const second = adapter();
  return first + second;
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let target_file = project.file("service.ts");
    let adapter = ts_definition(&analyzer, |cu| {
        cu.is_function() && cu.identifier() == "adapter" && cu.source() == &target_file
    });

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec![
                "service.ts".to_string(),
                "barrel.ts".to_string(),
                "consumer.ts".to_string(),
            ],
            fq_names: vec![adapter.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("No dead code or unused abstraction smells met minScore 8."),
        "{}",
        result.report
    );
}

#[test]
fn js_dead_code_smell_skips_unseedable_local_symbol() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "service.js",
            r#"
function helper() {
  return 1;
}

export function run() {
  return helper();
}
"#,
        )
        .build();
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());
    let target_file = project.file("service.js");
    let helper = js_definition(&analyzer, |cu| {
        cu.is_function() && cu.identifier() == "helper" && cu.source() == &target_file
    });

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.js".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        result.report.contains("usage analysis was ambiguous")
            || result.report.contains("no export seed resolved"),
        "{}",
        result.report
    );
    assert!(
        result
            .report
            .contains("No dead code or unused abstraction smells met minScore 8."),
        "{}",
        result.report
    );
}
