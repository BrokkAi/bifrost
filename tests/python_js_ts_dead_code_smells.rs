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
    let declarations = analyzer.get_all_declarations();
    declarations.into_iter().find(predicate).unwrap_or_else(|| {
        let available = analyzer
            .get_all_declarations()
            .into_iter()
            .map(|unit| format!("{}:{}:{:?}", unit.source(), unit.fq_name(), unit.kind()))
            .collect::<Vec<_>>()
            .join(", ");
        panic!("missing TS definition; available: {available}")
    })
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
        result
            .report
            .contains("one workspace inbound edge from consumer.run"),
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
fn python_dead_code_smell_skips_truncated_usage_candidates() {
    let mut builder = InlineTestProject::with_language(Language::Python).file(
        "service.py",
        r#"
def helper():
    return 1
"#,
    );
    for index in 0..=1000 {
        builder = builder.file(
            format!("consumer_{index}.py"),
            format!(
                r#"
from service import helper

def run_{index}():
    return helper()
"#
            ),
        );
    }
    let project = builder.build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let helper = python_definition(&analyzer, "service.helper");

    let mut file_paths = vec!["service.py".to_string()];
    file_paths.extend((0..=1000).map(|index| format!("consumer_{index}.py")));
    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths,
            fq_names: vec![helper.fq_name()],
            max_usage_candidate_files: 2000,
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("too many workspace inbound call sites (1001, limit 1000)"),
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

#[test]
fn python_dead_code_smell_honors_usage_candidate_file_cap() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
def helper():
    return 1
"#,
        )
        .file("consumer.py", "def run():\n    return 2\n")
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let helper = python_definition(&analyzer, "service.helper");

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.py".to_string(), "consumer.py".to_string()],
            fq_names: vec![helper.fq_name()],
            max_usage_candidate_files: 1,
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("Python usage graph candidate files exceeded cap 1 (2 Python files)"),
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

#[test]
fn python_dead_code_smell_honors_usage_cap() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
def helper():
    return 1
"#,
        )
        .file(
            "consumer.py",
            r#"
from service import helper

def first():
    return helper()

def second():
    return helper()
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
            max_usages_per_symbol: 1,
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("too many workspace inbound call sites (2, limit 1)"),
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

#[test]
fn python_dead_code_smell_clamps_usage_cap_to_graph_callsite_limit() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "service.py",
            r#"
def helper():
    return 1
"#,
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let helper = python_definition(&analyzer, "service.helper");

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.py".to_string()],
            fq_names: vec![helper.fq_name()],
            max_usages_per_symbol: 2000,
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("Usage cap per symbol: 1000 (clamped from 2000 by graph call-site cap)"),
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
        result
            .report
            .contains("one workspace inbound edge from run"),
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
fn ts_dead_code_smell_does_not_cross_count_duplicate_export_names() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("a.ts", "export function helper(): number { return 1; }\n")
        .file("b.ts", "export function helper(): number { return 2; }\n")
        .file(
            "consumer.ts",
            r#"
import { helper } from "./b";

export function run(): number {
  return helper();
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let a_file = project.file("a.ts");
    let helper = ts_definition(&analyzer, |cu| {
        cu.is_function() && cu.identifier() == "helper" && cu.source() == &a_file
    });

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["a.ts".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        result.report.contains("no non-self usages found"),
        "{}",
        result.report
    );
    assert!(!result.report.contains("| 1 | 1 |"), "{}", result.report);
}

#[test]
fn ts_dead_code_smell_does_not_cross_count_duplicate_owner_members() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "a.ts",
            r#"
export class Foo {
  static make(): number {
    return 1;
  }
}
"#,
        )
        .file(
            "b.ts",
            r#"
export class Foo {
  static make(): number {
    return 2;
  }
}
"#,
        )
        .file(
            "consumer.ts",
            r#"
import { Foo } from "./b";

export function run(): number {
  return Foo.make();
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let a_file = project.file("a.ts");
    let make = ts_definition(&analyzer, |cu| {
        cu.is_function() && cu.fq_name() == "Foo.make$static" && cu.source() == &a_file
    });

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["a.ts".to_string()],
            fq_names: vec![make.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        result.report.contains("no non-self usages found"),
        "{}",
        result.report
    );
    assert!(!result.report.contains("| 1 | 1 |"), "{}", result.report);

    let b_file = project.file("b.ts");
    let b_make = ts_definition(&analyzer, |cu| {
        cu.is_function() && cu.fq_name() == "Foo.make$static" && cu.source() == &b_file
    });
    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["b.ts".to_string()],
            fq_names: vec![b_make.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("one workspace inbound edge from run"),
        "{}",
        result.report
    );
    assert!(result.report.contains("| 1 | 1 |"), "{}", result.report);
}

#[test]
fn js_dead_code_smell_unproven_receiver_usage_is_inconclusive_not_dead() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "service.js",
            r#"
export class Service {
  target() {
    return 1;
  }

  unused() {
    return 2;
  }

  static used() {
    return 3;
  }
}
"#,
        )
        .file(
            "consumer.js",
            r#"
import { Service } from "./service";

export function useUnknown(service) {
  return service.target();
}

export function useProven() {
  return Service.used();
}
"#,
        )
        .build();
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());
    let service_file = project.file("service.js");
    let target = js_definition(&analyzer, |cu| {
        cu.is_function() && cu.fq_name() == "Service.target" && cu.source() == &service_file
    });
    let unused = js_definition(&analyzer, |cu| {
        cu.is_function() && cu.fq_name() == "Service.unused" && cu.source() == &service_file
    });
    let used = js_definition(&analyzer, |cu| {
        cu.is_function() && cu.identifier() == "used" && cu.source() == &service_file
    });

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.js".to_string(), "consumer.js".to_string()],
            fq_names: vec![target.fq_name(), unused.fq_name(), used.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("Service.target`: 1 structurally matching usage site(s)"),
        "{}",
        result.report
    );
    assert!(
        !result.report.contains("Service.target |"),
        "{}",
        result.report
    );
    assert!(
        result.report.contains("Service.unused")
            && result.report.contains("no non-self usages found"),
        "{}",
        result.report
    );
    assert!(
        result.report.contains("Service.used")
            && result
                .report
                .contains("one workspace inbound edge from useProven"),
        "{}",
        result.report
    );
}

#[test]
fn ts_dead_code_smell_unproven_receiver_usage_is_inconclusive_not_dead() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            r#"
export class Service {
  target(): number {
    return 1;
  }

  unused(): number {
    return 2;
  }

  static used(): number {
    return 3;
  }
}
"#,
        )
        .file(
            "consumer.ts",
            r#"
import { Service } from "./service";

export function useUnknown(value: unknown): number {
  const service = value;
  return service.target();
}

export function useProven(): number {
  return Service.used();
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let service_file = project.file("service.ts");
    let target = ts_definition(&analyzer, |cu| {
        cu.is_function() && cu.fq_name() == "Service.target" && cu.source() == &service_file
    });
    let unused = ts_definition(&analyzer, |cu| {
        cu.is_function() && cu.fq_name() == "Service.unused" && cu.source() == &service_file
    });
    let used = ts_definition(&analyzer, |cu| {
        cu.is_function() && cu.fq_name() == "Service.used$static" && cu.source() == &service_file
    });

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.ts".to_string(), "consumer.ts".to_string()],
            fq_names: vec![target.fq_name(), unused.fq_name(), used.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("Service.target`: 1 structurally matching usage site(s)"),
        "{}",
        result.report
    );
    assert!(
        !result.report.contains("Service.target |"),
        "{}",
        result.report
    );
    assert!(
        result.report.contains("Service.unused")
            && result.report.contains("no non-self usages found"),
        "{}",
        result.report
    );
    assert!(
        result.report.contains("Service.used")
            && result
                .report
                .contains("one workspace inbound edge from useProven"),
        "{}",
        result.report
    );
}

#[test]
fn ts_dead_code_smell_namespace_import_uses_target_module_not_local_name() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            "export function helper(): number { return 1; }\n",
        )
        .file(
            "consumer.ts",
            r#"
import * as api from "./service";

export function helper(): number {
  return 0;
}

export function run(): number {
  return api.helper();
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let service_file = project.file("service.ts");
    let helper = ts_definition(&analyzer, |cu| {
        cu.is_function() && cu.fq_name() == "helper" && cu.source() == &service_file
    });

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.ts".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("one workspace inbound edge from run"),
        "{}",
        result.report
    );
    assert!(
        !result.report.contains("no non-self usages found"),
        "{}",
        result.report
    );
}

#[test]
fn ts_dead_code_smell_namespace_import_follows_unambiguous_barrel_reexport() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            "export function adapter(): number { return 1; }\n",
        )
        .file("barrel.ts", "export * from \"./service\";\n")
        .file(
            "consumer.ts",
            r#"
import * as api from "./barrel";

export function run(): number {
  return api.adapter();
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let adapter = ts_definition(&analyzer, |cu| {
        cu.is_function() && cu.fq_name() == "adapter"
    });

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.ts".to_string()],
            fq_names: vec![adapter.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("one workspace inbound edge from run"),
        "{}",
        result.report
    );
    assert!(
        !result.report.contains("no non-self usages found"),
        "{}",
        result.report
    );
}

#[test]
fn ts_dead_code_smell_namespace_import_counts_static_member_chain() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            r#"
export class Foo {
  static make(): number {
    return 1;
  }
}
"#,
        )
        .file(
            "consumer.ts",
            r#"
import * as api from "./service";

export function run(): number {
  return api.Foo.make();
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let make = ts_definition(&analyzer, |cu| {
        cu.is_function() && cu.fq_name() == "Foo.make$static"
    });

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.ts".to_string()],
            fq_names: vec![make.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("one workspace inbound edge from run"),
        "{}",
        result.report
    );
    assert!(
        !result.report.contains("no non-self usages found"),
        "{}",
        result.report
    );
}

#[test]
fn ts_dead_code_smell_skips_ambiguous_star_reexport_alias() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("a.ts", "export function helper(): number { return 1; }\n")
        .file("b.ts", "export function helper(): number { return 2; }\n")
        .file(
            "barrel.ts",
            r#"
export * from "./a";
export * from "./b";
"#,
        )
        .file(
            "consumer.ts",
            r#"
import { helper } from "./barrel";

export function run(): number {
  return helper();
}
"#,
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let a_file = project.file("a.ts");
    let helper = ts_definition(&analyzer, |cu| {
        cu.is_function() && cu.identifier() == "helper" && cu.source() == &a_file
    });

    let result = report_dead_code_and_unused_abstraction_smells(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec![
                "a.ts".to_string(),
                "b.ts".to_string(),
                "barrel.ts".to_string(),
                "consumer.ts".to_string(),
            ],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        result
            .report
            .contains("JS/TS export identity was ambiguous"),
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
        result
            .report
            .contains("JS/TS export seed could not be resolved"),
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
