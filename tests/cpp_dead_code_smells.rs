mod common;

use brokk_bifrost::code_quality::{
    ReportDeadCodeAndUnusedAbstractionSmellsParams, report_dead_code_and_unused_abstraction_smells,
};
use brokk_bifrost::{CodeUnit, CodeUnitType, CppAnalyzer, IAnalyzer, Language};
use common::InlineTestProject;

fn cpp_analyzer_with_files(
    files: &[(&str, &str)],
) -> (common::BuiltInlineTestProject, CppAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Cpp);
    for (path, contents) in files {
        builder = builder.file(*path, *contents);
    }
    let project = builder.build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definition_by<F>(analyzer: &CppAnalyzer, mut predicate: F) -> CodeUnit
where
    F: FnMut(&CodeUnit) -> bool,
{
    let declarations = analyzer.get_all_declarations();
    declarations
        .iter()
        .find(|unit| predicate(unit))
        .cloned()
        .unwrap_or_else(|| panic!("missing matching C++ declaration in {declarations:#?}"))
}

fn class_definition(analyzer: &CppAnalyzer, name: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Class && unit.identifier() == name
    })
}

fn function_definition(analyzer: &CppAnalyzer, name: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function && unit.identifier() == name
    })
}

fn function_definition_in_package(
    analyzer: &CppAnalyzer,
    package_name: &str,
    name: &str,
) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.package_name() == package_name
            && unit.identifier() == name
    })
}

fn function_definition_with_signature(
    analyzer: &CppAnalyzer,
    name: &str,
    signature: &str,
) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == name
            && unit.signature() == Some(signature)
    })
}

fn member_function(analyzer: &CppAnalyzer, owner: &str, name: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Function
            && unit.identifier() == name
            && analyzer
                .parent_of(unit)
                .is_some_and(|parent| parent.identifier() == owner)
    })
}

fn member_field(analyzer: &CppAnalyzer, owner: &str, name: &str) -> CodeUnit {
    definition_by(analyzer, |unit| {
        unit.kind() == CodeUnitType::Field
            && unit.identifier() == name
            && analyzer
                .parent_of(unit)
                .is_some_and(|parent| parent.identifier() == owner)
    })
}

fn report(
    analyzer: &dyn IAnalyzer,
    params: ReportDeadCodeAndUnusedAbstractionSmellsParams,
) -> String {
    report_dead_code_and_unused_abstraction_smells(analyzer, params).report
}

#[test]
fn cpp_dead_code_smell_reports_unused_static_helper() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "service.cpp",
        r#"
static void helper() {}
void entry() {}
"#,
    )]);
    let helper = function_definition(&analyzer, "helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.cpp".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("helper"), "{report}");
    assert!(report.contains("no non-self usages found"), "{report}");
    assert!(report.contains("| 0 | 0 |"), "{report}");
    assert!(
        report.contains("C++ tree-sitter analysis and may be generated residue"),
        "{report}"
    );
}

#[test]
fn cpp_dead_code_smell_reports_one_call_free_function() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "service.cpp",
        r#"
static void leaf() {}
static void wrapper() { leaf(); }
"#,
    )]);
    let leaf = function_definition(&analyzer, "leaf");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.cpp".to_string()],
            fq_names: vec![leaf.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("leaf"), "{report}");
    assert!(
        report.contains("one workspace inbound edge from wrapper"),
        "{report}"
    );
    assert!(report.contains("| 1 | 1 |"), "{report}");
}

#[test]
fn cpp_dead_code_smell_bulk_scores_namespaced_free_function() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "service.cpp",
        r#"
namespace detail {
static void leaf() {}
static void wrapper() { leaf(); }
}
"#,
    )]);
    let leaf = function_definition_in_package(&analyzer, "detail", "leaf");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.cpp".to_string()],
            fq_names: vec![leaf.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("detail.leaf"), "{report}");
    assert!(
        report.contains("one workspace inbound edge from detail.wrapper"),
        "{report}"
    );
    assert!(report.contains("| 1 | 0 |"), "{report}");
}

#[test]
fn cpp_type_usage_from_another_file_prevents_finding() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        ("target.h", "class Target {};\n"),
        (
            "consumer.cpp",
            r#"
#include "target.h"
Target first();
Target second();
"#,
        ),
    ]);
    let target = class_definition(&analyzer, "Target");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["target.h".to_string()],
            fq_names: vec![target.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("Target |"), "{report}");
    assert!(
        report.contains("No dead code or unused abstraction smells"),
        "{report}"
    );
}

#[test]
fn cpp_symbol_with_two_distinct_inbound_callers_is_not_flagged() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "service.cpp",
        r#"
static int helper() { return 1; }
static int first() { return helper(); }
static int second() { return helper(); }
"#,
    )]);
    let helper = function_definition(&analyzer, "helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.cpp".to_string()],
            fq_names: vec![helper.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("helper |"), "{report}");
    assert!(
        report.contains("No dead code or unused abstraction smells"),
        "{report}"
    );
}

#[test]
fn cpp_dead_code_smell_honors_usage_candidate_file_cap() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[
        ("service.cpp", "static void helper() {}\n"),
        ("other.cpp", "class Other {};\n"),
    ]);
    let helper = function_definition(&analyzer, "helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.cpp".to_string()],
            fq_names: vec![helper.fq_name()],
            max_usage_candidate_files: 1,
            ..Default::default()
        },
    );

    assert!(
        report.contains("C++ precise usage strategy is unavailable"),
        "{report}"
    );
    assert!(!report.contains("helper |"), "{report}");
}

#[test]
fn cpp_dead_code_smell_honors_usage_cap() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "service.cpp",
        r#"
static int helper() { return 1; }
static int first() { return helper(); }
static int second() { return helper(); }
"#,
    )]);
    let helper = function_definition(&analyzer, "helper");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.cpp".to_string()],
            fq_names: vec![helper.fq_name()],
            max_usages_per_symbol: 1,
            ..Default::default()
        },
    );

    assert!(
        report.contains("too many workspace inbound call sites (2, limit 1)"),
        "{report}"
    );
    assert!(!report.contains("helper |"), "{report}");
}

#[test]
fn cpp_public_function_and_class_use_conservative_wording_and_score() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "api.h",
        r#"
class Api {};
void extension_point();
"#,
    )]);
    let extension_point = function_definition(&analyzer, "extension_point");
    let api = class_definition(&analyzer, "Api");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["api.h".to_string()],
            fq_names: vec![extension_point.fq_name(), api.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("extension_point"), "{report}");
    assert!(report.contains("Api"), "{report}");
    assert!(
        report.contains("public C++ symbol is unreferenced in workspace"),
        "{report}"
    );
    assert!(report.contains("0.55"), "{report}");
    assert!(!report.contains("generated residue"), "{report}");
}

#[test]
fn cpp_constructor_candidate_stays_on_precise_path() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "target.cpp",
        r#"
class Target {
public:
    Target() {}
};

Target build() { return Target(); }
"#,
    )]);
    let constructor = member_function(&analyzer, "Target", "Target");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["target.cpp".to_string()],
            fq_names: vec![constructor.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("no non-self usages found"), "{report}");
    assert!(!report.contains("one workspace inbound edge"), "{report}");
    assert!(
        report.contains("C++ precise usage strategy is unavailable"),
        "{report}"
    );
}

#[test]
fn cpp_member_method_candidate_stays_on_precise_path() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "target.cpp",
        r#"
class Target {
public:
    void run() {}
};

Target make();
void use() { make().run(); }
"#,
    )]);
    let run = member_function(&analyzer, "Target", "run");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["target.cpp".to_string()],
            fq_names: vec![run.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("no non-self usages found"), "{report}");
    assert!(!report.contains("one workspace inbound edge"), "{report}");
    assert!(
        report.contains("C++ precise usage strategy is unavailable"),
        "{report}"
    );
}

#[test]
fn cpp_overloaded_free_functions_stay_on_precise_path() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "service.cpp",
        r#"
void run() {}
void run(int value) {}
void use() { run(1); }
"#,
    )]);
    let one_arg = function_definition_with_signature(&analyzer, "run", "(int)");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["service.cpp".to_string()],
            fq_names: vec![one_arg.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("one workspace inbound edge"), "{report}");
    assert!(!report.contains("no non-self usages found"), "{report}");
    assert!(
        report.contains("C++ precise usage strategy is unavailable"),
        "{report}"
    );
}

#[test]
fn cpp_field_candidate_stays_on_precise_path() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "target.cpp",
        r#"
class Target {
public:
    int value;
};

int read(Target target) { return target.value; }
"#,
    )]);
    let value = member_field(&analyzer, "Target", "value");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["target.cpp".to_string()],
            fq_names: vec![value.fq_name()],
            ..Default::default()
        },
    );

    assert!(!report.contains("no non-self usages found"), "{report}");
    assert!(!report.contains("one workspace inbound edge"), "{report}");
    assert!(
        report.contains("C++ precise usage strategy is unavailable"),
        "{report}"
    );
}

#[test]
fn cpp_main_is_not_dead_code_candidate() {
    let (_project, analyzer) =
        cpp_analyzer_with_files(&[("main.cpp", "int main() { return 0; }\n")]);
    let main = function_definition(&analyzer, "main");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["main.cpp".to_string()],
            fq_names: vec![main.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        report.contains("No dead code or unused abstraction smells"),
        "{report}"
    );
    assert!(!report.contains("main |"), "{report}");
}

#[test]
fn cpp_namespaced_main_is_still_dead_code_candidate() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "detail.cpp",
        r#"
namespace detail {
static void main() {}
}
"#,
    )]);
    let main = function_definition_in_package(&analyzer, "detail", "main");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["detail.cpp".to_string()],
            fq_names: vec![main.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("detail.main"), "{report}");
    assert!(report.contains("no non-self usages found"), "{report}");
}

#[test]
fn cpp_member_main_is_still_dead_code_candidate() {
    let (_project, analyzer) = cpp_analyzer_with_files(&[(
        "harness.cpp",
        r#"
class Harness {
    void main() {}
};
"#,
    )]);
    let main = member_function(&analyzer, "Harness", "main");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["harness.cpp".to_string()],
            fq_names: vec![main.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("Candidate symbols analyzed: 1"), "{report}");
    assert!(!report.contains("Harness.main |"), "{report}");
}
