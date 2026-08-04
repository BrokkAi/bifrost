//! Kotlin dead-code detection (issue #1243): the precise per-candidate route
//! only (`analyze_candidate`, mirroring the Ruby precedent) — Kotlin has no
//! bulk (FQN-batch) usage-graph arm yet. Covers an unused private function,
//! `main()` staying excluded as a JVM entry point, and a function with two
//! distinct call sites staying unflagged.

use crate::common::InlineTestProject;
use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::code_quality::{
    ReportDeadCodeAndUnusedAbstractionSmellsParams, report_dead_code_and_unused_abstraction_smells,
};
use brokk_bifrost::{CodeUnit, IAnalyzer, KotlinAnalyzer, Language};

fn kotlin_analyzer_with_files(
    files: &[(&str, &str)],
) -> (crate::common::BuiltInlineTestProject, KotlinAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Kotlin);
    for (path, contents) in files {
        builder = builder.file(*path, *contents);
    }
    let project = builder.build();
    let analyzer = KotlinAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definition(analyzer: &KotlinAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing Kotlin definition for {fq_name}"))
}

fn report(
    analyzer: &dyn IAnalyzer,
    params: ReportDeadCodeAndUnusedAbstractionSmellsParams,
) -> String {
    report_dead_code_and_unused_abstraction_smells(analyzer, params).report
}

#[test]
fn kotlin_dead_code_smell_reports_unused_private_function() {
    let (_project, analyzer) = kotlin_analyzer_with_files(&[(
        "Service.kt",
        r#"
        package example

        class Service {
            private fun unused(): Int {
                return 1
            }
        }
        "#,
    )]);
    let unused = definition(&analyzer, "example.Service.unused");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Service.kt".to_string()],
            fq_names: vec![unused.fq_name()],
            ..Default::default()
        },
    );

    assert!(report.contains("Service.unused"), "{report}");
    assert!(report.contains("Kotlin tree-sitter analysis"), "{report}");
}

#[test]
fn kotlin_top_level_main_is_not_flagged() {
    let (_project, analyzer) = kotlin_analyzer_with_files(&[(
        "Main.kt",
        r#"
        package example

        fun main() {
            println("hi")
        }
        "#,
    )]);

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Main.kt".to_string()],
            ..Default::default()
        },
    );

    assert!(
        report.contains("No dead code or unused abstraction smells met minScore 8."),
        "{report}"
    );
}

#[test]
fn kotlin_function_called_from_two_sites_is_not_flagged() {
    let (_project, analyzer) = kotlin_analyzer_with_files(&[(
        "Service.kt",
        r#"
        package example

        class Service {
            fun used(): Int {
                return 1
            }
        }

        class Consumer {
            fun call(): Int {
                val service = Service()
                return service.used()
            }

            fun callAgain(): Int {
                val service = Service()
                return service.used()
            }
        }
        "#,
    )]);
    let used = definition(&analyzer, "example.Service.used");

    let report = report(
        &analyzer,
        ReportDeadCodeAndUnusedAbstractionSmellsParams {
            file_paths: vec!["Service.kt".to_string()],
            fq_names: vec![used.fq_name()],
            ..Default::default()
        },
    );

    assert!(
        report.contains("No dead code or unused abstraction smells met minScore 8."),
        "{report}"
    );
}
