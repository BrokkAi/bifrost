use brokk_bifrost_analysis::{
    AnalyzerConfig, ExceptionHandlingAnalysis, ExceptionHandlingSmell, ExceptionSmellWeights,
    code_quality::{ReportExceptionHandlingSmellsParams, report_exception_handling_smells},
};

use crate::common::InlineTestProject;

fn analyze(path: &str, source: &str) -> Vec<ExceptionHandlingSmell> {
    let project = InlineTestProject::new().file(path, source).build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    match workspace
        .analyzer()
        .find_exception_handling_smells(&project.file(path), ExceptionSmellWeights::defaults())
    {
        ExceptionHandlingAnalysis::Analyzed(findings) => findings,
        outcome => panic!("expected analyzed exception-smell result, got {outcome:?}"),
    }
}

fn assert_one_bad_handler(path: &str, source: &str, expected_type: &str) {
    let findings = analyze(path, source);
    assert_eq!(findings.len(), 1, "findings: {findings:#?}");
    assert!(
        findings[0].catch_type.contains(expected_type),
        "finding: {:#?}",
        findings[0]
    );
    assert!(
        findings[0]
            .reasons
            .iter()
            .any(|reason| reason == "empty-body" || reason.starts_with("small-body:")),
        "finding: {:#?}",
        findings[0]
    );
}

#[test]
fn cpp_flags_empty_generic_catch_but_not_meaningful_rethrow() {
    assert_one_bad_handler(
        "sample.cpp",
        r#"
#include <exception>
void audit() {}
void notify_ops() {}
void sample() {
    try {} catch (const std::exception& error) {}
    try {} catch (const std::exception& error) {
        audit();
        notify_ops();
        throw;
    }
}
"#,
        "exception",
    );
}

#[test]
fn javascript_and_jsx_flag_untyped_empty_catches() {
    for path in ["sample.js", "sample.jsx"] {
        assert_one_bad_handler(
            path,
            r#"
function sample() {
    try {} catch (error) {}
    try {} catch (error) {
        audit(error);
        notifyOps(error);
        throw error;
    }
}
"#,
            "<untyped>",
        );
    }
}

#[test]
fn typescript_and_tsx_flag_any_catches() {
    for path in ["sample.ts", "sample.tsx"] {
        assert_one_bad_handler(
            path,
            r#"
function sample() {
    try {} catch (error: any) {}
    try {} catch (error: Error) {
        audit(error);
        notifyOps(error);
        throw error;
    }
}
"#,
            "any",
        );
    }
}

#[test]
fn python_flags_bare_tiny_except_but_not_meaningful_reraise() {
    let findings = analyze(
        "sample.py",
        r#"
def sample():
    try:
        work()
    except:
        pass
    try:
        work()
    except Exception:
        audit()
        notify_ops()
        raise
"#,
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(findings[0].catch_type, "<bare>");
    assert_eq!(findings[0].body_statement_count, 0);
    assert!(
        findings[0]
            .reasons
            .iter()
            .any(|reason| reason == "empty-body")
    );
}

#[test]
fn php_flags_empty_generic_catch_but_not_meaningful_rethrow() {
    assert_one_bad_handler(
        "sample.php",
        r#"<?php
function sample() {
    try {} catch (Exception $error) {}
    try {} catch (Exception $error) {
        audit($error);
        notify_ops($error);
        throw $error;
    }
}
"#,
        "Exception",
    );
}

#[test]
fn csharp_flags_empty_generic_catch_but_not_meaningful_rethrow() {
    assert_one_bad_handler(
        "Sample.cs",
        r#"
using System;
class Sample {
    void Run() {
        try {} catch (Exception error) {}
        try {} catch (Exception error) {
            Audit(error);
            NotifyOps(error);
            throw;
        }
    }
}
"#,
        "Exception",
    );
}

#[test]
fn scala_flags_empty_generic_case_but_not_meaningful_rethrow() {
    assert_one_bad_handler(
        "Sample.scala",
        r#"
object Sample {
  def run(): Unit = {
    try work() catch { case error: Exception => }
    try work() catch {
      case error: Exception =>
        audit(error)
        notifyOps(error)
        throw error
    }
  }
}
"#,
        "Exception",
    );
}

#[test]
fn go_flags_empty_recover_and_err_handlers_but_not_plain_propagation() {
    let findings = analyze(
        "sample.go",
        r#"
package sample

func recoverBadly() {
    defer func() {
        if recovered := recover(); recovered != nil {}
    }()
}

func ignoreError() error {
    err := work()
    if err != nil {}
    return nil
}

func nestedRecover() {
    defer func() {
        defer func() {
            if recovered := recover(); recovered != nil {}
        }()
    }()
}

func propagateError() error {
    err := work()
    if err != nil { return err }
    return nil
}
"#,
    );
    assert_eq!(findings.len(), 3, "findings: {findings:#?}");
    assert!(
        findings
            .iter()
            .any(|finding| finding.catch_type == "recover()")
    );
    assert!(findings.iter().any(|finding| finding.catch_type == "error"));
    assert!(
        findings
            .iter()
            .all(|finding| !finding.excerpt.contains("return err")),
        "findings: {findings:#?}"
    );
}

#[test]
fn rust_flags_err_handlers_but_not_question_mark_propagation() {
    let findings = analyze(
        "lib.rs",
        r#"
fn match_badly() {
    match work() {
        Ok(value) => consume(value),
        Err(error) => {},
    }
}

fn if_let_badly() {
    if let Err(error) = work() {}
}

fn propagate() -> Result<(), Error> {
    work()?;
    Ok(())
}

fn propagate_match() -> Result<(), Error> {
    match work() {
        Ok(value) => Ok(value),
        Err(error) => return Err(error),
    }
}
"#,
    );
    assert_eq!(findings.len(), 2, "findings: {findings:#?}");
    assert!(findings.iter().all(|finding| finding.catch_type == "Err"));
    assert!(
        findings
            .iter()
            .all(|finding| !finding.excerpt.contains("work()?")),
        "findings: {findings:#?}"
    );
}

#[test]
fn ruby_flags_bare_empty_rescue_but_not_meaningful_reraise() {
    assert_one_bad_handler(
        "sample.rb",
        r#"
def sample
  begin
    work
  rescue
  end

  begin
    work
  rescue StandardError => error
    audit(error)
    notify_ops(error)
    raise
  end
end
"#,
        "StandardError",
    );
}

#[test]
fn kotlin_flags_empty_generic_catch_but_not_meaningful_rethrow() {
    assert_one_bad_handler(
        "Sample.kt",
        r#"
fun sample() {
    try { work() } catch (error: Exception) {}
    try { work() } catch (error: Exception) {
        audit(error)
        notifyOps(error)
        throw error
    }
}
"#,
        "Exception",
    );
}

#[test]
fn mixed_language_report_retains_findings_and_marks_unsupported_files() {
    let project = InlineTestProject::new()
        .file(
            "Sample.kt",
            "fun sample() { try { work() } catch (error: Exception) {} }",
        )
        .file(
            "sample.rs",
            "fn sample(value: Result<(), Error>) { match value { Err(error) => {}, Ok(()) => {} } }",
        )
        .file("notes.txt", "catch every error")
        .file("broken.py", "def broken(:\n    pass\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    let result = report_exception_handling_smells(
        workspace.analyzer(),
        ReportExceptionHandlingSmellsParams {
            file_paths: vec![
                "Sample.kt".to_string(),
                "sample.rs".to_string(),
                "notes.txt".to_string(),
                "broken.py".to_string(),
            ],
            ..Default::default()
        },
    );

    assert!(result.report.contains("`Sample.kt`"), "{}", result.report);
    assert!(result.report.contains("`sample.rs`"), "{}", result.report);
    assert_eq!(result.unsupported_files.len(), 1, "{result:#?}");
    assert_eq!(result.unsupported_files[0].file, "notes.txt");
    assert_eq!(result.failed_files.len(), 1, "{result:#?}");
    assert_eq!(result.failed_files[0].file, "broken.py");
    assert!(
        result.report.contains("Unsupported files:"),
        "{}",
        result.report
    );
    assert!(
        result.report.contains("Analysis failures:"),
        "{}",
        result.report
    );
    assert!(!result.report.contains("No exception-handling smells"));
}

#[test]
fn narrow_type_and_non_logging_identifier_do_not_gain_generic_or_log_scores() {
    for (path, source) in [
        (
            "sample.py",
            "try:\n    work()\nexcept DomainException:\n    process(logger)\n",
        ),
        (
            "Sample.cs",
            "class Sample { void Run() { try { Work(); } catch (DomainException error) { error.Handle(); } } }",
        ),
        (
            "sample.php",
            "<?php try { work(); } catch (DomainException $error) { process($logger); }",
        ),
        (
            "Sample.kt",
            "fun sample() { try { work() } catch (error: DomainException) { process(logger) } }",
        ),
    ] {
        let findings = analyze(path, source);
        assert!(
            findings.iter().all(|finding| {
                !finding
                    .reasons
                    .iter()
                    .any(|reason| reason.starts_with("generic-catch:") || reason == "log-only-body")
            }),
            "{path}: {findings:#?}"
        );
    }
}

#[test]
fn cpp_nested_recovery_statements_receive_meaningful_body_credit() {
    let findings = analyze(
        "sample.cpp",
        "void sample() { try {} catch (...) { if (recoverable()) { audit(); notify_ops(); recover(); } } }",
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(findings[0].body_statement_count, 3, "{findings:#?}");
    assert_eq!(findings[0].score, 2, "{findings:#?}");
}

#[test]
fn c_error_semantics_are_explicitly_unsupported() {
    let project = InlineTestProject::new()
        .file("sample.c", "int sample(void) { return -1; }")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let result = report_exception_handling_smells(
        workspace.analyzer(),
        ReportExceptionHandlingSmellsParams {
            file_paths: vec!["sample.c".to_string()],
            ..Default::default()
        },
    );
    assert_eq!(result.unsupported_files.len(), 1, "{result:#?}");
    assert!(result.report.contains("errno"), "{}", result.report);
}
