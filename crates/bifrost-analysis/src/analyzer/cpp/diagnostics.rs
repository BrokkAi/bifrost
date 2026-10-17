//! The analyzer-bound fixtures for [`brokk_bifrost_cpp::diagnostics`].
//!
//! The pass itself moved with the language knowledge; what it needs from this
//! side is a `CppAnalyzer` built over a real compile database, which the C++
//! crate cannot construct because it names no analyzer type.
//!
//! These assert on the report's outcomes, not just on its diagnostics: since
//! #1627 an empty diagnostic list means "nothing unknown here" only when the
//! report is also `Complete`.

use crate::analyzer::{
    CppAnalyzer, Language, ProjectFile, SemanticDiagnosticIncompleteReason,
    SemanticDiagnosticReport, SemanticDiagnosticReportStatus, TestProject,
};
use brokk_bifrost_cpp::diagnostics::collect_cpp_semantic_diagnostics;

fn analyzer_fixture(files: &[(&str, &str)]) -> (tempfile::TempDir, CppAnalyzer, ProjectFile) {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    for (path, source) in files {
        ProjectFile::new(root.clone(), path)
            .write(source)
            .expect("fixture file");
    }
    let project = TestProject::new(root.clone(), Language::Cpp);
    let analyzer = CppAnalyzer::from_project(project);
    let file = ProjectFile::new(root, "src/main.cpp");
    (temp, analyzer, file)
}

fn has_incomplete_reason(
    report: &SemanticDiagnosticReport,
    matcher: fn(&SemanticDiagnosticIncompleteReason) -> bool,
) -> bool {
    report.incomplete_reasons().any(matcher)
}

#[test]
fn a_file_the_compile_database_does_not_name_is_unjudged_not_clean() {
    let (_temp, analyzer, file) = analyzer_fixture(&[("src/main.cpp", "MissingType value;")]);
    let report = collect_cpp_semantic_diagnostics(&analyzer, &file, "MissingType value;");

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert_eq!(
        SemanticDiagnosticReportStatus::Incomplete,
        report.status(),
        "{:#?}",
        report.outcomes()
    );
    assert!(
        has_incomplete_reason(&report, |reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                boundary: crate::analyzer::structural::BoundaryStatus::ExternalUnknown
            }
        )),
        "{:#?}",
        report.outcomes()
    );
}
#[test]
fn a_command_line_macro_name_is_unjudged_rather_than_resolved() {
    let (_temp, analyzer, file) = analyzer_fixture(&[
        (
            "src/main.cpp",
            "FEATURE value;\ntemplate <typename T> T value_for();",
        ),
        (
            "compile_commands.json",
            r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-D","FEATURE","-c","src/main.cpp"]}]"#,
        ),
    ]);
    let source = "FEATURE value;\ntemplate <typename T> T value_for();";
    let report = collect_cpp_semantic_diagnostics(&analyzer, &file, source);

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        has_incomplete_reason(&report, |reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::UnsupportedGeneratedSurface { .. }
        )),
        "{:#?}",
        report.outcomes()
    );
}
