use crate::common::InlineTestProject;
use brokk_bifrost::{IAnalyzer, JavaAnalyzer, Language};
use brokk_bifrost_analysis::analyzer::{
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome, SemanticDiagnosticReport,
};

fn report(source: &str) -> SemanticDiagnosticReport {
    let project = InlineTestProject::with_language(Language::Java)
        .file("app/Consumer.java", source)
        .build();
    let analyzer = JavaAnalyzer::new(project.project_dyn());
    let file = project.file("app/Consumer.java");
    analyzer.semantic_diagnostics(&file, source)
}

#[test]
fn workspace_type_is_resolved() {
    let report = report("package app; class Consumer { Consumer value; }");
    assert!(report.diagnostics().is_empty());
    assert!(
        report
            .outcomes()
            .iter()
            .any(|outcome| matches!(outcome, SemanticDiagnosticOutcome::Resolved { .. }))
    );
}

#[test]
fn unknown_type_is_suppressed_without_dependency_proof() {
    let report = report("package app; class Consumer { MissingType value; }");
    assert!(report.diagnostics().is_empty());
    assert!(report.outcomes().iter().any(|outcome| matches!(
        outcome,
        SemanticDiagnosticOutcome::Incomplete { reasons, .. }
            if reasons.iter().any(|reason| matches!(
                reason,
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { .. }
            ))
    )));
}

#[test]
fn similar_value_name_does_not_satisfy_a_type_reference() {
    let report = report("package app; class Consumer { int MissingType; MissingType value; }");
    assert!(report.diagnostics().is_empty());
    assert!(
        report
            .outcomes()
            .iter()
            .any(|outcome| matches!(outcome, SemanticDiagnosticOutcome::Incomplete { .. }))
    );
}
