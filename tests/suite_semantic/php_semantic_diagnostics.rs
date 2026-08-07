//! PHP's semantic-diagnostic ladder without any indexed Composer pack.
//!
//! Every reference produces a typed outcome. Where the collector used to stay
//! silent about a vendor symbol or a dynamic construct, it now says which one
//! it saw and why the lookup could not finish.

use crate::common::InlineTestProject;
use brokk_bifrost::{IAnalyzer, Language, PhpAnalyzer};
use brokk_bifrost_analysis::analyzer::{
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome, SemanticDiagnosticReport,
};

fn report(source: &str) -> SemanticDiagnosticReport {
    let project = InlineTestProject::with_language(Language::Php)
        .file("src/Consumer.php", source)
        .build();
    let analyzer = PhpAnalyzer::new(project.project_dyn());
    let file = project.file("src/Consumer.php");
    analyzer.semantic_diagnostics(&file, source)
}

fn has_incomplete_reason(
    report: &SemanticDiagnosticReport,
    matcher: fn(&SemanticDiagnosticIncompleteReason) -> bool,
) -> bool {
    report.outcomes().iter().any(|outcome| {
        matches!(
            outcome,
            SemanticDiagnosticOutcome::Incomplete { reasons, .. }
                if reasons.iter().any(matcher)
        )
    })
}

#[test]
fn a_workspace_type_resolves_locally() {
    let report = report(
        r#"<?php
namespace App;

class Consumer {
    private Consumer $value;
}
"#,
    );

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        report
            .outcomes()
            .iter()
            .any(|outcome| matches!(outcome, SemanticDiagnosticOutcome::Resolved { .. }))
    );
}

#[test]
fn an_unindexed_vendor_type_is_incomplete_rather_than_an_error() {
    // The whole point of #1626: this used to vanish silently.
    let report = report(
        r#"<?php
namespace App;

class Consumer {
    private \Vendor\Package\MissingType $value;
}
"#,
    );

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        has_incomplete_reason(&report, |reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { .. }
        )),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_variable_class_name_reports_dynamic_behavior() {
    let report = report(
        r#"<?php
namespace App;

class Anchor {}

function run($className): void {
    new $className();
}
"#,
    );

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        has_incomplete_reason(&report, |reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::DynamicBehavior { .. }
        )),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_variable_member_name_reports_dynamic_behavior() {
    let report = report(
        r#"<?php
namespace App;

class Anchor {}

function run($target, $method): void {
    $target->$method();
}
"#,
    );

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        has_incomplete_reason(&report, |reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::DynamicBehavior { .. }
        )),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_magic_call_owner_reports_dynamic_behavior_instead_of_a_missing_member() {
    let report = report(
        r#"<?php
namespace App;

class DynamicService {
    public function __call(string $name, array $args): mixed {}
}

function run(DynamicService $service): void {
    $service->whateverMethod();
}
"#,
    );

    assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
    assert!(
        has_incomplete_reason(&report, |reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::DynamicBehavior { .. }
        )),
        "{:#?}",
        report.outcomes()
    );
}

#[test]
fn a_workspace_member_absence_is_proved_against_the_local_surface() {
    let report = report(
        r#"<?php
namespace App;

class Service {
    public function present(): void {}

    public function run(Service $service): void {
        $service->missing();
    }
}
"#,
    );

    assert_eq!(report.diagnostics().len(), 1, "{:#?}", report.outcomes());
    assert!(report.outcomes().iter().any(|outcome| matches!(
        outcome,
        SemanticDiagnosticOutcome::Absent(proof)
            if matches!(
                proof.domain,
                brokk_bifrost_analysis::analyzer::SemanticDiagnosticDomain::MemberSurface { .. }
            )
    )));
}

#[test]
fn a_malformed_file_reports_nothing_and_stays_complete() {
    // Parse diagnostics own a broken file. The semantic pass must not claim the
    // file is incomplete, because it deliberately did not look.
    let report =
        report("<?php\nnamespace App;\nclass Broken { public function run(: void { X; }\n");

    assert!(report.diagnostics().is_empty());
    assert!(report.outcomes().is_empty(), "{:#?}", report.outcomes());
}
