use std::sync::Arc;

use super::{PolicyRenderError, SarifToolIdentity, write_policy_sarif};
use crate::{
    CatalogRegistryLimits, DefaultPolicyEvaluator, EvidenceRef, PolicyBudget, PolicyDiagnostic,
    PolicyDiagnosticCode, PolicyDiagnosticImpact, PolicyDiagnosticSeverity,
    PolicyEvaluationContext, PolicyEvaluator, PolicyFinding, PolicyIncompleteReason,
    PolicyLocationRelationship, PolicyRegistry, PolicyRegistryLimits, PolicyReportDiagnostic,
    PolicyReportDiagnosticCode, PolicyReportDocument, PolicyRuleDescriptor, PolicyRun,
    PolicyRunCompletion, PolicyRunScope, PolicySourceIdentity, PolicyWorkReport,
    RelatedPolicyLocation, TaintCatalogRegistry,
};
use brokk_bifrost_analysis::analyzer::{Language, ProjectFile, TestProject};
use brokk_bifrost_js_ts_analysis::TypescriptAnalyzer;
use brokk_bifrost_rql::structural::CodeQueryDiagnosticCode;
use serde_json::Value;

const POLICY: &str = r#"(policy
  :schema-version 1
  :id "test.sarif-contract"
  :name "Readable rule name"
  :description "Explains the rule to a SARIF reader"
  :message "Target was selected"
  :severity warning
  :analysis (analysis :type match :selector
    (rql :schema-version 1 (language typescript (function :name "target")))))"#;

pub(super) fn evaluated_report() -> PolicyReportDocument {
    evaluated_report_with_policy(POLICY)
}

fn evaluated_report_with_policy(source: &str) -> PolicyReportDocument {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "app.ts")
        .write("export function target() { return 1; }\n")
        .unwrap();
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:sarif-contract"),
            source.as_bytes(),
        )
        .unwrap();
    let policy = registry.policies().next().unwrap();
    let descriptor = PolicyRuleDescriptor::from_loaded(policy);
    let run = DefaultPolicyEvaluator::new()
        .evaluate(
            policy,
            &PolicyEvaluationContext {
                analyzer: &analyzer,
                workspace: None,
                flow_state: &brokk_bifrost_flow::FlowWorkspaceState::new(),
                root_memo: None,
                cancellation: None,
                cvss_overlays: &[],
                organizational_risk: &[],
                incremental: None,
            },
            &mut PolicyBudget::default(),
        )
        .unwrap();
    PolicyReportDocument::try_new(vec![descriptor], vec![run], vec![], false, 0, None).unwrap()
}

fn render(report: &PolicyReportDocument, tool: &SarifToolIdentity) -> Value {
    let mut bytes = Vec::new();
    write_policy_sarif(report, tool, &mut bytes, usize::MAX).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn replace_run(report: &PolicyReportDocument, run: PolicyRun) -> PolicyReportDocument {
    PolicyReportDocument::try_new(
        report.rules().to_vec(),
        vec![run],
        report.diagnostics().to_vec(),
        false,
        0,
        None,
    )
    .unwrap()
}

#[test]
fn sarif_describes_real_policy_and_result() {
    let report = evaluated_report();
    let value = render(&report, &SarifToolIdentity::default());
    let run = &value["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "Bifrost");
    assert_eq!(run["tool"]["driver"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        run["tool"]["driver"]["informationUri"],
        env!("CARGO_PKG_HOMEPAGE")
    );
    let rule = &run["tool"]["driver"]["rules"][0];
    assert_eq!(rule["id"], "test.sarif-contract");
    assert_eq!(rule["name"], "Readable rule name");
    assert_eq!(rule["defaultConfiguration"]["level"], "warning");
    assert_eq!(
        rule["fullDescription"]["text"],
        "Explains the rule to a SARIF reader"
    );
    assert_eq!(
        run["properties"]["bifrost.policyReportSchemaVersion"],
        report.schema_version()
    );
    assert_eq!(run["results"][0]["ruleId"], "test.sarif-contract");
    assert_eq!(run["results"][0]["level"], "warning");
}

#[test]
fn sarif_refuses_whitespace_tool_name() {
    let error = write_policy_sarif(
        &evaluated_report(),
        &SarifToolIdentity::new(" \t "),
        Vec::new(),
        usize::MAX,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        PolicyRenderError::InvalidCanonicalReport { .. }
    ));
}

#[test]
fn sarif_preserves_explicit_tool_version_and_uri() {
    let tool = SarifToolIdentity::new("Bifrost")
        .with_version("test-release")
        .with_information_uri("https://example.test/tool");
    let value = render(&evaluated_report(), &tool);
    let driver = &value["runs"][0]["tool"]["driver"];
    assert_eq!(driver["version"], "test-release");
    assert_eq!(driver["informationUri"], "https://example.test/tool");
}

#[test]
fn sarif_error_policy_marks_rule_and_finding_error() {
    let source = POLICY.replace(":severity warning", ":severity error");
    let value = render(
        &evaluated_report_with_policy(&source),
        &SarifToolIdentity::default(),
    );
    let run = &value["runs"][0];
    assert_eq!(
        run["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"],
        "error"
    );
    assert_eq!(run["results"][0]["level"], "error");
}

#[test]
fn sarif_reports_diagnostics_and_incomplete_obligations() {
    let report = evaluated_report();
    let complete = &report.runs()[0];
    let diagnostic = PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::CodeQuery {
            code: CodeQueryDiagnosticCode::SemanticBudgetExhausted,
        },
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        "query budget exhausted",
        None,
        vec![],
    )
    .unwrap();
    let mut run = PolicyRun::try_new(
        complete.policy_id().clone(),
        complete.policy_hash(),
        complete.analysis_type(),
        PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::PipelineRowBudget]).unwrap(),
        complete.findings().to_vec(),
        vec![diagnostic],
        false,
        PolicyWorkReport::default(),
        &PolicyBudget::default(),
    )
    .unwrap();
    run.set_obligations(&[], true, 1, &PolicyBudget::default())
        .unwrap();
    let report_diagnostic = PolicyReportDiagnostic::try_new(
        PolicyReportDiagnosticCode::PolicyLoadFailed,
        PolicyDiagnosticSeverity::Error,
        "policy load failed",
        None,
        None,
        vec![],
    )
    .unwrap();
    let note = PolicyReportDiagnostic::try_new(
        PolicyReportDiagnosticCode::PolicyParseFailed,
        PolicyDiagnosticSeverity::Note,
        "advisory note",
        None,
        None,
        vec![],
    )
    .unwrap();
    let report = PolicyReportDocument::try_new(
        report.rules().to_vec(),
        vec![run],
        vec![report_diagnostic, note],
        false,
        0,
        None,
    )
    .unwrap();
    let value = render(&report, &SarifToolIdentity::default());
    let run = &value["runs"][0];
    assert_eq!(run["invocations"][0]["executionSuccessful"], false);
    let notifications = run["invocations"][0]["toolExecutionNotifications"]
        .as_array()
        .unwrap();
    assert!(
        notifications
            .iter()
            .any(|n| n["descriptor"]["id"] == "BIFROST_POLICY_INCONCLUSIVE"
                && n["level"] == "warning"
                && n["properties"]["bifrost.obligations"]["truncated"] == true)
    );
    assert!(
        notifications
            .iter()
            .any(|n| n["descriptor"]["id"] == "policy-parse-failed" && n["level"] == "note")
    );
    assert_eq!(
        run["properties"]["bifrost.policyRuns"][0]["diagnostics"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn sarif_names_changed_range_even_when_run_is_complete() {
    let report = evaluated_report();
    let run = report.runs()[0]
        .clone()
        .with_scope(Some(PolicyRunScope::changed_range(vec![], vec![])));
    let report = replace_run(&report, run);
    let value = render(&report, &SarifToolIdentity::default());
    let notifications = value["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        .as_array()
        .unwrap();
    assert!(
        notifications
            .iter()
            .any(|n| n["descriptor"]["id"] == "BIFROST_POLICY_RANGE_SCOPED")
    );
}

#[test]
fn sarif_related_location_ids_start_at_one() {
    let report = evaluated_report();
    let run = &report.runs()[0];
    let finding = &run.findings()[0];
    let source = RelatedPolicyLocation::try_new(
        PolicyLocationRelationship::Source,
        finding.primary().clone(),
        vec![EvidenceRef::try_new("test", "related source").unwrap()],
    )
    .unwrap();
    let sink = RelatedPolicyLocation::try_new(
        PolicyLocationRelationship::Sink,
        finding.primary().clone(),
        vec![EvidenceRef::try_new("test", "related sink").unwrap()],
    )
    .unwrap();
    let finding = PolicyFinding::try_new(
        finding.policy_id().clone(),
        finding.policy_hash(),
        finding.severity(),
        finding.message().to_string(),
        finding.classification().clone(),
        finding.certainty().clone(),
        finding.completeness().clone(),
        finding.primary().clone(),
        vec![source, sink],
        false,
        0,
        finding.evidence().clone(),
        false,
        0,
        finding.cvss().cloned(),
        finding.organizational_risk().cloned(),
        finding.proof().clone(),
        finding.witnesses().to_vec(),
        false,
        0,
        &PolicyBudget::default(),
    )
    .unwrap();
    let run = PolicyRun::try_new(
        run.policy_id().clone(),
        run.policy_hash(),
        run.analysis_type(),
        run.completion().clone(),
        vec![finding],
        run.diagnostics().to_vec(),
        false,
        run.work().clone(),
        &PolicyBudget::default(),
    )
    .unwrap();
    let value = render(&replace_run(&report, run), &SarifToolIdentity::default());
    let related = &value["runs"][0]["results"][0]["relatedLocations"][0];
    assert_eq!(related["id"], 1);
    assert_eq!(related["properties"]["bifrost.relationship"], "source");
    let locations = value["runs"][0]["results"][0]["relatedLocations"]
        .as_array()
        .unwrap();
    assert_eq!(locations[1]["id"], 2);
    assert_eq!(locations[1]["properties"]["bifrost.relationship"], "sink");
}
