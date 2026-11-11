use std::io::{self, Write};
use std::sync::Arc;

use super::{
    HumanRenderColor, HumanRenderDetail, HumanRenderOptions, PolicyRenderError, write_policy_human,
    write_policy_json,
};
use crate::finding::{
    PolicyDiagnostic, PolicyDiagnosticCode, PolicyDiagnosticImpact, PolicyDiagnosticSeverity,
    PolicyFinding, PolicyIncompleteReason, PolicyLocationRelationship, PolicyRun,
    PolicyRunCompletion, PolicySelectorGapSummary, PolicySourceLocation, ProofMetadata,
    ProofReason, ProofState, RelatedPolicyLocation,
};
use crate::finding_identity::EvidenceRef;
use crate::{
    CatalogRegistryLimits, DefaultPolicyEvaluator, PolicyBudget, PolicyEvaluationContext,
    PolicyEvaluator, PolicyRegistry, PolicyRegistryLimits, PolicyReportDocument,
    PolicyRuleDescriptor, PolicySourceIdentity, TaintCatalogRegistry,
};
use brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath;
use brokk_bifrost_analysis::analyzer::{Language, ProjectFile, TestProject};
use brokk_bifrost_js_ts_analysis::TypescriptAnalyzer;

fn evaluated_report(policy_id: &str, source: &str) -> PolicyReportDocument {
    let policy_source = format!(
        r#"(policy :schema-version 1 :id "{policy_id}"
      :name "Human detail" :message "Matched" :severity warning
      :analysis (analysis :type match :selector
        (rql :schema-version 1 (language typescript (function :name "target")))))"#
    );
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "app.ts")
        .write(source)
        .unwrap();
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:human-final"),
            policy_source.as_bytes(),
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
                identifier_typos: None,
            },
            &mut PolicyBudget::default(),
        )
        .unwrap();
    PolicyReportDocument::try_new(vec![descriptor], vec![run], Vec::new(), false, 0, None).unwrap()
}

fn render(report: &PolicyReportDocument, detail: HumanRenderDetail) -> String {
    let mut bytes = Vec::new();
    write_policy_human(
        report,
        &HumanRenderOptions::new(detail, HumanRenderColor::Plain),
        &mut bytes,
        usize::MAX,
    )
    .unwrap();
    String::from_utf8(bytes).unwrap()
}

fn changed_run(
    source: &PolicyRun,
    completion: PolicyRunCompletion,
    diagnostics: Vec<PolicyDiagnostic>,
) -> PolicyRun {
    PolicyRun::try_new(
        source.policy_id().clone(),
        source.policy_hash(),
        source.analysis_type(),
        completion,
        Vec::new(),
        diagnostics,
        false,
        source.work().clone(),
        &PolicyBudget::default(),
    )
    .unwrap()
}

#[test]
fn authored_proof_names_model_content_and_first_reference() {
    let report = evaluated_report("test.proof-detail", "export function target() {}\n");
    let run = &report.runs()[0];
    let original = &run.findings()[0];
    let proof = ProofMetadata::try_new(
        ProofState::Proven,
        vec![
            ProofReason::DirectStructuralMatch,
            ProofReason::AuthoredArmClosure {
                model: "model.alpha".to_owned(),
                content: "content.beta".to_owned(),
                contract_version: 7,
            },
        ],
        vec![
            EvidenceRef::try_new("policy", "first").unwrap(),
            EvidenceRef::try_new("policy", "second").unwrap(),
        ],
    )
    .unwrap();
    let finding = PolicyFinding::try_new(
        original.policy_id().clone(),
        original.policy_hash(),
        original.severity(),
        original.message().to_owned(),
        original.classification().clone(),
        original.certainty().clone(),
        original.completeness().clone(),
        original.primary().clone(),
        original.related().to_vec(),
        original.related_truncated(),
        original.omitted_related_locations_lower_bound(),
        original.evidence().clone(),
        original.evidence_refs_truncated(),
        original.omitted_evidence_refs_lower_bound(),
        original.cvss().cloned(),
        original.organizational_risk().cloned(),
        proof,
        original.witnesses().to_vec(),
        original.witnesses_truncated(),
        original.omitted_witnesses_lower_bound(),
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
        run.diagnostics_truncated(),
        run.work().clone(),
        &PolicyBudget::default(),
    )
    .unwrap();
    let report = PolicyReportDocument::try_new(
        report.rules().to_vec(),
        vec![run],
        Vec::new(),
        false,
        0,
        None,
    )
    .unwrap();
    let output = render(&report, HumanRenderDetail::Verbose);
    assert!(
        output.contains("authored arm closure model model.alpha content content.beta contract 7"),
        "{output}"
    );
    assert!(
        output.contains("  proof evidence: policy:first"),
        "{output}"
    );
    assert!(
        output.contains("  proof evidence: policy:second"),
        "{output}"
    );
}

#[test]
fn incomplete_and_summary_proven_runs_keep_their_completion_reasons() {
    let base = evaluated_report("test.completion", "export function other() {}\n");
    let source = &base.runs()[0];
    let inconclusive = changed_run(
        source,
        PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::Cancelled]).unwrap(),
        Vec::new(),
    );
    let report = PolicyReportDocument::try_new(
        base.rules().to_vec(),
        vec![inconclusive],
        Vec::new(),
        false,
        0,
        None,
    )
    .unwrap();
    let output = render(&report, HumanRenderDetail::Verbose);
    assert!(
        output.contains("inconclusive (cancelled); non-clean"),
        "{output}"
    );

    let summary = changed_run(source, PolicyRunCompletion::ProvenBySummary, Vec::new());
    let report = PolicyReportDocument::try_new(
        base.rules().to_vec(),
        vec![summary],
        Vec::new(),
        false,
        0,
        None,
    )
    .unwrap();
    let output = render(&report, HumanRenderDetail::Verbose);
    assert!(
        output.contains("proven by summary") && output.contains("non-exhaustive"),
        "{output}"
    );
}

#[test]
fn folded_diagnostic_count_and_related_locations_survive_rendering() {
    let base = evaluated_report("test.diagnostics", "export function other() {}\n");
    let source = &base.runs()[0];
    let related = ["src/first.ts", "src/second.ts"]
        .into_iter()
        .map(|path| {
            RelatedPolicyLocation::try_new(
                PolicyLocationRelationship::Evidence,
                PolicySourceLocation::artifact(WorkspaceRelativePath::new(path).unwrap()),
                Vec::new(),
            )
            .unwrap()
        })
        .collect();
    let diagnostic = PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        "two source diagnostics",
        None,
        related,
    )
    .unwrap()
    .with_family_count(2);
    let run = changed_run(
        source,
        PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::PartialDiscovery]).unwrap(),
        vec![diagnostic],
    );
    let report =
        PolicyReportDocument::try_new(base.rules().to_vec(), vec![run], Vec::new(), false, 0, None)
            .unwrap();
    let output = render(&report, HumanRenderDetail::Verbose);
    assert!(output.contains("[x2]"), "{output}");
    assert!(output.contains("src/first.ts"), "{output}");
    assert!(output.contains("src/second.ts"), "{output}");
}

#[test]
fn concise_selector_gap_caps_sites_and_counts_one_unlisted() {
    let base = evaluated_report("test.selector-limit", "export function other() {}\n");
    let source = &base.runs()[0];
    let sites = (1..=4).map(|index| (format!("src/site-{index}.ts"), Some(index)));
    let diagnostic = PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Warning,
        PolicyDiagnosticImpact::RunIncomplete,
        "selector discovery incomplete",
        None,
        Vec::new(),
    )
    .unwrap()
    .with_selector_gap(PolicySelectorGapSummary::new(
        "source Input.read",
        ["partial_discovery".to_owned()],
        sites,
    ));
    let run = changed_run(
        source,
        PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::PartialDiscovery]).unwrap(),
        vec![diagnostic],
    );
    let report =
        PolicyReportDocument::try_new(base.rules().to_vec(), vec![run], Vec::new(), false, 0, None)
            .unwrap();
    let output = render(&report, HumanRenderDetail::Concise);
    assert_eq!(output.matches("src/site-").count(), 3, "{output}");
    assert!(output.contains("and 1 more site"), "{output}");
}

struct FlushFailure(Vec<u8>);

impl Write for FlushFailure {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush refused"))
    }
}

#[test]
fn canonical_json_reports_flush_failure_after_writing_valid_bytes() {
    let report = evaluated_report("test.json-flush", "export function other() {}\n");
    let mut writer = FlushFailure(Vec::new());
    let result = write_policy_json(&report, &mut writer, usize::MAX);
    assert!(
        matches!(result, Err(PolicyRenderError::Output(_))),
        "{result:?}"
    );
    let round_trip: serde_json::Value = serde_json::from_slice(&writer.0).unwrap();
    assert_eq!(
        round_trip["schema_version"],
        PolicyReportDocument::SCHEMA_VERSION
    );
}
