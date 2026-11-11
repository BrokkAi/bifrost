use super::{HumanRenderColor, HumanRenderDetail, HumanRenderOptions, write_policy_human};
use crate::classification::{
    ClassificationProvenance, FindingClassification, TaxonomyClassification,
};
use crate::finding::{
    MatchFindingEvidence, PolicyFinding, PolicyFindingEvidence, PolicyQueryResultRef,
};
use crate::finding::{
    PolicyDiagnostic, PolicyDiagnosticCode, PolicyDiagnosticImpact, PolicyDiagnosticSeverity,
    PolicyIncompleteReason, PolicyLocationRelationship, PolicyRun, PolicyRunCompletion,
    PolicySelectorGapSummary, PolicySourceLocation, RelatedPolicyLocation,
};
use crate::finding_identity::EvidenceRef;
use crate::report::{PolicyDiffCounts, PolicyDiffReview, PolicyDiffUnqualifiedPolicy};
use crate::{
    CatalogRegistryLimits, DefaultPolicyEvaluator, PolicyEvaluationContext, PolicyEvaluator,
    PolicyRegistry, PolicyRegistryLimits, PolicyRuleDescriptor, PolicySourceIdentity,
    TaintCatalogRegistry,
};
use crate::{PolicyBatchBudget, PolicyBudget, PolicyReportBuilder, PolicyReportDocument};
use brokk_bifrost_analysis::analyzer::{Language, ProjectFile, TestProject};
use brokk_bifrost_js_ts_analysis::TypescriptAnalyzer;
use std::sync::Arc;

const POLICY: &str = r#"(policy :schema-version 1 :id "test.human-detail"
 :name "Human detail" :message "Matched" :severity warning
 :analysis (analysis :type match :selector
   (rql :schema-version 1 (language typescript (function :name "target")))))"#;

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

fn evaluated_report(source: &str) -> PolicyReportDocument {
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
            PolicySourceIdentity::new("test:human-detail"),
            POLICY.as_bytes(),
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

#[test]
fn human_views_keep_the_close_match_marker_when_contributor_details_are_cut() {
    let report = evaluated_report("export function target() {}\n");
    let budget = PolicyBudget::default();
    let snapshot = crate::test_support::close_match_snapshot();
    let mut run = crate::evaluator::apply_approximate_family_backstop(
        report.runs()[0].clone(),
        Some(snapshot.as_ref()),
        &budget,
    )
    .unwrap();
    let contributor = run.findings()[0].model_attribution().unwrap().contributors[0].clone();
    let finding = run.findings()[0].clone();
    run.findings_mut()[0] = finding
        .with_model_attribution(
            Some(crate::ModelAttribution::from_full(vec![contributor], 0)),
            &budget,
        )
        .unwrap();
    let marked = PolicyReportDocument::try_new(
        report.rules().to_vec(),
        vec![run],
        Vec::new(),
        false,
        0,
        None,
    )
    .unwrap();
    let json = serde_json::to_string(&marked).unwrap();
    assert!(json.contains("\"model_attribution\""), "{json}");
    assert!(json.contains("\"omitted_at_least\":1"), "{json}");
    for detail in [HumanRenderDetail::Verbose, HumanRenderDetail::Concise] {
        let text = render(&marked, detail);
        assert!(
            text.to_lowercase()
                .contains("may depend on approximate model evidence (active pack)"),
            "{text}"
        );
        assert!(text.contains("at least 1 more contributor"), "{text}");
    }
}

#[test]
fn located_selector_gap_keeps_distinct_sites() {
    let report = evaluated_report("export function other() {}\n");
    let source = &report.runs()[0];
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
        ["call_shape_coverage_incomplete".to_owned()],
        [
            ("src/first.rs".to_owned(), Some(5)),
            ("src/second.rs".to_owned(), Some(9)),
        ],
    ));
    let run = PolicyRun::try_new(
        source.policy_id().clone(),
        source.policy_hash(),
        source.analysis_type(),
        PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::PartialDiscovery]).unwrap(),
        Vec::new(),
        vec![diagnostic],
        false,
        source.work().clone(),
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
    let output = render(&report, HumanRenderDetail::Concise);
    assert!(output.contains("src/first.rs:5"), "{output}");
    assert!(output.contains("src/second.rs:9"), "{output}");
}

#[test]
fn unqualified_diff_names_completion_detail_and_each_diagnostic() {
    let report = evaluated_report("export function other() {}\n");
    let policy_id = report.runs()[0].policy_id().clone();
    let mut builder = PolicyReportBuilder::new(PolicyBatchBudget::default(), 1).unwrap();
    builder
        .register_policy(report.rules()[0].clone(), report.runs()[0].clone())
        .unwrap();
    builder
        .set_diff(PolicyDiffReview::new(
            "HEAD".to_owned(),
            "a".repeat(40),
            true,
            vec![PolicyDiffUnqualifiedPolicy::new(
                policy_id,
                "inconclusive",
                "base source bytes cut",
                vec![
                    "source budget cut".to_owned(),
                    "reference budget cut".to_owned(),
                ],
            )],
            PolicyDiffCounts {
                new: 0,
                persisting: 0,
                fixed: 0,
            },
            Vec::new(),
        ))
        .unwrap();
    let output = render(&builder.finish().unwrap(), HumanRenderDetail::Verbose);
    assert!(
        output.contains("(inconclusive): base source bytes cut"),
        "{output}"
    );
    assert!(output.contains("Diagnostic: source budget cut"), "{output}");
    assert!(
        output.contains("Diagnostic: reference budget cut"),
        "{output}"
    );
}

#[test]
fn analysis_classification_prints_every_evidence_reference() {
    let source_report = evaluated_report("export function target() { return 1; }\n");
    let run = &source_report.runs()[0];
    let descriptor = source_report.rules()[0].clone();
    let original = &run.findings()[0];
    let broad = TaxonomyClassification::try_new(
        "Test",
        "BROAD",
        None,
        ClassificationProvenance::PolicyFallback,
    )
    .unwrap();
    let refinement = TaxonomyClassification::try_new(
        "CWE",
        "CWE-020",
        None,
        ClassificationProvenance::analysis_evidence(
            "bifrost.match",
            vec![
                EvidenceRef::try_new("policy", "first").unwrap(),
                EvidenceRef::try_new("policy", "second").unwrap(),
            ],
        )
        .unwrap(),
    )
    .unwrap();
    let PolicyFindingEvidence::Match { evidence } = original.evidence() else {
        panic!("match policy must produce match evidence");
    };
    let evidence = PolicyFindingEvidence::Match {
        evidence: MatchFindingEvidence::try_new(
            evidence.result_domain(),
            evidence.anchor().clone(),
            PolicyQueryResultRef::StructuralMatch {
                kind: "function".to_owned(),
                location: original.primary().clone(),
                identity: None,
            },
            evidence.provenance().to_vec(),
            evidence.provenance_truncated(),
        )
        .unwrap(),
    };
    let finding = PolicyFinding::try_new(
        original.policy_id().clone(),
        original.policy_hash(),
        original.severity(),
        original.message().to_owned(),
        FindingClassification::classified(broad, vec![refinement]).unwrap(),
        original.certainty().clone(),
        original.completeness().clone(),
        original.primary().clone(),
        original.related().to_vec(),
        original.related_truncated(),
        original.omitted_related_locations_lower_bound(),
        evidence,
        original.evidence_refs_truncated(),
        original.omitted_evidence_refs_lower_bound(),
        original.cvss().cloned(),
        original.organizational_risk().cloned(),
        original.proof().clone(),
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
    let report =
        PolicyReportDocument::try_new(vec![descriptor], vec![run], Vec::new(), false, 0, None)
            .unwrap();
    let output = render(&report, HumanRenderDetail::Verbose);
    assert!(
        output.contains("        evidence: policy:first"),
        "{output}"
    );
    assert!(
        output.contains("        evidence: policy:second"),
        "{output}"
    );
    assert!(output.contains("identity unavailable"), "{output}");
}

#[test]
fn related_diagnostic_prints_its_evidence_suffix() {
    let report = evaluated_report("export function other() {}\n");
    let source = &report.runs()[0];
    let related = RelatedPolicyLocation::try_new(
        PolicyLocationRelationship::Evidence,
        PolicySourceLocation::artifact(
            brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath::new("src/input.ts")
                .unwrap(),
        ),
        vec![EvidenceRef::try_new("policy", "source-site").unwrap()],
    )
    .unwrap();
    let diagnostic = PolicyDiagnostic::try_new(
        PolicyDiagnosticCode::EvaluationFailure,
        PolicyDiagnosticSeverity::Note,
        PolicyDiagnosticImpact::Advisory,
        "related source evidence",
        None,
        vec![related],
    )
    .unwrap();
    let run = PolicyRun::try_new(
        source.policy_id().clone(),
        source.policy_hash(),
        source.analysis_type(),
        source.completion().clone(),
        Vec::new(),
        vec![diagnostic],
        false,
        source.work().clone(),
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
        output.contains("src/input.ts [evidence policy:source-site]"),
        "{output}"
    );
}
