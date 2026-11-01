//! Product report evidence from evaluated policies.

use std::sync::Arc;

use super::*;
use crate::{
    CatalogRegistryLimits, CvssEvaluationOverlay, CvssEvidenceScope, CvssMetric, CvssMetricValue,
    CvssMetricValueToken, CvssOverlayEvidenceMetadata, CvssThreatMetric, CvssThreatOverlayEvidence,
    DefaultPolicyEvaluator, EvidenceRef, PolicyBudget, PolicyEvaluationContext, PolicyEvaluator,
    PolicyRegistry, PolicyRegistryLimits, PolicySourceIdentity, TaintCatalogRegistry,
};
use brokk_bifrost_analysis::analyzer::{Language, ProjectFile, TestProject};
use brokk_bifrost_js_ts_analysis::TypescriptAnalyzer;

#[test]
fn assessed_threat_and_truncated_scenario_render_in_report() {
    let names = [
        "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
    ];
    let values = ["N", "L", "N", "N", "N", "H", "H", "H", "H", "H", "H"];
    let rules = names.iter().zip(values).map(|(name, value)| format!(
        "(metric :name {name} :value {value} :when (analysis-type :is match) :basis policy-assertion :scope {} :evidence-refs [policy:self] :rationale \"Verified {name}\")",
        if matches!(*name, "SC" | "SI" | "SA") { "subsequent-system" } else { "vulnerable-system" }
    )).collect::<Vec<_>>().join("\n");
    let source = format!(
        "(policy :id \"test.cvss-report\" :name \"CVSS report\" :message \"Target has scored evidence\" :severity (cvss-severity :when-unscored warning) :analysis (analysis :type match :selector (rql (function :name \"target\"))) :classification (classification :fallback (classification-id :taxonomy \"Bifrost\" :id \"CVSS-REPORT\") :cvss (cvss :version \"4.0\" :emit when-base-complete :metric-rules [{rules}])))"
    );
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "app.ts")
        .write("export function target() { return 1; }\n")
        .unwrap();
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let mut registry = PolicyRegistry::new_without_workspace(
        Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        )),
        PolicyRegistryLimits::default(),
    );
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:timestamp-report"),
            source.as_bytes(),
        )
        .unwrap();
    let policy = registry.policies().next().unwrap();
    let metric = CvssMetric::Threat {
        metric: CvssThreatMetric::E,
    };
    let baseline = DefaultPolicyEvaluator::new()
        .evaluate(
            policy,
            &PolicyEvaluationContext {
                analyzer: &analyzer,
                workspace: None,
                flow_state: &brokk_bifrost_flow::FlowWorkspaceState::default(),
                root_memo: None,
                cancellation: None,
                cvss_overlays: &[],
                organizational_risk: &[],
                incremental: None,
            },
            &mut PolicyBudget::default(),
        )
        .unwrap();
    let finding_id = baseline.findings()[0].id();
    let overlay = CvssEvaluationOverlay::ThreatFeed {
        scope: PolicyOverlayScope::Finding { finding_id },
        evidence: CvssThreatOverlayEvidence::try_new(
            CvssThreatMetric::E,
            CvssMetricValue::try_new(metric, CvssMetricValueToken::A).unwrap(),
            CvssOverlayEvidenceMetadata::try_new(
                vec![EvidenceRef::try_new("feed", "record-17").unwrap()],
                "Trusted feed record".into(),
                vec!["Production scope".into()],
                "test-feed".into(),
                "2026-07-18T10:34:56Z".into(),
                CvssEvidenceScope::Global,
                None,
            )
            .unwrap(),
        )
        .unwrap(),
    };
    let run = DefaultPolicyEvaluator::new()
        .evaluate(
            policy,
            &PolicyEvaluationContext {
                analyzer: &analyzer,
                workspace: None,
                flow_state: &brokk_bifrost_flow::FlowWorkspaceState::default(),
                root_memo: None,
                cancellation: None,
                cvss_overlays: &[overlay],
                organizational_risk: &[],
                incremental: None,
            },
            &mut PolicyBudget::default(),
        )
        .unwrap();
    assert_eq!(run.findings().len(), 1, "{run:?}");
    let report = PolicyReportDocument::try_new(
        vec![PolicyRuleDescriptor::from_loaded(policy)],
        vec![run],
        Vec::new(),
        false,
        0,
        None,
    )
    .unwrap();
    let mut bytes = Vec::new();
    write_policy_human(
        &report,
        &HumanRenderOptions::new(HumanRenderDetail::Verbose, HumanRenderColor::Plain),
        &mut bytes,
        usize::MAX,
    )
    .unwrap();
    let rendered = String::from_utf8(bytes).unwrap();
    assert!(
        rendered.contains("      metric: E=A (threat_feed, global; hash "),
        "{rendered}"
    );
    assert!(
        rendered.contains("        assessed at: 2026-07-18T10:34:56Z\n"),
        "{rendered}"
    );
    assert!(
        rendered.contains(&format!("      overlay scope: finding {finding_id}\n")),
        "{rendered}"
    );

    // The current reducer does not emit IncoherentScenario. Construct a
    // canonical report from this evaluated finding to cover its report form.
    let mut run = report.runs()[0].clone();
    let finding = &run.findings()[0];
    let PolicyFindingEvidence::Match { evidence } = finding.evidence() else {
        panic!("match policy finding");
    };
    let assessment = CvssAssessment::unscored(
        CvssVersion::V4_0,
        Vec::new(),
        vec![crate::CvssBaseMetric::Av],
        vec![
            CvssUnscoredReason::MissingBaseEvidence,
            CvssUnscoredReason::incoherent_scenario(
                crate::SourceScenarioSetHash::from_bytes([7; 32]),
                vec![crate::SourceScenarioId::try_new("test", "first").unwrap()],
                true,
                2,
                "Different source scenarios disagree".into(),
            )
            .unwrap(),
        ],
        crate::test_support::cvss_assessment_provenance(),
    )
    .unwrap();
    let variant = CvssAssessmentVariant::try_new(
        crate::VulnerabilityIdentity::from_bytes(
            crate::finding_identity::match_vulnerability_digest(evidence.anchor()),
        ),
        Vec::new(),
        false,
        0,
        crate::future_evidence::empty_source_scenario_set_hash(),
        Vec::new(),
        false,
        assessment,
    )
    .unwrap();
    let cvss = crate::CvssAssessmentSet::try_new(vec![variant], None).unwrap();
    let replacement = crate::PolicyFinding::try_new(
        finding.policy_id().clone(),
        finding.policy_hash(),
        crate::FindingSeverity::Warning,
        finding.message().into(),
        finding.classification().clone(),
        finding.certainty().clone(),
        finding.completeness().clone(),
        finding.primary().clone(),
        finding.related().to_vec(),
        finding.related_truncated(),
        finding.omitted_related_locations_lower_bound(),
        finding.evidence().clone(),
        finding.evidence_refs_truncated(),
        finding.omitted_evidence_refs_lower_bound(),
        Some(cvss),
        finding.organizational_risk().cloned(),
        finding.proof().clone(),
        finding.witnesses().to_vec(),
        finding.witnesses_truncated(),
        finding.omitted_witnesses_lower_bound(),
        &PolicyBudget::default(),
    )
    .unwrap();
    run.findings_mut()[0] = replacement;
    let report = PolicyReportDocument::try_new(
        report.rules().to_vec(),
        vec![run],
        Vec::new(),
        false,
        0,
        None,
    )
    .unwrap();
    let mut bytes = Vec::new();
    write_policy_human(
        &report,
        &HumanRenderOptions::new(HumanRenderDetail::Verbose, HumanRenderColor::Plain),
        &mut bytes,
        usize::MAX,
    )
    .unwrap();
    let rendered = String::from_utf8(bytes).unwrap();
    assert!(
        rendered.contains("      unscored reason: incoherent scenarios (set "),
        "{rendered}"
    );
    assert!(
        rendered.contains("        incoherent scenarios truncated: at least 2 omitted\n"),
        "{rendered}"
    );
}

#[test]
fn catalog_schema_and_exact_match_origin_have_distinct_report_labels() {
    use crate::{
        PolicyCategoryId, PolicyId, PolicyPort, PolicySelector, SchemaVersionOrigin,
        SchemaVersionResolution, TaintCatalogDefinition, TaintEntryId, TaintLabel, TaintSourceSpec,
    };
    use brokk_bifrost_rql::CodeQuery;

    let mut catalogs =
        TaintCatalogRegistry::new_without_workspace(CatalogRegistryLimits::default());
    catalogs
        .register(TaintCatalogDefinition {
            schema_version: 1,
            name: PolicyId::new("test.catalog").unwrap(),
            version: 1,
            categories: vec![PolicyCategoryId::new("input.user").unwrap()],
            sources: vec![TaintSourceSpec {
                id: TaintEntryId::new("request").unwrap(),
                display_name: "Catalog input".into(),
                categories: vec![PolicyCategoryId::new("input.user").unwrap()],
                selector: PolicySelector::Inline {
                    schema: SchemaVersionResolution {
                        version: brokk_bifrost_rql::SCHEMA_VERSION as u32,
                        origin: SchemaVersionOrigin::Explicit,
                    },
                    query: CodeQuery::from_sexp(
                        "(language typescript (call :callee (name \"input\")))",
                    )
                    .unwrap(),
                    resolved_locators: Vec::new(),
                },
                bind: PolicyPort::ReturnValue,
                labels: vec![TaintLabel::new("untrusted").unwrap()],
                threat_model: None,
                evidence: None,
            }],
            sinks: Vec::new(),
            sanitizers: Vec::new(),
            transforms: Vec::new(),
            external_models: Vec::new(),
        })
        .unwrap();
    let source = r#"(policy :schema-version 1 :id "test.endpoint-audit" :name "Endpoint audit" :message "Input reaches sink" :severity warning
        :analysis (analysis :type taint :mode may
          :sources (endpoint-set :include-sets [(catalog :name "test.catalog" :version 1)]
            :include-matches [(match-endpoints :ids [test.match])])
          :sinks (endpoint-set :entries [(sink :id sink :display-name "Sink" :categories [sink.data]
            :selector (rql :schema-version 1 (call :callee (name "sink")))
            :dangerous-operand (argument :index 0) :accepts [untrusted])])) )"#;
    let endpoint = r#"(endpoint :schema-version 1 :id "test.match" :name "Match input" :display-name "Match input" :role source
        :categories [input.user] :selector (rql :schema-version 1 (call :callee (name "input")))
        :binding return-value :taint (source-semantics :labels [untrusted]) :supersedes [])"#;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "app.ts").write("export function input() { return 'x'; }\nexport function sink(value: string) {}\nsink(input());\n").unwrap();
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let mut registry =
        PolicyRegistry::new_without_workspace(Arc::new(catalogs), PolicyRegistryLimits::default());
    registry
        .register_endpoint_bytes(
            PolicySourceIdentity::new("src/app.rqlp"),
            endpoint.as_bytes(),
        )
        .unwrap();
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:catalog-origin"),
            source.as_bytes(),
        )
        .unwrap();
    let policy = registry.policies().next().unwrap();
    let run = DefaultPolicyEvaluator::new()
        .evaluate(
            policy,
            &PolicyEvaluationContext {
                analyzer: &analyzer,
                workspace: None,
                flow_state: &brokk_bifrost_flow::FlowWorkspaceState::default(),
                root_memo: None,
                cancellation: None,
                cvss_overlays: &[],
                organizational_risk: &[],
                incremental: None,
            },
            &mut PolicyBudget::default(),
        )
        .unwrap();
    let report = PolicyReportDocument::try_new(
        vec![PolicyRuleDescriptor::from_loaded(policy)],
        vec![run],
        Vec::new(),
        false,
        0,
        None,
    )
    .unwrap();
    let mut bytes = Vec::new();
    write_policy_human(
        &report,
        &HumanRenderOptions::new(HumanRenderDetail::Verbose, HumanRenderColor::Plain),
        &mut bytes,
        usize::MAX,
    )
    .unwrap();
    let rendered = String::from_utf8(bytes).unwrap();
    assert!(
        rendered.contains("definition schema: catalog document 1"),
        "{rendered}"
    );
    assert!(
        rendered.contains("definition schema: policy document 1"),
        "{rendered}"
    );
    assert!(
        rendered
            .contains("origin: exact match /analysis/sources/include-matches/0 from src/app.rqlp"),
        "{rendered}"
    );
}
