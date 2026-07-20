mod common;

use std::sync::Arc;

use brokk_bifrost::policy::{
    CatalogRegistryLimits, CvssAssessment, CvssEnvironmentOverlayEvidence,
    CvssEnvironmentalOrSupplementalMetric as EnvironmentalMetric, CvssEvaluationOverlay,
    CvssEvidenceScope, CvssMetric, CvssMetricValue, CvssMetricValueToken as Token,
    CvssNomenclature, CvssOverlayEvidenceMetadata, CvssSeverity, CvssSystemScope, CvssThreatMetric,
    CvssThreatOverlayEvidence, DefaultPolicyEvaluator, EvidenceRef, FindingSeverity, PolicyBudget,
    PolicyEvaluationContext, PolicyEvaluator, PolicyOverlayScope, PolicyRegistry,
    PolicyRegistryLimits, PolicySourceIdentity, TaintCatalogRegistry,
};
use brokk_bifrost::{Language, TypescriptAnalyzer};
use common::InlineTestProject;

const BASE_NAMES: [&str; 11] = [
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
];

fn policy_source(id: &str, values: &[(&str, &str)]) -> String {
    let rules = values
        .iter()
        .map(|(metric, value)| {
            let scope = if matches!(*metric, "SC" | "SI" | "SA") {
                "subsequent-system"
            } else {
                "vulnerable-system"
            };
            format!(
                r#"(metric
                  :name {metric}
                  :value {value}
                  :when (analysis-type :is match)
                  :basis policy-assertion
                  :scope {scope}
                  :evidence-refs [policy:self]
                  :rationale "Pinned CVSS conformance evidence")"#
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"(policy
          :id "{id}"
          :name "CVSS conformance"
          :message "Selected target has CVSS evidence"
          :severity (cvss-severity :when-unscored warning)
          :analysis (analysis
            :type match
            :selector (rql (function :name "target")))
          :classification (classification
            :fallback (classification-id :taxonomy "Bifrost" :id "CVSS-CONFORMANCE")
            :cvss (cvss
              :version "4.0"
              :emit when-base-complete
              :metric-rules [
                {rules}])))"#
    )
}

fn registry_with_policy(source: &str) -> PolicyRegistry {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:cvss-classification"),
            source.as_bytes(),
        )
        .expect("valid CVSS policy");
    registry
}

fn analyzer() -> (common::BuiltInlineTestProject, TypescriptAnalyzer) {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", "export function target() { return 1; }\n")
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn evaluate(source: &str, overlays: &[CvssEvaluationOverlay]) -> brokk_bifrost::policy::PolicyRun {
    let (_project, analyzer) = analyzer();
    let registry = registry_with_policy(source);
    let policy = registry.policies().next().expect("one policy");
    let mut budget = PolicyBudget::default();
    DefaultPolicyEvaluator::new()
        .evaluate(
            policy,
            &PolicyEvaluationContext {
                analyzer: &analyzer,
                cancellation: None,
                cvss_overlays: overlays,
                organizational_risk: &[],
            },
            &mut budget,
        )
        .expect("policy evaluation")
}

fn metadata(id: &str, scope: CvssEvidenceScope) -> CvssOverlayEvidenceMetadata {
    CvssOverlayEvidenceMetadata::try_new(
        vec![EvidenceRef::try_new("cvss-conformance", id).unwrap()],
        "Pinned FIRST example overlay".to_string(),
        Vec::new(),
        "bifrost-test".to_string(),
        "2026-07-18T00:00:00Z".to_string(),
        scope,
        None,
    )
    .unwrap()
}

fn threat(token: Token) -> CvssEvaluationOverlay {
    let metric = CvssThreatMetric::E;
    CvssEvaluationOverlay::ThreatFeed {
        scope: PolicyOverlayScope::AllFindings,
        evidence: CvssThreatOverlayEvidence::try_new(
            metric,
            CvssMetricValue::try_new(CvssMetric::Threat { metric }, token).unwrap(),
            metadata("threat-E", CvssEvidenceScope::Global),
        )
        .unwrap(),
    }
}

fn environmental_scope(metric: EnvironmentalMetric) -> CvssEvidenceScope {
    match metric {
        EnvironmentalMetric::Mav
        | EnvironmentalMetric::Mac
        | EnvironmentalMetric::Mat
        | EnvironmentalMetric::Mpr
        | EnvironmentalMetric::Mui
        | EnvironmentalMetric::Mvc
        | EnvironmentalMetric::Mvi
        | EnvironmentalMetric::Mva => CvssEvidenceScope::System {
            system: CvssSystemScope::VulnerableSystem,
        },
        EnvironmentalMetric::Msc | EnvironmentalMetric::Msi | EnvironmentalMetric::Msa => {
            CvssEvidenceScope::System {
                system: CvssSystemScope::SubsequentSystem,
            }
        }
        EnvironmentalMetric::Cr
        | EnvironmentalMetric::Ir
        | EnvironmentalMetric::Ar
        | EnvironmentalMetric::S
        | EnvironmentalMetric::Au
        | EnvironmentalMetric::R
        | EnvironmentalMetric::V
        | EnvironmentalMetric::Re
        | EnvironmentalMetric::U => CvssEvidenceScope::Global,
    }
}

fn environment(metric: EnvironmentalMetric, token: Token) -> CvssEvaluationOverlay {
    let typed_metric = CvssMetric::EnvironmentalOrSupplemental { metric };
    CvssEvaluationOverlay::EnvironmentProfile {
        scope: PolicyOverlayScope::AllFindings,
        evidence: CvssEnvironmentOverlayEvidence::try_new(
            metric,
            CvssMetricValue::try_new(typed_metric, token).unwrap(),
            metadata(metric.first_label(), environmental_scope(metric)),
        )
        .unwrap(),
    }
}

struct ScoredExpectation<'a> {
    vector: &'a str,
    nomenclature: CvssNomenclature,
    score: f64,
    cvss_severity: CvssSeverity,
    finding_severity: FindingSeverity,
}

fn assert_scored_case(
    id: &str,
    base: &[(&str, &str)],
    overlays: Vec<CvssEvaluationOverlay>,
    expected: ScoredExpectation<'_>,
) {
    let run = evaluate(&policy_source(id, base), &overlays);
    assert_eq!(run.findings().len(), 1);
    let finding = &run.findings()[0];
    assert_eq!(finding.severity(), expected.finding_severity);
    let broad = finding
        .classification()
        .broad()
        .expect("fallback classification");
    assert_eq!(broad.taxonomy(), "Bifrost");
    assert_eq!(broad.identifier(), "CVSS-CONFORMANCE");
    assert!(finding.classification().refinements().is_empty());
    let set = finding.cvss().expect("CVSS assessment");
    assert_eq!(set.variants().len(), 1);
    let variant = &set.variants()[0];
    assert_eq!(set.selected_for_display(), Some(variant.id()));
    assert_eq!(
        set.selection_rationale(),
        Some("selected highest scored coherent variant; ties use canonical vector then variant id")
    );
    let CvssAssessment::Scored {
        nomenclature,
        vector,
        components,
        ..
    } = variant.assessment()
    else {
        panic!("complete base evidence must score");
    };
    assert_eq!(vector, expected.vector);
    assert_eq!(*nomenclature, expected.nomenclature);
    let selected = components
        .iter()
        .find(|component| component.nomenclature() == expected.nomenclature)
        .expect("named component");
    assert_eq!(selected.vector(), expected.vector);
    assert_eq!(selected.score(), expected.score);
    assert_eq!(selected.severity(), expected.cvss_severity);
    let wire = serde_json::to_value(finding).unwrap();
    assert_eq!(wire["cvss"]["variants"][0]["assessment"]["type"], "scored");
    assert_eq!(
        wire["cvss"]["variants"][0]["assessment"]["vector"],
        expected.vector
    );
}

#[test]
fn public_findings_recompute_all_pinned_first_vectors_scores_and_severities() {
    assert_scored_case(
        "test.cvss-b",
        &[
            ("AV", "L"),
            ("AC", "L"),
            ("AT", "P"),
            ("PR", "L"),
            ("UI", "N"),
            ("VC", "H"),
            ("VI", "H"),
            ("VA", "H"),
            ("SC", "N"),
            ("SI", "N"),
            ("SA", "N"),
        ],
        Vec::new(),
        ScoredExpectation {
            vector: "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            nomenclature: CvssNomenclature::B,
            score: 7.3,
            cvss_severity: CvssSeverity::High,
            finding_severity: FindingSeverity::Error,
        },
    );
    assert_scored_case(
        "test.cvss-bt",
        &[
            ("AV", "N"),
            ("AC", "L"),
            ("AT", "P"),
            ("PR", "N"),
            ("UI", "P"),
            ("VC", "H"),
            ("VI", "H"),
            ("VA", "H"),
            ("SC", "N"),
            ("SI", "N"),
            ("SA", "N"),
        ],
        vec![threat(Token::U)],
        ScoredExpectation {
            vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U",
            nomenclature: CvssNomenclature::BT,
            score: 5.2,
            cvss_severity: CvssSeverity::Medium,
            finding_severity: FindingSeverity::Warning,
        },
    );
    assert_scored_case(
        "test.cvss-be",
        &[
            ("AV", "N"),
            ("AC", "L"),
            ("AT", "P"),
            ("PR", "N"),
            ("UI", "N"),
            ("VC", "H"),
            ("VI", "L"),
            ("VA", "L"),
            ("SC", "N"),
            ("SI", "N"),
            ("SA", "N"),
        ],
        vec![
            environment(EnvironmentalMetric::Cr, Token::H),
            environment(EnvironmentalMetric::Ir, Token::L),
            environment(EnvironmentalMetric::Ar, Token::L),
            environment(EnvironmentalMetric::Mav, Token::N),
            environment(EnvironmentalMetric::Mac, Token::H),
            environment(EnvironmentalMetric::Mvc, Token::H),
            environment(EnvironmentalMetric::Mvi, Token::L),
            environment(EnvironmentalMetric::Mva, Token::L),
        ],
        ScoredExpectation {
            vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L",
            nomenclature: CvssNomenclature::BE,
            score: 8.1,
            cvss_severity: CvssSeverity::High,
            finding_severity: FindingSeverity::Error,
        },
    );
    assert_scored_case(
        "test.cvss-bte",
        &[
            ("AV", "N"),
            ("AC", "H"),
            ("AT", "P"),
            ("PR", "N"),
            ("UI", "N"),
            ("VC", "H"),
            ("VI", "H"),
            ("VA", "H"),
            ("SC", "N"),
            ("SI", "N"),
            ("SA", "N"),
        ],
        vec![
            threat(Token::P),
            environment(EnvironmentalMetric::Mac, Token::L),
            environment(EnvironmentalMetric::Mat, Token::N),
            environment(EnvironmentalMetric::Mvc, Token::N),
            environment(EnvironmentalMetric::Mvi, Token::N),
            environment(EnvironmentalMetric::Mva, Token::L),
        ],
        ScoredExpectation {
            vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/MAC:L/MAT:N/MVC:N/MVI:N/MVA:L",
            nomenclature: CvssNomenclature::BTE,
            score: 5.5,
            cvss_severity: CvssSeverity::Medium,
            finding_severity: FindingSeverity::Warning,
        },
    );
    assert_scored_case(
        "test.cvss-zero",
        &[
            ("AV", "N"),
            ("AC", "L"),
            ("AT", "N"),
            ("PR", "N"),
            ("UI", "N"),
            ("VC", "N"),
            ("VI", "N"),
            ("VA", "N"),
            ("SC", "N"),
            ("SI", "N"),
            ("SA", "N"),
        ],
        Vec::new(),
        ScoredExpectation {
            vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
            nomenclature: CvssNomenclature::B,
            score: 0.0,
            cvss_severity: CvssSeverity::None,
            finding_severity: FindingSeverity::Note,
        },
    );
}

#[test]
fn every_missing_base_metric_is_publicly_unscored_and_uses_the_authored_fallback() {
    let complete = [
        ("AV", "L"),
        ("AC", "L"),
        ("AT", "P"),
        ("PR", "L"),
        ("UI", "N"),
        ("VC", "H"),
        ("VI", "H"),
        ("VA", "H"),
        ("SC", "N"),
        ("SI", "N"),
        ("SA", "N"),
    ];
    for missing in BASE_NAMES {
        let values = complete
            .iter()
            .copied()
            .filter(|(metric, _)| *metric != missing)
            .collect::<Vec<_>>();
        let run = evaluate(
            &policy_source(
                &format!("test.missing-{}", missing.to_ascii_lowercase()),
                &values,
            ),
            &[],
        );
        let finding = &run.findings()[0];
        assert_eq!(finding.severity(), FindingSeverity::Warning);
        let set = finding.cvss().unwrap();
        assert_eq!(set.selected_for_display(), None);
        let CvssAssessment::Unscored {
            missing_base_metrics,
            ..
        } = set.variants()[0].assessment()
        else {
            panic!("missing {missing} unexpectedly scored");
        };
        assert_eq!(missing_base_metrics.len(), 1);
        assert_eq!(missing_base_metrics[0].first_label(), missing);
        assert_eq!(
            serde_json::to_value(finding).unwrap()["cvss"]["variants"][0]["assessment"]["type"],
            "unscored"
        );
    }
}

#[test]
fn authored_base_x_is_rejected_before_evaluation() {
    let source = policy_source(
        "test.base-x",
        &[
            ("AV", "X"),
            ("AC", "L"),
            ("AT", "P"),
            ("PR", "L"),
            ("UI", "N"),
            ("VC", "H"),
            ("VI", "H"),
            ("VA", "H"),
            ("SC", "N"),
            ("SI", "N"),
            ("SA", "N"),
        ],
    );
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    assert!(
        registry
            .register_policy_bytes(PolicySourceIdentity::new("test:base-x"), source.as_bytes(),)
            .is_err()
    );
}
