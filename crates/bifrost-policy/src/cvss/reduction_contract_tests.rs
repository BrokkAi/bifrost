use crate::CvssComponentResult;
use crate::PolicyOverlayScope;
use std::sync::Arc;

use super::*;
use crate::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
use crate::definition::{CvssMetricValue, CvssMetricValueToken};
use crate::evaluator::{CvssAnalystOverlayEvidence, CvssOverlayEvidenceMetadata};
use crate::finding_identity::{MatchResultDomain, OpaqueFindingKey};
use crate::registry::{PolicyRegistry, PolicyRegistryLimits};
use crate::source::PolicySourceIdentity;

fn policy() -> PolicyRegistry {
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    let source = r#"(policy :id "test.reduction" :name "Reduction" :message "M" :severity warning
      :analysis (analysis :type match :selector (rql (call)))
      :classification (classification :fallback (classification-id :taxonomy "test" :id "fallback")
        :cvss (cvss :version "4.0" :emit when-base-complete :metric-rules [(metric :name AV :value N :when (analysis-type :is match) :basis policy-assertion :scope vulnerable-system :evidence-refs [policy:self] :rationale "Network")])))"#;
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:reduction"),
            source.as_bytes(),
        )
        .unwrap();
    registry
}

fn anchor() -> MatchFindingAnchor {
    MatchFindingAnchor::weak(
        MatchResultDomain::File,
        brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath::new("src/lib.rs")
            .unwrap(),
        OpaqueFindingKey::try_new("test", "reduction").unwrap(),
    )
}

fn analyst_overlay(
    scope: PolicyOverlayScope,
    value: CvssMetricValueToken,
) -> CvssEvaluationOverlay {
    analyst_overlay_for_metric(CvssBaseMetric::Av, scope, value, "analyst")
}

fn analyst_overlay_for_metric(
    base_metric: CvssBaseMetric,
    scope: PolicyOverlayScope,
    value: CvssMetricValueToken,
    reference: &str,
) -> CvssEvaluationOverlay {
    let metric = CvssMetric::Base {
        metric: base_metric,
    };
    let metadata = CvssOverlayEvidenceMetadata::try_new(
        vec![EvidenceRef::try_new("test", reference).unwrap()],
        "Analyst observation".to_string(),
        Vec::new(),
        "analyst".to_string(),
        "2026-10-30T00:00:00Z".to_string(),
        base_metric.required_scope(),
        None,
    )
    .unwrap();
    CvssEvaluationOverlay::AnalystOverride {
        scope,
        evidence: CvssAnalystOverlayEvidence::try_new(
            metric,
            CvssMetricValue::try_new(metric, value).unwrap(),
            metadata,
        )
        .unwrap(),
    }
}

fn reduce_with(steps: usize, overlays: &[CvssEvaluationOverlay]) -> CvssReductionOutcome {
    let registry = policy();
    let policy = registry.policies().next().unwrap();
    let anchor = anchor();
    let budget = PolicyBudget::builder()
        .with_max_cvss_reduction_steps(steps)
        .unwrap()
        .build()
        .unwrap();
    reduce_cvss_for_finding(
        policy,
        CvssFindingProjection::Match { anchor: &anchor },
        overlays,
        &[],
        &[],
        usize::MAX,
        &budget,
    )
    .unwrap()
}

#[test]
fn reduction_charges_exactly_seven_steps_for_one_match_assertion() {
    // One predicate, one assertion, one evidence scan, one scope comparison, one highest-basis record, one group, and one seal.
    let exact = reduce_with(7, &[]);
    assert!(exact.incomplete_reason.is_none());
    assert!(exact.assessment.is_some());
    let cut = reduce_with(6, &[]);
    assert_eq!(
        cut.incomplete_reason,
        Some(PolicyIncompleteReason::CvssVariantBudget)
    );
}

#[test]
fn match_finding_scope_uses_the_authored_policy_identity() {
    let registry = policy();
    let loaded = registry.policies().next().unwrap();
    let anchor = anchor();
    let expected_id = PolicyFindingId::from_match_anchor(&loaded.definition().metadata.id, &anchor);
    let overlay = analyst_overlay(
        PolicyOverlayScope::Finding {
            finding_id: expected_id,
        },
        CvssMetricValueToken::N,
    );
    let result = reduce_cvss_for_finding(
        loaded,
        CvssFindingProjection::Match { anchor: &anchor },
        &[overlay],
        &[],
        &[],
        usize::MAX,
        &PolicyBudget::default(),
    )
    .unwrap();
    let assessment = result.assessment.unwrap();
    let variant = &assessment.variants()[0];
    let CvssAssessment::Unscored {
        established: selected,
        ..
    } = variant.assessment()
    else {
        panic!("one AV metric cannot score")
    };
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].basis(), CvssEvidenceBasis::AnalystOverride);
    assert_eq!(selected[0].value().first_label(), "N");
}

fn scoped_metric(
    base_metric: CvssBaseMetric,
    value: CvssMetricValueToken,
    hash: u8,
) -> ScopedMetricEvidence {
    let metric = CvssMetric::Base {
        metric: base_metric,
    };
    ScopedMetricEvidence {
        target_scope: PolicyOverlayScope::AllFindings,
        evidence: CvssMetricEvidence::try_new(
            metric,
            CvssMetricValue::try_new(metric, value).unwrap(),
            CvssEvidenceBasis::AnalystOverride,
            vec![EvidenceRef::try_new("test", format!("record-{hash}")).unwrap()],
            "Observed".to_string(),
            Vec::new(),
            "analyst".to_string(),
            None,
            base_metric.required_scope(),
            super::super::CvssEvidenceContentHash::from_bytes([hash; 32]),
        )
        .unwrap(),
    }
}

fn scored_policy() -> PolicyRegistry {
    let metrics = [
        ("AV", "N", "vulnerable-system"),
        ("AC", "L", "vulnerable-system"),
        ("AT", "N", "vulnerable-system"),
        ("PR", "N", "vulnerable-system"),
        ("UI", "N", "vulnerable-system"),
        ("VC", "H", "vulnerable-system"),
        ("VI", "H", "vulnerable-system"),
        ("VA", "H", "vulnerable-system"),
        ("SC", "H", "subsequent-system"),
        ("SI", "H", "subsequent-system"),
        ("SA", "H", "subsequent-system"),
    ];
    let rules = metrics.into_iter().map(|(metric, value, scope)| format!(
        "(metric :name {metric} :value {value} :when (analysis-type :is match) :basis policy-assertion :scope {scope} :evidence-refs [policy:self] :rationale \"Observed\")"
    )).collect::<Vec<_>>().join(" ");
    let source = format!(
        r#"(policy :id "test.score" :name "Score" :message "M" :severity warning
      :analysis (analysis :type match :selector (rql (call)))
      :classification (classification :fallback (classification-id :taxonomy "test" :id "fallback")
        :cvss (cvss :version "4.0" :emit when-base-complete :metric-rules [{rules}])))"#
    );
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(PolicySourceIdentity::new("test:score"), source.as_bytes())
        .unwrap();
    registry
}

#[test]
fn complete_reduction_keeps_base_evidence_and_published_score() {
    let registry = scored_policy();
    let policy = registry.policies().next().unwrap();
    let anchor = anchor();
    let result = reduce_cvss_for_finding(
        policy,
        CvssFindingProjection::Match { anchor: &anchor },
        &[],
        &[],
        &[],
        usize::MAX,
        &PolicyBudget::default(),
    )
    .unwrap();
    assert!(result.incomplete_reason.is_none());
    let assessment = result.assessment.unwrap();
    let CvssAssessment::Scored {
        vector,
        components,
        metrics,
        ..
    } = assessment.variants()[0].assessment()
    else {
        panic!("complete base metrics must score")
    };
    assert_eq!(metrics.len(), 11);
    assert_eq!(
        vector,
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    );
    assert_eq!(components[0].score(), 10.0);
}

#[test]
fn one_overlay_is_admitted_at_the_exact_overlay_limit() {
    let registry = policy();
    let loaded = registry.policies().next().unwrap();
    let overlay = analyst_overlay(
        PolicyOverlayScope::Policy {
            policy_id: loaded.definition().metadata.id.clone(),
        },
        CvssMetricValueToken::A,
    );
    let anchor = anchor();
    let projection = CvssFindingProjection::Match { anchor: &anchor };
    let budget = PolicyBudget::builder()
        .with_max_cvss_overlays(1)
        .unwrap()
        .build()
        .unwrap();
    let exact = reduce_cvss_for_finding(
        loaded,
        projection,
        std::slice::from_ref(&overlay),
        &[],
        &[],
        usize::MAX,
        &budget,
    )
    .unwrap();
    assert!(exact.incomplete_reason.is_none());
    let assessment = exact.assessment.unwrap();
    let CvssAssessment::Unscored { established, .. } = assessment.variants()[0].assessment() else {
        panic!("one metric cannot score")
    };
    assert_eq!(established.len(), 1);
    assert_eq!(established[0].value().first_label(), "A");
    let cut = reduce_cvss_for_finding(
        loaded,
        projection,
        &[overlay.clone(), overlay],
        &[],
        &[],
        usize::MAX,
        &budget,
    )
    .unwrap();
    assert_eq!(
        cut.incomplete_reason,
        Some(PolicyIncompleteReason::CvssVariantBudget)
    );
}

#[test]
fn higher_basis_analyst_evidence_wins_at_equal_scope() {
    let registry = policy();
    let loaded = registry.policies().next().unwrap();
    let overlay = analyst_overlay(
        PolicyOverlayScope::Policy {
            policy_id: loaded.definition().metadata.id.clone(),
        },
        CvssMetricValueToken::A,
    );
    let anchor = anchor();
    let result = reduce_cvss_for_finding(
        loaded,
        CvssFindingProjection::Match { anchor: &anchor },
        &[overlay],
        &[],
        &[],
        usize::MAX,
        &PolicyBudget::default(),
    )
    .unwrap();
    let assessment = result.assessment.unwrap();
    let CvssAssessment::Unscored {
        established,
        reasons,
        ..
    } = assessment.variants()[0].assessment()
    else {
        panic!("one metric cannot score")
    };
    assert_eq!(established.len(), 1);
    assert_eq!(established[0].basis(), CvssEvidenceBasis::AnalystOverride);
    assert_eq!(established[0].value().first_label(), "A");
    assert!(
        !reasons
            .iter()
            .any(|reason| matches!(reason, CvssUnscoredReason::ConflictingMetricEvidence { .. }))
    );
}

#[test]
fn corroborating_base_values_keep_one_vector_atom() {
    let values = [
        (CvssBaseMetric::Av, CvssMetricValueToken::N),
        (CvssBaseMetric::Ac, CvssMetricValueToken::L),
        (CvssBaseMetric::At, CvssMetricValueToken::N),
        (CvssBaseMetric::Pr, CvssMetricValueToken::N),
        (CvssBaseMetric::Ui, CvssMetricValueToken::N),
        (CvssBaseMetric::Vc, CvssMetricValueToken::H),
        (CvssBaseMetric::Vi, CvssMetricValueToken::H),
        (CvssBaseMetric::Va, CvssMetricValueToken::H),
        (CvssBaseMetric::Sc, CvssMetricValueToken::H),
        (CvssBaseMetric::Si, CvssMetricValueToken::H),
        (CvssBaseMetric::Sa, CvssMetricValueToken::H),
    ];
    let mut evidence = values
        .into_iter()
        .enumerate()
        .map(|(index, (metric, value))| {
            scoped_metric(metric, value, u8::try_from(index + 1).unwrap()).evidence
        })
        .collect::<Vec<_>>();
    evidence.push(scoped_metric(CvssBaseMetric::Av, CvssMetricValueToken::N, 20).evidence);
    let scored = score_metrics(&evidence).unwrap();
    assert_eq!(
        scored.full_vector,
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    );
    assert_eq!(scored.components[0].score(), 10.0);
}

#[test]
fn component_validation_rejects_wrong_score_with_correct_severity() {
    let result = CvssComponentResult::try_new(
        super::super::CvssNomenclature::B,
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H".to_string(),
        9.9,
        super::super::CvssSeverity::Critical,
    );
    assert!(matches!(result, Err(CvssValidationError::InvalidScore)));
}

#[test]
fn conflict_records_count_at_the_exact_evidence_budget() {
    use crate::definition::TaintLabel;
    use crate::finding_identity::SourceScenarioId;
    use crate::future_evidence::{TaintFindingAnchor, TaintPolicyProjectionFacts};

    let source = r#"(policy
      :id "test.conflict-budget" :name "Conflict budget"
      :message (generated-message :relation can-reach)
      :severity (cvss-severity :when-unscored warning)
      :analysis (analysis :type taint :mode may
        :sources (endpoint-set :entries [(source :id request :display-name "request"
          :categories [input.user] :selector (rql (name "request"))
          :bind return-value :labels [alpha])])
        :sinks (endpoint-set :entries [(sink :id store :display-name "store"
          :categories [data.sensitive] :selector (rql (name "store"))
          :dangerous-operand matched-value :accepts [alpha] :tags [internet])]))
      :classification (classification :fallback (classification-id :taxonomy "test" :id "TAINT")
        :cvss (cvss :version "4.0" :emit when-base-complete :metric-rules [
          (metric :name AV :value N :when (sink-tags :all [missing]) :basis policy-assertion
            :scope vulnerable-system :evidence-refs [policy:self] :rationale "Unused")])) )"#;
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("test:conflict-budget"),
            source.as_bytes(),
        )
        .unwrap();
    let loaded = registry.policies().next().unwrap();
    let spec = loaded.resolved_taint().unwrap();
    let source = &spec.sources[0];
    let sink = &spec.sinks[0];
    let mut scenarios =
        ["one", "two", "three"].map(|name| SourceScenarioId::try_new("test", name).unwrap());
    scenarios.sort();
    let fact = crate::test_support::taint_source_projection_fact(
        source.identity.clone(),
        source.semantic_hash,
        source.analysis_projection_hash,
        source.definition.display_name.clone(),
        source.definition.categories.clone(),
        TaintLabel::new("alpha").unwrap(),
        None,
        scenarios.to_vec(),
        EvidenceRef::try_new("test-source", "request").unwrap(),
    );
    let projection = TaintPolicyProjectionFacts::try_new(
        sink.identity.clone(),
        sink.semantic_hash,
        sink.analysis_projection_hash,
        sink.definition.display_name.clone(),
        sink.definition.categories.clone(),
        sink.definition.tags.clone(),
        sink.definition.impacts.clone(),
        vec![TaintLabel::new("alpha").unwrap()],
        vec![fact],
        &PolicyBudget::default(),
    )
    .unwrap();
    let anchor = TaintFindingAnchor::weak(OpaqueFindingKey::try_new("test", "conflict").unwrap());
    let finding = CvssFindingProjection::Taint {
        anchor: &anchor,
        projection: &projection,
        sources: &projection.source_facts,
    };
    let mut overlays = vec![analyst_overlay_for_metric(
        CvssBaseMetric::Av,
        PolicyOverlayScope::AllFindings,
        CvssMetricValueToken::N,
        "av",
    )];
    for (index, scenario) in scenarios.iter().enumerate() {
        let scope = PolicyOverlayScope::SourceScenario {
            scenario_id: scenario.clone(),
        };
        overlays.push(analyst_overlay_for_metric(
            CvssBaseMetric::Ac,
            scope.clone(),
            CvssMetricValueToken::L,
            "ac-low",
        ));
        overlays.push(analyst_overlay_for_metric(
            CvssBaseMetric::Ac,
            scope,
            CvssMetricValueToken::H,
            &format!("ac-high-{index}"),
        ));
    }
    let reduce = |limit| {
        let budget = PolicyBudget::builder()
            .with_max_cvss_evidence_records_per_finding(limit)
            .unwrap()
            .build()
            .unwrap();
        reduce_cvss_for_finding(
            loaded,
            finding,
            &overlays,
            &[],
            &scenarios,
            usize::MAX,
            &budget,
        )
        .unwrap()
    };
    let exact = reduce(6);
    assert!(exact.incomplete_reason.is_none());
    assert_eq!(exact.assessment.unwrap().variants().len(), 3);
    let cut = reduce(5);
    assert_eq!(
        cut.incomplete_reason,
        Some(PolicyIncompleteReason::CvssVariantBudget)
    );
}
