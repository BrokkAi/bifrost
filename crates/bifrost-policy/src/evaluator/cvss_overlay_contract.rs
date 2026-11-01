use super::*;
use crate::CvssMetricValueToken;

fn metadata(assumptions: Vec<String>) -> Result<CvssOverlayEvidenceMetadata, CvssEvidenceError> {
    CvssOverlayEvidenceMetadata::try_new(
        vec![crate::EvidenceRef::try_new("feed", "record-17").unwrap()],
        "trusted feed record".to_string(),
        assumptions,
        "test-feed".to_string(),
        "2026-07-18T10:34:56Z".to_string(),
        CvssEvidenceScope::Global,
        None,
    )
}

#[test]
fn threat_overlay_preserves_assumptions_and_assessment_time() {
    let metric = CvssMetric::Threat {
        metric: CvssThreatMetric::E,
    };
    let value = CvssMetricValue::try_new(metric, CvssMetricValueToken::A).unwrap();
    let overlay = CvssThreatOverlayEvidence::try_new(
        CvssThreatMetric::E,
        value,
        metadata(vec!["production scope".to_string()]).unwrap(),
    )
    .unwrap();
    let evidence = overlay
        .metadata()
        .try_new_metric_evidence(
            metric,
            value,
            CvssEvidenceBasis::ThreatFeed,
            overlay.content_hash(),
        )
        .unwrap();
    assert_eq!(evidence.assumptions(), &["production scope"]);
    assert_eq!(evidence.assessed_at(), Some("2026-07-18T10:34:56Z"));
}

#[test]
fn overlay_assumption_limit_is_inclusive() {
    let assumptions = (0..MAX_OVERLAY_ASSUMPTIONS)
        .map(|index| format!("scope-{index}"))
        .collect::<Vec<_>>();
    assert!(metadata(assumptions.clone()).is_ok());
    let mut over_limit = assumptions;
    over_limit.push("one-more".to_string());
    assert!(matches!(
        metadata(over_limit),
        Err(CvssEvidenceError::TooManyAssumptions)
    ));
}
