use super::*;
use crate::{CvssMetricValueToken, CvssSystemScope};

fn metadata(assumptions: Vec<String>, scope: CvssEvidenceScope) -> CvssOverlayEvidenceMetadata {
    CvssOverlayEvidenceMetadata::try_new(
        vec![crate::finding_identity::EvidenceRef::try_new("feed", "record").unwrap()],
        "feed assessment".to_string(),
        assumptions,
        "test-feed".to_string(),
        "2026-07-18T10:34:56Z".to_string(),
        scope,
        None,
    )
    .unwrap()
}

#[test]
fn overlay_rejects_scope_that_disagrees_with_metric() {
    let metric = CvssMetric::Threat {
        metric: CvssThreatMetric::E,
    };
    let value = CvssMetricValue::try_new(metric, CvssMetricValueToken::A).unwrap();
    let wrong_scope = metadata(
        Vec::new(),
        CvssEvidenceScope::System {
            system: CvssSystemScope::SubsequentSystem,
        },
    );
    assert!(CvssThreatOverlayEvidence::try_new(CvssThreatMetric::E, value, wrong_scope).is_err());
}

#[test]
fn overlay_hash_binds_every_assumption() {
    let metric = CvssMetric::Threat {
        metric: CvssThreatMetric::E,
    };
    let value = CvssMetricValue::try_new(metric, CvssMetricValueToken::A).unwrap();
    let first = CvssThreatOverlayEvidence::try_new(
        CvssThreatMetric::E,
        value,
        metadata(
            vec!["baseline".into(), "internet-facing".into()],
            CvssEvidenceScope::Global,
        ),
    )
    .unwrap();
    let changed = CvssThreatOverlayEvidence::try_new(
        CvssThreatMetric::E,
        value,
        metadata(
            vec!["baseline".into(), "internal-only".into()],
            CvssEvidenceScope::Global,
        ),
    )
    .unwrap();
    assert_ne!(first.content_hash(), changed.content_hash());
}
