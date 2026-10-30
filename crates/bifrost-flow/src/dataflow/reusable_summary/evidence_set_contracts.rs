use crate::analyzer::semantic::{EvidenceCompleteness, ProofStatus};
use crate::dataflow::{MAX_SUMMARY_EVIDENCE_REASONS, PathQuality, SummaryEvidence};

fn evidence(unproven: &[&str], incomplete: &[&str]) -> SummaryEvidence {
    SummaryEvidence::try_new(
        unproven.iter().map(|s| (*s).into()).collect(),
        incomplete.iter().map(|s| (*s).into()).collect(),
    )
    .unwrap()
}

#[test]
fn evidence_joins_form_canonical_reason_sets_and_quality_frontiers() {
    let a = evidence(&["a", "b"], &["d"]);
    let b = evidence(&["a", "c"], &["d", "e"]);
    let union = evidence(&["a", "b", "c"], &["d", "e"]);
    assert_eq!(a.join(&b).unwrap(), union);
    assert_eq!(b.join(&a).unwrap(), union);
    assert_eq!(a.conjoin(&b).unwrap(), union);
    assert_eq!(b.conjoin(&a).unwrap(), union);
    assert_eq!(a.join(&a).unwrap(), a);
    let full = SummaryEvidence::try_new(
        (0..MAX_SUMMARY_EVIDENCE_REASONS)
            .map(|n| format!("reason-{n:02}"))
            .collect(),
        vec![],
    )
    .unwrap();
    assert_eq!(full.join(&full).unwrap(), full);
    for reasons in [["b", "a", "b"], ["a", "b", "b"], ["b", "b", "a"]] {
        let permuted = evidence(&reasons, &reasons);
        let canonical = evidence(&["a", "b"], &["a", "b"]);
        assert_eq!(permuted, canonical);
        assert_eq!(permuted.conjoin(&canonical).unwrap(), canonical);
    }
    let partial = SummaryEvidence::from_semantic(
        &ProofStatus::Proven,
        &EvidenceCompleteness::Partial("incomplete".into()),
    )
    .unwrap();
    let unproven = SummaryEvidence::from_semantic(
        &ProofStatus::Unproven("unproven".into()),
        &EvidenceCompleteness::Complete,
    )
    .unwrap();
    let expected = [
        PathQuality::PROVEN_COMPLETE,
        PathQuality::PROVEN_PARTIAL,
        PathQuality::UNPROVEN_COMPLETE,
        PathQuality::UNPROVEN_PARTIAL,
    ]
    .into_iter()
    .filter(|q| [PathQuality::PROVEN_PARTIAL, PathQuality::UNPROVEN_COMPLETE].contains(q))
    .collect::<Vec<_>>();
    for joined in [
        partial.join(&unproven).unwrap(),
        unproven.join(&partial).unwrap(),
    ] {
        assert_eq!(
            joined
                .alternatives()
                .iter()
                .map(|a| a.quality())
                .collect::<Vec<_>>(),
            expected
        );
    }
}
