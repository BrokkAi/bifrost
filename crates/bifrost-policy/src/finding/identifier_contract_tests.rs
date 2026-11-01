use super::*;

#[test]
fn analyzer_evidence_identifier_is_canonical_at_construction() {
    assert!(CertaintyReason::analyzer_ambiguity("x").is_ok());
    assert!(CertaintyReason::analyzer_ambiguity(" x ").is_err());
    assert!(ProofReason::analyzer_evidence(" x ").is_err());
}
