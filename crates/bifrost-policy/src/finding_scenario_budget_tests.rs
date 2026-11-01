use super::*;
use crate::classification::FindingClassification;
use crate::definition::FindingSeverity;
use crate::finding::{
    FindingCertainty, FindingCompleteness, PolicyByteSpan, PolicyDisplayRegion, PolicyFinding,
    PolicyFindingError, PolicyFindingEvidence, ProofMetadata, ProofReason, ProofState,
    ReportValueError,
};
use crate::identity::PolicySemanticHash;

#[test]
fn finding_scenario_membership_cap_applies_after_evidence_construction() {
    let projection = taint_projection(vec![source_fact(
        "source",
        "untrusted",
        "source",
        &["path-a", "path-b"],
    )]);
    let evidence = taint_finding(&projection, false, 0, &PolicyBudget::default()).unwrap();
    let build = |budget: &PolicyBudget| {
        PolicyFinding::try_new(
            PolicyId::new("security.flow").unwrap(),
            PolicySemanticHash::from_lower_hex(&"01".repeat(32)).unwrap(),
            FindingSeverity::Warning,
            "store flow".into(),
            FindingClassification::Unclassified,
            FindingCertainty::Definite,
            FindingCompleteness::Complete,
            PolicySourceLocation::span(
                WorkspaceRelativePath::new("src/app.rs").unwrap(),
                PolicyByteSpan::new(0, 1).unwrap(),
                PolicyDisplayRegion::new(1, 1, 1, 2).unwrap(),
            ),
            vec![],
            false,
            0,
            PolicyFindingEvidence::Taint {
                evidence: evidence.clone(),
            },
            false,
            0,
            None,
            None,
            ProofMetadata::try_new(
                ProofState::Proven,
                vec![ProofReason::DataflowWitness],
                vec![],
            )
            .unwrap(),
            vec![],
            false,
            0,
            budget,
        )
    };
    let exact = PolicyBudget::builder()
        .with_max_projection_scenario_memberships(2)
        .unwrap()
        .build()
        .unwrap();
    let exact_finding = build(&exact);
    assert!(exact_finding.is_ok(), "{exact_finding:?}");
    let below = PolicyBudget::builder()
        .with_max_projection_scenario_memberships(1)
        .unwrap()
        .build()
        .unwrap();
    assert!(matches!(
        build(&below),
        Err(PolicyFindingError::Value(ReportValueError::TooManyItems {
            field: "finding_scenario_memberships",
            max_items: 1,
        }))
    ));
}
