use crate::analyzer::semantic::*;
use crate::dataflow::*;
use brokk_bifrost_analysis::test_support::source_anchor;
use brokk_bifrost_core::analyzer::model::Language;

fn identity(name: &str) -> ProcedureSummaryIdentity {
    let artifact = SemanticArtifactKey::new(
        WorkspaceMountId::hash_bytes(b"summary-contract"),
        WorkspaceRelativePath::new("src/Model.java").unwrap(),
        SemanticLanguage::Standard(Language::Java),
        SourceRevision::Disk {
            content: ContentIdentity::hash_bytes(b"source"),
        },
        AdapterSemanticsVersion::hash_bytes("contract", b"1").unwrap(),
        SemanticIrVersion::current(),
        ConfigurationFingerprint::hash_bytes(b"config"),
        DependencyFingerprint::hash_bytes(b"deps"),
    );
    ProcedureSummaryIdentity::new(
        artifact,
        DeclarationLocator::new(vec![
            DeclarationSegment::named(
                DeclarationSegmentKind::Method,
                name,
                source_anchor(0, 0, 0),
                0,
            )
            .unwrap(),
        ])
        .unwrap(),
        SummarySchemaVersion::CURRENT,
        SummarySemanticsVersion::hash_bytes(b"semantics"),
        SummaryContextKey::hash_bytes(b"context"),
        SummaryBehaviorKey::hash_bytes(b"behavior"),
        SummaryOrigin::Inferred,
    )
}

#[test]
fn model_and_ambiguous_callee_limits_are_inclusive() {
    let bounded = "x".repeat(MAX_EXTERNAL_SUMMARY_MODEL_ID_BYTES);
    assert_eq!(
        ExternalSummaryModelId::new(&bounded).unwrap().as_str(),
        bounded
    );
    assert!(matches!(
        ExternalSummaryModelId::new(format!("{bounded}x")),
        Err(SummaryValidationError::ExternalModelIdTooLarge { .. })
    ));
    for invalid in ["", " ", " x", "x ", "x\n"] {
        assert!(ExternalSummaryModelId::new(invalid).is_err());
    }
    let candidates = (0..=MAX_AMBIGUOUS_SUMMARY_CALLEES)
        .map(|i| SummaryDependencyKey::recursive(identity(&format!("method{i}"))))
        .collect::<Vec<_>>();
    let make = |values| {
        SummaryEffectKey::ambiguous_call(
            SummaryEventKey::hash_bytes(b"call"),
            SummaryPort::Parameter(0),
            values,
        )
    };
    assert!(make(candidates[..MAX_AMBIGUOUS_SUMMARY_CALLEES].to_vec()).is_ok());
    assert!(matches!(
        make(candidates),
        Err(SummaryValidationError::TooManyAmbiguousCallees { .. })
    ));
}

#[test]
fn recursive_group_identity_names_the_member_set_without_edges() {
    let a = identity("fooA");
    let b = identity("fooB");
    let group = |members: &[ProcedureSummaryIdentity]| {
        SummaryRecursiveGroupKey::from_closure(members, &[], &[]).unwrap()
    };
    assert_ne!(
        group(std::slice::from_ref(&a)).fingerprint(),
        group(std::slice::from_ref(&b)).fingerprint()
    );
    assert_eq!(group(&[a.clone(), b.clone()]), group(&[b, a]));
}

#[test]
fn sanitizer_labels_form_a_case_sensitive_canonical_set() {
    let make = |labels| {
        SummaryEffectKey::sanitize(SummaryPort::Parameter(0), SummaryPort::NormalReturn, labels)
    };
    let key = make(vec!["a", "A", "a"]);
    assert_eq!(key, make(vec!["A", "a"]));
    let SummaryEffectKey::Sanitize { removed, .. } = key else {
        panic!("sanitizer key")
    };
    assert_eq!(
        removed.iter().map(AsRef::as_ref).collect::<Vec<&str>>(),
        ["A", "a"]
    );
}

#[test]
fn incomplete_reasons_validate_payloads_and_canonicalize_before_limits() {
    for make_reason in [
        SummaryIncompleteReason::SemanticGap,
        SummaryIncompleteReason::BudgetExceeded,
    ] {
        for payload in [
            String::new(),
            "x".repeat(MAX_SUMMARY_REASON_BYTES),
            "\u{00e9}".repeat(MAX_SUMMARY_REASON_BYTES / 2),
            "x".repeat(MAX_SUMMARY_REASON_BYTES + 1),
        ] {
            let valid = !payload.is_empty() && payload.len() <= MAX_SUMMARY_REASON_BYTES;
            let reason = make_reason(payload.clone().into());
            assert_eq!(
                SummaryEvidence::try_new(vec![payload.clone()], vec![]).is_ok(),
                valid
            );
            assert_eq!(
                SummaryEvidence::try_new(vec![], vec![payload]).is_ok(),
                valid
            );
            assert_eq!(
                SummaryCompleteness::partial(vec![reason.clone()]).is_ok(),
                valid
            );
            assert_eq!(
                SummaryDimensionStatus::incomplete(vec![reason]).is_ok(),
                valid
            );
        }
    }
    let repeated = vec![SummaryIncompleteReason::Cancelled; MAX_SUMMARY_EVIDENCE_REASONS + 1];
    let single = vec![SummaryIncompleteReason::Cancelled];
    assert_eq!(
        SummaryCompleteness::partial(repeated.clone()).unwrap(),
        SummaryCompleteness::partial(single.clone()).unwrap()
    );
    assert_eq!(
        SummaryDimensionStatus::incomplete(repeated).unwrap(),
        SummaryDimensionStatus::incomplete(single).unwrap()
    );
    let reasons = (0..=MAX_SUMMARY_EVIDENCE_REASONS)
        .map(|i| SummaryIncompleteReason::SemanticGap(format!("gap-{i:03}").into()))
        .collect::<Vec<_>>();
    let bounded = reasons[..MAX_SUMMARY_EVIDENCE_REASONS].to_vec();
    let partial = SummaryCompleteness::partial(bounded.clone()).unwrap();
    assert_eq!(partial.reasons(), bounded);
    let mut reversed = bounded;
    reversed.reverse();
    assert_eq!(SummaryCompleteness::partial(reversed).unwrap(), partial);
    assert!(matches!(
        SummaryCompleteness::partial(reasons),
        Err(SummaryValidationError::TooManyEvidenceReasons { .. })
    ));
}
