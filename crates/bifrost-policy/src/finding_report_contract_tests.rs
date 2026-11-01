use super::*;

fn location() -> PolicySourceLocation {
    PolicySourceLocation::span(
        WorkspaceRelativePath::new("src/app.rs").unwrap(),
        PolicyByteSpan::new(4, 9).unwrap(),
        PolicyDisplayRegion::new(2, 3, 2, 8).unwrap(),
    )
}

#[test]
fn proof_reason_labels_keep_their_meaning() {
    assert_eq!(ProofReason::ResolvedReference.label(), "resolved_reference");
    assert_eq!(ProofReason::PartialWitness.label(), "partial_witness");
}

#[test]
fn authored_closure_requires_identifier_content() {
    assert!(
        ProofMetadata::try_new(
            ProofState::Proven,
            vec![ProofReason::AuthoredArmClosure {
                model: "model".into(),
                content: "not an identifier".into(),
                contract_version: 1,
            }],
            vec![],
        )
        .is_err()
    );
}

#[test]
fn related_location_keeps_its_evidence_links() {
    let evidence = EvidenceRef::try_new("query", "edge").unwrap();
    let related = RelatedPolicyLocation::try_new(
        PolicyLocationRelationship::Evidence,
        location(),
        vec![evidence.clone()],
    )
    .unwrap();
    assert_eq!(related.evidence_refs(), &[evidence]);
}

#[test]
fn omitted_witness_steps_require_truncation() {
    let step = WitnessStep::try_new(WitnessStepKind::Call, None, "ReadValue", vec![]).unwrap();
    assert_eq!(step.label(), "ReadValue");
    assert!(
        BoundedWitness::try_new(
            WitnessId::try_new("query", "path").unwrap(),
            vec![step],
            false,
            1,
        )
        .is_err()
    );
}

#[test]
fn witness_evidence_at_cap_is_valid() {
    let refs = (0..MAX_EVIDENCE_REFS)
        .map(|index| EvidenceRef::try_new("query", format!("edge_{index}")).unwrap())
        .collect();
    assert!(WitnessStep::try_new(WitnessStepKind::Call, None, "call", refs).is_ok());
    let over = (0..=MAX_EVIDENCE_REFS)
        .map(|index| EvidenceRef::try_new("query", format!("edge_{index}")).unwrap())
        .collect();
    assert!(WitnessStep::try_new(WitnessStepKind::Call, None, "call", over).is_err());
}

#[test]
fn selector_gap_keeps_distinct_sites() {
    let summary = PolicySelectorGapSummary::new(
        "source call",
        ["missing".to_owned()],
        [
            ("src/a.rs".to_owned(), Some(2)),
            ("src/b.rs".to_owned(), Some(3)),
        ],
    );
    assert_eq!(summary.sites().len(), 2);
    assert!(summary.sites().contains(&("src/a.rs".to_owned(), Some(2))));
    assert!(summary.sites().contains(&("src/b.rs".to_owned(), Some(3))));
}

#[test]
fn duplicate_work_metric_is_rejected() {
    let mut work = PolicyWorkReport::try_new(0, 0, 0, 0, 0, 0, 0, 0, vec![]).unwrap();
    let metric = PolicyWorkMetric::try_new("policy.time", PolicyWorkUnit::Count, 1).unwrap();
    work.try_push_metric(metric.clone()).unwrap();
    assert_eq!(
        work.try_push_metric(metric),
        Err(ReportValueError::DuplicateWorkMetric)
    );
}

#[test]
fn obligation_group_key_uses_full_byte_cap() {
    let key = "é".repeat(MAX_OBLIGATION_GROUP_KEY_BYTES / 2 + 1);
    let obligation = PolicyObligation::try_new(
        "by-site",
        PolicyObligationKind::VerdictRequiresWitnessedRows,
        "by-site",
        Some(&key),
        vec![],
        false,
        vec![PolicyIncompleteReason::Cancelled],
    )
    .unwrap();
    assert_eq!(
        obligation.group_key(),
        Some("é".repeat(MAX_OBLIGATION_GROUP_KEY_BYTES / 2).as_str())
    );
}

fn store_step(read_key: StoreDimensionEvidence) -> Result<WitnessStep, ReportValueError> {
    let model = ResolvedEndpointIdentity::MatchEndpoint {
        endpoint_id: crate::definition::EndpointId::new("store.model").unwrap(),
    };
    WitnessStep::try_new_with_provenance(
        WitnessStepKind::Call,
        None,
        "store flow",
        vec![],
        Some(WitnessStepProvenance::DeclaredStore {
            write_model: model.clone(),
            read_model: model,
            store: "store".into(),
            write_instance: StoreDimensionEvidence::Unproven,
            write_key: StoreDimensionEvidence::Unproven,
            read_instance: StoreDimensionEvidence::Unproven,
            read_key,
        }),
    )
}

#[test]
fn proven_store_dimension_requires_an_identity() {
    assert!(store_step(StoreDimensionEvidence::Proven { identities: vec![] }).is_err());
}

#[test]
fn first_store_identity_must_validate() {
    assert!(
        store_step(StoreDimensionEvidence::Proven {
            identities: vec!["bad name".into(), "valid".into()],
        })
        .is_err()
    );
}

#[test]
fn finding_evidence_at_cap_is_valid() {
    let loaded = loaded_match_policy();
    let witness = BoundedWitness::try_new(
        WitnessId::try_new("query", "path").unwrap(),
        vec![
            WitnessStep::try_new(
                WitnessStepKind::Call,
                Some(location()),
                "call",
                vec![EvidenceRef::try_new("query", "edge").unwrap()],
            )
            .unwrap(),
        ],
        false,
        0,
    )
    .unwrap();
    let exact = PolicyBudget::builder()
        .with_max_evidence_refs_per_finding(1)
        .unwrap()
        .build()
        .unwrap();
    assert!(
        finding_with(
            &loaded,
            match_evidence(),
            vec![witness.clone()],
            None,
            &exact
        )
        .is_ok()
    );
    let below = PolicyBudget::builder()
        .with_max_evidence_refs_per_finding(0)
        .unwrap()
        .build()
        .unwrap();
    assert!(finding_with(&loaded, match_evidence(), vec![witness], None, &below).is_err());
}

fn bulky_work() -> PolicyWorkReport {
    let metrics = (0..MAX_WORK_METRICS)
        .map(|index| {
            PolicyWorkMetric::try_new(
                format!("policy.metric_{index}_{}", "a".repeat(90)),
                PolicyWorkUnit::Count,
                0,
            )
            .unwrap()
        })
        .collect();
    PolicyWorkReport::try_new(0, 0, 0, 0, 0, 0, 0, 0, metrics).unwrap()
}

fn report_outcome(
    finding: &PolicyFinding,
    cap: usize,
) -> Option<crate::report::PolicyRetentionOutcome> {
    use crate::budget::PolicyBatchBudget;
    use crate::report::{PolicyReportBuilder, PolicyRuleDescriptor};

    let loaded = loaded_match_policy();
    let per_policy = PolicyBudget::builder()
        .with_max_retained_report_bytes(cap)
        .unwrap()
        .build()
        .unwrap();
    let budget = PolicyBatchBudget::builder()
        .with_max_retained_report_bytes(cap)
        .unwrap()
        .with_per_policy(per_policy)
        .unwrap()
        .build()
        .unwrap();
    let mut builder = PolicyReportBuilder::new(budget, 1).ok()?;
    let work = bulky_work();
    let run = PolicyRun::try_new(
        loaded.definition().metadata.id.clone(),
        loaded.semantic_hash(),
        PolicyAnalysisType::Match,
        PolicyRunCompletion::Complete,
        vec![],
        vec![],
        false,
        work,
        &PolicyBudget::default(),
    )
    .unwrap();
    builder
        .register_policy(PolicyRuleDescriptor::from_loaded(&loaded), run)
        .ok()?;
    builder.retain_finding(finding.clone()).ok()
}

fn report_admits(finding: &PolicyFinding, cap: usize) -> bool {
    matches!(
        report_outcome(finding, cap),
        Some(crate::report::PolicyRetentionOutcome::Retained)
    )
}

fn minimum_report_cap(finding: &PolicyFinding) -> usize {
    let mut low = 0;
    let mut high = 1_048_576;
    assert!(report_admits(finding, high));
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if report_admits(finding, middle) {
            high = middle;
        } else {
            low = middle;
        }
    }
    assert!(report_admits(finding, high));
    assert!(!report_admits(finding, high - 1));
    assert!(matches!(
        report_outcome(finding, high - 1),
        Some(crate::report::PolicyRetentionOutcome::Omitted {
            reason: PolicyIncompleteReason::ReportRetentionBudget
        })
    ));
    high
}

fn finding_for_report() -> PolicyFinding {
    let loaded = loaded_match_policy();
    finding_with(
        &loaded,
        match_evidence(),
        vec![],
        None,
        &PolicyBudget::default(),
    )
    .unwrap()
}

#[test]
fn finding_text_and_proof_codes_count_toward_report_bytes() {
    let short = finding_for_report();
    let mut long = short.clone();
    long.message = "m".repeat(200);
    assert!(minimum_report_cap(&long) >= minimum_report_cap(&short) + 190);

    let mut short = finding_for_report();
    short.proof = ProofMetadata::try_new(
        ProofState::Proven,
        vec![ProofReason::analyzer_evidence("a").unwrap()],
        vec![],
    )
    .unwrap();
    let mut long = short.clone();
    long.proof = ProofMetadata::try_new(
        ProofState::Proven,
        vec![ProofReason::analyzer_evidence("a".repeat(120)).unwrap()],
        vec![],
    )
    .unwrap();
    assert!(minimum_report_cap(&long) >= minimum_report_cap(&short) + 110);

    short.proof = ProofMetadata::try_new(
        ProofState::Proven,
        vec![ProofReason::AuthoredArmClosure {
            model: "model".into(),
            content: "a".into(),
            contract_version: 1,
        }],
        vec![],
    )
    .unwrap();
    long.proof = ProofMetadata::try_new(
        ProofState::Proven,
        vec![ProofReason::AuthoredArmClosure {
            model: "model".into(),
            content: "a".repeat(120),
            contract_version: 1,
        }],
        vec![],
    )
    .unwrap();
    assert!(minimum_report_cap(&long) >= minimum_report_cap(&short) + 110);
}

#[test]
fn related_labels_count_toward_report_bytes() {
    let mut short = finding_for_report();
    short.related = vec![
        RelatedPolicyLocation::try_new(PolicyLocationRelationship::Evidence, location(), vec![])
            .unwrap()
            .with_label("a".into())
            .unwrap(),
    ];
    let mut long = short.clone();
    long.related = vec![
        RelatedPolicyLocation::try_new(PolicyLocationRelationship::Evidence, location(), vec![])
            .unwrap()
            .with_label("a".repeat(120))
            .unwrap(),
    ];
    assert!(minimum_report_cap(&long) >= minimum_report_cap(&short) + 110);
}

#[test]
fn store_identity_bytes_count_toward_report_bytes() {
    let witness = |identity: &str| {
        BoundedWitness::try_new(
            WitnessId::try_new("query", "path").unwrap(),
            vec![
                store_step(StoreDimensionEvidence::Proven {
                    identities: vec![identity.into()],
                })
                .unwrap(),
            ],
            false,
            0,
        )
        .unwrap()
    };
    let mut short = finding_for_report();
    short.witnesses = vec![witness("a")];
    let mut long = short.clone();
    long.witnesses = vec![witness(&"a".repeat(120))];
    assert!(minimum_report_cap(&long) >= minimum_report_cap(&short) + 110);
}

#[test]
fn store_read_model_counts_toward_report_bytes() {
    let witness = |read_model: &str| {
        let step = WitnessStep::try_new_with_provenance(
            WitnessStepKind::Call,
            None,
            "store flow",
            vec![],
            Some(WitnessStepProvenance::DeclaredStore {
                write_model: ResolvedEndpointIdentity::MatchEndpoint {
                    endpoint_id: crate::definition::EndpointId::new("write.model").unwrap(),
                },
                read_model: ResolvedEndpointIdentity::MatchEndpoint {
                    endpoint_id: crate::definition::EndpointId::new(read_model).unwrap(),
                },
                store: "store".into(),
                write_instance: StoreDimensionEvidence::Unproven,
                write_key: StoreDimensionEvidence::Unproven,
                read_instance: StoreDimensionEvidence::Unproven,
                read_key: StoreDimensionEvidence::Unproven,
            }),
        )
        .unwrap();
        BoundedWitness::try_new(
            WitnessId::try_new("query", "path").unwrap(),
            vec![step],
            false,
            0,
        )
        .unwrap()
    };
    let mut short = finding_for_report();
    short.witnesses = vec![witness("a")];
    let mut long = short.clone();
    long.witnesses = vec![witness(&"a".repeat(120))];
    assert!(minimum_report_cap(&long) >= minimum_report_cap(&short) + 110);
}

fn obligation_run(root: &str, group: &str, group_key: &str) -> PolicyRun {
    let loaded = loaded_match_policy();
    let mut run = PolicyRun::try_new(
        loaded.definition().metadata.id.clone(),
        loaded.semantic_hash(),
        PolicyAnalysisType::Match,
        PolicyRunCompletion::inconclusive(vec![PolicyIncompleteReason::Cancelled]).unwrap(),
        vec![],
        vec![],
        false,
        bulky_work(),
        &PolicyBudget::default(),
    )
    .unwrap();
    let obligation = PolicyObligation::try_new(
        "by-site",
        PolicyObligationKind::VerdictRequiresWitnessedRows,
        group,
        Some(group_key),
        vec![PolicyCoveragePartition::new("family", root)],
        false,
        vec![PolicyIncompleteReason::Cancelled],
    )
    .unwrap();
    run.set_obligations(&[obligation], false, 0, &PolicyBudget::default())
        .unwrap();
    run
}

fn report_registers_run(run: &PolicyRun, cap: usize) -> bool {
    use crate::budget::PolicyBatchBudget;
    use crate::report::{PolicyReportBuilder, PolicyRuleDescriptor};
    let loaded = loaded_match_policy();
    let per_policy = PolicyBudget::builder()
        .with_max_retained_report_bytes(cap)
        .unwrap()
        .build()
        .unwrap();
    let budget = PolicyBatchBudget::builder()
        .with_max_retained_report_bytes(cap)
        .unwrap()
        .with_per_policy(per_policy)
        .unwrap()
        .build()
        .unwrap();
    let Ok(mut builder) = PolicyReportBuilder::new(budget, 1) else {
        return false;
    };
    builder
        .register_policy(PolicyRuleDescriptor::from_loaded(&loaded), run.clone())
        .is_ok()
}

fn minimum_run_cap(run: &PolicyRun) -> usize {
    let mut low = 0;
    let mut high = 1_048_576;
    assert!(report_registers_run(run, high));
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if report_registers_run(run, middle) {
            high = middle;
        } else {
            low = middle;
        }
    }
    assert!(report_registers_run(run, high));
    assert!(!report_registers_run(run, high - 1));
    high
}

#[test]
fn obligation_partition_and_group_text_count_toward_report_bytes() {
    let short = obligation_run("a", "by-site", "key");
    let long_root = obligation_run(&"a".repeat(120), "by-site", "key");
    assert!(minimum_run_cap(&long_root) >= minimum_run_cap(&short) + 110);

    let long_key = obligation_run("a", "by-site", &"k".repeat(120));
    assert!(minimum_run_cap(&long_key) >= minimum_run_cap(&short) + 110);

    let long_group = obligation_run("a", &"g".repeat(120), "key");
    assert!(minimum_run_cap(&long_group) >= minimum_run_cap(&short) + 110);
}
