use super::*;

#[test]
fn taint_projection_accepts_exact_scenario_membership_limit() {
    let projection = taint_projection(vec![source_fact(
        "source",
        "untrusted",
        "source",
        &["path-a", "path-b"],
    )]);
    let exact = PolicyBudget::builder()
        .with_max_projection_scenario_memberships(2)
        .unwrap()
        .build()
        .unwrap();
    let normalized = projection
        .clone()
        .try_normalized(&exact)
        .expect("two memberships fit a bound of two");
    assert_eq!(normalized.source_facts[0].source_scenario_ids.len(), 2);
    let short = PolicyBudget::builder()
        .with_max_projection_scenario_memberships(1)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        projection.try_normalized(&short),
        Err(FutureEvidenceError::ProjectionScenarioMembershipBudget { max_items: 1 })
    );
}

#[test]
fn taint_projection_order_normalizes_and_duplicate_facts_are_rejected() {
    let canonical = taint_projection(vec![
        source_fact("first", "untrusted", "first", &["path-a"]),
        source_fact("second", "untrusted", "second", &["path-b"]),
    ]);
    let mut reversed = canonical.clone();
    reversed.source_facts.reverse();
    assert_eq!(
        reversed.try_normalized(&PolicyBudget::default()),
        Ok(canonical.clone())
    );

    let mut duplicate = canonical.clone();
    duplicate
        .source_facts
        .push(canonical.source_facts[0].clone());
    assert_eq!(
        duplicate.try_normalized(&PolicyBudget::default()),
        Err(FutureEvidenceError::DuplicateProjectionFact { analysis: "taint" })
    );

    let mut different = canonical;
    different.source_facts[0].source_display_name = "different source".to_string();
    assert_eq!(
        different.try_normalized(&PolicyBudget::default()),
        Err(FutureEvidenceError::ProjectionFactsHashMismatch { analysis: "taint" })
    );
}

#[test]
fn source_and_sink_display_storage_counts_reserved_capacity() {
    let mut source = source_fact("source", "untrusted", "source", &["path"]);
    let before_source = source.retained_size();
    let before_capacity = source.source_display_name.capacity();
    source.source_display_name.reserve(128);
    assert_eq!(
        source.retained_size() - before_source,
        source.source_display_name.capacity() - before_capacity
    );

    let mut projection = taint_projection(vec![source]);
    let before_projection = projection.retained_size();
    let before_capacity = projection.sink_display_name.capacity();
    projection.sink_display_name.reserve(128);
    assert_eq!(
        projection.retained_size() - before_projection,
        projection.sink_display_name.capacity() - before_capacity
    );
}

#[test]
fn taint_anchors_account_for_strong_and_weak_payloads() {
    let projection = taint_projection(vec![source_fact(
        "source",
        "untrusted",
        "source",
        &["path"],
    )]);
    let fact = &projection.source_facts[0];
    let strong = TaintFindingAnchor::strong(
        stable_identity(StableIdentityDerivation::CanonicalAstIdentity, "sink-call"),
        0,
        fact.source_endpoint_analysis_projection_hash,
        projection.sink_endpoint_analysis_projection_hash,
        fact.scenario_set_hash,
    )
    .unwrap();
    let TaintFindingAnchor::Strong(payload) = &strong else {
        unreachable!()
    };
    assert!(retained_extra(&payload.sink_identity) > 0);
    assert_eq!(
        payload.retained_size(),
        size_of::<TaintStrongAnchor>() + retained_extra(&payload.sink_identity)
    );
    assert_eq!(
        strong.retained_size(),
        size_of::<TaintFindingAnchor>() + retained_extra(payload)
    );
    let weak =
        TaintFindingAnchor::weak(OpaqueFindingKey::try_new("taint", "snapshot-finding").unwrap());
    let TaintFindingAnchor::Weak(payload) = &weak else {
        unreachable!()
    };
    assert!(retained_extra(&payload.typed_key) > 0);
    assert_eq!(
        weak.retained_size(),
        size_of::<TaintFindingAnchor>() + retained_extra(payload)
    );
}

#[test]
fn typestate_anchors_account_for_boxed_and_weak_payloads() {
    let projection = typestate_projection();
    let strong = TypestateFindingAnchor::strong(
        projection.protocol_hash,
        stable_identity(StableIdentityDerivation::ProtocolSubject, "subject"),
        projection.violation_site.clone().unwrap(),
        projection.scenario_set_hash,
        &projection.violation,
    )
    .unwrap();
    let TypestateFindingAnchor::Strong(payload) = &strong else {
        unreachable!()
    };
    assert_ne!(
        retained_extra(&payload.subject_identity),
        retained_extra(&payload.violation_site_identity),
        "the test anchors need distinct owned sizes"
    );
    assert_eq!(
        payload.retained_size(),
        size_of::<TypestateStrongAnchor>()
            + retained_extra(&payload.subject_identity)
            + retained_extra(&payload.violation_site_identity)
    );
    assert_eq!(
        strong.retained_size(),
        size_of::<TypestateFindingAnchor>() + payload.retained_size()
    );
    let weak = TypestateFindingAnchor::weak(
        OpaqueFindingKey::try_new("typestate", "snapshot-finding").unwrap(),
    );
    let TypestateFindingAnchor::Weak(payload) = &weak else {
        unreachable!()
    };
    assert!(retained_extra(&payload.typed_key) > 0);
    assert_eq!(
        weak.retained_size(),
        size_of::<TypestateFindingAnchor>() + retained_extra(payload)
    );
}

#[test]
fn typestate_projection_enforces_empty_and_exact_membership_bounds() {
    let projection = typestate_projection();
    assert_eq!(projection.scenario_ids.len(), 2);
    let exact = PolicyBudget::builder()
        .with_max_projection_scenario_memberships(2)
        .unwrap()
        .build()
        .unwrap();
    let normalized = projection.clone().try_normalized(&exact).unwrap();
    assert_eq!(normalized.scenario_ids.len(), 2);
    let mut reversed = projection.clone();
    reversed.scenario_ids.reverse();
    assert_eq!(reversed.try_normalized(&exact), Ok(projection.clone()));
    let mut duplicate = projection.clone();
    duplicate
        .scenario_ids
        .push(projection.scenario_ids[0].clone());
    assert_eq!(
        duplicate.try_normalized(&PolicyBudget::default()),
        Err(FutureEvidenceError::DuplicateSemanticValue {
            field: "typestate_scenario_ids",
        })
    );
    let mut changed = projection.clone();
    changed.scenario_ids[0] = typestate_scenario("different");
    assert_eq!(
        changed.try_normalized(&PolicyBudget::default()),
        Err(FutureEvidenceError::ScenarioSetHashMismatch {
            field: "typestate_scenario_ids",
        })
    );

    let short = PolicyBudget::builder()
        .with_max_projection_scenario_memberships(1)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        projection.clone().try_normalized(&short),
        Err(FutureEvidenceError::ProjectionScenarioMembershipBudget { max_items: 1 })
    );
    let mut empty = projection;
    empty.scenario_ids.clear();
    assert_eq!(
        empty.try_normalized(&PolicyBudget::default()),
        Err(FutureEvidenceError::EmptySemanticSet {
            field: "typestate_scenario_ids",
        })
    );
}

#[test]
fn typestate_violation_counts_expected_states_and_event_endpoint() {
    let terminal = terminal_violation();
    let TypestateViolationEvidence::TerminalExpectation {
        expected_states, ..
    } = &terminal
    else {
        unreachable!()
    };
    assert!(retained_extra(expected_states) > 0);
    let mut without_expected = terminal.clone();
    let TypestateViolationEvidence::TerminalExpectation {
        expected_states, ..
    } = &mut without_expected
    else {
        unreachable!()
    };
    expected_states.clear();
    expected_states.shrink_to_fit();
    assert_eq!(
        terminal.retained_size() - without_expected.retained_size(),
        retained_extra(match &terminal {
            TypestateViolationEvidence::TerminalExpectation {
                expected_states, ..
            } => expected_states,
            _ => unreachable!(),
        })
    );

    let event = TypestateViolationEvidence::error_transition(
        TypestateEventId::new("close").unwrap(),
        Some(endpoint("long-endpoint-id")),
        TypestateStateId::new("open").unwrap(),
        TypestateStateId::new("closed").unwrap(),
    );
    let TypestateViolationEvidence::ErrorTransition {
        endpoint: Some(endpoint_identity),
        event_id,
        ..
    } = &event
    else {
        unreachable!()
    };
    assert_ne!(retained_extra(endpoint_identity), retained_extra(event_id));
    let mut without_endpoint = event.clone();
    let TypestateViolationEvidence::ErrorTransition {
        endpoint: endpoint_slot,
        ..
    } = &mut without_endpoint
    else {
        unreachable!()
    };
    *endpoint_slot = None;
    assert_eq!(
        event.retained_size() - without_endpoint.retained_size(),
        retained_extra(&Some(endpoint("long-endpoint-id")))
    );
}

#[test]
fn vulnerability_digest_separates_weak_keys_in_its_domain() {
    let first = TaintFindingAnchor::weak(OpaqueFindingKey::try_new("taint", "snapshot-a").unwrap());
    let same = TaintFindingAnchor::weak(OpaqueFindingKey::try_new("taint", "snapshot-a").unwrap());
    let second =
        TaintFindingAnchor::weak(OpaqueFindingKey::try_new("taint", "snapshot-b").unwrap());
    assert_eq!(
        taint_vulnerability_digest(&first),
        taint_vulnerability_digest(&same)
    );
    assert_ne!(
        taint_vulnerability_digest(&first),
        taint_vulnerability_digest(&second)
    );

    // The domain is part of the persisted vulnerability identity contract.
    // Derive its weak-anchor spelling independently, without pinning bytes.
    let TaintFindingAnchor::Weak(payload) = &first else {
        unreachable!()
    };
    let mut expected = Sha256::new();
    update_finding_value(&mut expected, POLICY_VULNERABILITY_DOMAIN);
    update_finding_value(&mut expected, b"taint");
    update_finding_value(&mut expected, b"weak");
    update_finding_value(&mut expected, payload.typed_key.as_str().as_bytes());
    let expected: [u8; 32] = expected.finalize().into();
    assert_eq!(taint_vulnerability_digest(&first), expected);
}

#[test]
fn typestate_finding_counts_scenarios_separately_from_witnesses() {
    let projection = typestate_projection();
    let anchor = TypestateFindingAnchor::strong(
        projection.protocol_hash,
        stable_identity(StableIdentityDerivation::ProtocolSubject, "subject"),
        projection.violation_site.clone().unwrap(),
        projection.scenario_set_hash,
        &projection.violation,
    )
    .unwrap();
    let mut evidence = TypestateFindingEvidence::try_new(
        AnalysisFindingId::try_new("typestate", "finding").unwrap(),
        anchor,
        projection.protocol_hash,
        projection.binding_plan_hash,
        AnalysisSubjectRef::try_new("typestate", "subject").unwrap(),
        projection.source_endpoint.clone(),
        projection.violation_site.clone(),
        projection.violation.clone(),
        projection.scenario_ids.clone(),
        false,
        0,
        projection.scenario_set_hash,
        Vec::new(),
        false,
        projection.semantic_hash,
        &PolicyBudget::default(),
    )
    .unwrap();
    let before = evidence.retained_size();
    let capacity = evidence.scenario_ids.capacity();
    evidence.scenario_ids.reserve(4);
    assert_eq!(
        evidence.retained_size() - before,
        (evidence.scenario_ids.capacity() - capacity) * size_of::<TypestateScenarioId>()
    );
    let bytes = before;
    let exact = PolicyBudget::builder()
        .with_max_evidence_bytes_per_finding(bytes)
        .unwrap()
        .build()
        .unwrap();
    let short = PolicyBudget::builder()
        .with_max_evidence_bytes_per_finding(bytes - 1)
        .unwrap()
        .build()
        .unwrap();
    let original = projection;
    let make = |budget: &PolicyBudget| {
        TypestateFindingEvidence::try_new(
            AnalysisFindingId::try_new("typestate", "finding").unwrap(),
            TypestateFindingAnchor::strong(
                original.protocol_hash,
                stable_identity(StableIdentityDerivation::ProtocolSubject, "subject"),
                original.violation_site.clone().unwrap(),
                original.scenario_set_hash,
                &original.violation,
            )
            .unwrap(),
            original.protocol_hash,
            original.binding_plan_hash,
            AnalysisSubjectRef::try_new("typestate", "subject").unwrap(),
            original.source_endpoint.clone(),
            original.violation_site.clone(),
            original.violation.clone(),
            original.scenario_ids.clone(),
            false,
            0,
            original.scenario_set_hash,
            Vec::new(),
            false,
            original.semantic_hash,
            budget,
        )
    };
    make(&exact).expect("exact retained evidence bound admits");
    assert_eq!(
        make(&short),
        Err(FutureEvidenceError::RetainedEvidenceBudget {
            field: "typestate_finding_evidence",
            max_bytes: bytes - 1,
        })
    );
}

#[test]
fn taint_origin_refs_and_finding_origins_contribute_to_retained_bytes() {
    let projection = taint_projection(vec![source_fact(
        "source",
        "untrusted",
        "source",
        &["path"],
    )]);
    let fact = &projection.source_facts[0];
    let origin = TaintOriginEvidence::try_new(
        fact.source_endpoint.clone(),
        fact.source_label.clone(),
        fact.source_evidence.clone(),
        PolicySourceLocation::artifact(WorkspaceRelativePath::new("src/source.rs").unwrap()),
        fact.source_scenario_ids[0].clone(),
        vec![fact.evidence_ref.clone()],
    )
    .unwrap();
    let mut without_refs = origin.clone();
    without_refs.evidence_refs = Vec::new();
    assert_eq!(
        origin.retained_size() - without_refs.retained_size(),
        retained_extra(&origin.evidence_refs)
    );

    let mut finding = taint_finding(&projection, false, 0, &PolicyBudget::default()).unwrap();
    let before = finding.retained_size();
    let capacity = finding.origins.capacity();
    finding.origins.reserve(4);
    assert_eq!(
        finding.retained_size() - before,
        (finding.origins.capacity() - capacity) * size_of::<TaintOriginEvidence>()
    );
}

#[test]
fn taint_finding_admits_the_exact_retained_evidence_byte_bound() {
    let projection = taint_projection(vec![source_fact(
        "source",
        "untrusted",
        "source",
        &["path"],
    )]);
    let evidence = taint_finding(&projection, false, 0, &PolicyBudget::default()).unwrap();
    let bytes = evidence.retained_size();
    let exact = PolicyBudget::builder()
        .with_max_evidence_bytes_per_finding(bytes)
        .unwrap()
        .build()
        .unwrap();
    taint_finding(&projection, false, 0, &exact).expect("exact byte bound admits the evidence");
    let short = PolicyBudget::builder()
        .with_max_evidence_bytes_per_finding(bytes - 1)
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        taint_finding(&projection, false, 0, &short),
        Err(FutureEvidenceError::RetainedEvidenceBudget {
            field: "taint_finding_evidence",
            max_bytes: bytes - 1,
        })
    );
}
