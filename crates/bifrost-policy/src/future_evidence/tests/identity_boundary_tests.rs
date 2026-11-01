use super::*;

#[test]
fn retained_evidence_admits_its_exact_byte_limit() {
    let projection = taint_projection(vec![source_fact(
        "source",
        "untrusted",
        "source",
        &["path-a"],
    )]);
    let evidence = taint_finding(&projection, false, 0, &PolicyBudget::default()).unwrap();
    let size = evidence.retained_size();
    let exact = PolicyBudget::builder()
        .with_max_evidence_bytes_per_finding(size)
        .unwrap()
        .build()
        .unwrap();
    assert!(taint_finding(&projection, false, 0, &exact).is_ok());
    let below = PolicyBudget::builder()
        .with_max_evidence_bytes_per_finding(size - 1)
        .unwrap()
        .build()
        .unwrap();
    assert!(matches!(
        taint_finding(&projection, false, 0, &below),
        Err(FutureEvidenceError::RetainedEvidenceBudget {
            field: "taint_finding_evidence",
            ..
        })
    ));
}

#[test]
fn scenario_ids_preserve_case_in_public_set_identity() {
    let upper = SourceScenarioSetHash::try_from_scenarios(vec![source_scenario("Path")]).unwrap();
    let lower = SourceScenarioSetHash::try_from_scenarios(vec![source_scenario("path")]).unwrap();
    assert_ne!(upper, lower);
}

#[test]
fn catalog_version_is_preserved_on_the_wire_and_in_projection_identity() {
    let catalog = |version| {
        ResolvedCatalogIdentity::try_new(
            PolicyId::new("catalog.sources").unwrap(),
            version,
            TaintCatalogHash::from_bytes([7; 32]),
        )
        .unwrap()
    };
    assert_eq!(serde_json::to_value(catalog(3)).unwrap()["version"], 3);
    let source = |version| {
        crate::test_support::taint_source_projection_fact(
            ResolvedEndpointIdentity::Catalog {
                catalog: catalog(version),
                entry_id: TaintEntryId::new("source").unwrap(),
            },
            EndpointSemanticHash::from_bytes([1; 32]),
            EndpointAnalysisProjectionHash::from_bytes([2; 32]),
            "source".to_owned(),
            vec![PolicyCategoryId::new("user-input").unwrap()],
            TaintLabel::new("untrusted").unwrap(),
            None,
            vec![source_scenario("path")],
            evidence_ref("source"),
        )
    };
    let first = source(2);
    let second = source(3);
    assert_ne!(first.content_hash, second.content_hash);
}

#[test]
fn typestate_projection_separates_optional_identity_and_event_payloads() {
    let base = typestate_projection();
    let make = |site, violation| {
        TypestatePolicyProjectionFacts::try_new(
            base.authoring_projection_hash,
            base.protocol_hash,
            base.binding_plan_hash,
            base.source_endpoint.clone(),
            base.source_endpoint_hash,
            base.source_endpoint_analysis_projection_hash,
            base.source_categories.clone(),
            base.source_display_name.clone(),
            site,
            violation,
            base.scenario_ids.clone(),
            &PolicyBudget::default(),
        )
        .unwrap()
        .semantic_hash
    };
    let site_a = base.violation_site.clone().unwrap();
    let site_b = stable_identity(
        StableIdentityDerivation::ProtocolViolationSite,
        "other-site",
    );
    assert_ne!(
        make(Some(site_a.clone()), base.violation.clone()),
        make(Some(site_b), base.violation.clone())
    );
    assert_ne!(
        make(Some(site_a), base.violation.clone()),
        make(None, base.violation.clone())
    );
    let normal = terminal_violation();
    let exceptional = TypestateViolationEvidence::try_terminal_expectation(
        TypestateExpectationId::new("closed-at-exit").unwrap(),
        ResolvedTypestateTerminal::SemanticEvent {
            event: PolicySemanticEvent::ExceptionalProcedureExit {
                scope: TypestateExitScope::AnalysisRoot,
            },
        },
        TypestateStateId::new("open").unwrap(),
        vec![TypestateStateId::new("closed").unwrap()],
    )
    .unwrap();
    assert_ne!(make(None, normal), make(None, exceptional));
    let transition = |endpoint| {
        TypestateViolationEvidence::error_transition(
            TypestateEventId::new("close").unwrap(),
            endpoint,
            TypestateStateId::new("open").unwrap(),
            TypestateStateId::new("closed").unwrap(),
        )
    };
    assert_ne!(
        make(None, transition(Some(endpoint("first")))),
        make(None, transition(Some(endpoint("second"))))
    );
    assert_ne!(
        make(None, transition(None)),
        make(None, transition(Some(endpoint("first"))))
    );
}

fn typestate_projection_hash(
    base: &TypestatePolicyProjectionFacts,
    site: Option<StableSemanticIdentity>,
    violation: TypestateViolationEvidence,
) -> TypestateProjectionFactsHash {
    TypestatePolicyProjectionFacts::try_new(
        base.authoring_projection_hash,
        base.protocol_hash,
        base.binding_plan_hash,
        base.source_endpoint.clone(),
        base.source_endpoint_hash,
        base.source_endpoint_analysis_projection_hash,
        base.source_categories.clone(),
        base.source_display_name.clone(),
        site,
        violation,
        base.scenario_ids.clone(),
        &PolicyBudget::default(),
    )
    .unwrap()
    .semantic_hash
}

#[test]
fn stable_identity_namespace_and_path_both_distinguish_projection() {
    let base = typestate_projection();
    let path = WorkspaceRelativePath::new("src/app.rs").unwrap();
    let other_path = WorkspaceRelativePath::new("src/other.rs").unwrap();
    let identity = |namespace, path| {
        StableSemanticIdentity::protocol_violation_site(namespace, path, "same-site").unwrap()
    };
    let first = typestate_projection_hash(
        &base,
        Some(identity("rust", path.clone())),
        base.violation.clone(),
    );
    assert_eq!(
        first,
        typestate_projection_hash(
            &base,
            Some(identity("rust", path.clone())),
            base.violation.clone()
        )
    );
    assert_ne!(
        first,
        typestate_projection_hash(
            &base,
            Some(identity("rust", other_path)),
            base.violation.clone()
        )
    );
    assert_ne!(
        first,
        typestate_projection_hash(&base, Some(identity("java", path)), base.violation.clone())
    );
}

#[test]
fn source_evidence_values_distinguish_content_identity() {
    let base = source_fact("source", "untrusted", "source", &["path"]);
    let make = |trust_boundary, system_entry| {
        TaintSourceProjectionFact::try_new(
            base.source_endpoint.clone(),
            base.source_endpoint_semantic_hash,
            base.source_endpoint_analysis_projection_hash,
            base.source_display_name.clone(),
            base.source_categories.clone(),
            base.source_label.clone(),
            Some(TaintSourceEvidence {
                trust_boundary,
                system_entry,
            }),
            base.source_scenario_ids.clone(),
            base.evidence_ref.clone(),
        )
        .unwrap()
        .content_hash
    };
    let first = make(
        Some(TaintTrustBoundary::External),
        Some(TaintSystemEntry::LocalInput),
    );
    assert_eq!(
        first,
        make(
            Some(TaintTrustBoundary::External),
            Some(TaintSystemEntry::LocalInput)
        )
    );
    assert_ne!(
        first,
        make(
            Some(TaintTrustBoundary::Internal),
            Some(TaintSystemEntry::LocalInput)
        )
    );
    assert_ne!(
        first,
        make(
            Some(TaintTrustBoundary::External),
            Some(TaintSystemEntry::Physical)
        )
    );
}

#[test]
fn typestate_terminal_phase_and_event_distinguish_projections() {
    let base = typestate_projection();
    let terminal = |phase| {
        TypestateViolationEvidence::try_terminal_expectation(
            TypestateExpectationId::new("closed-at-exit").unwrap(),
            ResolvedTypestateTerminal::Endpoint {
                endpoint: endpoint("terminal"),
                phase,
            },
            TypestateStateId::new("open").unwrap(),
            vec![TypestateStateId::new("closed").unwrap()],
        )
        .unwrap()
    };
    let at_match =
        typestate_projection_hash(&base, None, terminal(EndpointObservationPhase::AtMatch));
    assert_eq!(
        at_match,
        typestate_projection_hash(&base, None, terminal(EndpointObservationPhase::AtMatch))
    );
    assert_ne!(
        at_match,
        typestate_projection_hash(&base, None, terminal(EndpointObservationPhase::BeforeCall))
    );
    let normal = typestate_projection_hash(&base, None, terminal_violation());
    let exceptional = TypestateViolationEvidence::try_terminal_expectation(
        TypestateExpectationId::new("closed-at-exit").unwrap(),
        ResolvedTypestateTerminal::SemanticEvent {
            event: PolicySemanticEvent::ExceptionalProcedureExit {
                scope: TypestateExitScope::AnalysisRoot,
            },
        },
        TypestateStateId::new("open").unwrap(),
        vec![TypestateStateId::new("closed").unwrap()],
    )
    .unwrap();
    assert_ne!(normal, typestate_projection_hash(&base, None, exceptional));
}

#[test]
fn typestate_transition_target_distinguishes_projections() {
    let base = typestate_projection();
    let transition = |target| {
        TypestateViolationEvidence::error_transition(
            TypestateEventId::new("close").unwrap(),
            None,
            TypestateStateId::new("open").unwrap(),
            TypestateStateId::new(target).unwrap(),
        )
    };
    assert_ne!(
        typestate_projection_hash(&base, None, transition("closed")),
        typestate_projection_hash(&base, None, transition("failed")),
    );
}

#[test]
fn weak_vulnerability_identities_separate_taint_and_typestate() {
    let key = OpaqueFindingKey::try_new("test-adapter", "same-site").unwrap();
    let taint = TaintFindingAnchor::weak(key.clone());
    let typestate = TypestateFindingAnchor::weak(key);
    assert_eq!(
        taint_vulnerability_digest(&taint),
        taint_vulnerability_digest(&taint)
    );
    assert_ne!(
        taint_vulnerability_digest(&taint),
        typestate_vulnerability_digest(&typestate)
    );
}

#[test]
fn empty_untruncated_scenarios_report_the_scenario_field() {
    let projection = taint_projection(vec![source_fact(
        "source",
        "untrusted",
        "source",
        &["path"],
    )]);
    let fact = &projection.source_facts[0];
    let anchor = TaintFindingAnchor::strong(
        stable_identity(StableIdentityDerivation::CanonicalAstIdentity, "sink-call"),
        0,
        fact.source_endpoint_analysis_projection_hash,
        projection.sink_endpoint_analysis_projection_hash,
        fact.scenario_set_hash,
    )
    .unwrap();
    let origin = TaintOriginEvidence::try_new(
        fact.source_endpoint.clone(),
        fact.source_label.clone(),
        fact.source_evidence.clone(),
        PolicySourceLocation::artifact(WorkspaceRelativePath::new("src/source.rs").unwrap()),
        fact.source_scenario_ids[0].clone(),
        vec![fact.evidence_ref.clone()],
    )
    .unwrap();
    let error = TaintFindingEvidence::try_new(
        AnalysisFindingId::try_new("taint", "finding").unwrap(),
        anchor,
        AnalysisEventRef::try_new("taint", "sink-event").unwrap(),
        fact.source_endpoint.clone(),
        projection.sink_endpoint.clone(),
        fact.source_display_name.clone(),
        projection.sink_display_name.clone(),
        fact.source_categories.clone(),
        projection.sink_categories.clone(),
        None,
        projection.sink_tags.clone(),
        projection.sink_impacts.clone(),
        projection.reached_source_labels.clone(),
        vec![origin],
        false,
        Vec::new(),
        false,
        0,
        fact.scenario_set_hash,
        Vec::new(),
        false,
        projection.semantic_hash,
        &PolicyBudget::default(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        FutureEvidenceError::EmptySemanticSet {
            field: "source_scenarios"
        }
    ));
}

#[test]
fn weak_finding_identities_separate_taint_and_typestate() {
    let policy = PolicyId::new("security.flow").unwrap();
    let key = OpaqueFindingKey::try_new("test-adapter", "same-site").unwrap();
    let taint = TaintFindingAnchor::weak(key.clone());
    let typestate = TypestateFindingAnchor::weak(key);
    let taint_id = PolicyFindingId::from_taint_anchor(&policy, &taint);
    let typestate_id = PolicyFindingId::from_typestate_anchor(&policy, &typestate);
    assert_eq!(
        taint_id,
        PolicyFindingId::from_taint_anchor(&policy, &taint)
    );
    assert_ne!(taint_id, typestate_id);
}

#[test]
fn scenario_set_domains_separate_taint_and_typestate() {
    let source = SourceScenarioSetHash::try_from_scenarios(vec![
        SourceScenarioId::try_new("shared", "path").unwrap(),
    ])
    .unwrap();
    let typestate = TypestateScenarioSetHash::try_from_scenarios(vec![
        TypestateScenarioId::try_new("shared", "path").unwrap(),
    ])
    .unwrap();
    assert_ne!(source.as_bytes(), typestate.as_bytes());
}

#[test]
fn typestate_violation_site_and_subject_have_distinct_identity_roles() {
    let facts = typestate_projection();
    let subject = stable_identity(StableIdentityDerivation::ProtocolSubject, "subject-a");
    let other_subject = stable_identity(StableIdentityDerivation::ProtocolSubject, "subject-b");
    let site = facts.violation_site.clone().unwrap();
    let other_site = stable_identity(
        StableIdentityDerivation::ProtocolViolationSite,
        "other-site",
    );
    let make = |subject, site| {
        TypestateFindingAnchor::strong(
            facts.protocol_hash,
            subject,
            site,
            facts.scenario_set_hash,
            &facts.violation,
        )
        .unwrap()
    };
    let first = make(subject.clone(), site.clone());
    let changed_site = make(subject.clone(), other_site);
    let changed_subject = make(other_subject, site);
    assert_ne!(
        first.strong_fields().unwrap().violation_hash(),
        changed_site.strong_fields().unwrap().violation_hash(),
    );
    assert_eq!(
        first.strong_fields().unwrap().violation_hash(),
        changed_subject.strong_fields().unwrap().violation_hash(),
    );
    assert_ne!(
        typestate_vulnerability_digest(&first),
        typestate_vulnerability_digest(&changed_subject),
    );
    assert_eq!(
        typestate_vulnerability_digest(&first),
        typestate_vulnerability_digest(&first),
    );
}

#[test]
fn source_display_text_obeys_full_report_byte_limit_and_character_rules() {
    let make = |display: &str| {
        TaintSourceProjectionFact::try_new(
            endpoint("source"),
            EndpointSemanticHash::from_bytes([1; 32]),
            EndpointAnalysisProjectionHash::from_bytes([2; 32]),
            display.to_owned(),
            vec![PolicyCategoryId::new("user-input").unwrap()],
            TaintLabel::new("untrusted").unwrap(),
            None,
            vec![source_scenario("path")],
            evidence_ref("source"),
        )
    };
    assert!(make(&"a".repeat(MAX_REPORT_PROSE_BYTES)).is_ok());
    assert!(matches!(
        make(&"a".repeat(MAX_REPORT_PROSE_BYTES + 1)),
        Err(FutureEvidenceError::InvalidText {
            field: "source_display_name",
            reason: TextValidationError::TooLong {
                max_bytes: MAX_REPORT_PROSE_BYTES
            },
        })
    ));
    assert!(matches!(
        make(""),
        Err(FutureEvidenceError::InvalidText {
            field: "source_display_name",
            reason: TextValidationError::Empty,
        })
    ));
    assert!(matches!(
        make("a\nb"),
        Err(FutureEvidenceError::InvalidText {
            field: "source_display_name",
            reason: TextValidationError::UnsafeCharacter,
        })
    ));
}
