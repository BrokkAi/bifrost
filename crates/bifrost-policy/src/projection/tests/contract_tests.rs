use super::*;

fn typestate_authority<'a>(policy: &'a LoadedPolicy) -> TypestateProjectionAuthority<'a> {
    TypestateProjectionAuthority::from_loaded_compilation(
        policy,
        TypestateProtocolHash::from_canonical_bytes(b"protocol"),
        TypestateBindingPlanHash::from_canonical_bytes(b"bindings"),
    )
    .unwrap()
}

#[test]
fn stored_typestate_requires_the_witness_cut_field() {
    let registry = registry(&[(
        "test:typestate",
        crate::test_support::typestate_policy_source(
            "test.typestate-authority",
            "Typestate authority",
        ),
    )]);
    let authority = typestate_authority(registry.policies().next().unwrap());
    let projection = typestate_projected_finding(&authority);
    let mut value = serde_json::to_value(projection).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("witness_refs_truncated");
    let encoded = serde_json::to_string(&value).unwrap();
    let mut deserializer = serde_json::Deserializer::from_str(&encoded);
    assert!(
        serde::de::DeserializeSeed::deserialize(
            TypestateProjectedFindingSeed::new(&PolicyBudget::default()),
            &mut deserializer,
        )
        .is_err()
    );
}

#[test]
fn one_typestate_projection_fits_a_one_finding_budget() {
    let registry = registry(&[(
        "test:typestate",
        crate::test_support::typestate_policy_source(
            "test.typestate-authority",
            "Typestate authority",
        ),
    )]);
    let authority = typestate_authority(registry.policies().next().unwrap());
    let budget = PolicyBudget::builder()
        .with_max_findings(1)
        .unwrap()
        .build()
        .unwrap();
    let batch = authority.seal_batch(TypestateProjectionPayload {
        projections: vec![typestate_projected_finding(&authority)],
        completion: PolicyRunCompletion::Complete,
        diagnostics: Vec::new(),
        diagnostics_truncated: false,
        work: PolicyWorkReport::default(),
        subjects: None,
    });
    let validated = validate_typestate_batch(&authority, batch, &budget).unwrap();
    assert_eq!(validated.projections.len(), 1);
    assert!(matches!(
        validated.completion,
        PolicyRunCompletion::Complete
    ));
}

#[test]
fn typestate_facts_reject_another_binding_plan() {
    let registry = registry(&[(
        "test:typestate",
        crate::test_support::typestate_policy_source(
            "test.typestate-authority",
            "Typestate authority",
        ),
    )]);
    let authority = typestate_authority(registry.policies().next().unwrap());
    let original = typestate_facts(&authority, authority.protocol_hash());
    let facts = TypestatePolicyProjectionFacts::try_new(
        original.authoring_projection_hash,
        original.protocol_hash,
        TypestateBindingPlanHash::from_canonical_bytes(b"other bindings"),
        original.source_endpoint,
        original.source_endpoint_hash,
        original.source_endpoint_analysis_projection_hash,
        original.source_categories,
        original.source_display_name,
        original.violation_site,
        original.violation,
        original.scenario_ids,
        &PolicyBudget::default(),
    )
    .unwrap();
    assert!(matches!(
        validate_typestate_facts(&authority, facts, &PolicyBudget::default()),
        Err(ProjectionAuthorityError::CompiledProjectionHashMismatch)
    ));
}

#[test]
fn finding_budget_reports_its_own_incomplete_reason() {
    let registry = registry(&[("test:target", taint_policy("test.target"))]);
    let authority =
        TaintProjectionAuthority::from_loaded(registry.policies().next().unwrap()).unwrap();
    let facts = taint_meeting(
        authority.spec,
        vec![source_fact(&authority.spec.sources[0], "alpha")],
        None,
    );
    let budget = PolicyBudget::builder()
        .with_max_findings(1)
        .unwrap()
        .build()
        .unwrap();
    let batch = taint_batch(
        &authority,
        vec![
            taint_projection_envelope(facts.clone(), vec![taint_pair(&facts, 0, "call:first")]),
            taint_projection_envelope(facts.clone(), vec![taint_pair(&facts, 0, "call:second")]),
        ],
        PolicyRunCompletion::Complete,
        Vec::new(),
        false,
        PolicyWorkReport::default(),
    );
    let validated = validate_taint_batch(&authority, batch, &budget).unwrap();
    assert!(
        matches!(validated.completion, PolicyRunCompletion::Inconclusive { reasons, .. }
        if reasons.contains(&PolicyIncompleteReason::BatchFindingLimit))
    );
}

#[test]
fn evidence_reference_budget_counts_proof_and_admits_exact_limit() {
    let registry = registry(&[("test:target", taint_policy("test.target"))]);
    let authority =
        TaintProjectionAuthority::from_loaded(registry.policies().next().unwrap()).unwrap();
    let facts = taint_meeting(
        authority.spec,
        vec![source_fact(&authority.spec.sources[0], "alpha")],
        None,
    );
    let budget = PolicyBudget::builder()
        .with_max_evidence_refs_per_finding(1)
        .unwrap()
        .build()
        .unwrap();
    let limits = EffectiveReportLimits::new(authority.report, &budget);
    let exact = taint_pair(&facts, 0, "call:sink");
    assert!(validate_taint_pair(facts.clone(), exact.clone(), &budget, limits).is_ok());

    let mut exceeded = exact;
    exceeded.report.proof = crate::finding::ProofMetadata::try_new(
        crate::finding::ProofState::Proven,
        vec![crate::finding::ProofReason::DataflowWitness],
        vec![EvidenceRef::try_new("test", "independent-proof").unwrap()],
    )
    .unwrap();
    assert!(matches!(
        validate_taint_pair(facts, exceeded, &budget, limits),
        Err(ProjectionAuthorityError::ReportBudgetExceeded {
            field: "evidence_references",
            limit: 1
        })
    ));
}

#[test]
fn related_location_budget_admits_exact_limit() {
    let registry = registry(&[("test:target", taint_policy("test.target"))]);
    let authority =
        TaintProjectionAuthority::from_loaded(registry.policies().next().unwrap()).unwrap();
    let facts = taint_meeting(
        authority.spec,
        vec![source_fact(&authority.spec.sources[0], "alpha")],
        None,
    );
    let budget = PolicyBudget::builder()
        .with_max_related_locations_per_finding(1)
        .unwrap()
        .build()
        .unwrap();
    let limits = EffectiveReportLimits::new(authority.report, &budget);
    let related = crate::finding::RelatedPolicyLocation::try_new(
        crate::finding::PolicyLocationRelationship::Evidence,
        crate::test_support::policy_test_location("src/test.rs", 2, 2, 2),
        Vec::new(),
    )
    .unwrap();
    let mut exact = taint_pair(&facts, 0, "call:sink");
    exact.report.related.push(related.clone());
    assert!(validate_taint_pair(facts.clone(), exact.clone(), &budget, limits).is_ok());
    let mut exceeded = exact;
    exceeded.report.related.push(
        crate::finding::RelatedPolicyLocation::try_new(
            crate::finding::PolicyLocationRelationship::Evidence,
            crate::test_support::policy_test_location("src/test.rs", 3, 3, 3),
            Vec::new(),
        )
        .unwrap(),
    );
    assert!(matches!(
        validate_taint_pair(facts, exceeded, &budget, limits),
        Err(ProjectionAuthorityError::ReportBudgetExceeded {
            field: "related_locations",
            limit: 1
        })
    ));
}

#[test]
fn truncated_taint_origins_remain_marked_in_validated_batch() {
    let registry = registry(&[("test:target", taint_policy("test.target"))]);
    let authority =
        TaintProjectionAuthority::from_loaded(registry.policies().next().unwrap()).unwrap();
    let facts = taint_meeting(
        authority.spec,
        vec![source_fact(&authority.spec.sources[0], "alpha")],
        None,
    );
    let mut pair = taint_pair(&facts, 0, "call:sink");
    pair.origins.clear();
    pair.origins_truncated = true;
    let batch = taint_batch(
        &authority,
        vec![taint_projection_envelope(facts, vec![pair])],
        PolicyRunCompletion::Complete,
        Vec::new(),
        false,
        PolicyWorkReport::default(),
    );
    let validated = validate_taint_batch(&authority, batch, &PolicyBudget::default()).unwrap();
    assert_eq!(validated.projections.len(), 1);
    assert!(validated.projections[0].origins_truncated);
}

#[test]
fn truncated_typestate_witnesses_remain_marked_in_validated_batch() {
    let registry = registry(&[(
        "test:typestate",
        crate::test_support::typestate_policy_source(
            "test.typestate-authority",
            "Typestate authority",
        ),
    )]);
    let authority = typestate_authority(registry.policies().next().unwrap());
    let mut projection = typestate_projected_finding(&authority);
    projection.witness_refs_truncated = true;
    projection.report.witnesses_truncated = true;
    projection.report.omitted_witnesses_lower_bound = 1;
    projection.report.completeness = crate::finding::FindingCompleteness::partial(vec![
        crate::finding::FindingIncompleteReason::WitnessTruncated,
    ])
    .unwrap();
    let batch = authority.seal_batch(TypestateProjectionPayload {
        projections: vec![projection],
        completion: PolicyRunCompletion::Complete,
        diagnostics: Vec::new(),
        diagnostics_truncated: false,
        work: PolicyWorkReport::default(),
        subjects: None,
    });
    let validated = validate_typestate_batch(&authority, batch, &PolicyBudget::default()).unwrap();
    assert_eq!(validated.projections.len(), 1);
    assert!(validated.projections[0].witness_refs_truncated);
}

#[test]
fn dangling_witness_reference_rejects_a_taint_pair() {
    let registry = registry(&[("test:target", taint_policy("test.target"))]);
    let authority =
        TaintProjectionAuthority::from_loaded(registry.policies().next().unwrap()).unwrap();
    let facts = taint_meeting(
        authority.spec,
        vec![source_fact(&authority.spec.sources[0], "alpha")],
        None,
    );
    let mut pair = taint_pair(&facts, 0, "call:sink");
    let witness_id = crate::finding_identity::WitnessId::try_new("test", "orphan").unwrap();
    pair.witness_refs.push(witness_id);
    let limits = EffectiveReportLimits::new(authority.report, &PolicyBudget::default());
    assert!(matches!(
        validate_taint_pair(facts, pair, &PolicyBudget::default(), limits),
        Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
            field: "witness_references"
        })
    ));
}

#[test]
fn mixed_accepted_and_rejected_taint_labels_are_rejected() {
    let source = taint_policy("test.target").replace(
        ":accepts [untrusted confidential secret]",
        ":accepts [untrusted]",
    );
    let registry = registry(&[("test:target", source)]);
    let authority =
        TaintProjectionAuthority::from_loaded(registry.policies().next().unwrap()).unwrap();
    let source = &authority.spec.sources[0];
    let facts = taint_meeting(
        authority.spec,
        vec![
            source_fact_with_label(source, "untrusted", "first"),
            source_fact_with_label(source, "confidential", "second"),
        ],
        None,
    );
    assert!(matches!(
        validate_taint_facts(&authority, facts, &PolicyBudget::default()),
        Err(ProjectionAuthorityError::SinkRejectedReachedLabel)
    ));
}

#[test]
fn typestate_terminal_facts_must_join_the_compiled_expectation() {
    let registry = registry(&[(
        "test:typestate",
        crate::test_support::typestate_policy_source(
            "test.typestate-authority",
            "Typestate authority",
        ),
    )]);
    let authority = typestate_authority(registry.policies().next().unwrap());
    let original = typestate_facts(&authority, authority.protocol_hash());
    let violation = TypestateViolationEvidence::try_terminal_expectation(
        TypestateExpectationId::new("normal-exit").unwrap(),
        ResolvedTypestateTerminal::SemanticEvent {
            event: PolicySemanticEvent::NormalProcedureExit {
                scope: TypestateExitScope::AnalysisRoot,
            },
        },
        TypestateStateId::new("closed").unwrap(),
        vec![TypestateStateId::new("open").unwrap()],
    )
    .unwrap();
    let facts = TypestatePolicyProjectionFacts::try_new(
        original.authoring_projection_hash,
        original.protocol_hash,
        original.binding_plan_hash,
        original.source_endpoint,
        original.source_endpoint_hash,
        original.source_endpoint_analysis_projection_hash,
        original.source_categories,
        original.source_display_name,
        original.violation_site,
        violation,
        original.scenario_ids,
        &PolicyBudget::default(),
    )
    .unwrap();
    assert!(matches!(
        validate_typestate_facts(&authority, facts, &PolicyBudget::default()),
        Err(ProjectionAuthorityError::TypestateExpectationJoinMismatch)
    ));
}

#[test]
fn taint_pairs_must_name_one_sink_event() {
    let registry = registry(&[("test:target", taint_policy("test.target"))]);
    let authority =
        TaintProjectionAuthority::from_loaded(registry.policies().next().unwrap()).unwrap();
    let facts = taint_meeting(
        authority.spec,
        vec![
            source_fact(&authority.spec.sources[0], "alpha"),
            source_fact(&authority.spec.sources[1], "beta"),
        ],
        None,
    );
    let first = taint_pair(&facts, 0, "call:sink");
    let mut second = taint_pair(&facts, 1, "call:sink");
    second.sink = AnalysisEventRef::try_new("test", "other-sink-event").unwrap();
    let envelope = taint_projection_envelope(facts, vec![first, second]);
    let limits = EffectiveReportLimits::new(authority.report, &PolicyBudget::default());
    assert!(matches!(
        validate_taint_projection(&authority, envelope, &PolicyBudget::default(), limits),
        Err(ProjectionAuthorityError::FindingEnvelopeMismatch {
            field: "taint_common_sink"
        })
    ));
}

#[test]
fn typestate_authority_binds_the_loaded_authoring_projection() {
    let registry = registry(&[(
        "test:typestate",
        crate::test_support::typestate_policy_source(
            "test.typestate-authority",
            "Typestate authority",
        ),
    )]);
    let authority = typestate_authority(registry.policies().next().unwrap());
    assert_eq!(
        authority.seal.authoring_projection_hash,
        Some(authority.spec.authoring_projection_hash)
    );
}

#[test]
fn truncated_typestate_diagnostics_make_batch_inconclusive() {
    let registry = registry(&[(
        "test:typestate",
        crate::test_support::typestate_policy_source(
            "test.typestate-authority",
            "Typestate authority",
        ),
    )]);
    let authority = typestate_authority(registry.policies().next().unwrap());
    let batch = authority.seal_batch(TypestateProjectionPayload {
        projections: Vec::new(),
        completion: PolicyRunCompletion::Complete,
        diagnostics: Vec::new(),
        diagnostics_truncated: true,
        work: PolicyWorkReport::default(),
        subjects: None,
    });
    let validated = validate_typestate_batch(&authority, batch, &PolicyBudget::default()).unwrap();
    assert!(
        matches!(validated.completion, PolicyRunCompletion::Inconclusive { reasons, .. }
        if reasons.contains(&PolicyIncompleteReason::ReportRetentionBudget))
    );
}

#[test]
fn stored_typestate_facts_obey_the_reader_scenario_budget() {
    let registry = registry(&[(
        "test:typestate",
        crate::test_support::typestate_policy_source(
            "test.typestate-authority",
            "Typestate authority",
        ),
    )]);
    let authority = typestate_authority(registry.policies().next().unwrap());
    let projection = typestate_projected_finding(&authority);
    let encoded = serde_json::to_string(&projection).unwrap();
    let admit = PolicyBudget::builder()
        .with_max_projection_scenario_memberships(1)
        .unwrap()
        .build()
        .unwrap();
    let refuse = PolicyBudget::builder()
        .with_max_projection_scenario_memberships(0)
        .unwrap()
        .build()
        .unwrap();
    let mut admitted = serde_json::Deserializer::from_str(&encoded);
    assert!(
        serde::de::DeserializeSeed::deserialize(
            TypestateProjectedFindingSeed::new(&admit),
            &mut admitted
        )
        .is_ok()
    );
    let mut refused = serde_json::Deserializer::from_str(&encoded);
    assert!(
        serde::de::DeserializeSeed::deserialize(
            TypestateProjectedFindingSeed::new(&refuse),
            &mut refused
        )
        .is_err()
    );
}

#[test]
fn endpoint_terminal_accepts_its_declared_phase() {
    use crate::catalog::{CatalogRegistryLimits, TaintCatalogRegistry};
    use crate::inline_project::InlineTestProject;
    use crate::registry::PolicyRegistryLimits;
    use crate::resolved::ResolvedTypestateTerminalTrigger;
    use std::sync::Arc;

    const POLICY_PATH: &str = "policies/resource-lifecycle.rqlp";
    const POLICY: &str = r#"(policy
  :schema-version 1
  :id "test.endpoint-terminal"
  :name "Endpoint terminal"
  :message "Resource was not closed"
  :severity error
  :analysis (analysis
    :type typestate
    :mode may
    :subjects (subject-set
      :include-matches [(match-directory :path "policies/endpoints" :scope recursive
        :categories (all [resource.acquire]))]
      :entries [])
    :uncertainty (uncertainty :escape inconclusive)
    :automaton (automaton
      :states [open closed error]
      :initial open
      :accepting-states [closed]
      :error-states [error]
      :events [(event :id close
        :matches (match-directory :path "policies/endpoints" :scope recursive
          :role sink :phase after-normal-return :categories (all [resource.close]))
        :supersedes [])]
      :transitions [(transition :from open :on close :to closed)]
      :terminal-expectations [(terminal-expectation :id must-close
        :matches (match-directory :path "policies/endpoints" :scope recursive
          :role sink :phase after-normal-return :categories (all [resource.close]))
        :expected-states [closed] :supersedes [])])))"#;
    const ACQUIRE: &str = r#"(endpoint
      :schema-version 1 :id "test.acquire" :name "Acquire" :display-name "acquire"
      :role source :categories [resource.acquire]
      :selector (rql :schema-version 1 (language go (call :callee (name "OpenRes"))))
      :binding return-value :supersedes [])"#;
    const CLOSE: &str = r#"(endpoint
      :schema-version 1 :id "test.close" :name "Close" :display-name "close"
      :role sink :categories [resource.close]
      :selector (rql :schema-version 1 (language go (call :callee (name "Close"))))
      :binding receiver :supersedes [])"#;
    let project = InlineTestProject::with_language(brokk_bifrost_analysis::analyzer::Language::Go)
        .file("go.mod", "module example.com/endpoint-terminal\n")
        .file(POLICY_PATH, POLICY)
        .file("policies/endpoints/acquire.rqlp", ACQUIRE)
        .file("policies/endpoints/close.rqlp", CLOSE)
        .build();
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry = PolicyRegistry::new_for_workspace(
        project.root().to_path_buf(),
        catalogs,
        PolicyRegistryLimits::default(),
    )
    .unwrap();
    let policy = registry.load_policy_path(POLICY_PATH).unwrap();
    let authority = typestate_authority(policy);
    let subject = &authority.spec.subjects[0];
    let dependency = authority
        .spec
        .endpoint_dependencies
        .iter()
        .find(|dependency| dependency.identity() == &subject.identity)
        .unwrap();
    let expectation = &authority.spec.automaton.terminal_expectations[0];
    let ResolvedTypestateTerminalTrigger::MatchEndpoints { endpoints, phase } =
        &expectation.trigger
    else {
        panic!("fixture terminal must resolve an endpoint trigger");
    };
    let violation = TypestateViolationEvidence::try_terminal_expectation(
        expectation.id.clone(),
        ResolvedTypestateTerminal::Endpoint {
            endpoint: endpoints[0].clone(),
            phase: *phase,
        },
        TypestateStateId::new("open").unwrap(),
        expectation.expected_states.clone(),
    )
    .unwrap();
    let facts = TypestatePolicyProjectionFacts::try_new(
        authority.spec.authoring_projection_hash,
        authority.protocol_hash(),
        authority.binding_plan_hash(),
        subject.identity.clone(),
        subject.semantic_hash,
        subject.analysis_projection_hash,
        dependency.model().categories.clone(),
        dependency.model().display_name.clone(),
        None,
        violation,
        vec![TypestateScenarioId::try_new("test", "root").unwrap()],
        &PolicyBudget::default(),
    )
    .unwrap();
    assert!(validate_typestate_facts(&authority, facts, &PolicyBudget::default()).is_ok());
}
