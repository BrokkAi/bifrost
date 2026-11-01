use super::*;

struct TruncatedProtocolAdapter;

impl crate::projection::sealed::TypestateAdapter for TruncatedProtocolAdapter {}

impl crate::evaluator::TypestatePolicyEvaluator for TruncatedProtocolAdapter {
    fn compilation_hashes(
        &self,
        _policy: &LoadedPolicy,
        _spec: &crate::resolved::ResolvedTypestatePolicySpec,
        _context: &PolicyEvaluationContext<'_>,
        _budget: &PolicyBudget,
    ) -> Result<
        crate::projection::TypestateCompilationHashes,
        crate::evaluator::TypestateCompilationFailure,
    > {
        Ok(crate::projection::TypestateCompilationHashes::new(
            protocol_hash(),
            binding_plan_hash(),
        ))
    }

    fn evaluate_typestate(
        &self,
        _authority: &crate::projection::TypestateProjectionAuthority,
        _policy: &LoadedPolicy,
        spec: &crate::resolved::ResolvedTypestatePolicySpec,
        _context: &PolicyEvaluationContext<'_>,
        _budget: &PolicyBudget,
    ) -> crate::projection::TypestateProjectionPayload {
        let mut projected = fake_protocol_projection(
            spec,
            FakeProtocol {
                error_transition: false,
                witness: false,
            },
        );
        projected.report.related_truncated = true;
        projected.report.omitted_related_locations_lower_bound = 1;
        crate::projection::TypestateProjectionPayload {
            projections: vec![projected],
            completion: PolicyRunCompletion::Complete,
            diagnostics: Vec::new(),
            diagnostics_truncated: false,
            work: crate::finding::PolicyWorkReport::default(),
        }
    }
}

#[test]
fn typestate_explanation_reports_a_single_cut_child_family() {
    let fixture = Fixture::new();
    let registry = registry(TYPESTATE_POLICY);
    let policy = registry.policies().next().expect("one policy");
    let run = DefaultPolicyEvaluator::new()
        .with_typestate(&TruncatedProtocolAdapter)
        .evaluate(policy, &fixture.context(), &mut PolicyBudget::default())
        .expect("evaluate typestate policy");
    let finding = &run.findings()[0];
    assert!(finding.related_truncated());
    assert!(!finding.witnesses_truncated());
    let explanation = explain_finding(&run, &finding.id(), &ExplanationLimits::default())
        .expect("explain truncated related locations");
    assert!(explanation.root().children_truncated());
    assert!(explanation.root().omitted_children_lower_bound() >= 1);
}

#[test]
fn typestate_explanation_keeps_the_related_source_location() {
    let fixture = Fixture::new();
    let run = protocol_run(
        &fixture,
        FakeProtocol {
            error_transition: false,
            witness: true,
        },
    );
    let finding = &run.findings()[0];
    let explanation = explain_finding(&run, &finding.id(), &ExplanationLimits::default())
        .expect("explain retained typestate finding");
    let related = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.label() == "source_row")
        .expect("retained acquisition site");
    assert_eq!(related.kind(), ExplanationNodeKind::SourceFact);
    assert_eq!(related.location(), Some(finding.related()[0].location()));
}

#[test]
fn typestate_explanation_preserves_transition_direction() {
    use crate::definition::{TypestateEventId, TypestateStateId};
    use crate::future_evidence::{
        TypestateFindingAnchor, TypestateFindingEvidence, TypestateViolationEvidence,
    };

    let fixture = Fixture::new();
    let run = protocol_run(
        &fixture,
        FakeProtocol {
            error_transition: true,
            witness: false,
        },
    );
    let finding = &run.findings()[0];
    let PolicyFindingEvidence::Typestate { evidence } = finding.evidence() else {
        panic!("typestate evidence");
    };
    let violation = TypestateViolationEvidence::error_transition(
        TypestateEventId::new("fail").expect("event id"),
        Some(evidence.source_endpoint().clone()),
        TypestateStateId::new("open").expect("from state"),
        TypestateStateId::new("violated").expect("to state"),
    );
    let strong = evidence.anchor().strong_fields().expect("strong anchor");
    let anchor = TypestateFindingAnchor::strong(
        evidence.protocol_hash(),
        strong.subject_identity().clone(),
        strong.violation_site_identity().clone(),
        evidence.scenario_set_hash(),
        &violation,
    )
    .expect("endpoint transition anchor");
    let endpoint_evidence = TypestateFindingEvidence::try_new(
        evidence.analysis_finding_id().clone(),
        anchor,
        evidence.protocol_hash(),
        evidence.binding_plan_hash(),
        evidence.subject().clone(),
        evidence.source_endpoint().clone(),
        evidence.violation_site().cloned(),
        violation,
        evidence.scenario_ids().to_vec(),
        evidence.scenarios_truncated(),
        evidence.omitted_scenarios_lower_bound(),
        evidence.scenario_set_hash(),
        evidence.witness_refs().to_vec(),
        evidence.witness_refs_truncated(),
        evidence.projection_facts_hash(),
        &PolicyBudget::default(),
    )
    .expect("valid endpoint transition evidence");
    let explanation = super::super::why_typestate::explain_typestate_finding(
        &run,
        finding,
        &endpoint_evidence,
        &ExplanationLimits::default(),
    )
    .expect("explain endpoint transition");
    let transition = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.label() == "error_transition")
        .expect("retained transition");
    assert_eq!(transition.kind(), ExplanationNodeKind::Assertion);
    assert_eq!(transition.outcome(), ExplanationOutcome::Failed);
    let actual = transition.actual().expect("retained transition states");
    assert!(actual.contains(" at endpoint `"), "{actual}");
    assert!(
        actual.contains("moved the subject from `open` to `violated`"),
        "{actual}"
    );
}

#[test]
fn typestate_explanation_marks_a_cut_scenario_set_unknown() {
    use crate::future_evidence::TypestateFindingEvidence;

    let fixture = Fixture::new();
    let run = protocol_run(
        &fixture,
        FakeProtocol {
            error_transition: true,
            witness: false,
        },
    );
    let finding = &run.findings()[0];
    let PolicyFindingEvidence::Typestate { evidence } = finding.evidence() else {
        panic!("typestate finding evidence");
    };
    // The retained scenario is one of three; its original set hash and
    // anchor still identify the complete scenario set.
    let cut = TypestateFindingEvidence::try_new(
        evidence.analysis_finding_id().clone(),
        evidence.anchor().clone(),
        evidence.protocol_hash(),
        evidence.binding_plan_hash(),
        evidence.subject().clone(),
        evidence.source_endpoint().clone(),
        evidence.violation_site().cloned(),
        evidence.violation().clone(),
        evidence.scenario_ids().to_vec(),
        true,
        2,
        evidence.scenario_set_hash(),
        evidence.witness_refs().to_vec(),
        evidence.witness_refs_truncated(),
        evidence.projection_facts_hash(),
        &PolicyBudget::default(),
    )
    .expect("valid retained scenario subset");
    let explanation = super::super::why_typestate::explain_typestate_finding(
        &run,
        finding,
        &cut,
        &ExplanationLimits::default(),
    )
    .expect("explain cut evidence");
    let scenarios = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.label() == "protocol_scenarios")
        .expect("scenario obligation");
    assert_eq!(scenarios.outcome(), ExplanationOutcome::Unknown);
    assert_eq!(
        scenarios.actual(),
        Some("1 retained scenario(s): test:root; at least 2 scenario(s) omitted")
    );
}

#[test]
fn typestate_terminal_names_before_call_and_alternative_states() {
    use crate::definition::{EndpointObservationPhase, TypestateExpectationId, TypestateStateId};
    use crate::future_evidence::{
        ResolvedTypestateTerminal, TypestateFindingAnchor, TypestateFindingEvidence,
        TypestateViolationEvidence,
    };

    let fixture = Fixture::new();
    let run = protocol_run(
        &fixture,
        FakeProtocol {
            error_transition: false,
            witness: false,
        },
    );
    let finding = &run.findings()[0];
    let PolicyFindingEvidence::Typestate { evidence } = finding.evidence() else {
        panic!("typestate finding evidence");
    };
    let terminal = TypestateViolationEvidence::try_terminal_expectation(
        TypestateExpectationId::new("before-use").expect("expectation id"),
        ResolvedTypestateTerminal::Endpoint {
            endpoint: evidence.source_endpoint().clone(),
            phase: EndpointObservationPhase::BeforeCall,
        },
        TypestateStateId::new("violated").expect("observed state"),
        vec![
            TypestateStateId::new("closed").expect("expected state"),
            TypestateStateId::new("open").expect("expected state"),
        ],
    )
    .expect("valid terminal expectation");
    let strong = evidence
        .anchor()
        .strong_fields()
        .expect("strong protocol anchor");
    let anchor = TypestateFindingAnchor::strong(
        evidence.protocol_hash(),
        strong.subject_identity().clone(),
        strong.violation_site_identity().clone(),
        evidence.scenario_set_hash(),
        &terminal,
    )
    .expect("anchor for terminal expectation");
    let alternate = TypestateFindingEvidence::try_new(
        evidence.analysis_finding_id().clone(),
        anchor,
        evidence.protocol_hash(),
        evidence.binding_plan_hash(),
        evidence.subject().clone(),
        evidence.source_endpoint().clone(),
        evidence.violation_site().cloned(),
        terminal,
        evidence.scenario_ids().to_vec(),
        false,
        0,
        evidence.scenario_set_hash(),
        evidence.witness_refs().to_vec(),
        evidence.witness_refs_truncated(),
        evidence.projection_facts_hash(),
        &PolicyBudget::default(),
    )
    .expect("valid endpoint expectation evidence");
    let explanation = super::super::why_typestate::explain_typestate_finding(
        &run,
        finding,
        &alternate,
        &ExplanationLimits::default(),
    )
    .expect("explain endpoint expectation");
    let terminal = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.label() == "terminal_expectation")
        .expect("terminal expectation node");
    let expected = terminal.expected().expect("expected states and terminal");
    assert!(expected.contains("one of [`closed`, `open`]"), "{expected}");
    assert!(expected.contains("(before_call)"), "{expected}");
}

#[test]
fn relational_why_not_replays_a_boolean_join_key() {
    let source = "export function render(): number { return 1; }\nexport function second(): number { return 2; }\n";
    let policy = r#"(policy
      :id "test.explain.boolean-key"
      :name "Boolean key"
      :message "a declaration-only callable must have a peer"
      :severity warning
      :analysis (analysis :type assertion
        (bind :name site :query (rql (callable-signature (enclosing-decl (function :name "render")))))
        (bind :name peer :query (rql (callable-signature (enclosing-decl (function :name "second")))))
        (join :left site :right peer :kind anti :on ((declaration_only declaration_only)))
        (group :name orphaned :by (site.id) (aggregate :name sites :op count))
        (assert :group orphaned :value sites :cardinality (exactly 0))))"#;
    let fixture = Fixture::with_source(source);
    let explanation = relational_why_not(
        &fixture,
        policy,
        &candidate_in(source, "render"),
        &ExplanationLimits::default(),
    );
    assert_eq!(
        explanation.outcome(),
        ExplanationOutcome::Failed,
        "{explanation:#?}"
    );
    let join = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.label() == "anti_join")
        .expect("anti join replay");
    assert_eq!(
        join.outcome(),
        ExplanationOutcome::Satisfied,
        "{explanation:#?}"
    );
}
