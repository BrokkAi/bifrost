use super::*;

#[test]
fn reversed_candidate_range_reports_the_callers_bounds() {
    assert_eq!(
        ExplanationCandidate::in_range("app.ts", 9, 3).unwrap_err(),
        ExplainError::ReversedCandidateRange { start: 9, end: 3 },
    );
    let range = ExplanationCandidate::in_range("app.ts", 3, 9).unwrap();
    assert_eq!((range.byte_start(), range.byte_end()), (3, 9));
    assert!(row_covers_candidate(Some(&(3..9)), &range));
    assert!(!row_covers_candidate(Some(&(3..8)), &range));
    assert!(!row_covers_candidate(Some(&(4..9)), &range));
    assert!(!row_covers_candidate(
        Some(&(3..10)),
        &ExplanationCandidate::at_offset("app.ts", 10).unwrap()
    ));
}

#[test]
fn unsupported_why_not_questions_keep_the_requested_question() {
    let fixture = Fixture::new();
    let nominated = candidate("Widget");
    with_policy(TYPESTATE_POLICY, |policy| {
        let error = explain_candidate(
            policy,
            &fixture.context(),
            &nominated,
            &PolicyBudget::default(),
            &ExplanationLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ExplainError::ExplanationAdapterUnavailable {
                analysis_type: PolicyAnalysisType::Typestate,
                question: ExplanationQuestion::WhyNot,
                ..
            }
        ));
    });
    with_policy(TAINT_POLICY, |policy| {
        let error = explain_match_candidate(
            policy,
            &fixture.context(),
            &nominated,
            &PolicyBudget::default(),
            &ExplanationLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ExplainError::ExplanationAdapterUnavailable {
                analysis_type: PolicyAnalysisType::Taint,
                question: ExplanationQuestion::WhyNot,
                ..
            }
        ));
    });
}

#[test]
fn a_whole_file_row_covers_candidates_at_both_ends() {
    for range in [
        (0, 0),
        (0, 1),
        (FIXTURE.len() as u64 - 1, FIXTURE.len() as u64),
    ] {
        let candidate = ExplanationCandidate::in_range("app.ts", range.0, range.1).unwrap();
        assert!(row_covers_candidate(None, &candidate));
    }
}

#[test]
fn flow_origins_publish_all_retained_references() {
    struct OriginRefsAdapter;
    impl crate::projection::sealed::TaintAdapter for OriginRefsAdapter {}
    impl crate::evaluator::TaintPolicyEvaluator for OriginRefsAdapter {
        fn evaluate_taint(
            &self,
            _authority: &crate::projection::TaintProjectionAuthority,
            _policy: &LoadedPolicy,
            spec: &crate::resolved::ResolvedTaintPolicySpec,
            _context: &PolicyEvaluationContext<'_>,
            _budget: &PolicyBudget,
        ) -> crate::projection::TaintProjectionPayload {
            let mut projected = fake_projection(spec, FakePath::proved());
            let origin = &mut projected.pairs[0].origins[0];
            origin.evidence_refs.push(
                crate::finding_identity::EvidenceRef::try_new("test", "origin-beta").unwrap(),
            );
            crate::projection::TaintProjectionPayload {
                engine: None,
                scope: None,
                projections: vec![projected],
                completion: PolicyRunCompletion::Complete,
                diagnostics: Vec::new(),
                diagnostics_truncated: false,
                work: crate::finding::PolicyWorkReport::default(),
                authored_arm_closures: Vec::new(),
            }
        }
    }
    let fixture = Fixture::new();
    let run = with_policy(FLOW_POLICY, |policy| {
        DefaultPolicyEvaluator::new()
            .with_taint(&OriginRefsAdapter)
            .evaluate(policy, &fixture.context(), &mut PolicyBudget::default())
            .unwrap()
    });
    assert_eq!(
        run.findings().len(),
        1,
        "completion={:?} diagnostics={:?}",
        run.completion(),
        run.diagnostics()
    );
    let explanation =
        explain_finding(&run, &only_finding(&run), &ExplanationLimits::default()).unwrap();
    let actual = root_child(&explanation, "origin").actual().unwrap();
    assert!(
        actual.contains("[evidence test:origin-alpha test:origin-beta]"),
        "{actual}"
    );
}

#[test]
fn a_registered_match_endpoint_is_named_in_the_why_answer() {
    let fixture = Fixture::new();
    let catalogs =
        std::sync::Arc::new(crate::catalog::TaintCatalogRegistry::new_without_workspace(
            crate::catalog::CatalogRegistryLimits::default(),
        ));
    let mut registry = PolicyRegistry::new_without_workspace(
        catalogs,
        crate::registry::PolicyRegistryLimits::default(),
    );
    let endpoint = r#"(endpoint
        :id "specific_source" :name "Specific source" :display-name "Specific source"
        :role source :categories [input.user]
        :selector (rql (call :callee (name "alpha")))
        :binding return-value
        :taint (source-semantics :labels [untrusted])
        :supersedes [])"#;
    registry
        .register_endpoint_bytes(PolicySourceIdentity::new("source"), endpoint.as_bytes())
        .unwrap();
    let policy_source = r#"(policy
        :id "test.explain.registered-source" :name "Registered source"
        :message (generated-message :relation can-reach) :severity warning
        :analysis (analysis :type taint :mode may
            :sources (endpoint-set :include-matches [(match-endpoints :ids [specific_source])])
            :sinks (endpoint-set :entries [(sink :id store :display-name "sensitive store"
                :categories [data.sensitive] :selector (rql (name "store"))
                :dangerous-operand matched-value :accepts [untrusted])])))"#;
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("policy"),
            policy_source.as_bytes(),
        )
        .unwrap();
    let policy = registry.policies().next().unwrap();
    let run = DefaultPolicyEvaluator::new()
        .with_taint(&FakePathAdapter {
            shape: FakePath::proved(),
        })
        .evaluate(policy, &fixture.context(), &mut PolicyBudget::default())
        .unwrap();
    let explanation =
        explain_finding(&run, &only_finding(&run), &ExplanationLimits::default()).unwrap();
    assert!(
        root_child(&explanation, "taint_origin")
            .expected()
            .unwrap()
            .contains("specific_source")
    );
}

#[test]
fn a_file_row_retains_a_candidate_elsewhere_in_that_file() {
    const FILE_POLICY: &str = r#"(policy
        :id "test.explain.file" :name "File"
        :message "file selected" :severity warning
        :analysis (analysis :type match :selector
            (rql (file-of (function :name "render")))))"#;
    let fixture = Fixture::with_source(RELATIONAL_FIXTURE);
    let offset = RELATIONAL_FIXTURE.rfind("render").unwrap() as u64;
    let nominated = ExplanationCandidate::at_offset("app.ts", offset).unwrap();
    let explanation = why_not(&fixture, FILE_POLICY, &nominated, &PolicyBudget::default());
    assert!(
        matches!(explanation.subject(), ExplanationSubject::Candidate { path, byte_start, .. }
        if path == "app.ts" && *byte_start == offset)
    );
    assert_eq!(
        explanation.outcome(),
        ExplanationOutcome::Satisfied,
        "{explanation:#?}"
    );
    let file_stage = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.label() == "file_of")
        .unwrap();
    assert_eq!(file_stage.outcome(), ExplanationOutcome::Satisfied);
    assert!(
        file_stage.actual().unwrap().contains("whole-file"),
        "{file_stage:#?}"
    );
    assert!(
        file_stage.actual().unwrap().contains("retains it"),
        "{file_stage:#?}"
    );
}

#[test]
fn file_lineage_keeps_the_candidate_in_its_own_file() {
    const FILE_POLICY: &str = r#"(policy
        :id "test.explain.two-files" :name "Two files"
        :message "file selected" :severity warning
        :analysis (analysis :type match :selector
            (rql (file-of (function :name "render")))))"#;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    for name in ["a.ts", "b.ts"] {
        ProjectFile::new(root.clone(), name)
            .write(RELATIONAL_FIXTURE)
            .unwrap();
    }
    let analyzer = TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
    let fixture = Fixture {
        _temp: temp,
        analyzer,
        flow_state: brokk_bifrost_flow::FlowWorkspaceState::new(),
    };
    let offset = RELATIONAL_FIXTURE.rfind("render").unwrap() as u64;
    let nominated = ExplanationCandidate::at_offset("b.ts", offset).unwrap();
    let explanation = why_not(&fixture, FILE_POLICY, &nominated, &PolicyBudget::default());
    assert_eq!(
        explanation.outcome(),
        ExplanationOutcome::Satisfied,
        "{explanation:#?}"
    );
    assert!(
        matches!(explanation.subject(), ExplanationSubject::Candidate { path, byte_start, .. }
        if path == "b.ts" && *byte_start == offset)
    );
    assert_eq!(
        stage_labels(&explanation),
        vec![
            ("seed".to_owned(), ExplanationOutcome::Satisfied),
            ("file_of".to_owned(), ExplanationOutcome::Satisfied),
        ]
    );
}

#[test]
fn receiver_outcome_tracks_the_call_sites_exact_evidence() {
    const POLICY: &str = r#"(policy
        :id "test.explain.receiver-roles" :name "Receiver roles"
        :message "receiver" :severity warning
        :analysis (analysis :type match :selector
            (rql (receiver-outcome (occurrences :role [member_position value_reference])))))"#;
    let fixture = Fixture::with_source(MEMBER_FIXTURE);
    let offset = MEMBER_FIXTURE.rfind("run();").unwrap() as u64;
    let nominated = ExplanationCandidate::at_offset("app.ts", offset).unwrap();
    let explanation = why_not(&fixture, POLICY, &nominated, &PolicyBudget::default());
    assert!(
        matches!(explanation.subject(), ExplanationSubject::Candidate { path, byte_start, .. }
        if path == "app.ts" && *byte_start == offset)
    );
    assert_eq!(
        stage_labels(&explanation),
        vec![
            ("occurrences".to_owned(), ExplanationOutcome::Satisfied),
            ("receiver_outcome".to_owned(), ExplanationOutcome::Satisfied),
        ]
    );
    let source = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.label() == "occurrences")
        .unwrap();
    assert!(
        source
            .actual()
            .unwrap()
            .contains(&format!("bytes [{offset}, {})", offset + 3))
    );
    let receiver = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.label() == "receiver_outcome")
        .unwrap();
    assert!(
        receiver
            .actual()
            .unwrap()
            .contains("identity-preserving provenance path retains it")
    );
}

#[test]
fn candidate_hierarchy_names_the_rejected_stage_and_retained_source_row() {
    const SOURCE: &str = "class Base { run() {} }\nclass Child extends Base { run() {} }\nfunction caller(x: Base | Child) { x.run(); }\n";
    const POLICY: &str = r#"(policy
        :id "test.explain.candidate-hierarchy" :name "Candidate hierarchy"
        :message "candidate" :severity warning
        :analysis (analysis :type match :selector
            (rql (candidate-hierarchy (occurrences :role [member_position])))))"#;
    let fixture = Fixture::with_source(SOURCE);
    let offset = SOURCE.rfind("run();").unwrap() as u64;
    let nominated = ExplanationCandidate::at_offset("app.ts", offset).unwrap();
    let explanation = why_not(&fixture, POLICY, &nominated, &PolicyBudget::default());
    assert!(
        matches!(explanation.subject(), ExplanationSubject::Candidate { path, byte_start, .. }
        if path == "app.ts" && *byte_start == offset)
    );
    assert_eq!(
        stage_labels(&explanation),
        vec![
            ("occurrences".to_owned(), ExplanationOutcome::Satisfied),
            ("candidate_hierarchy".to_owned(), ExplanationOutcome::Failed),
        ]
    );
    let source = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.label() == "occurrences")
        .unwrap();
    assert!(
        source
            .actual()
            .unwrap()
            .contains(&format!("bytes [{offset}, {})", offset + 3))
    );
    let rejected = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.label() == "candidate_hierarchy")
        .unwrap();
    assert_eq!(
        rejected.actual(),
        Some("0 rows, none covering the candidate")
    );
}
