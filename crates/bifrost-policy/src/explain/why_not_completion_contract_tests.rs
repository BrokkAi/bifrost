use super::*;

#[test]
fn an_incomplete_selector_stage_names_its_completion() {
    let fixture = Fixture::new();
    let budget = PolicyBudget::builder()
        .with_query_limits(CodeQueryExecutionLimits {
            max_scanned_source_bytes: 1,
            ..CodeQueryExecutionLimits::default()
        })
        .unwrap()
        .build()
        .unwrap();
    let nominated = candidate("Widget");
    let explanation = why_not(&fixture, LOOSE_POLICY, &nominated, &budget);
    assert!(
        matches!(explanation.subject(), ExplanationSubject::Candidate { path, .. } if path == "app.ts")
    );
    assert_eq!(explanation.outcome(), ExplanationOutcome::Unknown);
    let stage = explanation
        .root()
        .children()
        .iter()
        .find(|node| node.kind() == ExplanationNodeKind::SelectorStage)
        .unwrap();
    assert_eq!(stage.outcome(), ExplanationOutcome::Unknown);
    let completion = stage
        .children()
        .iter()
        .find(|node| node.label() == "query_completion")
        .unwrap();
    assert_eq!(completion.outcome(), ExplanationOutcome::Unknown);
    assert_eq!(completion.actual(), Some("incomplete"));
    assert!(!completion.reasons().is_empty());
}

#[test]
fn hierarchy_hops_keep_the_candidate_site_across_stages() {
    const SOURCE: &str = "class BaseA { run() {} }\nclass BaseB { run() {} }\nclass ChildA extends BaseA {}\nclass ChildB extends BaseB {}\nfunction caller(x: ChildA | ChildB) { x.run(); }\n";
    const POLICY: &str = r#"(policy
        :id "test.explain.hop" :name "Hop"
        :message "hop" :severity warning
        :analysis (analysis :type match :selector
            (rql (candidate-hierarchy (occurrences :role [member_position])))))"#;
    let fixture = Fixture::with_source(SOURCE);
    let offset = SOURCE.rfind("run();").unwrap() as u64;
    let nominated = ExplanationCandidate::at_offset("app.ts", offset).unwrap();
    let query = brokk_bifrost_rql::structural::CodeQuery::from_sexp(
        "(candidate-hierarchy (occurrences :role [member_position]))",
    )
    .unwrap();
    let rows = brokk_bifrost_rql::structural::execute(&fixture.analyzer, &query);
    let hops = rows
        .results
        .iter()
        .filter_map(|row| {
            if let brokk_bifrost_rql::structural::CodeQueryResultValue::CandidateHop { value } =
                &row.value
            {
                Some((value.ast_id.as_str(), value.candidate_id.as_str()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert!(
        hops.iter().any(|left| hops
            .iter()
            .any(|right| left.0 == right.0 && left.1 != right.1)),
        "the fixture must have separate candidates at one AST: {hops:?}"
    );
    let explanation = why_not(&fixture, POLICY, &nominated, &PolicyBudget::default());
    assert!(
        matches!(explanation.subject(), ExplanationSubject::Candidate { path, byte_start, .. }
        if path == "app.ts" && *byte_start == offset)
    );
    assert_eq!(
        stage_labels(&explanation),
        vec![
            ("occurrences".to_owned(), ExplanationOutcome::Satisfied),
            (
                "candidate_hierarchy".to_owned(),
                ExplanationOutcome::Satisfied
            ),
        ]
    );
    for stage in explanation.root().children() {
        assert!(
            stage
                .actual()
                .unwrap()
                .contains(&format!("bytes [{offset}, {})", offset + 3)),
            "{stage:#?}"
        );
    }
}
