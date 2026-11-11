#[cfg(test)]
mod rust_departing_host_tests_tests {
    use brokk_bifrost_analysis::analyzer::semantic::ValueFlowOracle;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::limits::OracleLimits;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::OracleCallContext;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::value_flow::ValueFlowRelationKind;
    use brokk_bifrost_analysis::analyzer::semantic::partial_flow::FileLocalProjectionHost;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticBudget;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::project_procedure_relations;
    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_core::cancellation::CancellationToken;
    /// Where no store asks the heap oracle, the file-local host projects the
    /// same relations as the workspace oracle. A tuple, range or struct
    /// expression stores its members, so the fixture builds none.
    #[test]
    fn file_local_host_projects_the_workspace_relations_without_stores() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "src/lib.rs",
                r#"fn helper(x: i32) -> i32 {
    x
}

fn run(a: i32, flag: bool) -> i32 {
    let b = a;
    let c = if flag { helper(b) } else { b };
    let d = if flag { c } else { a };
    d
}
"#,
            )
            .build();
        let file = project.file("src/lib.rs");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("semantic materialization runs")
            .available_value()
            .cloned()
            .expect("the semantic artifact is available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|candidate| {
                candidate
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("run")
            })
            .and_then(|candidate| artifact.procedure_handle(candidate.id()))
            .expect("run is lowered");
        let context = OracleCallContext::empty();

        let oracle = WorkspaceSemanticOracle::new(&analyzer);
        let mut workspace_budget = SemanticBudget::default();
        let workspace = oracle
            .procedure_relations(
                &procedure,
                &context,
                &mut SemanticRequest::new(&mut workspace_budget, &cancellation),
            )
            .expect("workspace projection runs");
        let mut file_budget = SemanticBudget::default();
        let file_local = project_procedure_relations(
            &FileLocalProjectionHost { syntax: None },
            &procedure,
            &context,
            OracleLimits::default(),
            &mut SemanticRequest::new(&mut file_budget, &cancellation),
        )
        .expect("file-local projection runs");

        let workspace = workspace
            .available_value()
            .expect("workspace projection keeps its snapshot")
            .relations();
        let file_local = file_local
            .available_value()
            .expect("file-local projection keeps its snapshot")
            .relations();
        assert!(
            !workspace.is_empty()
                && workspace
                    .iter()
                    .all(|relation| relation.kind != ValueFlowRelationKind::MemoryStore),
            "the fixture projects relations and no store: {workspace:#?}"
        );
        // A relation handle compares by arena identity, and each projection
        // builds its own arena, so compare the record ids instead.
        let comparable = |relations: &[brokk_bifrost_analysis::analyzer::semantic::oracle::value_flow::ValueFlowRelation]| {
            relations
                .iter()
                .map(|relation| {
                    let mut relation = relation.clone();
                    let id = relation.id.id();
                    relation.id = workspace[0].id.clone();
                    (id, relation)
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(comparable(workspace), comparable(file_local));
    }

    /// The #9766 guard leaves the stored member of a returned join untransported.
    /// That is a content gap: coverage Open (published as Unknown), with no
    /// execution marker, the same from the workspace oracle and from the
    /// file-local host, and the same under a small but sufficient set of limits.
    /// Truncated is reserved for a real capacity cut.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10466: a rejected return member was typed as a budget truncation"
    )]
    fn rejected_return_member_snapshot_is_open_content_under_any_sufficient_limit() {
        use brokk_bifrost_analysis::analyzer::semantic::CandidateCoverage;

        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "src/lib.rs",
                "pub enum Reasons { Complete, Incomplete { reasons: u32 } }\n\
                 pub fn joined(empty: bool, reasons: u32) -> Reasons {\n    \
                     if empty { Reasons::Complete } else { Reasons::Incomplete { reasons } }\n}\n",
            )
            .build();
        let file = project.file("src/lib.rs");
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("semantic materialization runs")
            .available_value()
            .cloned()
            .expect("the semantic artifact is available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|candidate| {
                candidate
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("joined")
            })
            .and_then(|candidate| artifact.procedure_handle(candidate.id()))
            .expect("joined is lowered");
        let context = OracleCallContext::empty();

        let mut small = OracleLimits::default().values();
        small.provenance_records = 64;
        small.evidence_handles = 64;
        small.access_path_length = 4;
        let small = OracleLimits::new(small).expect("small limits are valid");

        let mut budget = SemanticBudget::default();
        let workspace = WorkspaceSemanticOracle::new(&analyzer)
            .procedure_relations(
                &procedure,
                &context,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("workspace projection runs");
        let mut answers = vec![("workspace", workspace)];
        for (name, limits) in [("default", OracleLimits::default()), ("small", small)] {
            let mut budget = SemanticBudget::default();
            answers.push((
                name,
                project_procedure_relations(
                    &FileLocalProjectionHost { syntax: None },
                    &procedure,
                    &context,
                    limits,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("file-local projection runs"),
            ));
        }
        for (name, outcome) in &answers {
            assert!(
                matches!(outcome, SemanticOutcome::Unknown { .. }),
                "{name}: {outcome:#?}"
            );
            let snapshot = outcome
                .available_value()
                .unwrap_or_else(|| panic!("{name}: the unknown answer keeps its snapshot"));
            assert_eq!(snapshot.coverage(), CandidateCoverage::Open, "{name}");
            assert!(
                !snapshot.is_execution_dependent(),
                "{name}: a content gap carries no execution marker"
            );
            assert!(
                snapshot.relations_may_be_missing(),
                "{name}: the untransported member is recorded on the snapshot"
            );
            assert_eq!(
                snapshot.relations().len(),
                answers[0].1.available_value().unwrap().relations().len(),
                "{name}: the same relations are published"
            );
        }
    }
}
