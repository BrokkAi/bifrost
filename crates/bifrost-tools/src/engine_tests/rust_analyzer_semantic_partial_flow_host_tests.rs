#[cfg(test)]
mod rust_departing_host_tests_tests {
    use brokk_bifrost_analysis::analyzer::semantic::ValueFlowOracle;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::limits::OracleLimits;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::OracleCallContext;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::value_flow::ValueFlowRelationKind;
    use brokk_bifrost_analysis::analyzer::semantic::partial_flow::FileLocalProjectionHost;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticBudget;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::value_flow::project_procedure_relations;
    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_core::cancellation::CancellationToken;
    /// Where no store asks the heap oracle, the file-local host projects the
    /// same relations as the workspace oracle.
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
    let pair = (c, a);
    pair.0
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
}
