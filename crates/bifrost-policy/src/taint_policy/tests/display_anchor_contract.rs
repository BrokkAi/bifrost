use super::*;
use crate::finding_identity::WitnessId;
use brokk_bifrost_analysis::analyzer::semantic::{SemanticLocator, WorkspaceRelativePath};

#[test]
fn fully_anchored_witness_wins_over_a_missing_sink_excerpt() {
    compose_rust(COMPOSED_FIELD_SOURCE, |_plan, outcome| {
        let project = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", COMPOSED_FIELD_SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        });
        let finding = &outcome.report.findings()[0];
        let origin = &finding.origins().evidence()[0];
        let witness = &origin.witnesses()[0];
        let origin_locator = origin.origin().value_flow_key().site();
        let sink_locator = finding.key().sink().site();
        let source_excerpt = crate::semantic_identity::source_excerpt(&workspace, origin_locator)
            .filter(|text| !text.trim().is_empty())
            .expect("real origin excerpt");
        let sink_excerpt = crate::semantic_identity::source_excerpt(&workspace, sink_locator)
            .filter(|text| !text.trim().is_empty())
            .expect("real sink excerpt");
        assert!(!source_excerpt.is_empty());

        let missing_sink = SemanticLocator::new(
            sink_locator.mount(),
            WorkspaceRelativePath::new("src/missing.rs").unwrap(),
            sink_locator.language(),
            sink_locator.declaration().clone(),
            sink_locator.role(),
            sink_locator.anchor(),
        );
        assert!(crate::semantic_identity::source_excerpt(&workspace, &missing_sink).is_none());
        let partial = crate::display_path::project_taint_display_candidate(
            &workspace,
            origin_locator,
            &missing_sink,
            WitnessId::try_new("test", "a").unwrap(),
            witness,
            false,
        )
        .unwrap();
        let complete = crate::display_path::project_taint_display_candidate(
            &workspace,
            origin_locator,
            sink_locator,
            WitnessId::try_new("test", "z").unwrap(),
            witness,
            false,
        )
        .unwrap();
        let selected =
            crate::display_path::select_taint_display_path([partial, complete], 0).unwrap();
        let wire = serde_json::to_value(selected).unwrap();
        let steps = wire["steps"].as_array().unwrap();
        assert_eq!(steps.last().unwrap()["label"], sink_excerpt);
    });
}
