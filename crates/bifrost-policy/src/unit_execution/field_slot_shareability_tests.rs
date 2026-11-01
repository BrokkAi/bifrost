use super::*;
use crate::inline_project::InlineTestProject;
use brokk_bifrost_analysis::FilesystemProject;

#[test]
fn refused_source_cannot_supply_reusable_field_slot_answers() {
    let refused = format!("value = {}\n", "o".repeat(17_000));
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", "import refused\nclass Client:\n    pass\n")
        .file("refused.py", refused)
        .build();
    let workspace = WorkspaceAnalyzer::build_persisted(
        Arc::new(FilesystemProject::new(project.root()).expect("project")),
        Default::default(),
    )
    .expect("persisted workspace");
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let budget = PolicyBudget::default();
    let answers = HeadFieldSlotAnswers::new(&workspace, &flow, &budget.query_limits());
    assert!(
        answers.acquire(Language::Python).is_none(),
        "a refused source must not make a partial field-slot index reusable"
    );
}
