use brokk_bifrost::{
    AnalyzerConfig, CancellationToken, CodeQuery, CodeQueryExecutionLimits, CodeQueryResponse,
    Language, execute_request_with_cancellation,
};
use serde_json::json;

mod common;
use common::InlineTestProject;

#[test]
fn public_cancellable_profile_returns_cancellation_observations() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/app.ts", "class Cancelled {}\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "execution_mode": "profile",
        "match": { "kind": "class" }
    }))
    .expect("profile query");
    let cancellation = CancellationToken::default();
    cancellation.cancel();

    let CodeQueryResponse::Profile(profile) = execute_request_with_cancellation(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits::default(),
        &cancellation,
    ) else {
        panic!("a cancelled profiled request must return its public report")
    };

    assert!(profile.result.truncated);
    assert!(
        profile
            .operators
            .iter()
            .any(|operator| operator.result_cancelled)
    );
}
