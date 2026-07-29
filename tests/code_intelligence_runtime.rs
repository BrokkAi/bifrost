//! Behavior tests for the protocol-neutral code-intelligence runtime.

mod common;

use brokk_bifrost::analyzer::policy::{
    PolicyEvaluationDate, PolicyEvaluationOptions, PolicyFailOn, PolicySourceIdentity,
};
use brokk_bifrost::analyzer::structural::CodeQuery;
use brokk_bifrost::code_intelligence::CodeIntelligenceRuntime;
use brokk_bifrost::{AnalyzerConfig, Language, WorkspaceAnalyzer};
use common::InlineTestProject;
use serde_json::json;

const DYNAMIC_EVAL_POLICY: &str = include_str!("fixtures/policies/dynamic-eval.rqlp");

#[test]
fn runtime_executes_structural_queries_and_live_policy_sources() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "src/app.py",
            "def run(user_code):\n    return eval(user_code)\n",
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let runtime = CodeIntelligenceRuntime::new(&workspace, None);

    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "eval" } }
    }))
    .expect("query should parse");
    assert_eq!(
        runtime
            .execute_query(&query, Default::default())
            .result()
            .expect("ordinary query result")
            .structural_matches()
            .len(),
        1
    );

    let outcome = runtime
        .evaluate_policy_source(
            project.root(),
            PolicySourceIdentity::new("runtime-dynamic-eval.rqlp"),
            DYNAMIC_EVAL_POLICY,
            &PolicyEvaluationOptions::new(
                PolicyEvaluationDate::from_ymd(2026, 7, 27).expect("fixed evaluation date"),
            )
            .with_fail_on(PolicyFailOn::Warning),
        )
        .expect("policy evaluation should succeed");
    assert_eq!(outcome.exit_status(), 1, "dynamic eval should be reported");
}
