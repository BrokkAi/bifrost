use brokk_bifrost::analyzer::structural::{
    CodeQueryControlEdge, CodeQueryProcedure, CodeQueryProgramPoint, CodeQueryProgramPointBoundary,
    CodeQueryProgramPointRef, CodeQueryRange, CodeQuerySemanticCompleteness,
    CodeQuerySemanticEvidence, CodeQuerySemanticProof,
};
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

#[test]
fn public_semantic_result_contracts_are_constructible_without_dense_ids() {
    let range = CodeQueryRange {
        start_line: 1,
        start_column: 1,
        end_line: 1,
        end_column: 9,
    };
    let evidence = CodeQuerySemanticEvidence {
        proof: CodeQuerySemanticProof::Proven,
        proof_reason: None,
        completeness: CodeQuerySemanticCompleteness::Complete,
        completeness_reason: None,
    };
    let procedure = CodeQueryProcedure {
        id: "11".repeat(32),
        artifact_id: "aa".repeat(32),
        path: "src/app.ts".to_string(),
        language: "typescript",
        procedure_kind: "function",
        range,
        evidence: evidence.clone(),
    };
    let point_ref = CodeQueryProgramPointRef {
        id: "22".repeat(32),
        procedure_id: procedure.id.clone(),
        path: procedure.path.clone(),
        range,
        boundary: Some(CodeQueryProgramPointBoundary::Entry),
    };
    let point = CodeQueryProgramPoint {
        id: point_ref.id.clone(),
        procedure_id: procedure.id.clone(),
        path: procedure.path.clone(),
        language: procedure.language,
        range,
        boundary: point_ref.boundary,
        event_count: 1,
        evidence: evidence.clone(),
    };
    let edge = CodeQueryControlEdge {
        id: "33".repeat(32),
        procedure_id: procedure.id.clone(),
        path: procedure.path.clone(),
        language: procedure.language,
        range,
        edge_kind: "normal",
        source: point_ref.clone(),
        target: point_ref,
        evidence,
    };

    for value in [
        serde_json::to_value(procedure).unwrap(),
        serde_json::to_value(point).unwrap(),
        serde_json::to_value(edge).unwrap(),
    ] {
        assert_eq!(value["path"], "src/app.ts");
        assert_eq!(value["language"], "typescript");
        assert!(value["id"].as_str().is_some_and(|id| id.len() == 64));
        assert!(!value.to_string().contains("artifact_key"));
    }
}
