use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryDiagnosticCode, CodeQueryExecutionLimits, CodeQueryResponse,
    CodeQueryResult, execute, execute_with_limits, execute_workspace, execute_workspace_request,
};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use serde_json::{Value, json};

fn run(files: &[(&str, &str)], query: Value) -> CodeQueryResult {
    let mut project = InlineTestProject::new();
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&query).expect("query should parse");
    execute_workspace(&workspace, &query)
}

fn serialized(result: &CodeQueryResult) -> Value {
    serde_json::to_value(result).expect("query result should serialize")
}

fn result_fq_names(value: &Value) -> Vec<String> {
    value["results"]
        .as_array()
        .expect("results array")
        .iter()
        .map(|result| {
            result["fq_name"]
                .as_str()
                .expect("declaration fq_name")
                .to_string()
        })
        .collect()
}

mod calls_and_references;
mod composition;
mod receivers;
mod semantic;
mod structural_relations;
