use super::*;
use crate::structural::search::units::{
    CodeQueryExecutionScope, UnitExecutionResult, execute_code_query_unit,
};

#[test]
fn decorated_parameter_unit_provenance_preserves_both_identities() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", "import { Query } from '@nestjs/common';\nclass Controller { method(@Query() value: string) {} }\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let flow = brokk_bifrost_flow::FlowWorkspaceState::new();
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "parameter"}, "steps": [{"op": "decorator_bindings"}],
        "result_detail": "full"
    }))
    .unwrap();
    let direct = execute_workspace(&workspace, &flow, &query);
    assert_eq!(direct.results.len(), 1, "{direct:?}");
    let CodeQueryResultValue::DecoratedParameter { value } = &direct.results[0].value else {
        panic!("{direct:?}");
    };
    assert_ne!(value.id, value.parameter_id);
    let traversed = CodeQuery::from_json(&json!({
        "match": {"kind": "parameter"},
        "steps": [{"op": "decorator_bindings"}, {"op": "file_of"}],
        "result_detail": "full"
    }))
    .unwrap();
    let unit = execute_code_query_unit(
        workspace.analyzer(),
        &flow,
        Some(&workspace),
        &traversed,
        CodeQueryExecutionLimits::default(),
        None,
        CodeQueryExecutionScope::whole_workspace(),
    );
    let decoded: UnitExecutionResult =
        serde_json::from_value(serde_json::to_value(&unit).unwrap()).unwrap();
    assert!(!decoded.rows.is_empty(), "{decoded:?}");
    let references: Vec<_> = decoded
        .rows
        .iter()
        .flat_map(|row| &row.item.provenance)
        .flat_map(|trace| &trace.steps)
        .filter_map(|step| match &step.result.value {
            crate::structural::search::units::UnitRowItemRefValue::DecoratedParameter {
                id,
                parameter_id,
                ..
            } => Some((id.as_ref(), parameter_id.as_ref())),
            _ => None,
        })
        .collect();
    assert_eq!(
        references,
        vec![(value.id.as_str(), value.parameter_id.as_str())]
    );
}
