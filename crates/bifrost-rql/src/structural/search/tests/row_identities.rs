use super::*;

#[test]
fn separate_member_sites_have_distinct_public_identities() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", "class Service { run() {} }\nexport function caller(service: Service) { service.run(); service.missing(); }\n")
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({
        "occurrences": {"role": ["member_position"]},
        "steps": [{"op": "member_selection"}],
        "result_detail": "full"
    }))
    .unwrap();
    let result = execute(&analyzer, &query);
    assert_eq!(result.results.len(), 2, "{result:?}");
    let rows: Vec<_> = result
        .results
        .iter()
        .map(|row| {
            let CodeQueryResultValue::MemberSelection { value } = &row.value else {
                panic!("expected member selection: {row:?}");
            };
            value
        })
        .collect();
    assert_ne!(rows[0].site_ast_id, rows[1].site_ast_id);
    assert_ne!(rows[0].id, rows[1].id);
    assert!(
        rows.iter()
            .any(|row| row.member == "run" && row.selected_count > 0)
    );
    assert!(
        rows.iter()
            .any(|row| row.member == "missing" && row.selected_count == 0)
    );
}

fn unavailable_runtime_read() -> CodeQueryResult {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("app.js", "function run() { return process.env.INPUT; }\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "field_access"},
        "steps": [{"op": "keyed_read_value", "runtime": "node", "global": "process", "container": "env", "property": "INPUT", "source_origin": "pristine_input"}],
        "result_detail": "full"
    })).unwrap();
    execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    )
}

#[test]
fn unavailable_runtime_read_keeps_unknown_key_kind() {
    let result = unavailable_runtime_read();
    let rows = serde_json::to_value(&result).unwrap();
    let rows = rows["results"].as_array().unwrap();
    assert!(!rows.is_empty(), "{result:?}");
    for row in rows {
        assert_eq!(row["key_kind"], "unknown", "{row}");
        assert_eq!(row["outcome"], "incomplete", "{row}");
    }
    assert!(!result.diagnostics.is_empty(), "{result:?}");
}

#[test]
fn unavailable_runtime_read_keeps_indeterminate_origin() {
    let result = unavailable_runtime_read();
    let rows = serde_json::to_value(&result).unwrap();
    let rows = rows["results"].as_array().unwrap();
    assert!(!rows.is_empty(), "{result:?}");
    for row in rows {
        assert_eq!(row["source_origin"], "indeterminate", "{row}");
    }
}

#[test]
fn field_write_rhs_identity_joins_to_the_input_occurrence() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", "class Box { value = \"\"; }\nexport function write(input: string) { const box = new Box(); box.value = input; }\n")
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "assignment", "left": {"kind": "field_access", "capture": "target", "name": "value"}, "right": {"capture": "rhs"}},
        "steps": [{"op": "member_targets", "capture": "target"}, {"op": "field_write_value"}],
        "result_detail": "full"
    })).unwrap();
    let writes = execute(&analyzer, &query);
    assert_eq!(writes.results.len(), 1, "{writes:?}");
    let CodeQueryResultValue::FieldWriteValue { value: write } = &writes.results[0].value else {
        panic!("expected field-write row: {writes:?}");
    };
    let reads = execute(
        &analyzer,
        &CodeQuery::from_source("(occurrences :role [value_reference])").unwrap(),
    );
    let inputs: Vec<_> = reads
        .results
        .iter()
        .filter_map(|row| match &row.value {
            CodeQueryResultValue::Occurrence { value } if value.raw_spelling == "input" => {
                Some(value)
            }
            _ => None,
        })
        .collect();
    assert_eq!(inputs.len(), 1, "{reads:?}");
    assert_eq!(write.rhs_ast_id, inputs[0].ast_id);
}
