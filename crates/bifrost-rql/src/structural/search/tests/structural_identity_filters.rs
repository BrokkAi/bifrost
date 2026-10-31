use super::*;

#[test]
fn structural_row_filters_use_the_published_row_and_ast_identities() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "main.ts",
            "function sample(left: number, right: number) { left = right; }\n",
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let seed = json!({"kind": "assignment"});
    let query = CodeQuery::from_json(&json!({"match": seed, "result_detail": "full"})).unwrap();
    let result = execute(&analyzer, &query);
    assert_eq!(result.results.len(), 1, "{result:?}");
    let wire = serde_json::to_value(&result.results[0]).unwrap();
    assert_ne!(wire["id"], wire["ast_id"], "{wire}");
    let occurrences = execute(
        &analyzer,
        &CodeQuery::from_source("(occurrences :role [value_reference])").unwrap(),
    );
    for (field, spelling) in [("left_ast_id", "left"), ("right_ast_id", "right")] {
        let occurrence = occurrences
            .results
            .iter()
            .find_map(|item| match &item.value {
                CodeQueryResultValue::Occurrence { value } if value.raw_spelling == spelling => {
                    Some(value)
                }
                _ => None,
            })
            .expect("authored operand occurrence");
        let filtered = CodeQuery::from_json(&json!({
            "match": seed, "result_detail": "full",
            "steps": [{"op": "filter", "where": [{
                "field": field, "op": "eq", "value": {"string": occurrence.ast_id}
            }]}]
        }))
        .unwrap();
        assert_eq!(execute(&analyzer, &filtered).results.len(), 1, "{field}");
    }
    for field in ["id", "ast_id"] {
        let filtered = CodeQuery::from_json(&json!({
            "match": seed, "result_detail": "full",
            "steps": [{"op": "filter", "where": [{
                "field": field, "op": "eq", "value": {"string": wire[field]}
            }]}]
        }))
        .unwrap();
        let selected = execute(&analyzer, &filtered);
        assert_eq!(selected.results.len(), 1, "{field}: {selected:?}");
    }
}
