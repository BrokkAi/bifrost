use super::navigation::{SearchSymbolHit, SearchSymbolsResult};

#[test]
fn search_symbols_schema_describes_overlay_json_shapes() {
    let result_schema = serde_json::to_value(schemars::schema_for!(SearchSymbolsResult)).unwrap();
    assert_eq!(
        result_schema["properties"]["model_symbols"]["type"], "array",
        "{result_schema}"
    );
    assert_eq!(
        result_schema["properties"]["model_symbols"]["items"]["type"], "object",
        "{result_schema}"
    );

    let hit_schema = serde_json::to_value(schemars::schema_for!(SearchSymbolHit)).unwrap();
    assert_eq!(
        hit_schema["properties"]["semantic_model"]["type"], "object",
        "{hit_schema}"
    );
}
