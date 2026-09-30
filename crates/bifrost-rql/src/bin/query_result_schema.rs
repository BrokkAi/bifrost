fn main() {
    let schema = brokk_bifrost_rql::code_query_result_json_schema();
    println!(
        "{}",
        serde_json::to_string_pretty(&schema).expect("a generated JSON Schema is serializable")
    );
}
