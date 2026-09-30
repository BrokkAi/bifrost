fn main() {
    let fixtures = brokk_bifrost_rql::code_query_result_fixtures_json();
    println!(
        "{}",
        serde_json::to_string_pretty(&fixtures)
            .expect("the canonical query result fixtures are serializable")
    );
}
