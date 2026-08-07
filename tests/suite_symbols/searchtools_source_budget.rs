use crate::common::InlineTestProject;
use brokk_bifrost::{
    CodeUnitIndex, Language, RustAnalyzer,
    searchtools::{SymbolLookupParams, get_symbol_sources_with_source_budget},
};

#[test]
fn symbol_source_budget_stops_before_cloning_an_oversized_fragment() {
    let body = (0..3_000)
        .map(|index| format!("    let value_{index} = {index};\n"))
        .collect::<String>();
    let source = format!("pub fn target() {{\n{body}}}\n");
    let project = InlineTestProject::with_language(Language::Rust)
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    let target = analyzer
        .search_definitions("target", false)
        .into_iter()
        .next()
        .expect("oversized target method")
        .fq_name();

    let error = get_symbol_sources_with_source_budget(
        &analyzer,
        SymbolLookupParams {
            symbols: vec![target],
        },
        1024,
    )
    .expect_err("oversized source must stop at the source response budget");

    assert_eq!(1024, error.max_source_bytes());
}
