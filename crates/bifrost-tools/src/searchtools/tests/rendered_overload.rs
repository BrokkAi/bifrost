use super::*;

#[test]
fn overloaded_search_names_candidate_total_before_ranking_cap() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let analyzer = CountingAnalyzer::new(root.clone(), &["src/Widget.java"])
        .with_search_definitions(widget_declarations(&root, 5));

    let result = search_symbols_with_cap(&analyzer, widget_search_params(100), 3, None);
    let text = result.render_text(RenderOptions::default());

    assert!(
        text.contains("5 symbols matched, over the 3 this search will rank"),
        "{text}"
    );
    assert!(!text.contains("## src/Widget.java"), "{text}");
}
