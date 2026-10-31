use super::*;

#[test]
fn generation_arguments_keep_their_own_source_spans() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "sample.rb",
            "class Record\n  attr_accessor :first, :second\nend\n",
        )
        .build();
    let analyzer = RubyAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_sexp("(generation-sites :kind accessor_macro)").unwrap();
    let result = execute(&analyzer, &query);
    assert_eq!(result.results.len(), 1, "{result:#?}");
    let CodeQueryResultValue::GenerationSite { value } = &result.results[0].value else {
        panic!("generation site");
    };
    // Each symbol argument creates a field, a reader and a writer.
    assert_eq!(
        value
            .generated
            .iter()
            .map(|generated| (
                generated.fq_name.as_str(),
                generated.argument_start_byte,
                generated.argument_end_byte,
                generated.argument_range.start_line,
                generated.argument_range.start_column,
                generated.argument_range.end_line,
                generated.argument_range.end_column,
            ))
            .collect::<Vec<_>>(),
        vec![
            ("Record.@first", 29, 35, 2, 17, 2, 23),
            ("Record.first", 29, 35, 2, 17, 2, 23),
            ("Record.first=", 29, 35, 2, 17, 2, 23),
            ("Record.@second", 37, 44, 2, 25, 2, 32),
            ("Record.second", 37, 44, 2, 25, 2, 32),
            ("Record.second=", 37, 44, 2, 25, 2, 32),
        ]
    );
}

#[test]
fn authored_declaration_state_keeps_its_source_location() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("sample.py", "def target():\n    pass\n")
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "function", "name": "target"},
        "steps": [{"op": "enclosing_decl"}, {"op": "declaration_state_of"}]
    }))
    .unwrap();
    let result = execute(&analyzer, &query);
    assert_eq!(result.results.len(), 1, "{result:#?}");
    let CodeQueryResultValue::DeclarationState { value } = &result.results[0].value else {
        panic!("declaration state");
    };
    let range = value.range.as_ref().expect("authored declaration range");
    assert_eq!((range.start_line, range.start_column), (1, 1));
    assert_eq!(value.start_byte, Some(0));
}
