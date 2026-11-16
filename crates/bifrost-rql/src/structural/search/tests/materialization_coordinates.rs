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

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7237: line-only enclosing lookup gave a same-line member or sibling its class symbol"
)]
fn same_line_members_and_siblings_keep_innermost_enclosing_symbols() {
    let one_line = concat!(
        "abstract class OneLine { ",
        "final int number = helper(1); ",
        "abstract void abstractMember(); ",
        "int first() { return helper(2); } ",
        "int second() { return helper(3); } ",
        "}\n",
    );
    let source = format!(
        "{one_line}class MultiLine {{\n    int number = helper(4);\n    int compute() {{\n        return helper(5);\n    }}\n    int helper(int v) {{\n        return v;\n    }}\n}}\n"
    );
    let project = InlineTestProject::with_language(Language::Java)
        .file("Sample.java", &source)
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());

    let extract_matches = |result: CodeQueryResult| -> Vec<CodeQueryMatch> {
        result
            .results
            .into_iter()
            .map(|row| match row.value {
                CodeQueryResultValue::StructuralMatch { value } => value,
                other => panic!("expected structural match, got {other:?}"),
            })
            .collect()
    };

    // Single query spanning a same-line field, two same-line sibling methods,
    // and ordinary multiline declarations.
    let call_query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "helper" } },
        "result_detail": "full"
    }))
    .unwrap();
    let calls = extract_matches(execute(&analyzer, &call_query));
    assert_eq!(calls.len(), 5, "{calls:#?}");
    let call_summary: Vec<_> = calls
        .iter()
        .map(|m| {
            let nr = m.node_range.as_ref().expect("full detail node_range");
            (
                m.text.as_str(),
                m.start_line,
                m.end_line,
                nr.start_column,
                nr.end_column,
                m.enclosing_symbol.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        call_summary,
        vec![
            ("helper(1)", 1, 1, 45, 54, Some("OneLine.number")),
            ("helper(2)", 1, 1, 109, 118, Some("OneLine.first")),
            ("helper(3)", 1, 1, 144, 153, Some("OneLine.second")),
            ("helper(4)", 3, 3, 18, 27, Some("MultiLine.number")),
            ("helper(5)", 5, 5, 16, 25, Some("MultiLine.compute")),
        ]
    );

    // Modifier query checks class-wide match alongside same-line abstract method.
    let abstract_query = CodeQuery::from_json(&json!({
        "match": { "kind": "declaration", "modifier": "abstract" },
        "result_detail": "full"
    }))
    .unwrap();
    let abstract_matches = extract_matches(execute(&analyzer, &abstract_query));
    let abstract_summary: Vec<_> = abstract_matches
        .iter()
        .map(|m| (m.kind, m.start_line, m.enclosing_symbol.as_deref()))
        .collect();
    assert_eq!(
        abstract_summary,
        vec![
            ("class", 1, Some("OneLine")),
            ("method", 1, Some("OneLine.abstractMember")),
        ],
        "{abstract_matches:#?}"
    );

    let field_query = CodeQuery::from_json(&json!({
        "match": { "kind": "assignment" },
        "result_detail": "full"
    }))
    .unwrap();
    let field_matches = extract_matches(execute(&analyzer, &field_query));
    let field_summary: Vec<_> = field_matches
        .iter()
        .map(|m| (m.kind, m.start_line, m.enclosing_symbol.as_deref()))
        .collect();
    assert_eq!(
        field_summary,
        vec![
            ("assignment", 1, Some("OneLine.number")),
            ("assignment", 3, Some("MultiLine.number")),
        ],
        "{field_matches:#?}"
    );

    // Class-wide matches preserve the enclosing class symbol.
    let class_query = CodeQuery::from_json(&json!({
        "match": { "kind": "class" },
        "result_detail": "full"
    }))
    .unwrap();
    let class_matches = extract_matches(execute(&analyzer, &class_query));
    let class_summary: Vec<_> = class_matches
        .iter()
        .map(|m| (m.start_line, m.enclosing_symbol.as_deref()))
        .collect();
    assert_eq!(
        class_summary,
        vec![(1, Some("OneLine")), (2, Some("MultiLine"))],
        "{class_matches:#?}"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#7237: enclosing-unit memo must key by byte range without losing read attribution"
)]
fn enclosing_unit_memo_keeps_same_line_entries_distinct_and_preserves_read_attribution() {
    let source = concat!(
        "class OneLine { ",
        "int number = helper(1); ",
        "int first() { return helper(2); } ",
        "int second() { return helper(3); } ",
        "static int helper(int v) { return v; } ",
        "}\n",
    );
    let project = InlineTestProject::with_language(Language::Java)
        .file("OneLine.java", source)
        .build();
    let analyzer = JavaAnalyzer::from_project(project.project().clone());
    let file = ProjectFile::new(project.root().to_path_buf(), PathBuf::from("OneLine.java"));
    let span_of = |needle: &str| {
        let start = source.find(needle).expect("needle present in fixture");
        (start, start + needle.len())
    };
    let (field_start, field_end) = span_of("helper(1)");
    let (first_start, first_end) = span_of("helper(2)");
    let (second_start, second_end) = span_of("helper(3)");
    let (class_start, class_end) = span_of("class OneLine");

    let mut cache = PipelineRenderCache::default();
    let (field_unit, field_reads) = crate::analyzer::capture_query_reads(&analyzer, || {
        cache.enclosing_unit_for_bytes(&analyzer, &file, field_start, field_end)
    });
    assert_eq!(
        field_unit.as_ref().map(|u| u.fq_name()),
        Some("OneLine.number".to_owned())
    );
    assert!(
        field_reads.keys().iter().any(|key| matches!(
            key,
            crate::analyzer::ReadKey::File { rel_path, .. } if rel_path.as_ref() == "OneLine.java"
        )),
        "expected file read attribution for OneLine.java: {:?}",
        field_reads.keys()
    );

    let (first_unit, first_reads) = crate::analyzer::capture_query_reads(&analyzer, || {
        cache.enclosing_unit_for_bytes(&analyzer, &file, first_start, first_end)
    });
    assert_eq!(
        first_unit.as_ref().map(|u| u.fq_name()),
        Some("OneLine.first".to_owned())
    );
    assert_eq!(first_reads.keys(), field_reads.keys());
    assert_eq!(first_reads.digest(), field_reads.digest());

    let (second_unit, second_reads) = crate::analyzer::capture_query_reads(&analyzer, || {
        cache.enclosing_unit_for_bytes(&analyzer, &file, second_start, second_end)
    });
    assert_eq!(
        second_unit.as_ref().map(|u| u.fq_name()),
        Some("OneLine.second".to_owned())
    );
    assert_eq!(second_reads.keys(), field_reads.keys());
    assert_eq!(second_reads.digest(), field_reads.digest());

    // Exact byte-span memo hit still replays read attribution.
    let (hit_unit, hit_reads) = crate::analyzer::capture_query_reads(&analyzer, || {
        cache.enclosing_unit_for_bytes(&analyzer, &file, first_start, first_end)
    });
    assert_eq!(
        hit_unit.as_ref().map(|u| u.fq_name()),
        Some("OneLine.first".to_owned())
    );
    assert_eq!(hit_reads.keys(), field_reads.keys());
    assert_eq!(hit_reads.digest(), field_reads.digest());

    let (class_unit, class_reads) = crate::analyzer::capture_query_reads(&analyzer, || {
        cache.enclosing_unit_for_bytes(&analyzer, &file, class_start, class_end)
    });
    assert_eq!(
        class_unit.as_ref().map(|u| u.fq_name()),
        Some("OneLine".to_owned())
    );
    assert_eq!(class_reads.keys(), field_reads.keys());
    assert_eq!(class_reads.digest(), field_reads.digest());
}
