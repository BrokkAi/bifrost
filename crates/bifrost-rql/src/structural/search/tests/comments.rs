use super::*;
use brokk_bifrost_test_macros::hardwon;

#[test]
fn comment_facts_publish_exact_spans_across_mapped_languages() {
    let fixtures = [
        (
            Language::Cpp,
            "cpp",
            "sample.cpp",
            "// lane marker\n/* block lane marker */\nint value = 1;\n",
            ["// lane marker", "/* block lane marker */"],
        ),
        (
            Language::CSharp,
            "csharp",
            "Sample.cs",
            "// lane marker\n/* block lane marker */\nclass Sample {}\n",
            ["// lane marker", "/* block lane marker */"],
        ),
        (
            Language::Go,
            "go",
            "sample.go",
            "// lane marker\n/* block lane marker */\npackage sample\n",
            ["// lane marker", "/* block lane marker */"],
        ),
        (
            Language::Java,
            "java",
            "Sample.java",
            "// lane marker\n/* block lane marker */\nclass Sample {}\n",
            ["// lane marker", "/* block lane marker */"],
        ),
        (
            Language::JavaScript,
            "javascript",
            "sample.js",
            "// lane marker\n/* block lane marker */\nconst value = 1;\n",
            ["// lane marker", "/* block lane marker */"],
        ),
        (
            Language::Kotlin,
            "kotlin",
            "Sample.kt",
            "// lane marker\n/* block lane marker */\nfun sample() {}\n",
            ["// lane marker", "/* block lane marker */"],
        ),
        (
            Language::Php,
            "php",
            "sample.php",
            "<?php // lane marker\n/* block lane marker */\n$value = 1;\n",
            ["// lane marker", "/* block lane marker */"],
        ),
        (
            Language::Python,
            "python",
            "sample.py",
            "# lane marker\n# block lane marker\nvalue = 1\n",
            ["# lane marker", "# block lane marker"],
        ),
        (
            Language::Ruby,
            "ruby",
            "sample.rb",
            "# lane marker\n# block lane marker\nvalue = 1\n",
            ["# lane marker", "# block lane marker"],
        ),
        (
            Language::Rust,
            "rust",
            "src/lib.rs",
            "// lane marker\n/* block lane marker */\npub fn sample() {}\n",
            ["// lane marker", "/* block lane marker */"],
        ),
        (
            Language::Scala,
            "scala",
            "Sample.scala",
            "// lane marker\n/* block lane marker */\nobject Sample {}\n",
            ["// lane marker", "/* block lane marker */"],
        ),
        (
            Language::TypeScript,
            "typescript",
            "sample.ts",
            "// lane marker\n/* block lane marker */\nconst value = 1;\n",
            ["// lane marker", "/* block lane marker */"],
        ),
    ];

    for (language, tag, path, source, expected_texts) in fixtures {
        let project = InlineTestProject::with_language(language)
            .file(path, source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let query =
            CodeQuery::from_source(&format!("(result-detail full (language {tag} (comment)))"))
                .unwrap_or_else(|error| panic!("{language:?}: {error}"));
        let detailed = execute_code_query_with_access_mode(
            workspace.analyzer(),
            &query,
            CodeQueryExecutionLimits::default(),
            StructuralAccessMode::ScanOnly,
            false,
        )
        .unwrap_or_else(|error| panic!("{language:?}: {error}"));
        let result = &detailed.result;
        assert_eq!(
            result.results.len(),
            expected_texts.len(),
            "{language:?}: {}",
            result.render_text()
        );
        for (index, (result, expected_text)) in
            result.results.iter().zip(expected_texts).enumerate()
        {
            let CodeQueryResultValue::StructuralMatch { value } = &result.value else {
                panic!("{language:?} must publish a structural match row");
            };
            assert_eq!(value.kind, "comment", "{language:?}");
            assert_eq!(value.start_line, index + 1, "{language:?}");
            assert_eq!(value.text, expected_text, "{language:?}");
            let evidence = detailed
                .evidence
                .iter()
                .find(|evidence| evidence.result_index == index)
                .expect("comment result has detailed evidence");
            let byte_span = evidence
                .byte_span
                .as_ref()
                .expect("comment result has exact byte span");
            assert_eq!(&source[byte_span.clone()], expected_text, "{language:?}");
        }
    }
}

#[test]
fn comment_block_regex_uses_maximal_adjacent_comments() {
    let source = "# block start\n# next line\n\n# separated block\nvalue = 1\n";
    let project = InlineTestProject::with_language(Language::Python)
        .file("sample.py", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query =
        CodeQuery::from_source(r#"(language python (comment :comment-block/regex "block start"))"#)
            .expect("comment block query");
    let result = execute_code_query_with_access_mode(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::ScanOnly,
        false,
    )
    .expect("comment block query execution")
    .result;

    assert_eq!(result.results.len(), 2, "{}", result.render_text());
    assert!(result.render_text().contains("# block start"));
    assert!(result.render_text().contains("# next line"));
    assert!(!result.render_text().contains("# separated block"));
}

#[test]
#[hardwon("#4647: blank lines and a docstring split a CodeQL comment block")]
fn python_commented_out_code_returns_source_spanned_comment_lines() {
    let source = "#if enabled:\n\n#    run_task()\nactive = True\n# This is documentation, not code.\n# It describes the example above.\nvalue = 1  # if enabled:\n";
    let project = InlineTestProject::with_language(Language::Python)
        .file("sample.py", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_source("(python-commented-out-code (language python (comment)))")
        .expect("commented-out-code query");
    let result = execute_code_query_with_access_mode(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits::default(),
        StructuralAccessMode::ScanOnly,
        false,
    )
    .expect("commented-out-code query execution")
    .result;

    let rows = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::PythonRuleFact { value } => Some(value.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1, "{}", result.render_text());
    assert_eq!(rows[0].relation, "commented_out_code_block");
    assert_eq!((rows[0].range.start_line, rows[0].range.end_line), (1, 3));
    assert_eq!(
        rows[0].comment_block_text.as_deref(),
        Some("#if enabled:\n\n#    run_task()")
    );
    assert_eq!(
        rows[0]
            .comment_block_lines
            .as_ref()
            .map(|lines| lines.iter().map(String::as_str).collect::<Vec<_>>()),
        Some(vec!["#if enabled:", "", "#    run_task()"])
    );
}
