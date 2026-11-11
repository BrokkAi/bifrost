//! Coverage of closed JavaScript/TypeScript language rules. A rule whose
//! relation cannot decide every candidate must report incomplete instead of
//! presenting its proven rows as exhaustive.

use super::*;
use brokk_bifrost_test_macros::hardwon;

#[test]
#[hardwon("#5196: unknown computed object keys reported complete coverage")]
fn overwritten_property_reports_unknown_computed_keys_incomplete() {
    let unknown_key = CodeQueryCompletion::Incomplete {
        codes: vec![CodeQueryDiagnosticCode::UnsupportedStructuralFeature],
    };
    let cases = [
        (
            "static duplicate",
            "const object = {\n  a: 1,\n  a: 2\n};\n",
            vec![2],
            CodeQueryCompletion::Complete,
        ),
        (
            "decoded computed keys join quoted keys",
            "const object = {\n  '&': 1,\n  [\"\\x26\"]: 2,\n  [`&`]: 3\n};\n",
            vec![2, 3],
            CodeQueryCompletion::Complete,
        ),
        (
            "unknown computed key alone",
            "const object = { [key]: 3 };\n",
            vec![],
            unknown_key.clone(),
        ),
        (
            "static duplicate beside an unknown computed key",
            "const object = {\n  a: 1,\n  a: 2,\n  [key]: 3,\n  [`${key}`]() {}\n};\n",
            vec![2],
            unknown_key,
        ),
    ];
    for (language, label, path) in [
        (Language::JavaScript, "javascript", "main.js"),
        (Language::TypeScript, "typescript", "main.ts"),
    ] {
        let query = CodeQuery::from_json(&json!({
            "languages": [label],
            "match": {
                "kind": "object_property",
                "language_rule": "js/overwritten-property"
            },
            "result_detail": "full"
        }))
        .expect("overwritten-property query");
        for (case, source, expected_lines, expected_completion) in &cases {
            let fixture = InlineTestProject::with_language(language)
                .file(path, *source)
                .build();
            let analyzer = language_analyzer(language, fixture.project().clone());
            let result = execute_code_query_with_access_mode(
                analyzer.as_ref(),
                &query,
                CodeQueryExecutionLimits::default(),
                StructuralAccessMode::ScanOnly,
                true,
            )
            .expect("overwritten-property query should execute")
            .result;
            assert_eq!(
                &result.completion(),
                expected_completion,
                "{label} {case}: {result:#?}"
            );
            let lines = result
                .results
                .iter()
                .map(|row| match &row.value {
                    CodeQueryResultValue::StructuralMatch { value } => value.start_line,
                    other => panic!("{label} {case}: expected a structural match: {other:#?}"),
                })
                .collect::<Vec<_>>();
            assert_eq!(&lines, expected_lines, "{label} {case}: {result:#?}");
        }
    }
}

#[test]
fn misspelled_identifier_skips_parts_the_identifier_dictionary_accepts() {
    use crate::structural::identifier_dictionary::IdentifierDictionary;
    use crate::structural::identifier_typos::IdentifierTypoTable;
    use crate::structural::search::units::{
        CodeQueryExecutionScope, execute_code_query_unit, plan_seed_files,
    };

    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "main.ts",
            "const length = 1;\nconst totalLength = length + length;\nconst lenght = 2;\n",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["typescript"],
        "match": {
            "kind": "identifier",
            "language_rule": "js/misspelled-identifier"
        },
        "result_detail": "full"
    }))
    .expect("misspelled-identifier query");
    let files = plan_seed_files(&query.plan, &workspace.analyzer().analyzed_files());
    let flow = brokk_bifrost_flow::FlowWorkspaceState::default();
    let flagged_lines = |scope: CodeQueryExecutionScope<'_>| {
        let unit = execute_code_query_unit(
            workspace.analyzer(),
            &flow,
            None,
            &query,
            CodeQueryExecutionLimits::default(),
            None,
            scope,
        );
        unit.rows
            .iter()
            .map(|row| row.item.range.as_ref().expect("a located match").start_line)
            .collect::<Vec<_>>()
    };

    let typos = IdentifierTypoTable::parse("lenght length\n").unwrap();
    let unrelated = IdentifierDictionary::parse("total\n").unwrap().dictionary;
    let accepted = IdentifierDictionary::parse("# our spelling\nLenght\n")
        .unwrap()
        .dictionary;
    let scope = || CodeQueryExecutionScope::for_seed_files(&files, &files);
    // No typo table: nothing is a known misspelling.
    assert_eq!(flagged_lines(scope()), Vec::<usize>::new());
    assert_eq!(flagged_lines(scope().with_identifier_typos(&typos)), [3]);
    assert_eq!(
        flagged_lines(
            scope()
                .with_identifier_typos(&typos)
                .with_identifier_dictionary(&unrelated)
        ),
        [3]
    );
    assert_eq!(
        flagged_lines(
            scope()
                .with_identifier_typos(&typos)
                .with_identifier_dictionary(&accepted)
        ),
        Vec::<usize>::new()
    );
}
