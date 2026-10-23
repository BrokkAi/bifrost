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
