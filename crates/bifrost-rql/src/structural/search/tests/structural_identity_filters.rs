use super::*;
use brokk_bifrost_test_macros::hardwon;

#[test]
#[hardwon("#9925: a nested Rust tuple-struct field binder was absent from RQL occurrence rows")]
fn rust_tuple_struct_field_binder_is_an_exact_occurrence() {
    for prefix in ["struct Query<T>(T);", "use poem::web::Query;"] {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "main.rs",
                format!(
                    "{prefix} fn handler(Query(file_name): Query<String>) {{ sink(file_name); }} fn sink(_: String) {{}}\n"
                ),
            )
            .build();
        let analyzer = RustAnalyzer::from_project(project.project().clone());
        let result = execute(
            &analyzer,
            &CodeQuery::from_source("(occurrences :class binding :role binder :namespace value)")
                .unwrap(),
        );
        assert!(
            result.results.iter().any(|row| matches!(
                &row.value,
                CodeQueryResultValue::Occurrence { value }
                    if value.raw_spelling == "file_name"
            )),
            "{prefix}: {result:?}"
        );
    }
}

#[test]
#[hardwon("#9925: Poem field sources require canonical constructor authority")]
fn rust_poem_field_rule_rejects_local_query_and_marks_unresolved_import_incomplete() {
    let query = CodeQuery::from_json(&json!({
        "languages": ["rust"],
        "match": {"kind": "identifier", "language_rule": "rust/poem-handler-param"}
    }))
    .expect("Poem field rule");
    for (prefix, expected_complete) in [
        ("struct Query<T>(T);", true),
        ("use poem::web::Query;", false),
    ] {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "main.rs",
                format!(
                    "{prefix} fn handler(Query(file_name): Query<String>) {{ sink(file_name); }} fn sink(_: String) {{}}\n"
                ),
            )
            .build();
        let analyzer = RustAnalyzer::from_project(project.project().clone());
        let result = execute(&analyzer, &query);
        assert!(result.results.is_empty(), "{prefix}: {result:?}");
        assert_eq!(
            matches!(result.completion(), CodeQueryCompletion::Complete),
            expected_complete,
            "{prefix}: {result:?}"
        );
    }
}

#[test]
fn rust_poem_test_only_declaration_pack_compiles() {
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        AuthoredSemanticModelPack, CompilerOptions, compile_pack,
    };
    let authored: AuthoredSemanticModelPack =
        serde_json::from_str(include_str!("fixtures/rust-poem-g3-test-only.json"))
            .expect("Poem test-only pack schema");
    compile_pack(&authored, &CompilerOptions::default())
        .expect("Poem test-only declaration pack compiles");
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10229: nested each captures retained quadratic source bytes without a row bound"
)]
fn nested_each_capture_bytes_are_bounded() {
    let suffix = std::iter::repeat_n("a", 120)
        .collect::<Vec<_>>()
        .join(" + ");
    let expression = format!("\"{}\" + {suffix}", "x".repeat(10_000));
    let source = format!("class C {{ int F(int a) {{ return {expression}; }} }}");
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Cases.cs", &source)
        .build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "binary_expression", "each": {"kind": "binary_expression", "capture": "part"}}
    }))
    .unwrap();
    let result = execute(&analyzer, &query);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted),
        "{result:?}"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10229: identical-captures expanded every pair before enforcing the comparison budget"
)]
fn identical_captures_pair_budget_has_one_diagnostic() {
    // 1001 x 1001 captures exceed the comparison budget's pair allowance. An
    // identical pair found before the budget runs out keeps the row; without
    // one, the walk stops at the budget and reports it once.
    let arguments = |name: &str| {
        std::iter::repeat_n(name, 1000)
            .collect::<Vec<_>>()
            .join(", ")
    };
    for (right, kept) in [
        (format!("M({})", arguments("a")), true),
        (format!("N({})", arguments("b")), false),
    ] {
        let source = format!(
            "class C {{ int F(int a, int b) {{ return M({}) ?? {right}; }} int M(params int[] a) {{ return 0; }} int N(params int[] b) {{ return 0; }} }}",
            arguments("a")
        );
        let project = InlineTestProject::with_language(Language::CSharp)
            .file("Cases.cs", &source)
            .build();
        let analyzer = CSharpAnalyzer::from_project(project.project().clone());
        let query = CodeQuery::from_json(&json!({
            "match": {"kind": "binary_expression", "operator": {"text": {"regex": "^\\?\\?$"}},
                "left": {"each": {"kind": "identifier", "capture": "left"}},
                "right": {"each": {"kind": "identifier", "capture": "right"}}},
            "steps": [{"op": "identical_captures", "left": "left", "right": "right"}]
        }))
        .unwrap();
        let result = execute(&analyzer, &query);
        let budget = result
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.message.contains("comparison budget exhausted"))
            .count();
        assert_eq!(result.results.len(), usize::from(kept), "{result:?}");
        assert_eq!(budget, usize::from(!kept), "{result:?}");
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10229: a row with an unbound identical-captures label needed syntax and answered open"
)]
fn identical_captures_drops_rows_without_a_pair_before_syntax() {
    // The source exceeds the 1 MiB identity syntax limit, so any row that
    // needs a proof is open. The second `any` alternative binds no `lhs`, so
    // its rows have no pair and are not identical without any syntax.
    let filler = format!("// {}\n", "x".repeat(96)).repeat(11 * 1024);
    let source = format!("class C {{ int F(int a) {{ a = a;\n{filler} return a; }} }}");
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Cases.cs", &source)
        .build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "assignment", "any": [
            {"kind": "assignment", "left": {"name": "absent", "capture": "lhs"}},
            {"kind": "assignment"}
        ]},
        "steps": [{"op": "identical_captures", "left": "lhs", "right": "lhs"}]
    }))
    .unwrap();
    let result = execute(&analyzer, &query);
    assert!(result.results.is_empty(), "{result:?}");
    assert!(
        result
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.impact != CodeQueryDiagnosticImpact::Incomplete),
        "{:?}",
        result.diagnostics
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10229: identical-captures formatted one open reason per undecided pair below the pair cap"
)]
fn identical_captures_open_pair_reasons_are_capped() {
    let left = (1..=5)
        .map(|index| format!("u{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let right = (1..=4)
        .map(|index| format!("v{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let source = format!(
        "class C {{ int F() {{ return M({left}) ?? M({right}); }} int M(params int[] a) {{ return 0; }} }}"
    );
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Cases.cs", &source)
        .build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "binary_expression", "operator": {"text": {"regex": "^\\?\\?$"}},
            "left": {"each": {"kind": "identifier", "name": {"regex": "^u[0-9]$"}, "capture": "left"}},
            "right": {"each": {"kind": "identifier", "name": {"regex": "^v[0-9]$"}, "capture": "right"}}},
        "steps": [{"op": "identical_captures", "left": "left", "right": "right"}]
    }))
    .unwrap();
    let result = execute(&analyzer, &query);
    let diagnostic = result
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.message.contains("open pairs total"))
        .unwrap_or_else(|| panic!("{result:?}"));
    // 5 x 4 pairs are all undecided; only the first 16 are listed.
    assert_eq!(
        diagnostic.message.matches(" vs ").count(),
        16,
        "{diagnostic:?}"
    );
    assert!(
        diagnostic
            .message
            .contains("20 open pairs total; 4 not listed"),
        "{diagnostic:?}"
    );
    assert!(result.results.is_empty(), "{result:?}");
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10229: a discarded each probe kept its capture bytes charged against a later retained each"
)]
fn discarded_each_probe_bytes_do_not_block_a_retained_each() {
    // Comment lines keep every line short (the line-length admission limit)
    // while the inner sum spans about 600 KiB.
    let filler = format!("// {}\n", "x".repeat(96)).repeat(6 * 1024);
    let source = format!("class C {{ int F(int a) {{ return (a\n{filler} + 1); }} }}");
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Cases.cs", &source)
        .build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    // The first alternative collects the ~600 KiB sum and then fails on
    // `not_has`; the second retains the same bytes. Together they exceed the
    // 1 MiB row cap, so the second only fits if the first was rolled back.
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "method", "any": [
            {"each": {"kind": "binary_expression", "capture": "discarded"},
                "not_has": {"kind": "binary_expression"}},
            {"each": {"kind": "binary_expression", "capture": "kept"}}
        ]}
    }))
    .unwrap();
    let result = execute(&analyzer, &query);
    assert!(
        !result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("each pattern is incomplete")),
        "{result:?}"
    );
    assert!(
        result.results.iter().any(|row| matches!(
            &row.value,
            CodeQueryResultValue::StructuralMatch { value }
                if value.captures.iter().any(|capture| capture.name == "kept")
        )),
        "{result:?}"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10229: a discarded any alternative left the row's each budget marked exhausted for later alternatives"
)]
fn exhausted_each_alternative_does_not_stop_a_later_alternative() {
    // Two nested sums of about 600 KiB each: the first alternative's `each`
    // passes the 1 MiB row cap on the inner sum and then fails on
    // `not_has`. The second alternative captures the small identifier `a` and
    // fits once the first alternative's charge is rolled back.
    let filler = format!("// {}\n", "x".repeat(96)).repeat(6 * 1024);
    let source = format!("class C {{ int F(int a) {{ return a\n{filler} + 1 + 2; }} }}");
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Cases.cs", &source)
        .build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "method", "any": [
            {"each": {"kind": "binary_expression", "capture": "discarded"},
                "not_has": {"kind": "binary_expression"}},
            {"each": {"kind": "identifier", "name": "a", "capture": "kept"}}
        ]}
    }))
    .unwrap();
    let result = execute(&analyzer, &query);
    assert!(
        result.results.iter().any(|row| matches!(
            &row.value,
            CodeQueryResultValue::StructuralMatch { value }
                if value.captures.iter().any(|capture| capture.name == "kept")
        )),
        "{result:?}"
    );
}

#[test]
fn structural_row_filters_use_the_published_row_and_ast_identities() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "main.ts",
            "function sample(left: number, right: number) { left = right; }\n",
        )
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());
    let seed = json!({"kind": "assignment"});
    let query = CodeQuery::from_json(&json!({"match": seed, "result_detail": "full"})).unwrap();
    let result = execute(&analyzer, &query);
    assert_eq!(result.results.len(), 1, "{result:?}");
    let wire = serde_json::to_value(&result.results[0]).unwrap();
    assert_ne!(wire["id"], wire["ast_id"], "{wire}");
    let occurrences = execute(
        &analyzer,
        &CodeQuery::from_source("(occurrences :role [value_reference])").unwrap(),
    );
    for (field, spelling) in [("left_ast_id", "left"), ("right_ast_id", "right")] {
        let occurrence = occurrences
            .results
            .iter()
            .find_map(|item| match &item.value {
                CodeQueryResultValue::Occurrence { value } if value.raw_spelling == spelling => {
                    Some(value)
                }
                _ => None,
            })
            .expect("authored operand occurrence");
        let filtered = CodeQuery::from_json(&json!({
            "match": seed, "result_detail": "full",
            "steps": [{"op": "filter", "where": [{
                "field": field, "op": "eq", "value": {"string": occurrence.ast_id}
            }]}]
        }))
        .unwrap();
        assert_eq!(execute(&analyzer, &filtered).results.len(), 1, "{field}");
    }
    for field in ["id", "ast_id"] {
        let filtered = CodeQuery::from_json(&json!({
            "match": seed, "result_detail": "full",
            "steps": [{"op": "filter", "where": [{
                "field": field, "op": "eq", "value": {"string": wire[field]}
            }]}]
        }))
        .unwrap();
        let selected = execute(&analyzer, &filtered);
        assert_eq!(selected.results.len(), 1, "{field}: {selected:?}");
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10229: an each child with many capture predicates copied every binding before the row budget was checked"
)]
fn many_capture_predicates_over_a_large_node_stop_at_the_budget() {
    // One ~600 KiB node, 200 capture predicates on the same child. Charging
    // after the child finished would copy about 120 MiB first.
    let filler = format!("// {}\n", "x".repeat(96)).repeat(6 * 1024);
    let source = format!("class C {{ int F(int a) {{ return (a\n{filler} + 1); }} }}");
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Cases.cs", &source)
        .build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    let predicates = (0..200)
        .map(|index| json!({"capture": format!("c{index}")}))
        .collect::<Vec<_>>();
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "method", "each": {"kind": "binary_expression", "all": predicates}}
    }))
    .unwrap();
    let before =
        crate::structural::matcher::EACH_BINDINGS_BUILT.load(std::sync::atomic::Ordering::Relaxed);
    let result = execute(&analyzer, &query);
    let built = crate::structural::matcher::EACH_BINDINGS_BUILT
        .load(std::sync::atomic::Ordering::Relaxed)
        - before;
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted),
        "{result:?}"
    );
    // The budget admits at most one ~600 KiB binding per row; allow slack for
    // other tests that share the counter under plain `cargo test`.
    assert!(built < 50, "{built} bindings were built");
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10229: a descendant's rollback cleared the capture cap, so each built and dropped bindings for every later descendant"
)]
fn each_walk_stops_after_a_descendant_meets_the_capture_cap() {
    // A left-nested sum of 100 operands: every binary expression spans the
    // ~600 KiB comment, and so does its left operand except at the innermost.
    // Each descendant binds one ~600 KiB capture and is refused the other.
    let filler = format!("// {}\n", "x".repeat(96)).repeat(6 * 1024);
    let operands = (1..=100)
        .map(|operand| format!(" + {operand}"))
        .collect::<String>();
    let source = format!("class C {{ int F(int a) {{ return a\n{filler}{operands}; }} }}");
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Cases.cs", &source)
        .build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "method", "each": {"kind": "binary_expression", "capture": "whole",
            "left": {"capture": "left"}}}
    }))
    .unwrap();
    let before =
        crate::structural::matcher::EACH_BINDINGS_BUILT.load(std::sync::atomic::Ordering::Relaxed);
    let result = execute(&analyzer, &query);
    let built = crate::structural::matcher::EACH_BINDINGS_BUILT
        .load(std::sync::atomic::Ordering::Relaxed)
        - before;
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted),
        "{result:?}"
    );
    // The walk stops at the first refused descendant; walking on built about
    // one binding per descendant. Slack covers tests that share the counter
    // under plain `cargo test`.
    assert!(built < 20, "{built} bindings were built");
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10229: argument-mode owner walks were charged to the fact budget only on the indexed path"
)]
fn argument_mode_scan_work_is_charged_to_the_fact_budget() {
    let arguments = std::iter::repeat_n("a", 300).collect::<Vec<_>>().join(", ");
    let source =
        format!("class C {{ void F(int a) {{ M({arguments}); }} void M(params int[] a) {{ }} }}");
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Cases.cs", &source)
        .build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    let run = |query: &CodeQuery, limits| {
        execute_code_query_with_access_mode(
            &analyzer,
            query,
            limits,
            StructuralAccessMode::ScanOnly,
            false,
        )
        .expect("scan access is always available")
    };
    // The same scan without `argument-mode` bounds the file's fact count.
    let plain =
        CodeQuery::from_json(&json!({"match": {"kind": "identifier"}, "limit": 1000})).unwrap();
    let baseline = run(&plain, CodeQueryExecutionLimits::default());
    assert!(!baseline.result.truncated, "{:?}", baseline.result);
    let scan_facts = usize::try_from(baseline.work.fact_nodes).expect("facts fit usize");
    let limits = CodeQueryExecutionLimits {
        max_fact_nodes: scan_facts.saturating_mul(2),
        ..CodeQueryExecutionLimits::default()
    };
    assert!(!run(&plain, limits).result.truncated);

    // Each of 300 arguments walks the call's 300 role edges: far more work
    // than the file's fact count.
    let moded = CodeQuery::from_json(&json!({
        "match": {"kind": "identifier", "argument_mode": ["plain"]}, "limit": 1000
    }))
    .unwrap();
    let result = run(&moded, limits).result;
    assert!(result.truncated, "{result:?}");
    assert!(
        result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
        }),
        "{:?}",
        result.diagnostics
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10229: argument-mode climbed from every node outside a call to the root, scanning each enclosing block"
)]
fn argument_mode_outside_calls_stops_at_the_role_owner() {
    // 200 assignments in one block and no call: each identifier's role owner
    // is its assignment. Climbing to the nearest argument owner instead
    // scanned the block's 200 statement edges, then every enclosing
    // declaration's, for each of 400 identifiers.
    let statements = "x = y;".repeat(200);
    let source = format!("class C {{ int x; int y; void F() {{ {statements} }} }}");
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Cases.cs", &source)
        .build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    let run = |query: &CodeQuery, limits| {
        execute_code_query_with_access_mode(
            &analyzer,
            query,
            limits,
            StructuralAccessMode::ScanOnly,
            false,
        )
        .expect("scan access is always available")
    };
    let plain =
        CodeQuery::from_json(&json!({"match": {"kind": "identifier"}, "limit": 1000})).unwrap();
    let baseline = run(&plain, CodeQueryExecutionLimits::default());
    assert!(!baseline.result.truncated, "{:?}", baseline.result);
    let limits = CodeQueryExecutionLimits {
        max_fact_nodes: usize::try_from(baseline.work.fact_nodes)
            .expect("facts fit usize")
            .saturating_mul(3),
        ..CodeQueryExecutionLimits::default()
    };
    let moded = CodeQuery::from_json(&json!({
        "match": {"kind": "identifier", "argument_mode": ["ref"]}, "limit": 1000
    }))
    .unwrap();
    let result = run(&moded, limits).result;
    assert!(!result.truncated, "{result:?}");
    assert!(result.results.is_empty(), "{result:?}");
    assert!(
        !result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted
        }),
        "{:?}",
        result.diagnostics
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#10229: an isolated count probe left the each capture budget exhausted for later siblings"
)]
fn count_probe_restores_each_capture_budget() {
    let filler = format!("// {}\n", "x".repeat(96)).repeat(6 * 1024);
    let source = format!("class C {{ int F(int a) {{ M(a\n{filler} + 1); return a; }} }}");
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Cases.cs", &source)
        .build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "call", "all": [
            {"count": {"role": "args", "min": 0, "pattern": {
                "each": {"all": [{"capture": "a"}, {"capture": "b"}]}
            }}},
            {"each": {"kind": "binary_expression", "capture": "result"}}
        ]}
    }))
    .unwrap();
    let result = execute(&analyzer, &query);
    // The probe's exhausted budget must not reach the sibling `each`, whose
    // one binary expression fits the row budget: the call is a row.
    assert_eq!(result.results.len(), 1, "{result:?}");
}
