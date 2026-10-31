use super::*;

#[test]
fn empty_union_branches_preserve_unsupported_relation_coverage() {
    let project = InlineTestProject::new()
        .file("Empty.java", "class Empty {}")
        .file("Empty.cs", "class Empty {}")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    for query in [
        "(branch-relations :relation [empty-arm] (union (language java (if)) (language csharp (if))))",
        "(branch-relations :relation [empty-arm] (union (language csharp (if)) (language java (if))))",
        "(union (branch-relations :relation [empty-arm] (language java (if))) (branch-relations :relation [empty-arm] (language csharp (if))))",
    ] {
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &CodeQuery::from_sexp(query).unwrap(),
        );
        assert!(result.results.is_empty(), "{result:#?}");
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| d.language == "java" && d.message.contains("unsupported_relation")),
            "{query}: {result:#?}"
        );
    }
}

#[test]
fn spawn_shapes_use_the_direct_operand_or_the_spawn_call_itself() {
    for (language, path, source, expected) in [
        (
            Language::Rust,
            "src/lib.rs",
            "fn launch() { tokio::spawn(async { inner(); }); }",
            "spawn",
        ),
        (
            Language::Go,
            "main.go",
            "package main\nfunc launch() { go outer(inner()) }\n",
            "outer",
        ),
    ] {
        let project = InlineTestProject::with_language(language)
            .file(path, source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let query = CodeQuery::from_json(
            &json!({"match":{"kind":"concurrent_spawn"},"steps":[{"op":"call_shape"}]}),
        )
        .unwrap();
        let result = execute_workspace(
            &workspace,
            &brokk_bifrost_flow::FlowWorkspaceState::new(),
            &query,
        );
        assert_eq!(result.results.len(), 1, "{result:#?}");
        let CodeQueryResultValue::CallShape { value } = &result.results[0].value else {
            panic!("call shape");
        };
        assert_eq!(value.callee_name.as_deref(), Some(expected), "{value:#?}");
    }
}

#[test]
fn direct_receiver_evidence_retains_the_known_module() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "sample.js",
            "import path from 'node:path'; export const name = path.basename('/tmp/a');",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": {"kind":"field_access", "name":"basename", "object":{"capture":"receiver"}},
        "steps":[{"op":"receiver_evidence"}],
        "result_detail":"full"
    }))
    .unwrap();
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(result.results.len(), 1, "{result:#?}");
    let rendered = serde_json::to_value(&result).unwrap().to_string();
    assert!(rendered.contains("module_or_export_object"), "{rendered}");
    assert!(rendered.contains("path"), "{rendered}");
}

#[test]
fn path_language_scope_excludes_unselected_adapter_diagnostics() {
    let project = InlineTestProject::new()
        .file("main.go", "package main\nfunc main() {}\n")
        .file("empty.py", "pass\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_sexp(
        "(nilness-operations (procedure-of (segment-target (segments-of (language go (paths))))))",
    )
    .unwrap();
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert!(result.results.is_empty(), "{result:#?}");
    assert!(
        !result
            .diagnostics
            .iter()
            .any(|d| d.language == "python" && d.message.contains("unsupported_relation")),
        "{result:#?}"
    );
}

#[test]
fn shared_seed_replay_reports_local_row_budget_truncation() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("sample.js", "first(); second();")
        .build();
    let analyzer = language_analyzer(Language::JavaScript, project.project().clone());
    let branch = json!({"match":{"kind":"call"}});
    let query = CodeQuery::from_json(&json!({"union":[branch.clone(),branch]})).unwrap();
    let response = execute_code_query_with_access_mode(
        analyzer.as_ref(),
        &query,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 3,
            ..CodeQueryExecutionLimits::default()
        },
        StructuralAccessMode::ScanOnly,
        true,
    )
    .unwrap();
    assert_eq!(response.result.results.len(), 2, "{response:#?}");
    assert!(response.result.truncated, "{response:#?}");
}
