use super::*;

#[test]
fn cfg_pipeline_resolves_a_source_backed_procedure() {
    let result = run(
        &[("src/main.rs", "fn target() {}\n")],
        json!({
            "schema_version": 3,
            "match": { "kind": "function", "name": "target" },
            "steps": [{ "op": "procedure_of" }]
        }),
    );
    let value = serialized(&result);

    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["results"][0]["result_type"], "procedure");
    assert_eq!(value["results"][0]["path"], "src/main.rs");
    assert_eq!(value["results"][0]["procedure_kind"], "function");
    assert_eq!(value["results"][0]["evidence"]["proof"], "proven");
    assert_eq!(value["results"][0]["evidence"]["completeness"], "complete");
    assert_eq!(value["results"][0]["id"].as_str().unwrap().len(), 64);
    assert_eq!(
        value["results"][0]["artifact_id"].as_str().unwrap().len(),
        64
    );
    assert_eq!(
        value["results"][0]["provenance"][0]["steps"][0]["op"],
        "procedure_of"
    );
    assert_eq!(value["truncated"], false);
    assert!(value.get("diagnostics").is_none());
}

#[test]
fn procedure_of_bridges_a_ruby_top_level_function_to_its_semantic_method() {
    let result = run(
        &[("src/main.rb", "def target(value)\n  value\nend\n")],
        json!({
            "schema_version": 3,
            "languages": ["ruby"],
            "match": { "kind": "function", "name": "target" },
            "steps": [{ "op": "procedure_of" }]
        }),
    );
    let value = serialized(&result);

    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["results"][0]["result_type"], "procedure");
    assert_eq!(value["results"][0]["procedure_kind"], "method");
    assert_eq!(value["results"][0]["path"], "src/main.rb");
    assert_eq!(value["truncated"], false, "{value}");
    assert!(value.get("diagnostics").is_none(), "{value}");
}

#[test]
fn analyzer_only_cfg_pipeline_requires_workspace_semantic_services() {
    let project = InlineTestProject::new()
        .file("src/main.rs", "fn target() {}\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "schema_version": 3,
        "match": { "kind": "function", "name": "target" },
        "steps": [{ "op": "procedure_of" }]
    }))
    .unwrap();

    let result = execute(workspace.analyzer(), &query);
    let value = serialized(&result);
    assert_eq!(value["results"], json!([]));
    assert_eq!(value["truncated"], true);
    assert_eq!(
        value["diagnostics"][0]["code"],
        "semantic_workspace_required"
    );
    assert_eq!(value["diagnostics"][0]["impact"], "incomplete");
}

#[test]
fn cfg_pipeline_traverses_entry_edges_and_preserves_typed_provenance() {
    let result = run(
        &[(
            "src/main.rs",
            "fn target(flag: bool) -> i32 {\n    if flag { 1 } else { 2 }\n}\n",
        )],
        json!({
            "schema_version": 3,
            "match": { "kind": "function", "name": "target" },
            "steps": [
                { "op": "procedure_of" },
                { "op": "cfg_entry" },
                { "op": "cfg_successor_edges" },
                { "op": "cfg_edge_target" }
            ]
        }),
    );
    let value = serialized(&result);

    assert!(!value["results"].as_array().unwrap().is_empty(), "{value}");
    for row in value["results"].as_array().unwrap() {
        assert_eq!(row["result_type"], "program_point", "{value}");
        assert_eq!(row["path"], "src/main.rs");
        assert_eq!(row["id"].as_str().unwrap().len(), 64);
        assert_eq!(row["procedure_id"].as_str().unwrap().len(), 64);
        let steps = row["provenance"][0]["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 4, "{value}");
        assert_eq!(steps[0]["op"], "procedure_of");
        assert_eq!(steps[1]["op"], "cfg_entry");
        assert_eq!(steps[2]["op"], "cfg_successor_edges");
        assert_eq!(steps[2]["result"]["result_type"], "control_edge");
        assert!(steps[2]["result"]["source_id"].is_string());
        assert!(steps[2]["result"]["target_id"].is_string());
        assert_eq!(steps[3]["op"], "cfg_edge_target");
    }
    assert_eq!(value["truncated"], false, "{value}");
    assert!(
        value["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .all(|diagnostic| diagnostic["code"] == "semantic_analysis_partial")
    );
    assert_eq!(value["results"][0]["evidence"]["completeness"], "partial");
}

#[test]
fn cfg_exits_are_normal_then_exceptional_with_stable_ids() {
    let query = json!({
        "schema_version": 3,
        "match": { "kind": "function", "name": "target" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "cfg_exits" }
        ]
    });
    let project = InlineTestProject::new()
        .file("src/main.rs", "fn target() -> i32 { 1 }\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let first_query = CodeQuery::from_json(&query).unwrap();
    let second_query = CodeQuery::from_json(&query).unwrap();
    let first = serialized(&execute_workspace(&workspace, &first_query));
    let second = serialized(&execute_workspace(&workspace, &second_query));

    assert_eq!(first["results"].as_array().unwrap().len(), 2, "{first}");
    assert_eq!(first["results"][0]["boundary"], "normal_exit");
    assert_eq!(first["results"][1]["boundary"], "exceptional_exit");
    assert_eq!(first["results"][0]["id"], second["results"][0]["id"]);
    assert_eq!(first["results"][1]["id"], second["results"][1]["id"]);
    assert_eq!(
        first["results"][0]["procedure_id"],
        first["results"][1]["procedure_id"]
    );
}

#[test]
fn cfg_profile_reports_request_cache_reuse_without_recharging_semantic_work() {
    let project = InlineTestProject::new()
        .file("src/main.rs", "fn first() {}\nfn second() {}\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "schema_version": 3,
        "execution_mode": "profile",
        "union": [
            {
                "match": { "kind": "function", "name": "first" },
                "steps": [{ "op": "procedure_of" }]
            },
            {
                "match": { "kind": "function", "name": "second" },
                "steps": [{ "op": "procedure_of" }]
            }
        ]
    }))
    .unwrap();

    let CodeQueryResponse::Profile(profile) = execute_workspace_request(&workspace, &query) else {
        panic!("profile query should return a profile");
    };
    assert_eq!(profile.result.results.len(), 2);
    assert_eq!(profile.work.semantic.materialization_attempts, 1);
    assert_eq!(profile.work.semantic.unique_materialized_files, 1);
    assert_eq!(profile.work.semantic.request_cache_hits, 1);
    assert!(profile.work.semantic.source_bytes > 0);
    assert!(profile.work.semantic.procedures >= 2);
    assert!(profile.work.semantic.retained_bytes > 0);
    assert!(profile.work.semantic.traversal_steps >= 2);
    assert!(!profile.work.semantic.budget_exhausted);

    let serialized_profile = serde_json::to_value(&profile).unwrap();
    assert!(
        serialized_profile["operators"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|operator| operator["operator"] == "pipeline_step")
            .any(|operator| {
                operator["work"]["semantic"]["materialization_attempts"]
                    .as_u64()
                    .is_some_and(|attempts| attempts > 0)
                    && operator["work"]["semantic"]["traversal_steps"]
                        .as_u64()
                        .is_some_and(|steps| steps > 0)
            }),
        "{serialized_profile}"
    );
}

#[test]
fn cfg_predecessor_and_edge_source_recover_the_traversed_source_point() {
    let result = serialized(&run(
        &[(
            "src/main.rs",
            "fn target(flag: bool) -> i32 {\n    if flag { 1 } else { 2 }\n}\n",
        )],
        json!({
            "schema_version": 3,
            "match": { "kind": "function", "name": "target" },
            "steps": [
                { "op": "procedure_of" },
                { "op": "cfg_entry" },
                { "op": "cfg_successor_edges" },
                { "op": "cfg_edge_target" },
                { "op": "cfg_predecessor_edges" },
                { "op": "cfg_edge_source" }
            ]
        }),
    ));

    let row = &result["results"][0];
    let steps = row["provenance"][0]["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 6, "{result}");
    assert_eq!(steps[4]["op"], "cfg_predecessor_edges");
    assert_eq!(steps[4]["result"]["result_type"], "control_edge");
    assert_eq!(steps[5]["op"], "cfg_edge_source");
    assert_eq!(row["id"], steps[1]["result"]["id"]);
}

#[test]
fn cfg_semantic_file_budget_is_typed_and_stops_new_materializations() {
    let project = InlineTestProject::new()
        .file("src/first.rs", "fn first() {}\n")
        .file("src/second.rs", "fn second() {}\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "schema_version": 3,
        "execution_mode": "profile",
        "union": [
            {
                "match": { "kind": "function", "name": "first" },
                "steps": [{ "op": "procedure_of" }]
            },
            {
                "match": { "kind": "function", "name": "second" },
                "steps": [{ "op": "procedure_of" }]
            }
        ]
    }))
    .unwrap();
    let mut limits = CodeQueryExecutionLimits::default();
    limits.semantic.max_materialized_files = 1;

    let CodeQueryResponse::Profile(profile) =
        brokk_bifrost::analyzer::structural::execute_workspace_request_with_limits(
            &workspace, &query, limits,
        )
    else {
        panic!("profile query should return a profile");
    };
    assert!(profile.result.truncated);
    assert!(
        profile.result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::SemanticBudgetExhausted
        })
    );
    assert_eq!(profile.work.semantic.materialization_attempts, 1);
    assert_eq!(profile.work.semantic.unique_materialized_files, 1);
    assert!(profile.work.semantic.budget_exhausted);
}

#[test]
fn cfg_zero_semantic_limit_is_an_invalid_plan() {
    let project = InlineTestProject::new()
        .file("src/main.rs", "fn target() {}\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "schema_version": 3,
        "match": { "kind": "function", "name": "target" },
        "steps": [{ "op": "procedure_of" }]
    }))
    .unwrap();
    let mut limits = CodeQueryExecutionLimits::default();
    limits.semantic.max_source_bytes = 0;

    let result = brokk_bifrost::analyzer::structural::execute_workspace_with_limits(
        &workspace, &query, limits,
    );
    assert_eq!(
        result.completion(),
        brokk_bifrost::analyzer::structural::CodeQueryCompletion::Invalid {
            codes: vec![CodeQueryDiagnosticCode::InvalidPlan],
        }
    );
}

#[test]
fn procedure_of_reports_a_proven_missing_enclosing_procedure_as_advisory() {
    let result = run(
        &[("src/main.rs", "struct Data;\n")],
        json!({
            "schema_version": 3,
            "match": { "kind": "class", "name": "Data" },
            "steps": [{ "op": "procedure_of" }]
        }),
    );

    assert!(result.results.is_empty());
    assert!(!result.truncated);
    assert_eq!(
        result.completion(),
        brokk_bifrost::analyzer::structural::CodeQueryCompletion::Complete
    );
    assert!(result.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::NoEnclosingProcedure
            && diagnostic.impact
                == brokk_bifrost::analyzer::structural::CodeQueryDiagnosticImpact::Advisory
    }));
}

#[test]
fn procedure_of_does_not_treat_nested_methods_as_enclosing_a_class() {
    let result = run(
        &[("src/app.ts", "class Data {\n  nested(): void {}\n}\n")],
        json!({
            "schema_version": 3,
            "languages": ["typescript"],
            "match": { "kind": "class", "name": "Data" },
            "steps": [{ "op": "procedure_of" }]
        }),
    );

    assert!(result.results.is_empty(), "{:?}", result.results);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code == CodeQueryDiagnosticCode::NoEnclosingProcedure })
    );
}

#[test]
fn cfg_public_ranges_use_character_columns_after_multibyte_text() {
    let source = "const café = 1; function target() {}\n";
    let result = serialized(&run(
        &[("src/app.ts", source)],
        json!({
            "schema_version": 3,
            "languages": ["typescript"],
            "match": { "kind": "function", "name": "target" },
            "steps": [{ "op": "procedure_of" }]
        }),
    ));
    let expected_column = source[..source.find("function").unwrap()].chars().count() + 1;

    assert_eq!(
        result["results"][0]["range"]["start_column"], expected_column,
        "{result}"
    );
}

#[test]
fn cfg_public_ids_are_checkout_independent_for_identical_content() {
    let query = json!({
        "schema_version": 3,
        "match": { "kind": "function", "name": "target" },
        "steps": [
            { "op": "procedure_of" },
            { "op": "cfg_entry" },
            { "op": "cfg_successor_edges" }
        ]
    });
    let run_in_new_root = || {
        let project = InlineTestProject::new()
            .file("src/main.rs", "fn target() { let value = 1; }\n")
            .build();
        let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
        let query = CodeQuery::from_json(&query).unwrap();
        serialized(&execute_workspace(&workspace, &query))
    };

    let first = run_in_new_root();
    let second = run_in_new_root();
    assert_eq!(first["results"][0]["id"], second["results"][0]["id"]);
    assert_eq!(
        first["results"][0]["procedure_id"],
        second["results"][0]["procedure_id"]
    );
}

#[test]
fn semantic_traversal_budget_bounds_procedure_lookup_work() {
    let project = InlineTestProject::new()
        .file("src/main.rs", "fn first() {}\nfn second() {}\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "schema_version": 3,
        "execution_mode": "profile",
        "match": { "kind": "function", "name": "second" },
        "steps": [{ "op": "procedure_of" }]
    }))
    .unwrap();
    let mut limits = CodeQueryExecutionLimits::default();
    limits.semantic.max_traversal_steps = 1;

    let CodeQueryResponse::Profile(profile) =
        brokk_bifrost::analyzer::structural::execute_workspace_request_with_limits(
            &workspace, &query, limits,
        )
    else {
        panic!("profile query should return a profile");
    };
    assert!(profile.result.results.is_empty());
    assert!(profile.result.truncated);
    assert_eq!(profile.work.semantic.traversal_steps, 1);
    assert!(profile.work.semantic.budget_exhausted);
    assert!(
        profile.result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::SemanticBudgetExhausted
        })
    );
}

#[test]
fn semantic_diagnostics_retain_set_branch_provenance() {
    let result = serialized(&run(
        &[(
            "src/app.ts",
            "class Data { nested(): void {} }\nfunction target(): void {}\n",
        )],
        json!({
            "schema_version": 3,
            "union": [
                {
                    "languages": ["typescript"],
                    "match": { "kind": "function", "name": "target" },
                    "steps": [{ "op": "procedure_of" }]
                },
                {
                    "languages": ["typescript"],
                    "match": { "kind": "class", "name": "Data" },
                    "steps": [{ "op": "procedure_of" }]
                }
            ]
        }),
    ));

    assert!(
        result["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["code"] == "no_enclosing_procedure"
                && diagnostic["branch"] == json!([1]))
    );
}

#[test]
fn typescript_cfg_pipeline_returns_source_backed_points() {
    let result = serialized(&run(
        &[(
            "src/app.ts",
            "function target(flag: boolean): number {\n  return flag ? 1 : 2;\n}\n",
        )],
        json!({
            "schema_version": 3,
            "languages": ["typescript"],
            "match": { "kind": "function", "name": "target" },
            "steps": [
                { "op": "procedure_of" },
                { "op": "cfg_entry" }
            ]
        }),
    ));

    assert_eq!(result["results"].as_array().unwrap().len(), 1, "{result}");
    assert_eq!(result["results"][0]["result_type"], "program_point");
    assert_eq!(result["results"][0]["boundary"], "entry");
    assert_eq!(result["results"][0]["path"], "src/app.ts");
    assert_eq!(result["results"][0]["language"], "typescript");
    assert_eq!(
        result["results"][0]["provenance"][0]["steps"][0]["result"]["result_type"],
        "procedure"
    );
}

#[test]
fn empty_seed_frontier_does_not_build_import_graph() {
    let project = InlineTestProject::new()
        .file("a.rb", "require_relative 'b'\ndef present; end\n")
        .file("b.rb", "def other; end\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "where": ["a.rb"],
        "match": { "kind": "function", "name": "absent" },
        "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_scanned_files: 1,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(!result.truncated, "{:?}", result.diagnostics);
    assert!(result.diagnostics.iter().all(|diagnostic| {
        diagnostic.code != CodeQueryDiagnosticCode::ImportGraphBudgetExhausted
    }));
}

#[test]
fn reverse_import_graph_work_is_bounded_and_diagnostic() {
    let project = InlineTestProject::new()
        .file("a.rb", "require_relative 'b'\ndef from_a; end\n")
        .file("b.rb", "require_relative 'c'\ndef from_b; end\n")
        .file("c.rb", "def target; end\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "where": ["c.rb"],
        "match": { "kind": "function", "name": "target" },
        "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_scanned_files: 1,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(result.truncated, "{:?}", result.diagnostics);
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == CodeQueryDiagnosticCode::ImportGraphBudgetExhausted
            })
            .count(),
        1,
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn import_graph_budget_rolls_forward_to_later_branches() {
    let project = InlineTestProject::new()
        .file(
            "a.py",
            "import b\nimport c\nimport d\ndef from_a():\n    pass\n",
        )
        .file("b.py", "def from_b():\n    pass\n")
        .file("c.py", "def from_c():\n    pass\n")
        .file("d.py", "def from_d():\n    pass\n")
        .file("y.py", "def from_y():\n    pass\n")
        .file("z.py", "import y\ndef from_z():\n    pass\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "union": [
            {
                "where": ["a.py"],
                "match": { "kind": "function", "name": "from_a" },
                "steps": [
                    { "op": "file_of" },
                    { "op": "imports_of" },
                    { "op": "imports_of" }
                ]
            },
            {
                "where": ["z.py"],
                "match": { "kind": "function", "name": "from_z" },
                "steps": [{ "op": "file_of" }, { "op": "imports_of" }]
            }
        ]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_scanned_files: 4,
            ..CodeQueryExecutionLimits::default()
        },
    );
    let value = serialized(&result);
    assert!(result.truncated, "{value}");
    assert!(
        value["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["path"] == "y.py" && item["provenance"][0]["branch"] == json!([1])),
        "{value}"
    );
    assert!(
        value["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["branch"] == json!([0])
                && diagnostic["message"]
                    .as_str()
                    .unwrap()
                    .contains("import graph budget exhausted")),
        "{value}"
    );
}
