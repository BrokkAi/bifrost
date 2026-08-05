use super::*;

#[test]
fn typed_set_operators_use_stable_endpoint_identity_and_branch_order() {
    let files = [(
        "app.py",
        "def alpha():\n    pass\ndef beta():\n    pass\ndef gamma():\n    pass\n",
    )];

    let union = serialized(&run(
        &files,
        json!({
            "union": [
                { "match": { "kind": "function", "name": "beta" } },
                { "match": { "kind": "function", "name": "alpha" } },
                { "match": { "kind": "function", "name": "beta" } }
            ]
        }),
    ));
    let union_results = union["results"].as_array().unwrap();
    assert_eq!(union_results.len(), 2, "{union}");
    assert!(
        union_results[0]["text"]
            .as_str()
            .unwrap()
            .starts_with("def beta"),
        "{union}"
    );
    assert!(
        union_results[1]["text"]
            .as_str()
            .unwrap()
            .starts_with("def alpha"),
        "{union}"
    );
    assert_eq!(
        union_results[0]["provenance"][0]["branch"],
        json!([0]),
        "{union}"
    );
    assert_eq!(
        union_results[0]["provenance"][1]["branch"],
        json!([2]),
        "{union}"
    );

    let intersection = serialized(&run(
        &files,
        json!({
            "intersect": [
                { "match": { "kind": "function" } },
                { "match": { "kind": "function", "name": { "regex": "^(alpha|gamma)$" } } }
            ]
        }),
    ));
    let intersection_names = intersection["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| {
            result["text"].as_str().unwrap()[4..]
                .split('(')
                .next()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(intersection_names, ["alpha", "gamma"], "{intersection}");

    let difference = serialized(&run(
        &files,
        json!({
            "except": [
                { "match": { "kind": "function" } },
                { "match": { "kind": "function", "name": "beta" } },
                { "match": { "kind": "function", "name": "gamma" } }
            ]
        }),
    ));
    let difference_names = difference["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| {
            result["text"].as_str().unwrap()[4..]
                .split('(')
                .next()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(difference_names, ["alpha"], "{difference}");
}

#[test]
fn typed_set_composition_supports_nested_paths_and_common_typed_steps() {
    let result = serialized(&run(
        &[("app.py", "def alpha():\n    pass\ndef beta():\n    pass\n")],
        json!({
            "union": [
                { "match": { "kind": "function", "name": "alpha" } },
                {
                    "intersect": [
                        { "match": { "kind": "function", "name": "beta" } },
                        { "match": { "kind": "function" } }
                    ]
                }
            ],
            "steps": [{ "op": "enclosing_decl" }, { "op": "file_of" }]
        }),
    ));
    assert_eq!(result["results"].as_array().unwrap().len(), 1, "{result}");
    assert_eq!(result["results"][0]["result_type"], "file", "{result}");
    let branches = result["results"][0]["provenance"]
        .as_array()
        .unwrap()
        .iter()
        .map(|trace| trace["branch"].clone())
        .collect::<Vec<_>>();
    assert_eq!(branches, [json!([0]), json!([1, 0]), json!([1, 1])]);
}

#[test]
fn capture_sensitive_suffixes_preserve_each_branch_binding() {
    let files = [(
        "app.ts",
        r#"
interface Runner {
  sendRequest(method: string, payload: object): void;
}
declare const runner: Runner;
const method = "run";
runner.sendRequest(method, {});
"#,
    )];
    let branch = |capture_receiver: bool| {
        if capture_receiver {
            json!({
                "match": {
                    "kind": "call",
                    "callee": { "name": "sendRequest" },
                    "receiver": { "capture": "x" }
                }
            })
        } else {
            json!({
                "match": {
                    "kind": "call",
                    "callee": { "name": "sendRequest" },
                    "args": [{ "capture": "x" }]
                }
            })
        }
    };
    let query = |receiver_first: bool| {
        let branches = if receiver_first {
            vec![branch(true), branch(false)]
        } else {
            vec![branch(false), branch(true)]
        };
        json!({
            "union": branches,
            "steps": [{ "op": "points_to", "capture": "x" }],
            "result_detail": "full"
        })
    };

    let forward = serialized(&run(&files, query(true)));
    let reverse = serialized(&run(&files, query(false)));
    let summarize = |value: &serde_json::Value| {
        let mut rows = value["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row["text"].as_str().unwrap().to_string(),
                    row["outcome"].as_str().unwrap().to_string(),
                )
            })
            .collect::<Vec<_>>();
        rows.sort();
        rows
    };
    assert_eq!(
        summarize(&forward),
        summarize(&reverse),
        "forward={forward}\nreverse={reverse}"
    );
    assert_eq!(forward["results"].as_array().unwrap().len(), 2, "{forward}");
    assert_eq!(reverse["results"].as_array().unwrap().len(), 2, "{reverse}");
    for result in forward["results"].as_array().unwrap() {
        assert_eq!(
            result["provenance"].as_array().unwrap().len(),
            1,
            "{result}"
        );
        let expected_branch = if result["text"] == "runner" { 0 } else { 1 };
        assert_eq!(
            result["provenance"][0]["branch"],
            json!([expected_branch]),
            "{result}"
        );
    }
    for result in reverse["results"].as_array().unwrap() {
        assert_eq!(
            result["provenance"].as_array().unwrap().len(),
            1,
            "{result}"
        );
        let expected_branch = if result["text"] == "runner" { 1 } else { 0 };
        assert_eq!(
            result["provenance"][0]["branch"],
            json!([expected_branch]),
            "{result}"
        );
    }
}

#[test]
fn except_capture_suffix_uses_the_surviving_first_branch_binding() {
    let result = serialized(&run(
        &[(
            "app.ts",
            r#"
interface Runner {
  sendRequest(method: string): void;
}
declare const runner: Runner;
runner.sendRequest("run");
"#,
        )],
        json!({
            "except": [
                {
                    "match": {
                        "kind": "call",
                        "callee": { "name": "sendRequest" },
                        "receiver": { "capture": "service" }
                    }
                },
                {
                    "match": {
                        "kind": "call",
                        "callee": { "name": "ignored" }
                    }
                }
            ],
            "steps": [{ "op": "points_to", "capture": "service" }]
        }),
    ));
    assert_eq!(result["results"].as_array().unwrap().len(), 1, "{result}");
    assert_eq!(result["results"][0]["text"], "runner", "{result}");
    assert_eq!(result["results"][0]["provenance"][0]["branch"], json!([0]));
}

#[test]
fn identical_composed_seeds_share_structural_scan_work() {
    let project = InlineTestProject::new()
        .file("app.py", "def target():\n    pass\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "union": [
            { "match": { "kind": "function", "name": "target" } },
            { "match": { "kind": "function", "name": "target" } }
        ]
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
    let value = serialized(&result);
    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(
        value["results"][0]["provenance"].as_array().unwrap().len(),
        2
    );
}

#[test]
fn truncated_identical_seeds_reuse_partial_materialization() {
    let project = InlineTestProject::new()
        .file(
            "app.py",
            "def first():\n    pass\ndef second():\n    pass\n",
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    for operator in ["union", "intersect"] {
        let branches = json!([
            { "match": { "kind": "function" } },
            { "match": { "kind": "function" } }
        ]);
        let query_json = if operator == "union" {
            json!({ "union": branches })
        } else {
            json!({ "intersect": branches })
        };
        let query = CodeQuery::from_json(&query_json).unwrap();
        let result = execute_with_limits(
            workspace.analyzer(),
            &query,
            CodeQueryExecutionLimits {
                max_scanned_files: 1,
                max_pipeline_rows: 2,
                ..CodeQueryExecutionLimits::default()
            },
        );
        let value = serialized(&result);
        assert!(result.truncated, "{operator}: {value}");
        assert_eq!(
            value["results"].as_array().unwrap().len(),
            1,
            "{operator}: {value}"
        );
        assert_eq!(
            value["results"][0]["provenance"].as_array().unwrap().len(),
            2,
            "{operator}: {value}"
        );
        assert!(
            value["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .all(|diagnostic| {
                    !diagnostic["message"]
                        .as_str()
                        .unwrap()
                        .contains("scanned 2 files")
                }),
            "{operator}: {value}"
        );
    }
}

#[test]
fn fair_branch_budgets_preserve_later_branches_and_attribute_diagnostics() {
    let project = InlineTestProject::new()
        .file("a.py", "def first():\n    pass\n")
        .file("b.py", "def second():\n    pass\n")
        .file("z.py", "def important():\n    pass\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "union": [
            { "match": { "kind": "function" } },
            { "match": { "kind": "function", "name": "important" } }
        ]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 3,
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
            .any(|item| item["text"].as_str().unwrap().starts_with("def important")),
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
                    .contains("pipeline budget exhausted")),
        "{value}"
    );
}

#[test]
fn fair_scan_budgets_do_not_charge_rejected_work_to_later_branches() {
    let large_source = format!(
        "# missing\n{}",
        (0..64)
            .map(|index| format!("value_{index} = {index}\n"))
            .collect::<String>()
    );
    let important_source = "def important():\n    pass\n";
    let project = InlineTestProject::new()
        .file("a.py", &large_source)
        .file("b.py", "value = 1\n")
        .file("z.py", important_source)
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "union": [
            {
                "where": ["a.py", "b.py"],
                "match": { "kind": "function", "name": "missing" }
            },
            {
                "where": ["z.py"],
                "match": { "kind": "function", "name": "important" }
            }
        ]
    }))
    .unwrap();
    let finds_important = |limits| {
        let result = execute_with_limits(workspace.analyzer(), &query, limits);
        let value = serialized(&result);
        assert!(
            value["results"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["text"].as_str().unwrap().starts_with("def important")),
            "{value}"
        );
    };

    finds_important(CodeQueryExecutionLimits {
        max_scanned_files: 2,
        ..CodeQueryExecutionLimits::default()
    });
    finds_important(CodeQueryExecutionLimits {
        max_scanned_source_bytes: large_source.len(),
        ..CodeQueryExecutionLimits::default()
    });
    finds_important(CodeQueryExecutionLimits {
        max_fact_nodes: 10,
        ..CodeQueryExecutionLimits::default()
    });
}

#[test]
fn global_result_limit_is_applied_after_set_composition() {
    let result = serialized(&run(
        &[(
            "app.py",
            "def alpha():\n    pass\ndef beta():\n    pass\ndef gamma():\n    pass\n",
        )],
        json!({
            "union": [
                { "match": { "kind": "function", "name": "gamma" } },
                { "match": { "kind": "function" } }
            ],
            "limit": 2
        }),
    ));
    assert_eq!(result["truncated"], true, "{result}");
    let names = result["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            item["text"].as_str().unwrap()[4..]
                .split('(')
                .next()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(names, ["gamma", "alpha"], "{result}");
}

#[test]
fn set_composition_uses_exact_identity_for_every_typed_terminal_domain() {
    let project = InlineTestProject::new()
        .file(
            "app.ts",
            r#"class Service { run(payload: string) {} }
function target(payload: string) {}
export function caller() {
    const service = new Service();
    service.run("member");
    target("input");
}
"#,
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let cases = [
        (
            "structural_match",
            json!({ "match": { "kind": "function", "name": "target" } }),
        ),
        (
            "declaration",
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [{ "op": "enclosing_decl" }]
            }),
        ),
        (
            "file",
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [{ "op": "file_of" }]
            }),
        ),
        (
            "reference_site",
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "references_of", "proof": "proven" }
                ]
            }),
        ),
        (
            "call_site",
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "call_sites_to", "proof": "proven" }
                ]
            }),
        ),
        (
            "expression_site",
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [
                    { "op": "enclosing_decl" },
                    { "op": "call_sites_to", "proof": "proven" },
                    { "op": "call_input", "parameter_index": 0 }
                ]
            }),
        ),
        (
            "receiver_analysis",
            json!({
                "match": { "kind": "call", "callee": { "name": "run" } },
                "steps": [{ "op": "receiver_targets" }]
            }),
        ),
    ];

    for (expected_type, branch) in cases {
        let query = CodeQuery::from_json(&json!({
            "union": [branch.clone(), branch]
        }))
        .unwrap_or_else(|error| panic!("{expected_type} query: {error}"));
        let value = serialized(&execute(workspace.analyzer(), &query));
        let results = value["results"].as_array().unwrap();
        assert!(!results.is_empty(), "{expected_type}: {value}");
        assert!(
            results
                .iter()
                .all(|result| result["result_type"] == expected_type),
            "{expected_type}: {value}"
        );
        for result in results {
            let branches = result["provenance"]
                .as_array()
                .unwrap()
                .iter()
                .map(|trace| trace["branch"].clone())
                .collect::<Vec<_>>();
            assert_eq!(
                branches,
                [json!([0]), json!([1])],
                "{expected_type}: {value}"
            );
        }
    }
}

#[test]
fn composed_capability_diagnostics_identify_their_branch() {
    let result = serialized(&run(
        &[
            ("app.py", "audit(payload=\"ok\")\n"),
            ("app.js", "audit({ payload: 'unsupported' });\n"),
        ],
        json!({
            "union": [
                {
                    "languages": ["python"],
                    "match": {
                        "kind": "call",
                        "callee": { "name": "audit" },
                        "kwargs": { "payload": { "capture": "value" } }
                    }
                },
                {
                    "languages": ["javascript"],
                    "match": {
                        "kind": "call",
                        "callee": { "name": "audit" },
                        "kwargs": { "payload": { "capture": "value" } }
                    }
                }
            ]
        }),
    ));

    assert_eq!(result["results"].as_array().unwrap().len(), 1, "{result}");
    assert_eq!(result["results"][0]["provenance"][0]["branch"], json!([0]));
    assert!(
        result["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["branch"] == json!([1])
                && diagnostic["language"] == "javascript"
                && diagnostic["message"].as_str().unwrap().contains("kwargs")),
        "{result}"
    );
}
