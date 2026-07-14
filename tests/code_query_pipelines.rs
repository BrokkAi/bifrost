mod common;

use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryExecutionLimits, CodeQueryResult, execute, execute_with_limits,
};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use common::InlineTestProject;
use serde_json::{Value, json};

fn run(files: &[(&str, &str)], query: Value) -> CodeQueryResult {
    let mut project = InlineTestProject::new();
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&query).expect("query should parse");
    execute(workspace.analyzer(), &query)
}

fn serialized(result: &CodeQueryResult) -> Value {
    serde_json::to_value(result).expect("query result should serialize")
}

fn result_fq_names(value: &Value) -> Vec<String> {
    value["results"]
        .as_array()
        .expect("results array")
        .iter()
        .map(|result| {
            result["fq_name"]
                .as_str()
                .expect("declaration fq_name")
                .to_string()
        })
        .collect()
}

#[test]
fn java_reference_steps_preserve_exact_site_and_semantic_owner() {
    let files = [
        ("Target.java", "class Target { int status; }\n"),
        (
            "User.java",
            "class User { int read(Target target) { return target.status; } }\n",
        ),
    ];
    let references = serialized(&run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "members" },
                { "op": "references_of" }
            ],
            "result_detail": "full"
        }),
    ));
    assert_eq!(
        references["results"].as_array().unwrap().len(),
        1,
        "{references}"
    );
    let site = &references["results"][0];
    assert_eq!(site["result_type"], "reference_site", "{references}");
    assert_eq!(site["path"], "User.java", "{references}");
    assert_eq!(site["target"]["fq_name"], "Target.status", "{references}");
    assert_eq!(
        site["enclosing_declaration"]["fq_name"], "User.read",
        "{references}"
    );
    assert_eq!(site["proof"], "proven", "{references}");
    assert!(
        site["range"]["start_column"].as_u64().unwrap() > 0,
        "{references}"
    );

    let used_by = serialized(&run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "members" },
                { "op": "used_by" }
            ]
        }),
    ));
    assert_eq!(result_fq_names(&used_by), vec!["User.read"], "{used_by}");
    assert_eq!(
        used_by["results"][0]["provenance"][0]["steps"][2]["via"]["result_type"], "reference_site",
        "{used_by}"
    );
}

#[test]
fn java_uses_is_inverse_of_used_by_and_reference_file_composes() {
    let files = [
        ("Target.java", "class Target { int status; }\n"),
        (
            "User.java",
            "class User { int read(Target target) { return target.status; } }\n",
        ),
    ];
    let uses = serialized(&run(
        &files,
        json!({
            "match": { "kind": "method", "name": "read" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "uses" }
            ]
        }),
    ));
    assert!(
        result_fq_names(&uses)
            .iter()
            .any(|name| name == "Target.status"),
        "{uses}"
    );
    let status = uses["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|result| result["fq_name"] == "Target.status")
        .expect("status dependency");
    assert_eq!(
        status["provenance"][0]["steps"][1]["via"]["target_fq_name"], "Target.status",
        "{uses}"
    );

    let files_result = serialized(&run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "members" },
                { "op": "references_of" },
                { "op": "file_of" }
            ]
        }),
    ));
    assert_eq!(
        files_result["results"][0]["path"], "User.java",
        "{files_result}"
    );
}

#[test]
fn java_reference_kind_filter_distinguishes_field_writes() {
    let result = serialized(&run(
        &[
            ("Target.java", "class Target { int status; }\n"),
            (
                "User.java",
                "class User { int update(Target target) { target.status = 1; return target.status; } }\n",
            ),
        ],
        json!({
            "match": { "kind": "class", "name": "Target" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "members" },
                { "op": "references_of", "reference_kinds": ["field_write"] }
            ]
        }),
    ));
    assert_eq!(result["results"].as_array().unwrap().len(), 1, "{result}");
    assert_eq!(
        result["results"][0]["reference_kind"], "field_write",
        "{result}"
    );
}

#[test]
fn enclosing_decl_is_inclusive_and_excludes_file_scope() {
    let files = [(
        "app.py",
        "class Outer:\n    def inner(self):\n        audit()\n\ndef audit():\n    pass\n\naudit()\n",
    )];
    let nested = run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "inside": { "kind": "method", "name": "inner" },
            "steps": [{ "op": "enclosing_decl" }]
        }),
    );
    let nested = serialized(&nested);
    assert_eq!(nested["results"][0]["result_type"], "declaration");
    assert_eq!(nested["results"][0]["kind"], "function");
    assert!(
        nested["results"][0]["fq_name"]
            .as_str()
            .is_some_and(|name| name.ends_with("inner")),
        "{nested}"
    );

    let declaration = run(
        &files,
        json!({
            "match": { "kind": "method", "name": "inner" },
            "steps": [{ "op": "enclosing_decl" }]
        }),
    );
    let declaration = serialized(&declaration);
    assert!(
        declaration["results"][0]["fq_name"]
            .as_str()
            .is_some_and(|name| name.ends_with("inner")),
        "{declaration}"
    );

    let top_level = run(
        &files,
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "not_inside": { "kind": "callable" },
            "steps": [{ "op": "enclosing_decl" }]
        }),
    );
    let top_level = serialized(&top_level);
    assert_eq!(
        top_level["results"][0]["result_type"], "declaration",
        "{top_level}"
    );
    assert_ne!(top_level["results"][0]["kind"], "file scope");
}

#[test]
fn enclosing_decl_skips_synthetic_cpp_members_for_real_parent() {
    let result = run(
        &[(
            "widget.cpp",
            "int audit();\nclass Widget {\npublic:\n    void run(int value = audit());\n};\n",
        )],
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "steps": [{ "op": "enclosing_decl" }]
        }),
    );
    let value = serialized(&result);
    assert_eq!(value["results"][0]["result_type"], "declaration", "{value}");
    assert_eq!(value["results"][0]["kind"], "class", "{value}");
    assert_eq!(value["results"][0]["fq_name"], "Widget", "{value}");
}

#[test]
fn full_results_include_stable_terminal_and_provenance_identities() {
    let result = run(
        &[(
            "app.py",
            "class Outer:\n    def inner(self):\n        audit()\n",
        )],
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "steps": [{ "op": "enclosing_decl" }],
            "result_detail": "full"
        }),
    );
    let value = serialized(&result);
    let terminal = &value["results"][0];
    assert_eq!(terminal["result_type"], "declaration", "{value}");
    assert!(terminal["id"].is_string(), "{value}");
    assert!(terminal["node_range"].is_object(), "{value}");

    let trace = &terminal["provenance"][0];
    assert_eq!(trace["seed"]["result_type"], "structural_match", "{value}");
    assert!(trace["seed"]["id"].is_string(), "{value}");
    assert!(trace["seed"]["node_range"].is_object(), "{value}");
    assert_eq!(trace["steps"][0]["op"], "enclosing_decl", "{value}");
    assert_eq!(trace["steps"][0]["result"]["id"], terminal["id"], "{value}");
}

#[test]
fn file_of_deduplicates_and_caps_deterministic_provenance() {
    let calls = (0..17)
        .map(|_| "    audit()")
        .collect::<Vec<_>>()
        .join("\n");
    let source = format!("def run():\n{calls}\n");
    let result = run(
        &[("app.py", &source)],
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "steps": [{ "op": "file_of" }]
        }),
    );
    let value = serialized(&result);
    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["results"][0]["result_type"], "file");
    assert_eq!(value["results"][0]["path"], "app.py");
    assert_eq!(
        value["results"][0]["provenance"].as_array().unwrap().len(),
        16
    );
    assert_eq!(value["results"][0]["provenance_truncated"], true);
}

#[test]
fn ruby_importers_are_direct_and_repeat_for_multiple_hops() {
    let files = [
        ("a.rb", "require_relative 'b'\ndef from_a; end\n"),
        ("b.rb", "require_relative 'c'\ndef from_b; end\n"),
        ("c.rb", "def target; end\n"),
    ];
    let direct = run(
        &files,
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
        }),
    );
    let direct = serialized(&direct);
    assert_eq!(direct["results"].as_array().unwrap().len(), 1, "{direct}");
    assert_eq!(direct["results"][0]["path"], "b.rb");

    let repeated = run(
        &files,
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [
                { "op": "file_of" },
                { "op": "importers_of" },
                { "op": "importers_of" }
            ]
        }),
    );
    let repeated = serialized(&repeated);
    assert_eq!(
        repeated["results"].as_array().unwrap().len(),
        1,
        "{repeated}"
    );
    assert_eq!(repeated["results"][0]["path"], "a.rb");
}

#[test]
fn importers_of_does_not_require_target_language_provider() {
    let result = run(
        &[
            (
                "a.rb",
                "require_relative 'target.php'\ndef from_ruby; end\n",
            ),
            ("target.php", "<?php\nfunction target() {}\n"),
        ],
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
        }),
    );
    let value = serialized(&result);
    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["results"][0]["path"], "a.rb", "{value}");
}

#[test]
fn side_effect_import_keeps_declaration_free_file_edge() {
    let result = run(
        &[
            (
                "entry.js",
                "import './empty.js';\nexport function target() {}\n",
            ),
            ("empty.js", "// side effect only\n"),
        ],
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [{ "op": "file_of" }, { "op": "imports_of" }]
        }),
    );
    let value = serialized(&result);
    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["results"][0]["path"], "empty.js", "{value}");
}

#[test]
fn file_level_import_resolvers_keep_declaration_free_targets() {
    let cases = [
        (
            vec![
                ("go.mod", "module example.com/app\n\ngo 1.22\n"),
                (
                    "main.go",
                    "package main\nimport _ \"example.com/app/sideeffects\"\nfunc target() {}\n",
                ),
                ("sideeffects/init.go", "package sideeffects\n"),
            ],
            "sideeffects/init.go",
        ),
        (
            vec![
                (
                    "entry.ts",
                    "import './empty';\nexport function target() {}\n",
                ),
                ("empty.ts", "// side effect only\n"),
            ],
            "empty.ts",
        ),
        (
            vec![
                (
                    "main.cpp",
                    "#include \"empty.h\"\nint target() { return 1; }\n",
                ),
                ("empty.h", "// intentionally empty\n"),
            ],
            "empty.h",
        ),
    ];

    for (files, expected) in cases {
        let result = run(
            &files,
            json!({
                "match": { "kind": "function", "name": "target" },
                "steps": [{ "op": "file_of" }, { "op": "imports_of" }]
            }),
        );
        let value = serialized(&result);
        assert_eq!(
            value["results"].as_array().unwrap().len(),
            1,
            "expected {expected}: {value}"
        );
        assert_eq!(value["results"][0]["path"], expected, "{value}");
    }
}

#[test]
fn direct_importers_work_across_supported_language_adapters() {
    let cases = [
        (
            "python",
            "target",
            vec![
                ("target.py", "def target():\n    pass\n"),
                (
                    "consumer.py",
                    "from target import target\n\ndef consume():\n    target()\n",
                ),
            ],
            "consumer.py",
        ),
        (
            "java",
            "target",
            vec![
                (
                    "example/Target.java",
                    "package example;\npublic class Target { public static void target() {} }\n",
                ),
                (
                    "example/Consumer.java",
                    "package example;\nimport example.Target;\npublic class Consumer { void consume() { Target.target(); } }\n",
                ),
            ],
            "example/Consumer.java",
        ),
        (
            "javascript",
            "target",
            vec![
                ("target.js", "export function target() {}\n"),
                (
                    "consumer.js",
                    "import { target } from './target.js';\ntarget();\n",
                ),
            ],
            "consumer.js",
        ),
        (
            "typescript",
            "target",
            vec![
                ("target.ts", "export function target(): void {}\n"),
                (
                    "consumer.ts",
                    "import { target } from './target';\ntarget();\n",
                ),
            ],
            "consumer.ts",
        ),
        (
            "go",
            "Target",
            vec![
                ("go.mod", "module example.com/project\n\ngo 1.22\n"),
                ("target/target.go", "package target\nfunc Target() {}\n"),
                (
                    "main.go",
                    "package main\nimport \"example.com/project/target\"\nfunc consume() { target.Target() }\n",
                ),
            ],
            "main.go",
        ),
        (
            "cpp",
            "target",
            vec![
                ("target.h", "inline int target() { return 0; }\n"),
                (
                    "main.cpp",
                    "#include \"target.h\"\nint consume() { return target(); }\n",
                ),
            ],
            "main.cpp",
        ),
        (
            "rust",
            "target",
            vec![
                (
                    "Cargo.toml",
                    "[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                ),
                ("src/shared.rs", "pub fn target() {}\n"),
                (
                    "src/main.rs",
                    "mod shared;\nuse crate::shared::target;\nfn consume() { target(); }\n",
                ),
            ],
            "src/main.rs",
        ),
        (
            "scala",
            "target",
            vec![
                (
                    "example/Target.scala",
                    "package example\nobject Target { def target(): Unit = () }\n",
                ),
                (
                    "example/Consumer.scala",
                    "package example\nimport example.Target\nobject Consumer { def consume(): Unit = Target.target() }\n",
                ),
            ],
            "example/Consumer.scala",
        ),
        (
            "csharp",
            "target",
            vec![
                (
                    "Target.cs",
                    "namespace Example; public class Target { public static void target() {} }\n",
                ),
                (
                    "Consumer.cs",
                    "using Example; public class Consumer { void Consume() { Target.target(); } }\n",
                ),
            ],
            "Consumer.cs",
        ),
        (
            "ruby",
            "target",
            vec![
                ("target.rb", "def target; end\n"),
                (
                    "consumer.rb",
                    "require_relative 'target'\ndef consume; target; end\n",
                ),
            ],
            "consumer.rb",
        ),
    ];

    for (language, name, files, expected) in cases {
        let result = run(
            &files,
            json!({
                "languages": [language],
                "match": { "kind": "callable", "name": name },
                "steps": [{ "op": "file_of" }, { "op": "importers_of" }]
            }),
        );
        let value = serialized(&result);
        assert_eq!(
            value["results"].as_array().unwrap().len(),
            1,
            "{language}: {value}"
        );
        assert_eq!(value["results"][0]["path"], expected, "{language}: {value}");
    }
}

#[test]
fn imports_of_is_direct_and_cycles_terminate() {
    let files = [
        ("a.rb", "require_relative 'b'\ndef target; end\n"),
        ("b.rb", "require_relative 'c'\ndef from_b; end\n"),
        ("c.rb", "require_relative 'a'\ndef from_c; end\n"),
    ];
    let result = run(
        &files,
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [
                { "op": "file_of" },
                { "op": "imports_of" },
                { "op": "imports_of" },
                { "op": "imports_of" }
            ]
        }),
    );
    let value = serialized(&result);
    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["results"][0]["path"], "a.rb");
    assert!(!result.truncated);
}

#[test]
fn unsupported_import_provider_is_diagnostic_not_silent() {
    let result = run(
        &[("app.php", "<?php\nfunction target() {}\n")],
        json!({
            "match": { "kind": "function", "name": "target" },
            "steps": [{ "op": "file_of" }, { "op": "imports_of" }]
        }),
    );
    let value = serialized(&result);
    assert!(value["results"].as_array().unwrap().is_empty(), "{value}");
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.language == "php"
                && diagnostic.message.contains("structured import analysis")),
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn terminal_limit_is_applied_after_file_deduplication() {
    let result = run(
        &[
            ("a.py", "audit()\naudit()\n"),
            ("b.py", "audit()\naudit()\n"),
        ],
        json!({
            "match": { "kind": "call", "callee": { "name": "audit" } },
            "steps": [{ "op": "file_of" }],
            "limit": 1
        }),
    );
    let value = serialized(&result);
    assert_eq!(value["results"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["results"][0]["path"], "a.py");
    assert!(result.truncated);
}

#[test]
fn pipeline_budget_returns_partial_results_with_diagnostic() {
    let project = InlineTestProject::new()
        .file("app.py", "audit()\naudit()\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "audit" } },
        "steps": [{ "op": "file_of" }]
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
    assert!(result.truncated);
    assert_eq!(result.results.len(), 1);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("pipeline budget exhausted")),
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn intermediate_budget_exhaustion_never_returns_wrong_terminal_type() {
    let project = InlineTestProject::new()
        .file("app.py", "def run():\n    audit()\n    audit()\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "audit" } },
        "steps": [{ "op": "enclosing_decl" }, { "op": "file_of" }]
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
    assert!(result.truncated);
    assert!(
        result.results.is_empty(),
        "intermediate rows must not escape"
    );
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.message.contains("pipeline budget exhausted"))
            .count(),
        1,
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn hierarchy_steps_are_direct_by_default_and_depth_is_a_bounded_closure() {
    let files = [(
        "hierarchy.py",
        "class Root:\n    pass\n\nclass Left(Root):\n    pass\n\nclass Right(Root):\n    pass\n\nclass Leaf(Left, Right):\n    pass\n",
    )];

    let direct = serialized(&run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Leaf" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }]
        }),
    ));
    assert_eq!(
        result_fq_names(&direct),
        vec!["hierarchy.Left", "hierarchy.Right"]
    );

    let bounded = serialized(&run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Leaf" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "supertypes", "depth": 2 }
            ]
        }),
    ));
    assert_eq!(
        result_fq_names(&bounded),
        vec!["hierarchy.Left", "hierarchy.Right", "hierarchy.Root"]
    );
    let root = bounded["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|result| result["fq_name"] == "hierarchy.Root")
        .unwrap();
    assert_eq!(root["provenance"].as_array().unwrap().len(), 2, "{bounded}");
    assert!(
        root["provenance"]
            .as_array()
            .unwrap()
            .iter()
            .all(|trace| trace["steps"].as_array().unwrap().len() == 3),
        "enclosing_decl plus two hierarchy edges should be visible: {bounded}"
    );

    let descendants = serialized(&run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Root" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "subtypes", "transitive": true }
            ]
        }),
    ));
    assert_eq!(
        result_fq_names(&descendants),
        vec!["hierarchy.Left", "hierarchy.Right", "hierarchy.Leaf"]
    );
}

#[test]
fn members_and_owner_preserve_overload_identity_and_round_trip() {
    let files = [(
        "Service.java",
        "class Service {\n  int value;\n  int run(int input) { return input; }\n  String run(String input) { return input; }\n  class Nested {}\n}\n",
    )];
    let members = serialized(&run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Service" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "members" }]
        }),
    ));
    let results = members["results"].as_array().unwrap();
    assert_eq!(
        results
            .iter()
            .filter(|result| result["fq_name"] == "Service.run")
            .count(),
        2,
        "{members}"
    );
    assert!(
        results
            .iter()
            .any(|result| result["fq_name"] == "Service.value"),
        "{members}"
    );
    assert!(
        results
            .iter()
            .any(|result| result["fq_name"] == "Service.Nested"),
        "{members}"
    );

    let owner = serialized(&run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Service" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "members" },
                { "op": "owner" }
            ]
        }),
    ));
    assert_eq!(result_fq_names(&owner), vec!["Service"]);
    assert!(owner["results"][0]["provenance"].as_array().unwrap().len() >= 4);
}

#[test]
fn ruby_modules_are_type_owners_for_members_and_owner() {
    let result = serialized(&run(
        &[("tools.rb", "module Tools\n  def run\n  end\nend\n")],
        json!({
            "match": { "kind": "class", "name": "Tools" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "members" },
                { "op": "owner" }
            ]
        }),
    ));
    assert_eq!(result_fq_names(&result), vec!["Tools"]);
    assert_eq!(result["results"][0]["kind"], "module", "{result}");
}

#[test]
fn invalid_semantic_inputs_are_diagnostic_but_supported_leaves_are_not() {
    let files = [(
        "app.py",
        "def helper():\n    pass\n\nclass Leaf:\n    pass\n",
    )];
    let invalid = run(
        &files,
        json!({
            "match": { "kind": "function", "name": "helper" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "members" }]
        }),
    );
    assert!(invalid.results.is_empty());
    assert!(
        invalid
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("not a type declaration")),
        "{:?}",
        invalid.diagnostics
    );

    let invalid_hierarchy = run(
        &files,
        json!({
            "match": { "kind": "function", "name": "helper" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }]
        }),
    );
    assert!(invalid_hierarchy.results.is_empty());
    assert!(
        invalid_hierarchy
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic
                .message
                .contains("not a supported type declaration")),
        "{:?}",
        invalid_hierarchy.diagnostics
    );

    let leaf = run(
        &files,
        json!({
            "match": { "kind": "class", "name": "Leaf" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }]
        }),
    );
    assert!(leaf.results.is_empty());
    assert!(leaf.diagnostics.is_empty(), "{:?}", leaf.diagnostics);
}

#[test]
fn mixed_valid_and_invalid_hierarchy_inputs_keep_valid_rows() {
    let result = serialized(&run(
        &[(
            "mixed.py",
            "class Root:\n    pass\n\nclass Child(Root):\n    pass\n\ndef helper():\n    pass\n",
        )],
        json!({
            "match": {
                "kind": "declaration",
                "name": { "regex": "^(Child|helper)$" }
            },
            "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }]
        }),
    ));
    assert_eq!(result_fq_names(&result), vec!["mixed.Root"]);
    assert_eq!(
        result["diagnostics"].as_array().unwrap().len(),
        1,
        "{result}"
    );
    assert!(
        result["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("omitted 1 input"),
        "{result}"
    );
}

#[test]
fn hierarchy_preserves_module_scoped_identity_and_cycles_do_not_return_the_seed() {
    let exact = serialized(&run(
        &[
            ("p1/Base.java", "package p1; public class Base {}\n"),
            ("p2/Base.java", "package p2; public class Base {}\n"),
            (
                "p1/Child.java",
                "package p1; public class Child extends Base {}\n",
            ),
        ],
        json!({
            "match": { "kind": "class", "name": "Child" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }]
        }),
    ));
    assert_eq!(result_fq_names(&exact), vec!["p1.Base"]);

    let cyclic = serialized(&run(
        &[("cycle.py", "class A(B):\n    pass\nclass B(A):\n    pass\n")],
        json!({
            "match": { "kind": "class", "name": "A" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "supertypes", "transitive": true }
            ]
        }),
    ));
    assert_eq!(result_fq_names(&cyclic), vec!["cycle.B"]);
}

#[test]
fn subtypes_and_owner_preserve_duplicate_fq_name_identity() {
    let files = [
        (
            "left/Types.java",
            "package duplicate; class Base { void leftMember() {} } class LeftChild extends Base {}\n",
        ),
        (
            "right/Types.java",
            "package duplicate; class Base { void rightMember() {} } class RightChild extends Base {}\n",
        ),
    ];
    let subtypes = serialized(&run(
        &files,
        json!({
            "where": ["left/**"],
            "match": { "kind": "class", "name": "Base" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "subtypes" }]
        }),
    ));
    assert_eq!(result_fq_names(&subtypes), vec!["duplicate.LeftChild"]);
    assert_eq!(
        subtypes["results"][0]["path"], "left/Types.java",
        "{subtypes}"
    );

    let owner = serialized(&run(
        &files,
        json!({
            "where": ["left/**"],
            "match": { "kind": "class", "name": "Base" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "members" },
                { "op": "owner" }
            ]
        }),
    ));
    assert_eq!(result_fq_names(&owner), vec!["duplicate.Base"]);
    assert_eq!(owner["results"][0]["path"], "left/Types.java", "{owner}");
}

#[test]
fn empty_semantic_frontier_does_not_project_workspace_declarations() {
    let project = InlineTestProject::new()
        .file("app.py", "class Present:\n    pass\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    workspace
        .analyzer()
        .reset_full_declaration_scan_count_for_test();
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "class", "name": "Missing" },
        "steps": [{ "op": "enclosing_decl" }, { "op": "members" }]
    }))
    .unwrap();
    let result = execute(workspace.analyzer(), &query);
    assert!(result.results.is_empty());
    assert_eq!(
        workspace.analyzer().full_declaration_scan_count_for_test(),
        0
    );
}

#[test]
fn narrow_semantic_query_does_not_project_workspace_declarations() {
    let project = InlineTestProject::new()
        .file(
            "target.py",
            "class Target:\n    def member(self):\n        pass\n",
        )
        .file("unrelated_a.py", "class UnrelatedA:\n    pass\n")
        .file("unrelated_b.py", "class UnrelatedB:\n    pass\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    workspace
        .analyzer()
        .reset_full_declaration_scan_count_for_test();
    let query = CodeQuery::from_json(&json!({
        "where": ["target.py"],
        "match": { "kind": "class", "name": "Target" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "members" },
            { "op": "owner" }
        ]
    }))
    .unwrap();
    let result = execute(workspace.analyzer(), &query);
    assert_eq!(result.results.len(), 1);
    assert_eq!(
        workspace.analyzer().full_declaration_scan_count_for_test(),
        0
    );
}

#[test]
fn members_stop_examining_edges_at_the_pipeline_budget() {
    let methods = (0..20)
        .map(|index| format!("    def member_{index}(self):\n        pass\n"))
        .collect::<String>();
    let project = InlineTestProject::new()
        .file("wide.py", format!("class Wide:\n{methods}"))
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "class", "name": "Wide" },
        "steps": [{ "op": "enclosing_decl" }, { "op": "members" }],
        "limit": 100
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
    assert!(result.truncated);
    assert_eq!(result.results.len(), 1);
}

#[test]
fn standalone_owner_stops_scanning_at_the_pipeline_budget() {
    let project = InlineTestProject::new()
        .file(
            "Owners.java",
            "class A {} class B {} class ZTarget { void target() { sink(); } void sink() {} }\n",
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "sink" } },
        "steps": [{ "op": "enclosing_decl" }, { "op": "owner" }]
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
    assert!(result.results.is_empty(), "{value}");
}

#[test]
fn deep_hierarchy_provenance_is_bounded_by_pipeline_work_budget() {
    let mut source = String::from("class C0:\n    pass\n");
    for index in 1..200 {
        source.push_str(&format!("class C{index}(C{}):\n    pass\n", index - 1));
    }
    let project = InlineTestProject::new().file("deep.py", source).build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "class", "name": "C0" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "subtypes", "transitive": true }
        ],
        "limit": 1000
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 1000,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(result.truncated);
    assert!(result.results.len() < 100, "{}", result.results.len());
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.message.contains("pipeline budget exhausted") })
    );
}

#[test]
fn hierarchy_does_not_manufacture_unindexed_library_declarations() {
    let result = run(
        &[("app.py", "class Local(ExternalLibraryType):\n    pass\n")],
        json!({
            "match": { "kind": "class", "name": "Local" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "supertypes" }]
        }),
    );
    assert!(result.results.is_empty());
    assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
}

#[test]
fn hierarchy_budget_is_terminally_partial_but_not_intermediately_mistyped() {
    let project = InlineTestProject::new()
        .file(
            "hierarchy.py",
            "class Root:\n    pass\nclass Left(Root):\n    pass\nclass Right(Root):\n    pass\n",
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let terminal = CodeQuery::from_json(&json!({
        "match": { "kind": "class", "name": "Root" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "subtypes", "transitive": true }
        ]
    }))
    .unwrap();
    let terminal = execute_with_limits(
        workspace.analyzer(),
        &terminal,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 3,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(terminal.truncated);
    assert_eq!(terminal.results.len(), 1);

    let intermediate = CodeQuery::from_json(&json!({
        "match": { "kind": "class", "name": "Root" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "subtypes", "transitive": true },
            { "op": "members" }
        ]
    }))
    .unwrap();
    let intermediate = execute_with_limits(
        workspace.analyzer(),
        &intermediate,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 3,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(intermediate.truncated);
    assert!(intermediate.results.is_empty());
}

#[test]
fn seed_budget_emits_one_aggregated_diagnostic() {
    let project = InlineTestProject::new()
        .file("app.py", "audit()\naudit()\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": "audit" } },
        "steps": [{ "op": "file_of" }]
    }))
    .unwrap();
    let result = execute_with_limits(
        workspace.analyzer(),
        &query,
        CodeQueryExecutionLimits {
            max_pipeline_rows: 1,
            ..CodeQueryExecutionLimits::default()
        },
    );
    assert!(result.truncated);
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.message.contains("pipeline budget exhausted"))
            .count(),
        1,
        "{:?}",
        result.diagnostics
    );
}

#[test]
fn invalid_programmatic_pipeline_is_diagnostic_not_panic() {
    let project = InlineTestProject::new().file("app.py", "audit()\n").build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let mut query = CodeQuery::from_json(&json!({
        "match": { "kind": "call" }
    }))
    .unwrap();
    query.steps = vec![brokk_bifrost::analyzer::structural::QueryStep::ImportsOf];

    let result = execute(workspace.analyzer(), &query);
    assert!(result.results.is_empty());
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("invalid query at steps[0]")),
        "{:?}",
        result.diagnostics
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
    assert!(
        result
            .diagnostics
            .iter()
            .all(|diagnostic| !diagnostic.message.contains("import graph budget exhausted"))
    );
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
            .filter(|diagnostic| diagnostic.message.contains("import graph budget exhausted"))
            .count(),
        1,
        "{:?}",
        result.diagnostics
    );
}
