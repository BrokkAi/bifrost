//! Planner-level tests for `search_ast` (issue #328, ExecPlan milestone 3):
//! anchor pruning skips files that provably cannot match, the facts cache
//! serves repeated queries without re-extraction, negation never prunes, and
//! unsupported workspace languages surface as diagnostics. Extraction counts
//! come from `StructuralSearchProvider::structural_extraction_count`, which
//! counts facts-cache misses (parse + normalize runs).

mod common;

use brokk_bifrost::AnalyzerConfig;
use brokk_bifrost::analyzer::structural::{
    AstQuery, SearchAstExecutionLimits, SearchAstOutput, execute, execute_with_limits,
};
use brokk_bifrost::{IAnalyzer, Language, WorkspaceAnalyzer};
use common::InlineTestProject;
use serde_json::json;

const USES_EVAL_PY: &str = r#"def handler(request):
    eval(request.form["q"])
"#;

const NO_EVAL_PY: &str = r#"def helper(value):
    print(value)
    return value
"#;

fn python_workspace() -> (common::BuiltInlineTestProject, WorkspaceAnalyzer) {
    let project = InlineTestProject::with_language(Language::Python)
        .file("src/uses_eval.py", USES_EVAL_PY)
        .file("src/no_eval.py", NO_EVAL_PY)
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    (project, workspace)
}

fn run(analyzer: &dyn IAnalyzer, query: serde_json::Value) -> SearchAstOutput {
    let query = AstQuery::from_json(&query).expect("query should parse");
    execute(analyzer, &query)
}

fn run_with_limits(
    analyzer: &dyn IAnalyzer,
    query: serde_json::Value,
    limits: SearchAstExecutionLimits,
) -> SearchAstOutput {
    let query = AstQuery::from_json(&query).expect("query should parse");
    execute_with_limits(analyzer, &query, limits)
}

fn extraction_count(analyzer: &dyn IAnalyzer) -> u64 {
    let providers = analyzer.structural_search_providers();
    assert_eq!(providers.len(), 1, "expected exactly one python provider");
    providers[0].structural_extraction_count()
}

#[test]
fn anchor_pruning_skips_files_without_the_anchor() {
    let (_project, workspace) = python_workspace();
    let analyzer = workspace.analyzer();

    let output = run(
        analyzer,
        json!({ "match": { "kind": "call", "callee": { "name": "eval" } } }),
    );
    assert_eq!(output.matches.len(), 1);
    assert_eq!(output.matches[0].path, "src/uses_eval.py");
    assert_eq!(
        extraction_count(analyzer),
        1,
        "no_eval.py lacks the literal anchor and must not be parsed"
    );
}

#[test]
fn facts_cache_serves_repeated_queries() {
    let (_project, workspace) = python_workspace();
    let analyzer = workspace.analyzer();

    // Unanchored query: both files are parsed once.
    let broad = json!({ "match": { "kind": "callable" } });
    let first = run(analyzer, broad.clone());
    assert_eq!(first.matches.len(), 2);
    assert_eq!(extraction_count(analyzer), 2);

    // Same query again: served entirely from the facts cache.
    let second = run(analyzer, broad);
    assert_eq!(second.matches.len(), 2);
    assert_eq!(
        extraction_count(analyzer),
        2,
        "second run must not re-parse"
    );

    // A different query still hits the same cached facts.
    run(analyzer, json!({ "match": { "kind": "call" } }));
    assert_eq!(extraction_count(analyzer), 2);
}

#[test]
fn negative_constraints_never_prune() {
    let (_project, workspace) = python_workspace();
    let analyzer = workspace.analyzer();

    // The negated names do not occur anywhere in no_eval.py. If negation
    // wrongly contributed anchors, the file would be skipped and the match
    // lost; correct behavior is to parse it and match.
    let output = run(
        analyzer,
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "print" },
                "not_has": { "name": "Sandbox" }
            },
            "not_inside": { "kind": "class", "name": "Sandbox" }
        }),
    );
    assert_eq!(output.matches.len(), 1);
    assert_eq!(output.matches[0].path, "src/no_eval.py");
}

#[test]
fn where_globs_prune_before_any_parse() {
    let (_project, workspace) = python_workspace();
    let analyzer = workspace.analyzer();

    let output = run(
        analyzer,
        json!({ "where": ["lib/**/*.py"], "match": { "kind": "call" } }),
    );
    assert!(output.matches.is_empty());
    assert_eq!(
        extraction_count(analyzer),
        0,
        "glob-excluded files must not parse"
    );
}

#[test]
fn where_globs_allow_matching_project_relative_paths() {
    let (_project, workspace) = python_workspace();
    let analyzer = workspace.analyzer();

    let output = run(
        analyzer,
        json!({
            "where": ["src/**/*.py"],
            "match": { "kind": "call", "callee": { "name": "eval" } }
        }),
    );
    assert_eq!(output.matches.len(), 1);
    assert_eq!(output.matches[0].path, "src/uses_eval.py");
}

#[test]
fn limit_truncates_across_files_deterministically() {
    let (_project, workspace) = python_workspace();
    let analyzer = workspace.analyzer();

    let output = run(
        analyzer,
        json!({ "match": { "kind": "callable" }, "limit": 1 }),
    );
    assert_eq!(output.matches.len(), 1);
    assert!(output.truncated);
    // Files are visited in sorted path order: no_eval.py before uses_eval.py.
    assert_eq!(output.matches[0].path, "src/no_eval.py");
}

#[test]
fn limit_stops_after_global_truncation_is_known() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("src/a.py", "def a():\n    pass\n")
        .file("src/b.py", "def b():\n    pass\n")
        .file("src/c.py", "def c():\n    pass\n")
        .file("src/d.py", "def d():\n    pass\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let analyzer = workspace.analyzer();

    let output = run(
        analyzer,
        json!({ "match": { "kind": "callable" }, "limit": 1 }),
    );
    assert_eq!(output.matches.len(), 1);
    assert!(output.truncated);
    assert_eq!(
        extraction_count(analyzer),
        2,
        "only enough files to prove global truncation should be parsed"
    );
}

#[test]
fn execution_budget_bounds_unanchored_no_match_queries() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("src/a.py", "def a():\n    print('a')\n")
        .file("src/b.py", "def b():\n    print('b')\n")
        .file("src/c.py", "def c():\n    print('c')\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let analyzer = workspace.analyzer();

    let output = run_with_limits(
        analyzer,
        json!({
            "match": { "kind": "call", "text": { "regex": "a^" } },
            "limit": 1
        }),
        SearchAstExecutionLimits {
            max_scanned_files: 1,
            max_scanned_source_bytes: usize::MAX,
            max_fact_nodes: usize::MAX,
        },
    );

    assert!(output.matches.is_empty(), "unexpected matches: {output:?}");
    assert!(output.truncated, "budget exhaustion should mark truncation");
    assert!(
        output
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.language == "workspace"
                && diagnostic.message.contains("execution budget")),
        "missing execution-budget diagnostic: {:?}",
        output.diagnostics
    );
    assert_eq!(
        extraction_count(analyzer),
        1,
        "budget should stop before parsing every unanchored candidate"
    );
}

#[test]
fn unsupported_languages_surface_as_diagnostics() {
    let project = InlineTestProject::new()
        .file("src/app.py", USES_EVAL_PY)
        .file("src/tool.rb", "def run\n  eval(input)\nend\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let analyzer = workspace.analyzer();

    let output = run(
        analyzer,
        json!({ "match": { "kind": "call", "callee": { "name": "eval" } } }),
    );
    // Python side still matches; the Ruby file is reported, not silently
    // skipped.
    assert_eq!(output.matches.len(), 1);
    assert_eq!(output.matches[0].language, "python");
    assert!(
        output
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.language == "ruby"),
        "expected a ruby capability diagnostic, got: {:?}",
        output.diagnostics
    );

    // An explicit language filter for an unsupported language yields no
    // matches but keeps the diagnostic.
    let filtered = run(
        analyzer,
        json!({ "languages": ["ruby"], "match": { "kind": "call" } }),
    );
    assert!(filtered.matches.is_empty());
    assert!(
        filtered
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.language == "ruby")
    );
}

#[test]
fn where_scope_suppresses_out_of_scope_language_diagnostics() {
    let project = InlineTestProject::new()
        .file("src/app.py", USES_EVAL_PY)
        .file("tools/tool.rb", "def run\n  eval(input)\nend\n")
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let analyzer = workspace.analyzer();

    let output = run(
        analyzer,
        json!({
            "where": ["src/**/*.py"],
            "match": { "kind": "call", "callee": { "name": "eval" } }
        }),
    );

    assert_eq!(output.matches.len(), 1);
    assert!(
        output.diagnostics.is_empty(),
        "ruby is outside the where scope and should not warn: {:?}",
        output.diagnostics
    );
}

#[test]
fn not_kind_precision_limits_surface_as_capability_diagnostics() {
    let (_project, workspace) = python_workspace();
    let analyzer = workspace.analyzer();

    let output = run(
        analyzer,
        json!({
            "languages": ["python"],
            "match": { "kind": "callable", "not_kind": "constructor" }
        }),
    );

    assert!(
        output
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.language == "python"
                && diagnostic.message.contains("constructor")),
        "not_kind constraints should be validated: {:?}",
        output.diagnostics
    );
}
