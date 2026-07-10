//! Planner-level tests for `search_ast` (issue #328, ExecPlan milestone 3):
//! anchor pruning skips files that provably cannot match, the facts cache
//! serves repeated queries without re-extraction, negation never prunes, and
//! language scoping and capability diagnostics stay deterministic. Extraction counts
//! come from `StructuralSearchProvider::structural_extraction_count`, which
//! counts facts-cache misses (parse + normalize runs).

mod common;

use brokk_bifrost::analyzer::structural::{
    AstQuery, SearchAstExecutionLimits, SearchAstOutput, execute, execute_with_limits,
};
use brokk_bifrost::{
    AnalyzerConfig, CodeUnit, DeclarationInfo, IAnalyzer, Language, Project, ProjectFile, Range,
    WorkspaceAnalyzer,
};
use common::InlineTestProject;
use serde_json::json;
use std::collections::BTreeSet;
use std::sync::Arc;

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

#[derive(Clone)]
struct NoProviderAnalyzer {
    project: Arc<dyn Project>,
    files: BTreeSet<ProjectFile>,
    languages: BTreeSet<Language>,
}

impl NoProviderAnalyzer {
    fn new(project: Arc<dyn Project>, file: ProjectFile, language: Language) -> Self {
        Self {
            project,
            files: BTreeSet::from([file]),
            languages: BTreeSet::from([language]),
        }
    }
}

impl IAnalyzer for NoProviderAnalyzer {
    fn indexed_source<'a>(&'a self, _file: &ProjectFile) -> Option<&'a str> {
        None
    }

    fn analyzed_files<'a>(&'a self) -> Box<dyn Iterator<Item = &'a ProjectFile> + 'a> {
        Box::new(self.files.iter())
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.languages.clone()
    }

    fn update(&self, _changed_files: &BTreeSet<ProjectFile>) -> Self
    where
        Self: Sized,
    {
        self.clone()
    }

    fn update_all(&self) -> Self
    where
        Self: Sized,
    {
        self.clone()
    }

    fn project(&self) -> &dyn Project {
        self.project.as_ref()
    }

    fn all_declarations<'a>(&'a self) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        Box::new(std::iter::empty())
    }

    fn extract_call_receiver(&self, _reference: &str) -> Option<String> {
        None
    }

    fn enclosing_code_unit(&self, _file: &ProjectFile, _range: &Range) -> Option<CodeUnit> {
        None
    }

    fn enclosing_code_unit_for_lines(
        &self,
        _file: &ProjectFile,
        _start_line: usize,
        _end_line: usize,
    ) -> Option<CodeUnit> {
        None
    }

    fn is_access_expression(
        &self,
        _file: &ProjectFile,
        _start_byte: usize,
        _end_byte: usize,
    ) -> bool {
        false
    }

    fn find_nearest_declaration(
        &self,
        _file: &ProjectFile,
        _start_byte: usize,
        _end_byte: usize,
        _ident: &str,
    ) -> Option<DeclarationInfo> {
        None
    }

    fn get_skeleton(&self, _code_unit: &CodeUnit) -> Option<String> {
        None
    }

    fn get_skeleton_header(&self, _code_unit: &CodeUnit) -> Option<String> {
        None
    }

    fn get_source(&self, _code_unit: &CodeUnit, _include_comments: bool) -> Option<String> {
        None
    }

    fn get_sources(&self, _code_unit: &CodeUnit, _include_comments: bool) -> BTreeSet<String> {
        BTreeSet::new()
    }

    fn search_definitions(&self, _pattern: &str, _auto_quote: bool) -> BTreeSet<CodeUnit> {
        BTreeSet::new()
    }
}

fn assert_truncation_diagnostic(output: &SearchAstOutput, limit: usize) {
    assert!(
        output
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.language == "workspace"
                && diagnostic
                    .message
                    .contains(&format!("returned the first {limit} matches"))
                && diagnostic.message.contains("after scanning")
                && diagnostic.message.contains("project-relative path")
                && diagnostic.message.contains("where")
                && diagnostic.message.contains("languages")
                && diagnostic.message.contains("exact")),
        "missing truncation diagnostic: {:?}",
        output.diagnostics
    );
}

fn has_broad_query_diagnostic(output: &SearchAstOutput) -> bool {
    output.diagnostics.iter().any(|diagnostic| {
        diagnostic.language == "workspace"
            && diagnostic.message.contains("broad unanchored")
            && diagnostic.message.contains("where")
            && diagnostic.message.contains("languages")
            && diagnostic.message.contains("exact name")
    })
}

fn assert_broad_query_diagnostic(output: &SearchAstOutput) {
    assert!(
        has_broad_query_diagnostic(output),
        "missing broad-query diagnostic: {:?}",
        output.diagnostics
    );
}

fn assert_no_broad_query_diagnostic(output: &SearchAstOutput) {
    assert!(
        !has_broad_query_diagnostic(output),
        "unexpected broad-query diagnostic: {:?}",
        output.diagnostics
    );
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
    assert_truncation_diagnostic(&output, 1);
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
    assert_truncation_diagnostic(&output, 1);
    assert_eq!(
        extraction_count(analyzer),
        2,
        "only enough files to prove global truncation should be parsed"
    );
}

#[test]
fn broad_unanchored_truncated_queries_get_guidance() {
    let (_project, workspace) = python_workspace();
    let analyzer = workspace.analyzer();

    let output = run(
        analyzer,
        json!({ "match": { "kind": "callable" }, "limit": 1 }),
    );

    assert!(output.truncated);
    assert_truncation_diagnostic(&output, 1);
    assert_broad_query_diagnostic(&output);
}

#[test]
fn anchored_and_scoped_queries_do_not_get_broad_guidance() {
    let (_project, workspace) = python_workspace();
    let analyzer = workspace.analyzer();

    let anchored = run(
        analyzer,
        json!({ "match": { "kind": "call", "callee": { "name": "eval" } } }),
    );
    assert_eq!(anchored.matches.len(), 1);
    assert!(!anchored.truncated);
    assert_no_broad_query_diagnostic(&anchored);

    let scoped = run(
        analyzer,
        json!({ "languages": ["python"], "match": { "kind": "callable" }, "limit": 1 }),
    );
    assert!(scoped.truncated);
    assert_truncation_diagnostic(&scoped, 1);
    assert_no_broad_query_diagnostic(&scoped);
}

#[test]
fn broad_unanchored_large_complete_queries_get_guidance() {
    let mut project = InlineTestProject::with_language(Language::Python);
    for index in 0..100 {
        project = project.file(
            format!("src/file_{index:03}.py"),
            format!("def function_{index}():\n    pass\n"),
        );
    }
    let project = project.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let analyzer = workspace.analyzer();

    let output = run(analyzer, json!({ "match": { "kind": "class" } }));

    assert!(output.matches.is_empty(), "unexpected matches: {output:?}");
    assert!(!output.truncated);
    assert_broad_query_diagnostic(&output);
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
fn analyzer_language_without_provider_surfaces_as_diagnostic() {
    let project = InlineTestProject::new()
        .file("src/tool.rb", "def run\n  eval(input)\nend\n")
        .build();
    let analyzer = NoProviderAnalyzer::new(
        project.project_dyn(),
        project.file("src/tool.rb"),
        Language::Ruby,
    );

    let output = run(
        &analyzer,
        json!({ "match": { "kind": "call", "callee": { "name": "eval" } } }),
    );

    assert!(output.matches.is_empty(), "unexpected matches: {output:?}");
    assert!(
        output
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.language == "ruby"
                && diagnostic
                    .message
                    .contains("no structural adapter for ruby yet")),
        "expected a ruby no-provider diagnostic, got: {:?}",
        output.diagnostics
    );
}

#[test]
fn formerly_unsupported_languages_are_searched_after_adapter_registration() {
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
    assert_eq!(output.matches.len(), 2);
    let languages: Vec<_> = output.matches.iter().map(|mat| mat.language).collect();
    assert_eq!(languages, vec!["python", "ruby"]);
    assert!(
        output.diagnostics.is_empty(),
        "ruby now has a structural adapter and should not warn: {:?}",
        output.diagnostics
    );

    // An explicit language filter searches the registered Ruby provider.
    let filtered = run(
        analyzer,
        json!({ "languages": ["ruby"], "match": { "kind": "call" } }),
    );
    assert_eq!(filtered.matches.len(), 1);
    assert_eq!(filtered.matches[0].language, "ruby");
    assert!(
        filtered.diagnostics.is_empty(),
        "explicit ruby search should not produce adapter diagnostics: {:?}",
        filtered.diagnostics
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
