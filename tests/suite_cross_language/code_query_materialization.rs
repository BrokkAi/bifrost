//! End-to-end conformance for the declaration-materialization typed domains
//! (#1476, Milestone 6), one scenario per mined-commit shape.
//!
//! Every scenario runs the public query surface over an inline fixture and
//! asserts either classified rows or an honest incomplete/unsupported
//! diagnostic — never a silently empty complete answer.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryDiagnosticCode, CodeQueryResult, execute_workspace,
};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use serde_json::{Value, json};

fn run(files: &[(&str, &str)], query: Value) -> CodeQueryResult {
    let mut project = InlineTestProject::new();
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&query).expect("query should parse");
    execute_workspace(&workspace, &query)
}

fn serialized(result: &CodeQueryResult) -> Value {
    serde_json::to_value(result).expect("query result should serialize")
}

fn rows(value: &Value) -> &Vec<Value> {
    value["results"].as_array().expect("results array")
}

fn strings(value: &Value, field: &str) -> Vec<String> {
    rows(value)
        .iter()
        .filter_map(|row| row[field].as_str().map(str::to_string))
        .collect()
}

fn has_diagnostic(result: &CodeQueryResult, code: CodeQueryDiagnosticCode) -> bool {
    result
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == code)
}

/// 96e332f/97876f4: literal Ruby generation, including the singleton context
/// and the alias whose *target* must not become a second declaration.
const RUBY_GENERATION: &str = "\
class Widget
  attr_accessor :name

  class << self
    attr_reader :registry
  end

  def base; end
  alias_method :aliased, :base
end
";

/// 97876f4's near miss: a dynamic macro name generates something the analyzer
/// must refuse to name.
const RUBY_DYNAMIC: &str = "class Widget\n  attr_reader label.to_sym\nend\n";

#[test]
fn ruby_literal_generation_has_exact_sets_and_alias_targets_are_not_declared() {
    let result = run(
        &[("lib/widget.rb", RUBY_GENERATION)],
        json!({ "generation_sites": {}, "steps": [{ "op": "generates" }] }),
    );
    assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
    let value = serialized(&result);
    let generated = strings(&value, "fq_name");
    assert_eq!(
        generated,
        vec![
            "Widget.@name",
            "Widget.name",
            "Widget.name=",
            // The singleton-context reader keeps its singleton identity.
            "Widget.$singleton.@registry",
            "Widget.registry",
            // The alias generates exactly one method; its target `base`
            // stays a parsed declaration rather than a second generated one.
            "Widget.aliased",
        ],
        "{value:#}"
    );
    assert!(
        strings(&value, "origin")
            .iter()
            .all(|origin| origin == "generated"),
        "{value:#}"
    );

    // The inverse join: the generated reader points back at exactly one site.
    let result = run(
        &[("lib/widget.rb", RUBY_GENERATION)],
        json!({
            "generation_sites": {},
            "steps": [
                { "op": "generates" },
                { "op": "generated_by" },
            ],
        }),
    );
    let value = serialized(&result);
    // Three literal sites, each rejoined from its generated set.
    assert_eq!(rows(&value).len(), 3, "{value:#}");
}

#[test]
fn ruby_dynamic_generation_is_incomplete_never_empty() {
    let result = run(
        &[("lib/widget.rb", RUBY_DYNAMIC)],
        json!({ "generation_sites": { "input": ["dynamic"] } }),
    );
    let value = serialized(&result);
    assert_eq!(
        rows(&value).len(),
        1,
        "the site itself is visible: {value:#}"
    );
    assert!(
        has_diagnostic(
            &result,
            CodeQueryDiagnosticCode::MaterializationDerivationIncomplete
        ),
        "{:?}",
        result.diagnostics
    );
}

/// da26602: @overload stubs are declaration-only and link to the runnable
/// def; the orphan's missing implementation is expressible as set difference.
const PYTHON_OVERLOADS: &str = "\
from typing import overload
@overload
def parse(value: int) -> int: ...
@overload
def parse(value: str) -> str: ...
def parse(value):
    return value
@overload
def orphan(value: int) -> int: ...
";

#[test]
fn python_overload_stubs_link_to_their_implementation() {
    let files = &[("app/over.py", PYTHON_OVERLOADS)];
    let result = run(
        files,
        json!({
            "match": { "kind": "callable" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "declaration_state_of", "declaration_only": true },
                { "op": "implementation_of" },
            ],
        }),
    );
    assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
    let value = serialized(&result);
    let implementations = strings(&value, "fq_name");
    // Both parse stubs reach the one runnable def; the orphan reaches nothing.
    assert_eq!(implementations, vec!["app.over.parse"], "{value:#}");

    // The stubs are three rows; only one distinct implementation answers
    // them, and the orphan is the stub the forward join never reaches. An
    // inverse listing (implementation -> its stubs, or the orphans directly)
    // is not yet composable on the query surface; the plan records that
    // bound and its follow-up.
    let result = run(
        files,
        json!({
            "match": { "kind": "callable" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "declaration_state_of", "declaration_only": true },
            ],
        }),
    );
    let value = serialized(&result);
    let stubs = strings(&value, "fq_name");
    assert_eq!(
        stubs,
        vec!["app.over.parse", "app.over.parse", "app.over.orphan"],
        "three declaration-only stubs exist: {value:#}"
    );
}

/// f5ee137: anonymous default exports and CommonJS members are export rows
/// whose materialized declarations are reachable; `export default name` is a
/// row that deliberately materializes nothing.
const JS_EXPORTS: &str = "\
const messages = { greet: 'hi' };
export default messages;
";
const JS_ANONYMOUS: &str = "export default { greet: 'hi' };\n";
const JS_COMMONJS: &str = "\
const local = () => 1;
module.exports = {
  inline() { return 2; },
  local,
};
";

#[test]
fn javascript_export_forms_separate_materializing_from_reexporting() {
    // The re-export of an existing binding materializes no declaration.
    let result = run(
        &[("src/exports.js", JS_EXPORTS)],
        json!({
            "exports": { "form": ["default_named"] },
            "steps": [{ "op": "export_target" }],
        }),
    );
    let value = serialized(&result);
    assert!(
        rows(&value).is_empty(),
        "`export default name` points at an existing binding: {value:#}"
    );

    // The anonymous default materializes its synthetic `default` unit.
    let result = run(
        &[("src/anonymous.js", JS_ANONYMOUS)],
        json!({
            "exports": { "form": ["default_anonymous"] },
            "steps": [{ "op": "export_target" }, { "op": "declaration_state_of" }],
        }),
    );
    let value = serialized(&result);
    assert_eq!(strings(&value, "fq_name"), vec!["default"], "{value:#}");
    assert_eq!(strings(&value, "origin"), vec!["generated"], "{value:#}");

    // A CommonJS in-place member is generated; the reference member is not.
    let result = run(
        &[("src/commonjs.js", JS_COMMONJS)],
        json!({ "exports": { "form": ["common_js_member"] } }),
    );
    let value = serialized(&result);
    assert_eq!(
        strings(&value, "exported_name"),
        vec!["inline", "local"],
        "{value:#}"
    );
    let targets: Vec<bool> = rows(&value)
        .iter()
        .map(|row| row.get("target_fq_name").is_some())
        .collect();
    assert_eq!(
        targets,
        vec![true, false],
        "only the in-place member materializes a declaration: {value:#}"
    );
}

/// adbc585 and 948d495: a `#define` is a generation site producing its macro
/// unit, and declarations under preprocessor conditionals are configuration
/// gated with an honest no-active-configuration answer.
const CPP_CONFIG: &str = "\
#define WIDGET_MAX 8
#ifdef USE_FAST
int fast_path() { return 1; }
#else
int slow_path() { return 2; }
#endif
int always() { return 3; }
";

#[test]
fn cpp_defines_generate_and_conditional_declarations_are_gated() {
    let files = &[("include/config.h", CPP_CONFIG)];
    let result = run(
        files,
        json!({
            "generation_sites": { "kind": ["preprocessor_definition"] },
            "steps": [{ "op": "generates" }],
        }),
    );
    let value = serialized(&result);
    assert_eq!(strings(&value, "fq_name"), vec!["WIDGET_MAX"], "{value:#}");

    let result = run(
        files,
        json!({
            "match": { "kind": "callable" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "declaration_state_of", "config_gated": true },
            ],
        }),
    );
    let value = serialized(&result);
    let gated = strings(&value, "fq_name");
    assert!(
        gated.contains(&"fast_path".to_string()) && gated.contains(&"slow_path".to_string()),
        "both branches exist under an unevaluated configuration: {value:#}"
    );
    assert!(
        !gated.contains(&"always".to_string()),
        "an unconditional declaration is not gated: {value:#}"
    );
    assert!(
        has_diagnostic(
            &result,
            CodeQueryDiagnosticCode::MaterializationDerivationIncomplete
        ),
        "no active configuration is known: {:?}",
        result.diagnostics
    );
}

/// f7a2bb5: an export-annotation macro breaks the parse; the recovered class
/// says it was recovered instead of masquerading as a clean declaration.
const CPP_RECOVERED: &str = "\
class CORE_EXPORT QgsPoint : public QgsAbstractGeometry
{
  public:
    QgsPoint( double x, double y );
};
";

#[test]
fn cpp_recovered_declarations_state_their_origin() {
    let result = run(
        &[("src/exported.h", CPP_RECOVERED)],
        json!({
            "match": { "kind": "class" },
            "steps": [
                { "op": "enclosing_decl" },
                { "op": "declaration_state_of", "origin": ["recovered"] },
            ],
        }),
    );
    let value = serialized(&result);
    assert_eq!(strings(&value, "fq_name"), vec!["QgsPoint"], "{value:#}");
}

/// An unclaimed language abstains with a typed diagnostic rather than an
/// empty complete answer.
#[test]
fn unclaimed_languages_report_axis_unsupported() {
    let result = run(
        &[("main.go", "package main\n\nfunc main() {}\n")],
        json!({ "generation_sites": {} }),
    );
    assert!(
        serialized(&result)["results"]
            .as_array()
            .expect("results")
            .is_empty()
    );
    assert!(
        has_diagnostic(
            &result,
            CodeQueryDiagnosticCode::MaterializationAxisUnsupported
        ),
        "{:?}",
        result.diagnostics
    );
}
