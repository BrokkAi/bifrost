//! Cross-language conformance for the #1477 Milestone 4 bounded-dispatch rows.
//!
//! The invariants under test are the milestone's honesty rules. The outcome
//! row is mandatory per input site, so an absent, unknown, or open dispatch
//! states a typed reason instead of vanishing. Coverage is `exhaustive` only
//! when the workspace oracle itself said so, and `proven_dispatch` requires a
//! proven, complete arm inside an exhaustive set, so open-world dispatch can
//! never satisfy an exact-set claim.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::structural::{CodeQuery, CodeQueryResult, execute_workspace};
use brokk_bifrost::{AnalyzerConfig, Language, WorkspaceAnalyzer};
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

/// Every call to `callee` in `path`, expanded by one dispatch step.
fn call_query(path: &str, callee: &str, step: &str) -> Value {
    json!({
        "where": [path],
        "match": { "kind": "call", "callee": { "name": callee } },
        "steps": [{ "op": step }],
        "result_detail": "full"
    })
}

/// A closed monomorphic call: `caller` calls exactly one statically known
/// procedure in the same workspace.
const CLOSED_JAVA: &str = r#"public class App {
  static int helper() { return 1; }
  static int caller() { int total = 0; return total + helper(); }
}
"#;

/// An open interface receiver with two implementations. Nothing about the
/// runtime receiver is decided at the call.
const OPEN_JAVA: &str = r#"interface Shape { int area(); }
class Square implements Shape { public int area() { return 1; } }
class Circle implements Shape { public int area() { return 2; } }
public class App {
  static int caller(Shape shape) { return shape.area(); }
}
"#;

/// A call whose callee is declared outside the workspace.
const EXTERNAL_JAVA: &str = r#"public class App {
  static int caller(String text) { return text.length(); }
}
"#;

/// A closed monomorphic call yields one resolved, exhaustive outcome row and
/// one proven target arm that renders the exact callee declaration.
#[test]
fn closed_monomorphic_call_yields_an_exhaustive_proven_dispatch() {
    let files = [("App.java", CLOSED_JAVA)];

    let outcome = serialized(&run(
        &files,
        call_query("App.java", "helper", "dispatch_outcome"),
    ));
    assert_eq!(rows(&outcome).len(), 1, "{outcome}");
    let site = &rows(&outcome)[0];
    assert_eq!(site["result_type"], "dispatch_outcome", "{outcome}");
    assert_eq!(site["outcome"], "resolved", "{outcome}");
    assert_eq!(site["coverage"], "exhaustive", "{outcome}");
    assert_eq!(site["call_site_count"], 1, "{outcome}");
    assert_eq!(site["target_count"], 1, "{outcome}");
    assert_eq!(site["targets_truncated"], false, "{outcome}");
    assert!(
        site["semantic_unsupported"].is_null() && site["exceeded_limit"].is_null(),
        "a resolved outcome states no capability or budget gap: {outcome}"
    );

    let targets = serialized(&run(
        &files,
        call_query("App.java", "helper", "dispatch_targets"),
    ));
    assert_eq!(rows(&targets).len(), 1, "{targets}");
    let target = &rows(&targets)[0];
    assert_eq!(target["result_type"], "dispatch_target", "{targets}");
    assert_eq!(target["site_id"], site["site_id"], "{targets}");
    assert_eq!(target["ordinal"], 0, "{targets}");
    assert_eq!(target["proof"], "proven", "{targets}");
    assert_eq!(target["completeness"], "complete", "{targets}");
    assert_eq!(target["coverage"], "exhaustive", "{targets}");
    assert_eq!(target["dispatch"], "proven_dispatch", "{targets}");
    assert!(
        target["boundary_kind"].is_null(),
        "a materialized candidate is not a boundary arm: {targets}"
    );
    assert_eq!(
        target["target_declaration"]["fq_name"], "App.helper",
        "the arm renders the exact callee declaration: {targets}"
    );
    assert!(
        target["target_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()),
        "every arm carries a semantic target identity: {targets}"
    );
}

/// An open interface receiver keeps its arm at `may_dispatch`. Coverage stays
/// non-exhaustive, so the completeness gate turns an exact-set assertion over
/// this site unreliable rather than clean, and no per-arm proof upgrades it.
#[test]
fn open_interface_receiver_never_upgrades_to_proven_dispatch() {
    let files = [("App.java", OPEN_JAVA)];

    let outcome = serialized(&run(
        &files,
        call_query("App.java", "area", "dispatch_outcome"),
    ));
    assert_eq!(rows(&outcome).len(), 1, "{outcome}");
    let site = &rows(&outcome)[0];
    assert_ne!(
        site["coverage"], "exhaustive",
        "an open receiver must never claim an exhaustive target set: {outcome}"
    );

    let targets = serialized(&run(
        &files,
        call_query("App.java", "area", "dispatch_targets"),
    ));
    assert!(!rows(&targets).is_empty(), "{targets}");
    for target in rows(&targets) {
        assert_eq!(
            target["dispatch"], "may_dispatch",
            "an arm inside a non-exhaustive set stays a may-dispatch: {targets}"
        );
        assert_ne!(
            target["coverage"], "exhaustive",
            "the arm repeats the site's own coverage: {targets}"
        );
    }
    assert!(
        rows(&targets)
            .iter()
            .any(|target| target["boundary_kind"] == "unmaterialized"),
        "the interface member is reported as a typed boundary arm: {targets}"
    );
}

/// A position that holds no call is not silently dropped. It emits exactly one
/// outcome row stating `unknown` with no located call and no target, and its
/// target relation is empty.
#[test]
fn a_position_with_no_call_emits_one_unknown_outcome_and_no_target() {
    let files = [("App.java", CLOSED_JAVA)];
    let binder_query = |step: &str| {
        json!({
            "where": ["App.java"],
            "occurrences": { "role": ["binder"] },
            "steps": [{ "op": step }],
            "result_detail": "full"
        })
    };

    let outcome = serialized(&run(&files, binder_query("dispatch_outcome")));
    assert_eq!(
        rows(&outcome).len(),
        1,
        "the local variable binder is one input site, so it gets one row: {outcome}"
    );
    let site = &rows(&outcome)[0];
    assert_eq!(site["outcome"], "unknown", "{outcome}");
    assert_ne!(site["coverage"], "exhaustive", "{outcome}");
    assert_eq!(site["call_site_count"], 0, "{outcome}");
    assert_eq!(site["target_count"], 0, "{outcome}");

    let targets = serialized(&run(&files, binder_query("dispatch_targets")));
    assert!(
        rows(&targets).is_empty(),
        "an unknown dispatch retains no arm: {targets}"
    );
}

/// A callee declared outside the workspace is the same discipline: one
/// outcome row states that nothing is known, and no arm is invented for it.
#[test]
fn an_external_callee_emits_one_unknown_outcome_and_no_target() {
    let files = [("App.java", EXTERNAL_JAVA)];

    let outcome = serialized(&run(
        &files,
        call_query("App.java", "length", "dispatch_outcome"),
    ));
    assert_eq!(rows(&outcome).len(), 1, "{outcome}");
    let site = &rows(&outcome)[0];
    assert_eq!(site["outcome"], "unknown", "{outcome}");
    assert_ne!(site["coverage"], "exhaustive", "{outcome}");
    assert_eq!(site["target_count"], 0, "{outcome}");

    let targets = serialized(&run(
        &files,
        call_query("App.java", "length", "dispatch_targets"),
    ));
    assert!(rows(&targets).is_empty(), "{targets}");
}

/// An occurrence input correlates without comparing text or ranges: the
/// dispatch rows carry the occurrence's own `ast_id` as `site_ast_id`, and the
/// target rows carry the outcome row's `site_id`.
#[test]
fn occurrence_input_correlates_dispatch_rows_by_ast_id() {
    let files = [("App.java", CLOSED_JAVA)];
    let member_query = |step: Option<&str>| {
        let steps = step.map_or_else(Vec::new, |step| vec![json!({ "op": step })]);
        json!({
            "where": ["App.java"],
            "occurrences": { "role": ["member_position"] },
            "steps": steps,
            "result_detail": "full"
        })
    };

    let occurrences = serialized(&run(&files, member_query(None)));
    assert_eq!(rows(&occurrences).len(), 1, "{occurrences}");
    let ast_id = rows(&occurrences)[0]["ast_id"].clone();
    assert!(ast_id.as_str().is_some(), "{occurrences}");

    let outcome = serialized(&run(&files, member_query(Some("dispatch_outcome"))));
    assert_eq!(rows(&outcome).len(), 1, "{outcome}");
    let site = &rows(&outcome)[0];
    assert_eq!(site["site_ast_id"], ast_id, "{outcome}");
    assert_eq!(site["outcome"], "resolved", "{outcome}");

    let targets = serialized(&run(&files, member_query(Some("dispatch_targets"))));
    assert_eq!(rows(&targets).len(), 1, "{targets}");
    assert_eq!(rows(&targets)[0]["site_ast_id"], ast_id, "{targets}");
    assert_eq!(rows(&targets)[0]["site_id"], site["site_id"], "{targets}");
}

/// Both dispatch domains answer `file_of`.
#[test]
fn dispatch_rows_project_to_their_workspace_file() {
    let files = [("App.java", CLOSED_JAVA)];
    for step in ["dispatch_outcome", "dispatch_targets"] {
        let value = serialized(&run(
            &files,
            json!({
                "where": ["App.java"],
                "match": { "kind": "call", "callee": { "name": "helper" } },
                "steps": [{ "op": step }, { "op": "file_of" }],
                "result_detail": "full"
            }),
        ));
        assert_eq!(rows(&value).len(), 1, "{step}: {value}");
        assert_eq!(rows(&value)[0]["result_type"], "file", "{step}: {value}");
        assert_eq!(rows(&value)[0]["path"], "App.java", "{step}: {value}");
    }
}

/// Expected gap, pinned deliberately: a file whose language the workspace does
/// not analyze produces no input site at all, so the dispatch steps produce no
/// row rather than an `unsupported` outcome row.
///
/// The mandatory-outcome contract is per input site, and a file with no
/// analyzer delegate yields no structural match and no occurrence to be a
/// site. Every language the workspace does analyze registers a program
/// semantics provider, so the `unsupported` outcome label is reachable only
/// from a provider that reports an unsupported capability, not from an
/// unanalyzed file. This test exists so that a future delegate without a
/// semantics provider is noticed here rather than silently emitting nothing.
#[test]
fn a_file_outside_the_analyzed_languages_yields_no_dispatch_site() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("App.java", CLOSED_JAVA)
        .file(
            "app.py",
            "def target():\n    return 1\n\ndef caller():\n    return target()\n",
        )
        .build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());

    let analyzed = CodeQuery::from_json(&call_query("App.java", "helper", "dispatch_outcome"))
        .expect("query should parse");
    let analyzed = serialized(&execute_workspace(&workspace, &analyzed));
    assert_eq!(rows(&analyzed).len(), 1, "{analyzed}");
    assert_eq!(rows(&analyzed)[0]["outcome"], "resolved", "{analyzed}");

    let unanalyzed = CodeQuery::from_json(&call_query("app.py", "target", "dispatch_outcome"))
        .expect("query should parse");
    let unanalyzed = serialized(&execute_workspace(&workspace, &unanalyzed));
    assert!(
        rows(&unanalyzed).is_empty(),
        "an unanalyzed file has no input site to carry a mandatory outcome: {unanalyzed}"
    );
}
