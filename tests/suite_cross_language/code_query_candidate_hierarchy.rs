//! Conformance for the #1477 `candidate-hierarchy` hop rows.
//!
//! A hop row is one edge the production resolver's own member walk took. The
//! invariants under test are the milestone's: a candidate found `n` hierarchy
//! hops away emits exactly `n` contiguous rows that terminate at its owner,
//! every row joins back to its candidate by `candidate_id`, a direct member
//! emits none while the candidate row still states depth zero, and a language
//! that classifies no member-position occurrence emits none while stating the
//! capability gap as a diagnostic.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::structural::{CodeQuery, CodeQueryResult, execute_workspace};
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

/// The member-position query over one file, for one step.
fn member_query(path: &str, op: &str) -> Value {
    json!({
        "where": [path],
        "occurrences": { "role": ["member_position"] },
        "steps": [{"op": op}],
        "result_detail": "full"
    })
}

/// Java's three-level hierarchy: `run` is declared on `Root`, the receiver is
/// a `Service`, and the resolver walks `Service -> Base -> Root`. The selected
/// candidate therefore has exactly two hops, numbered 0 and 1, contiguous and
/// terminating at the candidate's owner. Each hop names the candidate row it
/// belongs to by that row's own `id`.
#[test]
fn java_inherited_member_emits_a_contiguous_route_joined_to_its_candidate() {
    let files = [(
        "App.java",
        r#"class Root { void run() {} }
class Base extends Root { }
class Service extends Base { }
class Decoy { void run() {} }
class Caller {
    void call(Service service) { service.run(); }
}
"#,
    )];

    let candidates = serialized(&run(&files, member_query("App.java", "candidates_of")));
    let selected = rows(&candidates)
        .iter()
        .filter(|row| row["outcome"] == "selected")
        .collect::<Vec<_>>();
    assert_eq!(selected.len(), 1, "{candidates}");
    let candidate = selected[0];
    assert_eq!(
        candidate["candidate"]["unit"]["fq_name"], "Root.run",
        "{candidates}"
    );
    assert_eq!(candidate["hierarchy_depth"], 2, "{candidates}");
    let candidate_id = candidate["id"].as_str().expect("candidate id");

    let hops = serialized(&run(
        &files,
        member_query("App.java", "candidate_hierarchy"),
    ));
    let hop_rows = rows(&hops);
    assert_eq!(hop_rows.len(), 2, "{hops}");
    for row in hop_rows {
        assert_eq!(row["result_type"], "candidate_hop", "{hops}");
        assert_eq!(row["candidate_id"], candidate_id, "{hops}");
        assert_eq!(row["ast_id"], candidate["ast_id"], "{hops}");
        assert_eq!(row["relation"], "supertype", "{hops}");
    }
    assert_eq!(hop_rows[0]["hop"], 0, "{hops}");
    assert_eq!(hop_rows[0]["from"]["fq_name"], "Service", "{hops}");
    assert_eq!(hop_rows[0]["to"]["fq_name"], "Base", "{hops}");
    assert_eq!(hop_rows[1]["hop"], 1, "{hops}");
    assert_eq!(hop_rows[1]["from"]["fq_name"], "Base", "{hops}");
    assert_eq!(hop_rows[1]["to"]["fq_name"], "Root", "{hops}");
    assert_eq!(
        hop_rows[1]["to"]["fq_name"], candidate["owner"]["fq_name"],
        "the last hop must terminate at the candidate's owner: {hops}"
    );
}

/// A direct member is found at depth zero, so its route is empty by
/// construction. Zero hop rows is the correct answer, and the depth-zero
/// attribution is still stated on the candidate row -- the absent hops are not
/// an absent attribution.
#[test]
fn java_direct_member_emits_no_hops_while_the_candidate_states_depth_zero() {
    let files = [(
        "App.java",
        r#"class Base { void run() {} }
class Service extends Base { void run() {} }
class Caller {
    void call(Service service) { service.run(); }
}
"#,
    )];

    let candidates = serialized(&run(&files, member_query("App.java", "candidates_of")));
    let selected = rows(&candidates)
        .iter()
        .filter(|row| row["outcome"] == "selected")
        .collect::<Vec<_>>();
    assert_eq!(selected.len(), 1, "{candidates}");
    assert_eq!(
        selected[0]["candidate"]["unit"]["fq_name"], "Service.run",
        "{candidates}"
    );
    assert_eq!(selected[0]["hierarchy_depth"], 0, "{candidates}");
    assert_eq!(
        selected[0]["dispatch_tier"], "inherent_or_direct",
        "{candidates}"
    );

    let hops = serialized(&run(
        &files,
        member_query("App.java", "candidate_hierarchy"),
    ));
    assert!(rows(&hops).is_empty(), "{hops}");
}

/// Go does not classify member-position occurrences, so there is no site to
/// walk a hierarchy for. The run must say so through the same incomplete
/// occurrence-role diagnostic the selection sweep relies on, rather than
/// return a silent empty result that a policy would read as a proven-empty
/// route.
#[test]
fn an_untraced_language_emits_no_hops_and_states_the_capability_gap() {
    let files = [(
        "app.go",
        "package main\n\ntype Service struct{}\n\nfunc (s Service) Run() {}\n\ntype Decoy struct{}\n\nfunc (d Decoy) Run() {}\n\nfunc caller(s Service) { s.Run() }\n",
    )];
    let hops = serialized(&run(&files, member_query("app.go", "candidate_hierarchy")));
    assert!(rows(&hops).is_empty(), "{hops}");
    let role_unsupported = hops["diagnostics"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|diagnostic| {
            diagnostic["code"] == "occurrence_role_unsupported"
                && diagnostic["impact"] == "incomplete"
        });
    assert!(
        role_unsupported,
        "zero hop rows require a stated occurrence-role capability gap: {hops}"
    );
}
