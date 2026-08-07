//! Cross-language conformance for the #1477 Milestone 4 method-family rows.
//!
//! The invariants under test are the milestone's honesty rules. The
//! `member_family` outcome row is mandatory per member declaration, so an
//! unsupported language, an excluded member, or an unprovable overload
//! identity states a typed reason instead of vanishing. Edge rows are emitted
//! only from a proven family, the inverse direction is the bounded inversion of
//! the forward edges rather than an independent resolution, and both ends of
//! one edge carry the same `family_id`.
//!
//! Measured Java capability, pinned by
//! `overload_identity_uses_parameter_type_spellings`: the Java declaration walk
//! records each parameter's declared type *spelling* from its own AST `type`
//! node, beside a structured `CallableArity`. It records no resolved or erased
//! parameter types. The family relation therefore narrows an ancestor's
//! candidates structurally first (terminal name plus recorded arity) and falls
//! back to the spellings only when that leaves a genuine overload set -- and it
//! publishes `proof: "unproven"` on the edge derived that way, because a
//! spelling is not an erasure proof. If Java ever records erased parameter
//! types, `capability` becomes `erased_parameter_types` and that `proof`
//! expectation is what must be revisited.

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

/// Every member of `owner` in `path`, expanded by one family step. Going
/// through `members` rather than a name match is what reaches constructors as
/// well as methods.
fn family_query(path: &str, owner: &str, step: &str) -> Value {
    json!({
        "where": [path],
        "match": { "kind": "class", "name": owner },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "members" },
            { "op": step }
        ],
        "result_detail": "full"
    })
}

/// The one outcome row whose member is `fq_name`.
fn family_of<'a>(value: &'a Value, fq_name: &str) -> &'a Value {
    let mut matching = rows(value)
        .iter()
        .filter(|row| row["member"]["fq_name"] == fq_name);
    let row = matching
        .next()
        .unwrap_or_else(|| panic!("no family row for {fq_name}: {value}"));
    assert!(
        matching.next().is_none(),
        "exactly one outcome row per member: {value}"
    );
    row
}

/// The edge rows whose source member is `fq_name`, in emission order.
fn edges_of<'a>(value: &'a Value, fq_name: &str) -> Vec<&'a Value> {
    rows(value)
        .iter()
        .filter(|row| row["source"]["fq_name"] == fq_name)
        .collect()
}

/// A plain superclass override.
const OVERRIDE_JAVA: &str = r#"class Base { void run() {} }
class Service extends Base { void run() {} }
"#;

/// An interface implementation.
const INTERFACE_JAVA: &str = r#"interface Runner { void run(); }
class Service implements Runner { public void run() {} }
"#;

/// A genuine overload set: two `run` members at the same arity in the
/// superclass, one of which the subclass redefines.
const OVERLOAD_JAVA: &str = r#"class Base {
  void run(int x) {}
  void run(String s) {}
}
class Service extends Base { void run(int x) {} }
"#;

/// A same-name method on a class outside the hierarchy.
const DECOY_JAVA: &str = r#"class Base { void run() {} }
class Other { void run() {} }
class Service extends Base { void run() {} }
"#;

/// A static same-name pair and the constructors beside them.
const STATIC_JAVA: &str = r#"class Base {
  Base() {}
  static void run() {}
}
class Service extends Base {
  Service() {}
  static void run() {}
}
"#;

/// A superclass override yields one forward `overrides` edge on the subclass
/// member, one `overridden_by` inverse on the superclass member, and one
/// family id shared by both directions.
#[test]
fn java_superclass_override_round_trips_through_one_family() {
    let files = [("App.java", OVERRIDE_JAVA)];

    let summary = serialized(&run(
        &files,
        family_query("App.java", "Service", "member_family"),
    ));
    let family = family_of(&summary, "Service.run");
    assert_eq!(family["result_type"], "member_family", "{summary}");
    assert_eq!(family["outcome"], "proven", "{summary}");
    assert_eq!(family["coverage"], "exhaustive", "{summary}");
    assert_eq!(
        family["capability"], "parameter_type_spellings",
        "{summary}"
    );
    assert_eq!(family["overrides_count"], 1, "{summary}");
    assert_eq!(family["implements_count"], 0, "{summary}");
    assert_eq!(family["overridden_by_count"], 0, "{summary}");
    assert_eq!(family["root_count"], 1, "{summary}");
    assert!(
        family["reason"].is_null(),
        "a proven family states no reason: {summary}"
    );
    let family_id = family["family_id"]
        .as_str()
        .unwrap_or_else(|| panic!("proven family carries an id: {summary}"))
        .to_string();

    let forward = serialized(&run(
        &files,
        family_query("App.java", "Service", "family_edges"),
    ));
    let edges = edges_of(&forward, "Service.run");
    assert_eq!(edges.len(), 1, "{forward}");
    let edge = edges[0];
    assert_eq!(edge["result_type"], "member_family_edge", "{forward}");
    assert_eq!(edge["relation"], "overrides", "{forward}");
    assert_eq!(edge["target"]["fq_name"], "Base.run", "{forward}");
    assert_eq!(edge["hierarchy_depth"], 1, "{forward}");
    assert_eq!(edge["proof"], "proven", "{forward}");
    assert_eq!(edge["completeness"], "complete", "{forward}");
    assert_eq!(edge["coverage"], "exhaustive", "{forward}");
    assert_eq!(edge["family_id"], family_id.as_str(), "{forward}");

    let inverse = serialized(&run(
        &files,
        family_query("App.java", "Base", "family_edges"),
    ));
    let back_edges = edges_of(&inverse, "Base.run");
    assert_eq!(back_edges.len(), 1, "{inverse}");
    let back = back_edges[0];
    assert_eq!(back["relation"], "overridden_by", "{inverse}");
    assert_eq!(back["target"]["fq_name"], "Service.run", "{inverse}");
    assert_eq!(
        back["family_id"],
        family_id.as_str(),
        "both directions of one edge carry one family id: {inverse}"
    );
    assert_eq!(
        back["target_id"], edge["member_id"],
        "the inverse row's target identity is the forward row's member identity: {inverse}"
    );
    assert_eq!(
        back["member_id"], edge["target_id"],
        "and the reverse holds too, so the pair round-trips: {inverse}"
    );

    let superclass = serialized(&run(
        &files,
        family_query("App.java", "Base", "member_family"),
    ));
    let root_family = family_of(&superclass, "Base.run");
    assert_eq!(root_family["overrides_count"], 0, "{superclass}");
    assert_eq!(root_family["overridden_by_count"], 1, "{superclass}");
    assert_eq!(
        root_family["family_id"],
        family_id.as_str(),
        "a family root and its overrider share one family id: {superclass}"
    );
}

/// An interface implementation yields `implements` forward and
/// `implemented_by` inverse, not `overrides`.
#[test]
fn java_interface_implementation_states_implements_in_both_directions() {
    let files = [("App.java", INTERFACE_JAVA)];

    let forward = serialized(&run(
        &files,
        family_query("App.java", "Service", "family_edges"),
    ));
    let edges = edges_of(&forward, "Service.run");
    assert_eq!(edges.len(), 1, "{forward}");
    let edge = edges[0];
    assert_eq!(edge["relation"], "implements", "{forward}");
    assert_eq!(edge["target"]["fq_name"], "Runner.run", "{forward}");
    assert_eq!(edge["proof"], "proven", "{forward}");

    let inverse = serialized(&run(
        &files,
        family_query("App.java", "Runner", "family_edges"),
    ));
    let back_edges = edges_of(&inverse, "Runner.run");
    assert_eq!(back_edges.len(), 1, "{inverse}");
    let back = back_edges[0];
    assert_eq!(back["relation"], "implemented_by", "{inverse}");
    assert_eq!(back["target"]["fq_name"], "Service.run", "{inverse}");
    assert_eq!(back["family_id"], edge["family_id"], "{inverse}");

    let summary = serialized(&run(
        &files,
        family_query("App.java", "Service", "member_family"),
    ));
    let family = family_of(&summary, "Service.run");
    assert_eq!(family["implements_count"], 1, "{summary}");
    assert_eq!(family["overrides_count"], 0, "{summary}");
}

/// The measured Java capability level, pinned. See the module comment.
#[test]
fn overload_identity_uses_parameter_type_spellings() {
    let files = [("App.java", OVERLOAD_JAVA)];

    let summary = serialized(&run(
        &files,
        family_query("App.java", "Service", "member_family"),
    ));
    let family = family_of(&summary, "Service.run");
    assert_eq!(
        family["capability"], "parameter_type_spellings",
        "measured Java capability: {summary}"
    );
    assert_eq!(family["outcome"], "proven", "{summary}");
    assert_eq!(family["overrides_count"], 1, "{summary}");

    let forward = serialized(&run(
        &files,
        family_query("App.java", "Service", "family_edges"),
    ));
    let edges = edges_of(&forward, "Service.run");
    assert_eq!(edges.len(), 1, "{forward}");
    let edge = edges[0];
    assert_eq!(edge["relation"], "overrides", "{forward}");
    assert_eq!(
        edge["target"]["signature"], "(int)",
        "the edge names run(int), never the same-name run(String): {forward}"
    );
    assert_eq!(
        edge["proof"], "unproven",
        "a spelling discriminator is not an erasure proof: {forward}"
    );

    // The sibling overload is not in the family: exactly one of the two `run`
    // members in `Base` has an inverse edge, and it is the `int` one.
    let inverse = serialized(&run(
        &files,
        family_query("App.java", "Base", "family_edges"),
    ));
    let signatures: Vec<_> = rows(&inverse)
        .iter()
        .map(|row| {
            (
                row["source"]["signature"].as_str().unwrap_or_default(),
                row["relation"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        signatures,
        vec![("(int)", "overridden_by")],
        "only the int overload is overridden: {inverse}"
    );
}

/// A same-name method on a class outside the hierarchy is not a family member
/// in either direction.
#[test]
fn wrong_owner_decoy_yields_no_family_edge() {
    let files = [("App.java", DECOY_JAVA)];

    let summary = serialized(&run(
        &files,
        family_query("App.java", "Other", "member_family"),
    ));
    let family = family_of(&summary, "Other.run");
    assert_eq!(family["outcome"], "proven", "{summary}");
    assert_eq!(family["edge_count"], 0, "{summary}");
    assert_eq!(family["coverage"], "exhaustive", "{summary}");
    let decoy_family_id = family["family_id"]
        .as_str()
        .expect("a member that overrides nothing is still its own family root");

    let edges = serialized(&run(
        &files,
        family_query("App.java", "Other", "family_edges"),
    ));
    assert!(
        rows(&edges).is_empty(),
        "an unrelated same-name member has no family edge: {edges}"
    );

    // The real family is unaffected by the decoy, and is a different family.
    let real = serialized(&run(
        &files,
        family_query("App.java", "Base", "family_edges"),
    ));
    let back_edges = edges_of(&real, "Base.run");
    assert_eq!(back_edges.len(), 1, "{real}");
    assert_eq!(back_edges[0]["target"]["fq_name"], "Service.run", "{real}");
    assert_ne!(
        back_edges[0]["family_id"], decoy_family_id,
        "the decoy is a different family: {real}"
    );
}

/// Static methods never override, and constructors are outside families
/// entirely. Both state a proven exclusion with zero edges rather than an
/// unexplained empty answer.
#[test]
fn static_methods_and_constructors_are_proven_exclusions() {
    let files = [("App.java", STATIC_JAVA)];

    for (owner, member, reason) in [
        ("Service", "Service.run", "static_member_excluded"),
        ("Base", "Base.run", "static_member_excluded"),
        ("Service", "Service.Service", "constructor_excluded"),
        ("Base", "Base.Base", "constructor_excluded"),
    ] {
        let summary = serialized(&run(
            &files,
            family_query("App.java", owner, "member_family"),
        ));
        let family = family_of(&summary, member);
        assert_eq!(family["outcome"], "no_family", "{member}: {summary}");
        assert_eq!(family["reason"], reason, "{member}: {summary}");
        assert_eq!(family["edge_count"], 0, "{member}: {summary}");
        assert!(
            family["family_id"].is_null(),
            "an excluded member has no family id: {summary}"
        );
        assert_eq!(
            family["coverage"], "exhaustive",
            "a proven exclusion is a complete answer: {summary}"
        );

        let edges = serialized(&run(
            &files,
            family_query("App.java", owner, "family_edges"),
        ));
        assert!(edges_of(&edges, member).is_empty(), "{member}: {edges}");
    }
}

/// A language with no landed family answers `unsupported` with `open`
/// coverage, never an empty exhaustive family.
#[test]
fn unsupported_languages_state_the_gap_instead_of_an_empty_family() {
    for (path, source, owner, member) in [
        (
            "service.go",
            "package main\n\ntype Base struct{}\n\nfunc (b Base) Run() {}\n",
            "Base",
            "main.Base.Run",
        ),
        (
            "service.rb",
            "class Base\n  def run\n  end\nend\n",
            "Base",
            "Base.run",
        ),
    ] {
        let files = [(path, source)];
        let summary = serialized(&run(&files, family_query(path, owner, "member_family")));
        let family = family_of(&summary, member);
        assert_eq!(family["outcome"], "unsupported", "{path}: {summary}");
        assert_eq!(
            family["reason"], "unsupported_language",
            "{path}: {summary}"
        );
        assert_eq!(family["capability"], "unsupported", "{path}: {summary}");
        assert_eq!(
            family["coverage"], "open",
            "{path}: an unsupported family is never exhaustive: {summary}"
        );
        assert!(family["family_id"].is_null(), "{path}: {summary}");

        let edges = serialized(&run(&files, family_query(path, owner, "family_edges")));
        assert!(edges_of(&edges, member).is_empty(), "{path}: {edges}");
    }
}

/// Both operations are reachable through their RQL spellings, in both the
/// hyphenated and underscored forms the registry declares.
#[test]
fn rql_spellings_reach_the_same_rows() {
    let files = [("App.java", OVERRIDE_JAVA)];
    let baseline = rows(&serialized(&run(
        &files,
        family_query("App.java", "Service", "member_family"),
    )))
    .len();
    for spelling in ["member-family", "member_family"] {
        let source = format!(
            "({spelling} (members (enclosing-decl (where \"App.java\" (class :name \"Service\")))))"
        );
        let query = CodeQuery::from_source(&source).expect("rql should parse");
        let project = InlineTestProject::new()
            .file("App.java", OVERRIDE_JAVA)
            .build();
        let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
        let result = serialized(&execute_workspace(&workspace, &query));
        assert_eq!(rows(&result).len(), baseline, "{spelling}: {result}");
        assert_eq!(rows(&result)[0]["result_type"], "member_family", "{result}");
    }
}
