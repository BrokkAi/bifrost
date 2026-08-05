//! End-to-end coverage of the canonical reference-edge domain (#1479).
//!
//! The load-bearing test here is
//! `the_two_producers_agree_field_for_field_at_one_call_site`: the whole domain
//! exists so the resolver's forward answer and the usage index's inverse answer
//! can be stated in one row shape and compared. That test runs both projections
//! over one workspace and compares the site bytes, the AST identity, the target,
//! the reference kind, the owner relation and the generation -- so a drift
//! between the two production analyses fails here rather than being invisible.
//!
//! One wire detail shapes every assertion below. `CodeQueryResultItem`
//! serializes its pipeline `provenance` traces alongside the flattened row, and
//! a reference edge carries a `provenance` field of its own. When a query
//! records pipeline traces, the item's array wins the JSON key, so the edge's
//! own producer label is unreadable from the serialized row. Producer identity
//! is therefore asserted through the typed result value by
//! [`edge_provenances`], never through the JSON.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryCompletion, CodeQueryDiagnosticCode, CodeQueryResult, CodeQueryResultValue,
    execute_workspace,
};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use serde_json::{Value, json};

/// One inline workspace that answers more than one query.
///
/// Both edge producers must be observed against the *same* analysis
/// generation for a parity claim to mean anything, so the parity tests run
/// their two queries through one of these rather than two `run` calls.
struct Fixture {
    workspace: WorkspaceAnalyzer,
    _project: crate::common::BuiltInlineTestProject,
}

impl Fixture {
    fn new(files: &[(&str, &str)]) -> Self {
        let mut project = InlineTestProject::new();
        for (path, source) in files {
            project = project.file(*path, *source);
        }
        let project = project.build();
        let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
        Self {
            workspace,
            _project: project,
        }
    }

    fn run(&self, query: Value) -> CodeQueryResult {
        let query = CodeQuery::from_json(&query).expect("query should parse");
        execute_workspace(&self.workspace, &query)
    }

    fn json(&self, query: Value) -> Value {
        serialized(&self.run(query))
    }
}

fn run(files: &[(&str, &str)], query: Value) -> CodeQueryResult {
    Fixture::new(files).run(query)
}

fn serialized(result: &CodeQueryResult) -> Value {
    serde_json::to_value(result).expect("query result should serialize")
}

fn rows(value: &Value) -> &Vec<Value> {
    value["results"].as_array().expect("results array")
}

/// Only the reference-edge rows of a result, so a pipeline that also renders
/// its seed can never be read as if every row were an edge.
fn edge_rows(value: &Value) -> Vec<&Value> {
    rows(value)
        .iter()
        .filter(|row| row["result_type"] == json!("reference_edge"))
        .collect()
}

/// The edge rows whose target fq-name ends with `suffix`, so a fixture can
/// name its subject without spelling the package.
fn edges_to<'a>(value: &'a Value, suffix: &str) -> Vec<&'a Value> {
    edge_rows(value)
        .into_iter()
        .filter(|row| {
            row["target"]["fq_name"]
                .as_str()
                .is_some_and(|fq_name| fq_name.ends_with(suffix))
        })
        .collect()
}

/// The producer label of every reference-edge row, read from the typed value
/// because the JSON key is claimed by the item's pipeline provenance.
fn edge_provenances(result: &CodeQueryResult) -> Vec<&'static str> {
    result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::ReferenceEdge { value } => Some(value.provenance),
            _ => None,
        })
        .collect()
}

fn has_diagnostic(result: &CodeQueryResult, code: CodeQueryDiagnosticCode) -> bool {
    result
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == code)
}

const JAVA_REGISTRY: &str =
    "package fixture;\n\npublic class Registry {\n    public void register() {\n    }\n}\n";
const JAVA_STARTUP: &str = "package fixture;\n\npublic class Startup {\n    void boot(Registry registry) {\n        registry.register();\n    }\n}\n";

fn java_call_fixture() -> Fixture {
    Fixture::new(&[
        ("src/Registry.java", JAVA_REGISTRY),
        ("src/Startup.java", JAVA_STARTUP),
    ])
}

/// The inverse projection of a plain cross-file Java call: one use-site row,
/// fully classified, and addressable as an AST node rather than only as bytes.
#[test]
fn inverse_edges_of_a_java_method_name_its_one_calling_site() {
    let fixture = java_call_fixture();
    let result = fixture.run(json!({
        "match": { "kind": "callable", "name": "register" },
        "steps": [{ "op": "enclosing_decl" }, { "op": "edges_of", "usage": ["reference"] }]
    }));
    assert_eq!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "a deep adapter answers both projections, so nothing is incomplete: {:?}",
        result.diagnostics
    );
    assert_eq!(
        edge_provenances(&result),
        vec!["inverse"],
        "the usage index derived this row"
    );

    let value = serialized(&result);
    let edges = edge_rows(&value);
    assert_eq!(
        edges.len(),
        1,
        "the fixture calls `register` exactly once: {value:#}"
    );
    let edge = edges[0];
    assert_eq!(edge["reference_kind"], json!("method_call"), "{edge:#}");
    assert_eq!(edge["proof"], json!("proven"), "{edge:#}");
    assert_eq!(edge["usage_kind"], json!("reference"), "{edge:#}");
    assert_eq!(edge["site_class"], json!("use_site"), "{edge:#}");
    assert_eq!(edge["owner_relation"], json!("external"), "{edge:#}");
    assert!(
        edge["ast_id"].is_string(),
        "an inverse row whose site token is an identifier fact carries the same \
         AST identity the forward producer states: {edge:#}"
    );
    assert!(
        edge["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("Startup.java")),
        "the site is the caller's file, not the target's: {edge:#}"
    );
    assert_eq!(
        edge["target"]["fq_name"],
        json!("fixture.Registry.register"),
        "{edge:#}"
    );
}

/// The parity claim, at query level: the same call site reached from the two
/// opposite directions is one fact stated twice.
///
/// Both queries run over one workspace, so the generation equality below is a
/// real agreement rather than an artefact of two identical builds.
#[test]
fn the_two_producers_agree_field_for_field_at_one_call_site() {
    let fixture = java_call_fixture();

    let inverse_result = fixture.run(json!({
        "match": { "kind": "callable", "name": "register" },
        "steps": [{ "op": "enclosing_decl" }, { "op": "edges_of", "usage": ["reference"] }]
    }));
    let forward_result = fixture.run(json!({
        "languages": ["java"],
        "where": ["**/Startup.java"],
        "occurrences": { "class": ["reference"] },
        "steps": [{ "op": "edges_from" }]
    }));
    assert_eq!(edge_provenances(&inverse_result), vec!["inverse"]);
    assert!(
        edge_provenances(&forward_result)
            .iter()
            .all(|provenance| *provenance == "forward"),
        "every row of an edges-from answer comes from the resolver: {:?}",
        edge_provenances(&forward_result)
    );

    let inverse = serialized(&inverse_result);
    let forward = serialized(&forward_result);
    let inverse_edges = edges_to(&inverse, "Registry.register");
    assert_eq!(
        inverse_edges.len(),
        1,
        "one inverse row for the call: {inverse:#}"
    );
    let inverse_edge = inverse_edges[0];
    let forward_edges = edges_to(&forward, "Registry.register");
    assert_eq!(
        forward_edges.len(),
        1,
        "one forward row for the same call: {forward:#}"
    );
    let forward_edge = forward_edges[0];

    for field in [
        "path",
        "start_byte",
        "end_byte",
        "ast_id",
        "reference_kind",
        "proof",
        "usage_kind",
        "site_class",
        "owner_relation",
        "generation",
    ] {
        assert_eq!(
            forward_edge[field], inverse_edge[field],
            "the two producers must agree on {field}:\nforward {forward_edge:#}\ninverse {inverse_edge:#}"
        );
    }
    assert_eq!(
        forward_edge["target"]["fq_name"], inverse_edge["target"]["fq_name"],
        "one target, two directions:\nforward {forward_edge:#}\ninverse {inverse_edge:#}"
    );
    assert!(
        forward_edge["ast_id"].is_string(),
        "the shared identity must be a real one, not two absences: {forward_edge:#}"
    );
}

const JAVA_SIBLINGS: &str = "package fixture;\n\npublic class Widget {\n    int render() {\n        return helper();\n    }\n\n    int helper() {\n        return 1;\n    }\n}\n";

/// A method calling a sibling of its own class is classified `same_owner`, and
/// the `:relation` filter selects exactly that row.
///
/// The call is also classified `self_receiver` rather than `reference`: the
/// fixture spells `helper()` with an implicit receiver, and the usage surface
/// separates that from a reference through a named receiver. The filter below
/// therefore names the relation, never the usage kind.
#[test]
fn a_java_sibling_call_is_classified_same_owner_and_the_relation_filter_selects_it() {
    let fixture = Fixture::new(&[("src/Widget.java", JAVA_SIBLINGS)]);

    let unfiltered = fixture.json(json!({
        "match": { "kind": "callable", "name": "helper" },
        "steps": [{ "op": "enclosing_decl" }, { "op": "edges_of" }]
    }));
    let edges = edges_to(&unfiltered, "Widget.helper");
    assert_eq!(edges.len(), 1, "one sibling call: {unfiltered:#}");
    assert_eq!(
        edges[0]["owner_relation"],
        json!("same_owner"),
        "the caller and the target share an owner: {unfiltered:#}"
    );
    assert_eq!(
        edges[0]["usage_kind"],
        json!("self_receiver"),
        "an implicit-receiver call is a self-receiver usage: {unfiltered:#}"
    );
    assert_eq!(edges[0]["reference_kind"], json!("method_call"));

    let filtered = fixture.json(json!({
        "match": { "kind": "callable", "name": "helper" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "edges_of", "relation": ["same_owner"] }
        ]
    }));
    assert_eq!(
        edges_to(&filtered, "Widget.helper").len(),
        1,
        "the relation filter keeps the row it classifies: {filtered:#}"
    );
    for row in edge_rows(&filtered) {
        assert_eq!(row["owner_relation"], json!("same_owner"), "{row:#}");
    }
}

const RUST_SIBLINGS: &str = "pub struct Widget;\n\nimpl Widget {\n    pub fn render(&self) -> usize {\n        self.helper()\n    }\n\n    pub fn helper(&self) -> usize {\n        1\n    }\n}\n";

/// The same shape in Rust. The classifier is one shared computation over
/// `CodeUnit` owners, so the two languages agree here for a structural reason:
/// both methods' parent declaration is the same inherent-impl owner, and both
/// call sites go through the implicit or explicit self receiver.
#[test]
fn a_rust_sibling_call_reports_the_same_owner_relation_java_does() {
    let fixture = Fixture::new(&[("src/lib.rs", RUST_SIBLINGS)]);
    let value = fixture.json(json!({
        "match": { "kind": "callable", "name": "helper" },
        "steps": [{ "op": "enclosing_decl" }, { "op": "edges_of" }]
    }));
    let edges = edges_to(&value, "Widget.helper");
    assert_eq!(edges.len(), 1, "one sibling call: {value:#}");
    assert_eq!(
        edges[0]["owner_relation"],
        json!("same_owner"),
        "both methods hang off the same inherent impl: {value:#}"
    );
    assert_eq!(
        edges[0]["usage_kind"],
        json!("self_receiver"),
        "`self.helper()` is a self-receiver usage: {value:#}"
    );
}

const JAVA_RECURSION: &str = "package fixture;\n\npublic class Walker {\n    int walk(int depth) {\n        if (depth == 0) {\n            return 0;\n        }\n        return walk(depth - 1);\n    }\n}\n";

/// A recursive call is the one shape where the site's enclosing declaration is
/// the target itself, so the relation must be `self_reference` rather than
/// collapsed into `same_owner`.
///
/// Only the forward producer states it. The usage index enumerates no site at
/// all for the recursive call -- on the external-usages surface *and* on the
/// `lsp-references` surface -- so the second half of this test records that
/// asymmetry rather than hiding it: the two producers legitimately disagree
/// here, which is exactly the kind of gap this domain exists to make visible.
#[test]
fn only_the_forward_producer_states_a_recursive_call_and_it_is_a_self_reference() {
    let fixture = Fixture::new(&[("src/Walker.java", JAVA_RECURSION)]);
    let forward = fixture.json(json!({
        "languages": ["java"],
        "occurrences": { "class": ["reference"] },
        "steps": [{ "op": "edges_from" }]
    }));
    let edges = edges_to(&forward, "Walker.walk");
    assert!(
        !edges.is_empty(),
        "the recursive call must be a forward edge: {forward:#}"
    );
    assert!(
        edges
            .iter()
            .any(|row| row["owner_relation"] == json!("self_reference")),
        "a call inside the target's own body is a self reference: {forward:#}"
    );

    for surface in [
        json!(null),
        json!("external_usages"),
        json!("lsp_references"),
    ] {
        let mut step = json!({ "op": "edges_of" });
        if !surface.is_null() {
            step["surface"] = surface.clone();
        }
        let inverse = fixture.json(json!({
            "match": { "kind": "callable", "name": "walk" },
            "steps": [{ "op": "enclosing_decl" }, step]
        }));
        assert!(
            edge_rows(&inverse).is_empty(),
            "the usage index enumerates no inverse site for a recursive call \
             (surface {surface}): {inverse:#}"
        );
    }
}

/// `edge-target` projects an edge back to the exact declaration it names, and
/// that declaration is the one a plain declaration query returns.
#[test]
fn edge_target_projects_back_to_the_declaration_the_edge_names() {
    let fixture = java_call_fixture();
    let declarations = fixture.json(json!({
        "match": { "kind": "callable", "name": "register" },
        "steps": [{ "op": "enclosing_decl" }]
    }));
    let declared = rows(&declarations)
        .iter()
        .filter_map(|row| row["fq_name"].as_str().map(str::to_string))
        .collect::<Vec<_>>();
    assert_eq!(
        declared,
        vec!["fixture.Registry.register".to_string()],
        "the fixture declares one `register`: {declarations:#}"
    );

    let projected = fixture.json(json!({
        "match": { "kind": "callable", "name": "register" },
        "steps": [
            { "op": "enclosing_decl" },
            { "op": "edges_of", "usage": ["reference"] },
            { "op": "edge_target" }
        ]
    }));
    let targets = rows(&projected)
        .iter()
        .filter_map(|row| row["fq_name"].as_str().map(str::to_string))
        .collect::<Vec<_>>();
    assert_eq!(
        targets, declared,
        "the projection lands on the same declaration: {projected:#}"
    );
    for row in rows(&projected) {
        assert_eq!(row["result_type"], json!("declaration"), "{row:#}");
    }
}

const KOTLIN_CALL: &str = "package fixture\n\nclass Registry {\n    fun register() {\n    }\n}\n\nclass Startup(private val registry: Registry) {\n    fun boot() {\n        registry.register()\n    }\n}\n";

/// An adapter that has not declared an edge axis abstains in the open: the run
/// is incomplete and names the axis, so a caller cannot read the rows as if
/// every part of them were vouched for.
///
/// Kotlin's usage index answers the inverse projection, so the row is there --
/// but the adapter declares no owner classification, and the run says so even
/// though the shared classifier did put a value in the field.
#[test]
fn an_undeclared_edge_axis_is_reported_rather_than_silently_trusted() {
    let result = run(
        &[("src/Main.kt", KOTLIN_CALL)],
        json!({
            "match": { "kind": "callable", "name": "register" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "edges_of" }]
        }),
    );
    assert!(
        result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == CodeQueryDiagnosticCode::EdgeAxisUnsupported
                && diagnostic.message.contains("owner_classification")
        }),
        "the undeclared axis must be named: {:?}",
        result.diagnostics
    );
    assert_ne!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "an undeclared axis cannot yield a complete run: {:?}",
        result.diagnostics
    );
    let value = serialized(&result);
    assert_eq!(
        edges_to(&value, "Registry.register").len(),
        1,
        "the inverse projection Kotlin does declare still answers: {value:#}"
    );
}

/// The forward projection over a language that declares it unsupported cannot
/// be reached through an occurrence seed today: the same adapters that lack a
/// forward projection also classify no occurrence roles, so the seed is empty
/// before any edge step runs.
///
/// The honesty guarantee still holds one level up, and that is what this test
/// pins: the answer is empty *and* incomplete, with the missing classification
/// named, so an empty edge answer is never a clean one.
#[test]
fn an_edges_from_query_over_an_unclassified_language_is_empty_and_incomplete() {
    let result = run(
        &[("src/Main.kt", KOTLIN_CALL)],
        json!({
            "languages": ["kotlin"],
            "occurrences": { "class": ["reference"] },
            "steps": [{ "op": "edges_from" }]
        }),
    );
    assert!(
        has_diagnostic(&result, CodeQueryDiagnosticCode::OccurrenceRoleUnsupported),
        "the missing classification must be named: {:?}",
        result.diagnostics
    );
    assert_ne!(
        result.completion(),
        CodeQueryCompletion::Complete,
        "an unclassified seed cannot yield a complete run: {:?}",
        result.diagnostics
    );
    let value = serialized(&result);
    assert!(
        edge_rows(&value).is_empty(),
        "an abstaining pipeline emits no rows to be mistaken for an answer: {value:#}"
    );
}

/// Both frontends lower the edge surface to one canonical query, so an author
/// can spell it in RQL or JSON and get identical execution.
#[test]
fn rql_and_json_lower_the_edge_surface_to_one_canonical_query() {
    for (rql, json_value) in [
        (
            r#"(edges-of :reference-kinds [method-call] :proof proven (enclosing-decl (callable :name "register")))"#,
            json!({
                "match": { "kind": "callable", "name": "register" },
                "steps": [{ "op": "enclosing_decl" }, {
                    "op": "edges_of",
                    "reference_kinds": ["method_call"],
                    "proof": "proven"
                }]
            }),
        ),
        (
            r#"(edge-target (edges-of :surface external-usages :usage [reference self-receiver] :relation [same-owner external] :site-class [use-site] (enclosing-decl (callable :name "register"))))"#,
            json!({
                "match": { "kind": "callable", "name": "register" },
                "steps": [
                    { "op": "enclosing_decl" },
                    {
                        "op": "edges_of",
                        "surface": "external_usages",
                        "usage": ["reference", "self_receiver"],
                        "relation": ["same_owner", "external"],
                        "site_class": ["use_site"]
                    },
                    { "op": "edge_target" }
                ]
            }),
        ),
        (
            "(edges-from :proof unproven (occurrences :class reference))",
            json!({
                "occurrences": { "class": ["reference"] },
                "steps": [{ "op": "edges_from", "proof": "unproven" }]
            }),
        ),
    ] {
        let from_rql = CodeQuery::from_sexp(rql).expect("RQL should parse");
        let from_json = CodeQuery::from_json(&json_value).expect("JSON should parse");
        assert_eq!(
            from_rql.to_canonical_json(),
            from_json.to_canonical_json(),
            "both frontends must lower {rql} to one query"
        );
    }
}

const PYTHON_TARGET: &str = "class Registry:\n    def register(self):\n        return 1\n";
const PYTHON_CALLER: &str = "from registry import Registry\n\n\ndef boot(registry: Registry):\n    return registry.register()\n";

const TS_TARGET: &str =
    "export class Registry {\n    register(): number {\n        return 1;\n    }\n}\n";
const TS_CALLER: &str = "import { Registry } from \"./registry\";\n\nexport function boot(registry: Registry): number {\n    return registry.register();\n}\n";

/// The four-language parity claim, for the two deep languages the Java tests
/// above do not cover: a plain cross-file call produces a forward row and an
/// inverse row that agree on the site bytes, the target and the proof.
#[test]
fn python_and_typescript_agree_across_both_producers_at_a_cross_file_call() {
    for (language, target_path, target_source, caller_path, caller_source, target_suffix) in [
        (
            "python",
            "registry.py",
            PYTHON_TARGET,
            "startup.py",
            PYTHON_CALLER,
            "Registry.register",
        ),
        (
            "typescript",
            "registry.ts",
            TS_TARGET,
            "startup.ts",
            TS_CALLER,
            "Registry.register",
        ),
    ] {
        let fixture = Fixture::new(&[(target_path, target_source), (caller_path, caller_source)]);
        let inverse = fixture.json(json!({
            "match": { "kind": "callable", "name": "register" },
            "steps": [{ "op": "enclosing_decl" }, { "op": "edges_of", "usage": ["reference"] }]
        }));
        let forward = fixture.json(json!({
            "languages": [language],
            "where": [format!("**/{caller_path}")],
            "occurrences": { "class": ["reference"] },
            "steps": [{ "op": "edges_from" }]
        }));

        let inverse_edges = edges_to(&inverse, target_suffix);
        assert_eq!(
            inverse_edges.len(),
            1,
            "{language}: one inverse row for the call: {inverse:#}"
        );
        let forward_edges = edges_to(&forward, target_suffix);
        assert_eq!(
            forward_edges.len(),
            1,
            "{language}: one forward row for the call: {forward:#}"
        );
        for field in ["start_byte", "end_byte", "proof"] {
            assert_eq!(
                forward_edges[0][field], inverse_edges[0][field],
                "{language}: the producers must agree on {field}:\nforward {:#}\ninverse {:#}",
                forward_edges[0], inverse_edges[0]
            );
        }
        assert_eq!(
            forward_edges[0]["target"]["fq_name"], inverse_edges[0]["target"]["fq_name"],
            "{language}: one target, two directions:\nforward {:#}\ninverse {:#}",
            forward_edges[0], inverse_edges[0]
        );
    }
}
