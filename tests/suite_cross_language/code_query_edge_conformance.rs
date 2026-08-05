//! Conformance fixtures for the canonical reference-edge domain (#1479, M6).
//!
//! Every test below re-expresses one mined bug-fix commit from the issue
//! inventory as a behavior test that would have caught the regression. The
//! doc comment of each test names the commit it stands for.
//!
//! Two of the mined commits fixed languages that have no forward edge surface
//! today (C++ and Go). Their shapes are still worth pinning, so they are
//! re-expressed in a claimed deep language -- Java and Rust respectively --
//! and the doc comment says so.
//!
//! Rules that hold everywhere in this file:
//!
//! - No assertion is a bare count of an unnamed set. Every claim names the
//!   field it reads, and every failure message prints the complete row
//!   collection so a break is diagnosable from the failure alone.
//! - Producer identity is read from the typed result value by
//!   [`edge_provenances`], never from the JSON: `CodeQueryResultItem`
//!   serializes its pipeline traces under the same `provenance` key the edge
//!   uses, so the row's own producer label is unreadable from the wire form.
//! - Where the engine's behavior differs from the mined commit's intent, the
//!   test asserts the true current behavior and its doc comment is marked
//!   `KNOWN GAP:`. Nothing here is `#[ignore]`d and nothing is forced green.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::structural::{
    CodeQuery, CodeQueryCompletion, CodeQueryResult, CodeQueryResultValue, execute_workspace,
};
use brokk_bifrost::{AnalyzerConfig, WorkspaceAnalyzer};
use serde_json::{Value, json};

/// One inline workspace that answers more than one query.
///
/// A parity claim relates two projections of one analysis, so both queries
/// must run against the same workspace generation. Building two workspaces
/// and comparing them would compare two snapshots instead.
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

fn serialized(result: &CodeQueryResult) -> Value {
    serde_json::to_value(result).expect("query result should serialize")
}

fn rows(value: &Value) -> &Vec<Value> {
    value["results"].as_array().expect("results array")
}

/// Only the reference-edge rows, so a pipeline that also renders its seed can
/// never be read as if every row were an edge.
fn edge_rows(value: &Value) -> Vec<&Value> {
    rows(value)
        .iter()
        .filter(|row| row["result_type"] == json!("reference_edge"))
        .collect()
}

/// The edge rows whose target fq-name ends with `suffix`, so a fixture can
/// name its subject without spelling the package or module path.
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

/// The `(path, start_byte)` identity of each edge row, for set comparisons
/// across the two directions.
fn sites(value: &Value, suffix: &str) -> Vec<(String, u64)> {
    let mut sites = edges_to(value, suffix)
        .into_iter()
        .map(|row| {
            (
                row["path"]
                    .as_str()
                    .expect("an edge row states its file")
                    .to_string(),
                row["start_byte"]
                    .as_u64()
                    .expect("an edge row states its start byte"),
            )
        })
        .collect::<Vec<_>>();
    sites.sort();
    sites
}

/// The inverse projection of a declaration named `name`, over the complete row
/// set unless a `surface` is named.
fn inverse_query(name: &str, kind: &str, surface: Option<&str>) -> Value {
    let mut step = json!({ "op": "edges_of" });
    if let Some(surface) = surface {
        step["surface"] = json!(surface);
    }
    json!({
        "match": { "kind": kind, "name": name },
        "steps": [{ "op": "enclosing_decl" }, step]
    })
}

/// The forward projection over one file.
fn forward_query(language: &str, path: &str) -> Value {
    json!({
        "languages": [language],
        "where": [format!("**/{path}")],
        "occurrences": { "class": ["reference"] },
        "steps": [{ "op": "edges_from" }]
    })
}

/// Assert the two directions state one call site as one fact.
///
/// Shared because five scenarios below make exactly this claim and would
/// otherwise each spell the same field walk.
fn assert_parity_at_one_site(forward: &Value, inverse: &Value, suffix: &str, label: &str) {
    let forward_edges = edges_to(forward, suffix);
    assert_eq!(
        forward_edges.len(),
        1,
        "{label}: the resolver states exactly one forward edge to {suffix}: {forward:#}"
    );
    let inverse_edges = edges_to(inverse, suffix);
    assert_eq!(
        inverse_edges.len(),
        1,
        "{label}: the usage index states exactly one inverse edge to {suffix}: {inverse:#}"
    );
    for field in ["start_byte", "end_byte", "reference_kind", "proof"] {
        assert_eq!(
            forward_edges[0][field], inverse_edges[0][field],
            "{label}: the two producers must agree on {field}:\nforward {:#}\ninverse {:#}",
            forward_edges[0], inverse_edges[0]
        );
    }
    assert_eq!(
        forward_edges[0]["target"]["fq_name"], inverse_edges[0]["target"]["fq_name"],
        "{label}: one target, two directions:\nforward {:#}\ninverse {:#}",
        forward_edges[0], inverse_edges[0]
    );
}

// ---------------------------------------------------------------------------
// Scenario 1 -- 02abec289 "Fix Java forward-inverse reference parity".
// ---------------------------------------------------------------------------

const JAVA_SERVICE: &str = "package fixture;\n\npublic class Service {\n    public int start() {\n        return 1;\n    }\n}\n";

const JAVA_LAUNCHER: &str = "package fixture;\n\nimport java.util.ArrayList;\n\npublic class Launcher {\n    int launch(Service service) {\n        ArrayList<String> pending = new ArrayList<String>();\n        pending.add(\"boot\");\n        return service.start() + pending.size();\n    }\n}\n";

/// 02abec289 -- a Java cross-file call site is one fact stated twice.
///
/// The regression this stands for had the two producers disagree at a plain
/// cross-file call: one direction saw the site, the other did not, or they
/// classified it differently. Here both directions must state the same bytes,
/// the same target, the same reference kind and the same proof.
///
/// Two near misses ride along, both taken from the issue text. The
/// declaration-name token in `Service.java` is not a reference, so the forward
/// projection of the *declaring* file states no edge to `start`. And the
/// `java.util.ArrayList` calls in the caller reach a dependency that is not in
/// the workspace index, so no edge may claim a `java.` target -- an
/// unresolvable external is an absence, never an invented row.
#[test]
fn java_cross_file_call_agrees_in_both_directions() {
    let fixture = Fixture::new(&[
        ("src/Service.java", JAVA_SERVICE),
        ("src/Launcher.java", JAVA_LAUNCHER),
    ]);

    let inverse_result = fixture.run(inverse_query("start", "callable", None));
    assert_eq!(
        inverse_result.completion(),
        CodeQueryCompletion::Complete,
        "a parity verdict must be read from a complete run: {:?}",
        inverse_result.diagnostics
    );
    assert_eq!(
        edge_provenances(&inverse_result),
        vec!["inverse"],
        "an edges-of answer comes from the usage index"
    );
    let forward_result = fixture.run(forward_query("java", "Launcher.java"));
    assert!(
        edge_provenances(&forward_result)
            .iter()
            .all(|provenance| *provenance == "forward"),
        "an edges-from answer comes from the resolver: {:?}",
        edge_provenances(&forward_result)
    );

    let inverse = serialized(&inverse_result);
    let forward = serialized(&forward_result);
    assert_parity_at_one_site(&forward, &inverse, "Service.start", "java");
    assert_eq!(
        edges_to(&forward, "Service.start")[0]["reference_kind"],
        json!("method_call"),
        "the site is spelled as a call through a named receiver: {forward:#}"
    );

    // Near miss: the declaration's own name token is not a reference.
    let declaring_file = fixture.json(forward_query("java", "Service.java"));
    assert!(
        edges_to(&declaring_file, "Service.start").is_empty(),
        "the declaration head is not a use site, so it produces no forward edge: {declaring_file:#}"
    );

    // Near miss: an unindexed external dependency yields no edge at all.
    let external = edge_rows(&forward)
        .into_iter()
        .filter(|row| {
            row["target"]["fq_name"]
                .as_str()
                .is_some_and(|fq_name| fq_name.starts_with("java."))
        })
        .collect::<Vec<_>>();
    assert!(
        external.is_empty(),
        "a call into an unindexed dependency has no target to name: {external:#?}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 2 -- 7cac14b63 "Fix Python forward-inverse reference parity".
// ---------------------------------------------------------------------------

const PYTHON_SERVICE: &str = "class Service:\n    def start(self):\n        return 1\n";
const PYTHON_LAUNCHER: &str =
    "from service import Service\n\n\ndef launch(service: Service):\n    return service.start()\n";

/// 7cac14b63 -- the same parity shape in Python.
///
/// Python reaches the target through a module import and an annotated
/// parameter rather than a package-scoped type name, so the two producers run
/// entirely different analyses to reach it. Agreement here is therefore a
/// separate claim from the Java one, not a repetition of it.
#[test]
fn python_cross_file_call_agrees_in_both_directions() {
    let fixture = Fixture::new(&[
        ("service.py", PYTHON_SERVICE),
        ("launcher.py", PYTHON_LAUNCHER),
    ]);

    let inverse_result = fixture.run(inverse_query("start", "callable", None));
    assert_eq!(
        inverse_result.completion(),
        CodeQueryCompletion::Complete,
        "a parity verdict must be read from a complete run: {:?}",
        inverse_result.diagnostics
    );
    let inverse = serialized(&inverse_result);
    let forward = fixture.json(forward_query("python", "launcher.py"));
    assert_parity_at_one_site(&forward, &inverse, "Service.start", "python");

    // Near miss: `def start` in the declaring module is not a use site.
    let declaring_file = fixture.json(forward_query("python", "service.py"));
    assert!(
        edges_to(&declaring_file, "Service.start").is_empty(),
        "the declaration head produces no forward reference edge: {declaring_file:#}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 3 -- 5b4b0371f "Reuse Rust receiver type proof for usages".
// ---------------------------------------------------------------------------

const RUST_TYPED_RECEIVER: &str = "pub struct Widget;\n\nimpl Widget {\n    pub fn new() -> Widget {\n        Widget\n    }\n\n    pub fn run(&self) -> usize {\n        1\n    }\n}\n\npub fn drive() -> usize {\n    let s = Widget::new();\n    s.run()\n}\n";

/// 5b4b0371f -- a Rust call through a typed local receiver is proven on both
/// sides.
///
/// The regression this stands for had the forward resolver know the receiver's
/// type while the usage index reported the same site as an unproven name
/// match. A proof that depends on which direction you ask from is not a proof,
/// so both rows are read explicitly here.
///
/// KNOWN GAP: the owner classifier cannot relate a Rust free function to the
/// inherent impl that owns the target, so both rows state `owner_relation`
/// `unknown` where the same shape in Java states `external`. That is honest --
/// `unknown` is never silently widened to `external` -- but it is a gap, and
/// the assertions below pin the observed value so closing it shows up here.
#[test]
fn rust_typed_receiver_call_is_proven_in_both_directions() {
    let fixture = Fixture::new(&[("src/lib.rs", RUST_TYPED_RECEIVER)]);

    let inverse = fixture.json(inverse_query("run", "callable", None));
    let forward = fixture.json(forward_query("rust", "lib.rs"));
    assert_parity_at_one_site(&forward, &inverse, "Widget.run", "rust");

    let forward_edge = edges_to(&forward, "Widget.run")[0];
    let inverse_edge = edges_to(&inverse, "Widget.run")[0];
    assert_eq!(
        forward_edge["proof"],
        json!("proven"),
        "the resolver knows `s` from `Widget::new()`: {forward_edge:#}"
    );
    assert_eq!(
        inverse_edge["proof"],
        json!("proven"),
        "the usage index must reuse that receiver type rather than fall back to \
         an unproven name match: {inverse_edge:#}"
    );
    for (direction, edge) in [("forward", forward_edge), ("inverse", inverse_edge)] {
        assert_eq!(
            edge["owner_relation"],
            json!("unknown"),
            "{direction}: KNOWN GAP -- a free-function caller is not related to the \
             target's inherent impl, and the classifier says so rather than \
             guessing `external`: {edge:#}"
        );
    }
}

// ---------------------------------------------------------------------------
// Scenario 4 -- 5f553eaf3 "scan_usages: uniform, honest, inspectable
// same-owner usage policy".
// ---------------------------------------------------------------------------

const JAVA_EXPLICIT_THIS: &str = "package fixture;\n\npublic class Panel {\n    int render() {\n        return this.helper();\n    }\n\n    int helper() {\n        return 1;\n    }\n}\n";

/// 5f553eaf3 -- a same-owner call is classified, not silently dropped.
///
/// The policy this commit made uniform is only worth anything if it is
/// visible, so both halves are asserted: the complete row set carries the
/// sibling call with `same_owner` / `self_receiver`, and the external-usages
/// surface -- the one an agent or a call graph reads -- excludes exactly that
/// row. A silent drop and an honest classification look identical from the
/// external surface alone, which is why the first half exists.
#[test]
fn java_same_owner_sibling_call_is_classified_and_excluded_from_external_usages() {
    let fixture = Fixture::new(&[("src/Panel.java", JAVA_EXPLICIT_THIS)]);

    let complete = fixture.json(inverse_query("helper", "callable", None));
    let edges = edges_to(&complete, "Panel.helper");
    assert_eq!(
        edges.len(),
        1,
        "the complete row set carries the sibling call: {complete:#}"
    );
    assert_eq!(
        edges[0]["owner_relation"],
        json!("same_owner"),
        "`render` and `helper` hang off one class: {complete:#}"
    );
    assert_eq!(
        edges[0]["usage_kind"],
        json!("self_receiver"),
        "`this.helper()` is a self-receiver usage: {complete:#}"
    );
    assert_eq!(
        edges[0]["reference_kind"],
        json!("method_call"),
        "{complete:#}"
    );

    let external = fixture.json(inverse_query("helper", "callable", Some("external_usages")));
    assert!(
        edges_to(&external, "Panel.helper").is_empty(),
        "the external-usages surface excludes a self-receiver usage: {external:#}"
    );
    let lsp = fixture.json(inverse_query("helper", "callable", Some("lsp_references")));
    assert_eq!(
        edges_to(&lsp, "Panel.helper").len(),
        1,
        "the editor surface keeps it: {lsp:#}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 5 -- 6b8ad034e "cpp: record bare implicit-this calls as unproven
// inbound, not dropped".
// ---------------------------------------------------------------------------

const JAVA_BARE_THIS: &str = "package fixture;\n\npublic class Sheet {\n    int render() {\n        return helper();\n    }\n\n    int helper() {\n        return 1;\n    }\n}\n";

/// 6b8ad034e, expressed in Java -- a bare implicit-this call is recorded, not
/// dropped.
///
/// The mined commit fixed C++, which declares no forward edge projection, so
/// the contract is re-expressed in Java where the same spelling exists. The
/// contract is presence, not a particular proof: a call with no written
/// receiver must still produce an inbound row on the surface that carries it,
/// because dropping it is what makes a caller believe the method is dead. The
/// proof field is asserted at whatever the engine actually states, so a change
/// in confidence shows up here as a diff rather than as silence.
#[test]
fn java_bare_implicit_this_call_is_recorded_inbound_rather_than_dropped() {
    let fixture = Fixture::new(&[("src/Sheet.java", JAVA_BARE_THIS)]);

    let complete = fixture.json(inverse_query("helper", "callable", None));
    let edges = edges_to(&complete, "Sheet.helper");
    assert_eq!(
        edges.len(),
        1,
        "the bare call must be present, not dropped: {complete:#}"
    );
    assert_eq!(
        edges[0]["usage_kind"],
        json!("self_receiver"),
        "an implicit receiver is still a self receiver: {complete:#}"
    );
    assert_eq!(
        edges[0]["proof"],
        json!("proven"),
        "the observed proof for a Java implicit-this call: {complete:#}"
    );
    assert_eq!(
        edges[0]["site_class"],
        json!("use_site"),
        "the row addresses the call, not the declaration head: {complete:#}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 6 -- 76faeff2d "Fix C# nested type usage resolution".
// ---------------------------------------------------------------------------

const JAVA_OUTER: &str = "package fixture;\n\npublic class Outer {\n    public static class Inner {\n        public int size() {\n            return 1;\n        }\n    }\n}\n";

const JAVA_NESTED_HOST: &str = "package fixture;\n\npublic class NestedHost {\n    int run() {\n        Outer.Inner inner = new Outer.Inner();\n        return inner.size();\n    }\n}\n";

/// 76faeff2d, expressed in Java -- a nested type resolves to the nested
/// declaration, in both directions.
///
/// The mined commit fixed C#; Java spells the same shape, so the contract is
/// pinned here. The regression it stands for resolved `Outer.Inner` to the
/// outer class, or to nothing. The fq-name assertions below are the whole
/// point: a row that named `fixture.Outer` would pass a bare "an edge exists"
/// check.
///
/// KNOWN GAP: the forward producer states no edge whose target is the nested
/// class itself. Java's adapter cannot assign a namespace to the
/// `path_segment` role, so the `Outer.Inner` type operand and the
/// `new Outer.Inner()` allocation are not reachable as forward edges from
/// either a `reference`-class seed or a `type_operand`-role seed. Both
/// absences are asserted below rather than skipped, so the day the role is
/// classified this test fails and is upgraded to a parity claim. What the
/// forward producer *does* state -- `inner.size()` resolved through the nested
/// owner -- is asserted positively, because that is the half of the nested
/// resolution it can answer today.
#[test]
fn java_nested_type_reference_targets_the_nested_declaration_both_ways() {
    let fixture = Fixture::new(&[
        ("src/Outer.java", JAVA_OUTER),
        ("src/NestedHost.java", JAVA_NESTED_HOST),
    ]);

    let inverse = fixture.json(inverse_query("Inner", "class", None));
    let inverse_edges = edges_to(&inverse, "Outer.Inner");
    for row in &inverse_edges {
        assert_eq!(
            row["target"]["fq_name"],
            json!("fixture.Outer.Inner"),
            "the target is the nested class, not its container: {row:#}"
        );
        assert!(
            row["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("NestedHost.java")),
            "the use sites are all in the referring file: {row:#}"
        );
    }
    let mut kinds = inverse_edges
        .iter()
        .map(|row| row["reference_kind"].clone())
        .collect::<Vec<_>>();
    kinds.sort_by_key(|kind| kind.as_str().unwrap_or_default().to_string());
    assert_eq!(
        kinds,
        vec![json!("constructor_call"), json!("type_reference")],
        "the declared type and the allocation are both inbound references to the \
         nested class: {inverse:#}"
    );

    let forward = fixture.json(forward_query("java", "NestedHost.java"));
    let forward_members = edges_to(&forward, "Outer.Inner.size");
    assert_eq!(
        forward_members.len(),
        1,
        "the resolver reaches the nested class's member through the receiver: {forward:#}"
    );
    assert_eq!(
        forward_members[0]["target"]["fq_name"],
        json!("fixture.Outer.Inner.size"),
        "the member is named on the nested owner, not the outer one: {forward:#}"
    );
    assert_eq!(
        forward_members[0]["reference_kind"],
        json!("method_call"),
        "{forward:#}"
    );

    // KNOWN GAP, both halves. Neither seed reaches the nested type operand.
    let forward_types = edges_to(&forward, "Outer.Inner");
    assert!(
        forward_types.is_empty(),
        "KNOWN GAP: the forward producer states no edge targeting the nested \
         class itself, so this must stay empty until `path_segment` is \
         namespaced: {forward_types:#?}"
    );
    let by_role = fixture.json(json!({
        "languages": ["java"],
        "where": ["**/NestedHost.java"],
        "occurrences": { "role": ["type_operand"] },
        "steps": [{ "op": "edges_from" }]
    }));
    assert!(
        edge_rows(&by_role).is_empty(),
        "KNOWN GAP: a type-operand seed reaches no nested-type site either: {by_role:#}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 7 -- 2436a6627 "Resolve C# self fields and null-forgiving method
// groups".
// ---------------------------------------------------------------------------

const TS_SELF_FIELD: &str = "export class Toolbar {\n    render(): number {\n        return this.helper();\n    }\n\n    helper(): number {\n        return 1;\n    }\n}\n";

/// 2436a6627, expressed in TypeScript -- a `this.` member reference resolves
/// to the member of the enclosing class.
///
/// The mined commit fixed C# self-field resolution. TypeScript spells the same
/// receiver, so the contract is pinned here: the forward producer must state
/// an edge for `this.helper()` and must relate its owner, not shrug.
///
/// KNOWN GAP: the two producers classify the *usage kind* of this site
/// differently. The inverse row says `self_receiver`, which is what routes it
/// off the external-usages surface; the forward row says `reference`. Both
/// agree on `same_owner`, so the owner relation is not the gap -- the usage
/// kind is, and a forward-only consumer filtering on it would count a
/// `this.` call as an external usage. Both values are asserted so the
/// disagreement is a row in this file rather than a silent divergence.
#[test]
fn typescript_self_receiver_call_states_a_forward_edge_with_a_related_owner() {
    let fixture = Fixture::new(&[("toolbar.ts", TS_SELF_FIELD)]);

    let forward = fixture.json(forward_query("typescript", "toolbar.ts"));
    let forward_edges = edges_to(&forward, "Toolbar.helper");
    assert_eq!(
        forward_edges.len(),
        1,
        "`this.helper()` is one forward edge: {forward:#}"
    );
    assert_eq!(
        forward_edges[0]["owner_relation"],
        json!("same_owner"),
        "the site's enclosing declaration shares the target's owner: {forward:#}"
    );
    assert_eq!(
        forward_edges[0]["reference_kind"],
        json!("method_call"),
        "{forward:#}"
    );

    let inverse = fixture.json(inverse_query("helper", "callable", None));
    let inverse_edges = edges_to(&inverse, "Toolbar.helper");
    assert_eq!(inverse_edges.len(), 1, "the same site inbound: {inverse:#}");
    assert_eq!(
        inverse_edges[0]["start_byte"], forward_edges[0]["start_byte"],
        "the two rows are the same site:\nforward {:#}\ninverse {:#}",
        forward_edges[0], inverse_edges[0]
    );
    assert_eq!(
        inverse_edges[0]["usage_kind"],
        json!("self_receiver"),
        "the usage index classifies the `this.` receiver: {inverse:#}"
    );
    assert_eq!(
        forward_edges[0]["usage_kind"],
        json!("reference"),
        "KNOWN GAP: the resolver does not classify the same site as a \
         self-receiver usage: {forward:#}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 8 -- 7a562e143 "Fix JS Rust and Scala reference differential gaps".
// ---------------------------------------------------------------------------

const TS_REGISTRY: &str =
    "export class Registry {\n    register(): number {\n        return 1;\n    }\n}\n";

const TS_BOOT: &str = "import { Registry } from \"./registry\";\n\nexport function boot(registry: Registry): number {\n    return registry.register();\n}\n";

/// 7a562e143 -- a TypeScript cross-file import and call, with the import
/// binding classified rather than counted as a usage.
///
/// The differential gaps this commit closed were exactly the case where one
/// direction saw a module-scoped reference and the other did not. The second
/// half is the near miss from the issue text: the `import { Registry }`
/// binding site is editor-visible but is not a usage of the class, so it must
/// appear on `lsp_references` with `usage_kind` `import` and be absent from
/// `external_usages`.
#[test]
fn typescript_import_and_call_agree_and_the_binding_is_not_a_usage() {
    let fixture = Fixture::new(&[("registry.ts", TS_REGISTRY), ("boot.ts", TS_BOOT)]);

    let inverse = fixture.json(inverse_query("register", "callable", None));
    let forward = fixture.json(forward_query("typescript", "boot.ts"));
    assert_parity_at_one_site(&forward, &inverse, "Registry.register", "typescript");

    let lsp = fixture.json(inverse_query("Registry", "class", Some("lsp_references")));
    let bindings = edges_to(&lsp, "Registry")
        .into_iter()
        .filter(|row| row["usage_kind"] == json!("import"))
        .collect::<Vec<_>>();
    assert_eq!(
        bindings.len(),
        1,
        "the editor surface shows the import binding: {lsp:#}"
    );
    assert!(
        bindings[0]["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("boot.ts")),
        "the binding site is the importing file: {:#}",
        bindings[0]
    );

    let external = fixture.json(inverse_query("Registry", "class", Some("external_usages")));
    let external_imports = edges_to(&external, "Registry")
        .into_iter()
        .filter(|row| row["usage_kind"] == json!("import"))
        .collect::<Vec<_>>();
    assert!(
        external_imports.is_empty(),
        "an import binding is not an external usage: {external:#}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 9 -- ec9ed1787 "Finish JS/TS usagebench parity fixes".
// ---------------------------------------------------------------------------

const TS_SHARED: &str = "export function shared(): number {\n    return 1;\n}\n";
const TS_FIRST: &str = "import { shared } from \"./shared\";\n\nexport function first(): number {\n    return shared();\n}\n";
const TS_SECOND: &str = "import { shared } from \"./shared\";\n\nexport function second(): number {\n    return shared() + 1;\n}\n";

/// ec9ed1787 -- two callers, and the two directions enumerate the same set.
///
/// A single-site parity test cannot catch a producer that finds the first
/// caller and stops, which is the shape of the usagebench gaps this commit
/// closed. The assertion is therefore set equality of `(path, start_byte)`
/// pairs: the union of the per-file forward answers must equal the inverse
/// answer exactly.
#[test]
fn typescript_export_used_twice_enumerates_one_site_set_in_both_directions() {
    let fixture = Fixture::new(&[
        ("shared.ts", TS_SHARED),
        ("first.ts", TS_FIRST),
        ("second.ts", TS_SECOND),
    ]);

    let inverse = fixture.json(inverse_query("shared", "callable", Some("external_usages")));
    let inverse_sites = sites(&inverse, "shared");
    assert_eq!(
        inverse_sites.len(),
        2,
        "both callers are enumerated: {inverse:#}"
    );

    let mut forward_sites = Vec::new();
    for caller in ["first.ts", "second.ts"] {
        let forward = fixture.json(forward_query("typescript", caller));
        let per_file = sites(&forward, "shared");
        assert_eq!(
            per_file.len(),
            1,
            "{caller}: the resolver states its own call: {forward:#}"
        );
        forward_sites.extend(per_file);
    }
    forward_sites.sort();

    assert_eq!(
        forward_sites, inverse_sites,
        "the two directions must enumerate one site set:\nforward {forward_sites:#?}\ninverse {inverse_sites:#?}"
    );
}

// ---------------------------------------------------------------------------
// Scenario 10 -- a04e3e85d "Preserve Java constructor receiver type usages".
// ---------------------------------------------------------------------------

const JAVA_WIDGET: &str = "package fixture;\n\npublic class Widget {\n    public int size() {\n        return 1;\n    }\n}\n";

const JAVA_WIDGET_HOST: &str = "package fixture;\n\npublic class WidgetHost {\n    int run() {\n        Widget widget = new Widget();\n        return widget.size();\n    }\n}\n";

/// a04e3e85d -- `new Widget()` is stated as a constructor edge by both
/// producers.
///
/// The regression this stands for lost the constructor's receiver type, which
/// made the allocation site invisible as a usage of the class. The reference
/// kind is asserted explicitly on both rows, because a constructor call
/// downgraded to a plain type reference would still satisfy a weaker check.
#[test]
fn java_constructor_call_is_stated_as_a_constructor_edge_both_ways() {
    let fixture = Fixture::new(&[
        ("src/Widget.java", JAVA_WIDGET),
        ("src/WidgetHost.java", JAVA_WIDGET_HOST),
    ]);

    let inverse = fixture.json(inverse_query("Widget", "class", None));
    let forward = fixture.json(forward_query("java", "WidgetHost.java"));

    let inverse_constructors = edges_to(&inverse, "fixture.Widget")
        .into_iter()
        .filter(|row| row["reference_kind"] == json!("constructor_call"))
        .collect::<Vec<_>>();
    assert_eq!(
        inverse_constructors.len(),
        1,
        "the usage index states one constructor edge: {inverse:#}"
    );
    let forward_constructors = edges_to(&forward, "fixture.Widget")
        .into_iter()
        .filter(|row| row["reference_kind"] == json!("constructor_call"))
        .collect::<Vec<_>>();
    assert_eq!(
        forward_constructors.len(),
        1,
        "the resolver states one constructor edge: {forward:#}"
    );
    for field in ["path", "start_byte", "end_byte", "proof"] {
        assert_eq!(
            forward_constructors[0][field], inverse_constructors[0][field],
            "the two producers must agree on {field}:\nforward {:#}\ninverse {:#}",
            forward_constructors[0], inverse_constructors[0]
        );
    }
}

// ---------------------------------------------------------------------------
// Scenario 11 -- f852b12d5 "Go usages: resolve qualified field types across
// packages".
// ---------------------------------------------------------------------------

const RUST_CRATE_ROOT: &str = "pub mod a;\npub mod b;\n";
const RUST_MODULE_A: &str = "pub struct Widget;\n";
const RUST_MODULE_B: &str = "pub struct Holder {\n    pub widget: crate::a::Widget,\n}\n";

/// f852b12d5, expressed in Rust -- a field whose type lives in another module
/// is a use site of that type.
///
/// The mined commit fixed Go, which declares no forward edge projection, so
/// the contract is re-expressed in Rust: `crate::a::Widget` in a struct field
/// is a qualified cross-module type reference, exactly the shape Go's
/// package-qualified field types have. The inverse projection must state it,
/// with `type_reference` as the kind, and the forward projection of the
/// holding module must meet it at the same site.
#[test]
fn rust_cross_module_field_type_is_a_reference_in_both_directions() {
    let fixture = Fixture::new(&[
        ("src/lib.rs", RUST_CRATE_ROOT),
        ("src/a.rs", RUST_MODULE_A),
        ("src/b.rs", RUST_MODULE_B),
    ]);

    let inverse = fixture.json(inverse_query("Widget", "class", None));
    let inverse_edges = edges_to(&inverse, "Widget");
    assert_eq!(
        inverse_edges.len(),
        1,
        "the field's type annotation is the one use site: {inverse:#}"
    );
    assert_eq!(
        inverse_edges[0]["reference_kind"],
        json!("type_reference"),
        "a field type annotation is a type reference: {inverse:#}"
    );
    assert!(
        inverse_edges[0]["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("b.rs")),
        "the site is the holding module: {inverse:#}"
    );

    let forward = fixture.json(forward_query("rust", "b.rs"));
    let forward_edges = edges_to(&forward, "Widget");
    assert_eq!(
        forward_edges.len(),
        1,
        "the resolver states the same type operand: {forward:#}"
    );
    assert_eq!(
        forward_edges[0]["start_byte"], inverse_edges[0]["start_byte"],
        "the two directions meet at one site:\nforward {:#}\ninverse {:#}",
        forward_edges[0], inverse_edges[0]
    );
}
