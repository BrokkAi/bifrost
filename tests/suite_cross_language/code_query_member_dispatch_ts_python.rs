//! TypeScript/JavaScript and Python member-dispatch attribution (#1477, M3).
//!
//! The Java family proves the enrichment contract for a resolver that walks a
//! type hierarchy. These fixtures prove what the two selection-only families
//! can honestly say: which owner the lookup asked about, at which hop distance,
//! in which language-neutral dispatch tier -- and, where a family's resolver
//! never performs a hierarchy walk at all, that no row claims one.

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

fn candidate_rows(files: &[(&str, &str)], path: &str) -> Value {
    serialized(&run(
        files,
        json!({
            "where": [path],
            "occurrences": { "role": ["member_position"] },
            "steps": [{"op": "candidates_of"}],
            "result_detail": "full"
        }),
    ))
}

fn selected(candidates: &Value) -> Vec<&Value> {
    rows(candidates)
        .iter()
        .filter(|row| row["outcome"] == "selected")
        .collect()
}

/// A TypeScript member found on the receiver's own class is attributed to that
/// class at depth zero, in the direct tier, and a same-name decoy owner never
/// wins. The static form of the same lookup is attributed to the
/// static/companion tier, because that is the form the index answered from.
///
/// The fixtures use an inline construction receiver and a static receiver on
/// purpose: those are the member lookups this route performs itself. A receiver
/// typed by a parameter annotation or a local binding is answered by the JS/TS
/// receiver fact provider (`crates/bifrost-js-ts/src/graph/receiver_analysis.rs`),
/// which returns member declarations without the owner it used, so those rows
/// stay unattributed rather than attributed to a re-derived guess.
#[test]
fn typescript_own_member_is_attributed_at_depth_zero_beside_a_decoy() {
    let files = [(
        "app.ts",
        r#"class Service { run() {} }
class Decoy { run() {} }
export function caller() { new Service().run(); }
"#,
    )];
    let candidates = candidate_rows(&files, "app.ts");
    let selected = selected(&candidates);
    assert!(!selected.is_empty(), "{candidates}");
    for row in &selected {
        assert_eq!(
            row["candidate"]["unit"]["fq_name"], "Service.run",
            "{candidates}"
        );
        assert_eq!(row["owner"]["fq_name"], "Service", "{candidates}");
        assert_eq!(row["hierarchy_depth"], 0, "{candidates}");
        assert_eq!(row["dispatch_tier"], "inherent_or_direct", "{candidates}");
        assert_eq!(row["applicability"], "unknown", "{candidates}");
    }
}

/// The static form of the same lookup states the tier it was answered at.
#[test]
fn typescript_static_member_is_attributed_to_the_static_tier() {
    let files = [(
        "app.ts",
        r#"class Service { static run() {} }
class Decoy { static run() {} }
export function caller() { Service.run(); }
"#,
    )];
    let candidates = candidate_rows(&files, "app.ts");
    let selected = selected(&candidates);
    assert!(!selected.is_empty(), "{candidates}");
    for row in &selected {
        assert_eq!(row["owner"]["fq_name"], "Service", "{candidates}");
        assert_eq!(row["hierarchy_depth"], 0, "{candidates}");
        assert_eq!(row["dispatch_tier"], "static_or_companion", "{candidates}");
    }
}

/// EXPECTED GAP (#1477): a receiver typed by a parameter annotation is resolved
/// by the JS/TS receiver fact provider, which reports the member declarations
/// without the owner it selected them through. The candidate row is therefore
/// unattributed. Absence is honest here -- it is not depth zero -- but the
/// attribution is only recoverable by instrumenting that provider in
/// `crates/bifrost-js-ts`.
#[test]
fn typescript_provider_resolved_receiver_leaves_candidates_unattributed() {
    let files = [(
        "app.ts",
        r#"class Service { run() {} }
class Decoy { run() {} }
export function caller(service: Service) { service.run(); }
"#,
    )];
    let candidates = candidate_rows(&files, "app.ts");
    let selected = selected(&candidates);
    assert!(!selected.is_empty(), "{candidates}");
    for row in &selected {
        assert_eq!(
            row["candidate"]["unit"]["fq_name"], "Service.run",
            "the production answer is unchanged: {candidates}"
        );
        assert!(
            row["owner"].is_null() && row["hierarchy_depth"].is_null(),
            "expected gap: this seam cannot name its owner, so it claims none: {candidates}"
        );
    }
}

/// EXPECTED GAP (#1477): TypeScript get-definition performs no superclass or
/// interface walk for a member lookup. `ts_member_candidates` asks the index
/// for `<receiver fq>.<member>` and nothing else, so a member declared only on
/// a base class does not resolve at all -- the selection summary says
/// `unresolved` with zero candidates.
///
/// That is what this test pins, deliberately: the honest consequence for the
/// enrichment contract is that no candidate row exists to attribute, never a
/// row attributed to a hierarchy hop the resolver did not take. Adding the walk
/// is a resolver behavior change and belongs to its own change; when it lands,
/// this test must become the depth-1 `inherited_or_promoted` assertion its
/// Java sibling already makes.
#[test]
fn typescript_inherited_member_is_an_unresolved_gap_not_a_false_attribution() {
    let files = [(
        "app.ts",
        r#"class Base { run() {} }
class Service extends Base { }
export function caller(service: Service) { service.run(); }
"#,
    )];
    let selection = serialized(&run(
        &files,
        json!({
            "where": ["app.ts"],
            "occurrences": { "role": ["member_position"] },
            "steps": [{"op": "member_selection"}],
            "result_detail": "full"
        }),
    ));
    assert_eq!(rows(&selection).len(), 1, "{selection}");
    let summary = &rows(&selection)[0];
    assert_eq!(summary["member"], "run", "{selection}");
    assert_eq!(
        summary["outcome"], "unresolved",
        "the mandatory summary states the gap instead of omitting the site: {selection}"
    );
    assert_eq!(summary["selected_count"], 0, "{selection}");
    assert_eq!(
        summary["coverage"], "open",
        "a selection-only trace can never claim an exhaustive empty set: {selection}"
    );

    let candidates = candidate_rows(&files, "app.ts");
    assert!(
        rows(&candidates).is_empty(),
        "an unresolved lookup must not manufacture candidate rows: {candidates}"
    );
}

/// A Python member inherited through one base class is attributed to the base
/// that declares it, at hop distance one, in the inherited tier, with a
/// contiguous `extends` route from the receiver to that owner.
#[test]
fn python_inherited_member_attributes_owner_depth_and_route() {
    let files = [(
        "app.py",
        "class Base:\n    def run(self):\n        pass\n\nclass Service(Base):\n    pass\n\nclass Decoy:\n    def run(self):\n        pass\n\ndef caller(service: Service):\n    service.run()\n",
    )];
    let candidates = candidate_rows(&files, "app.py");
    let selected = selected(&candidates);
    assert!(!selected.is_empty(), "{candidates}");
    for row in &selected {
        assert_eq!(
            row["candidate"]["unit"]["fq_name"], "app.Base.run",
            "the winner is the declaring base, not the same-name decoy: {candidates}"
        );
        assert_eq!(row["owner"]["fq_name"], "app.Base", "{candidates}");
        assert_eq!(row["hierarchy_depth"], 1, "{candidates}");
        assert_eq!(
            row["dispatch_tier"], "inherited_or_promoted",
            "{candidates}"
        );
        assert_eq!(row["applicability"], "unknown", "{candidates}");
    }
}

/// A Python member declared on the receiver's own class outranks the same-name
/// inherited one, and the row states the direct find: owner is the receiver's
/// class, depth zero, direct tier. The deeper declaration is never reached, so
/// no row claims it was considered.
#[test]
fn python_own_member_precedence_is_attributed_at_depth_zero() {
    let files = [(
        "app.py",
        "class Base:\n    def run(self):\n        pass\n\nclass Service(Base):\n    def run(self):\n        pass\n\ndef caller(service: Service):\n    service.run()\n",
    )];
    let candidates = candidate_rows(&files, "app.py");
    let selected = selected(&candidates);
    assert!(!selected.is_empty(), "{candidates}");
    for row in &selected {
        assert_eq!(
            row["candidate"]["unit"]["fq_name"], "app.Service.run",
            "{candidates}"
        );
        assert_eq!(row["owner"]["fq_name"], "app.Service", "{candidates}");
        assert_eq!(row["hierarchy_depth"], 0, "{candidates}");
        assert_eq!(row["dispatch_tier"], "inherent_or_direct", "{candidates}");
    }
    assert!(
        rows(&candidates)
            .iter()
            .all(|row| row["candidate"]["unit"]["fq_name"] != "app.Base.run"),
        "the hidden deeper member is never computed by the production lookup, \
         so no row may claim it was considered: {candidates}"
    );
}

/// A union annotation names every one of its arms. The declared-type lookup
/// reads the annotation's `union_type` node, so a two-arm receiver resolves
/// ambiguously to both classes instead of reporting the first arm as one
/// precise answer (#1477).
/// The declared type of the `service.run()` receiver on the third line of a
/// one-file TypeScript fixture, through the public type lookup.
fn receiver_type_lookup(source: &str) -> brokk_bifrost::searchtools::TypeLookupResult {
    let project = InlineTestProject::new().file("app.ts", source).build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let line = source.lines().nth(2).expect("caller line");
    let mut result = brokk_bifrost::searchtools::get_type_by_location(
        workspace.analyzer(),
        brokk_bifrost::searchtools::GetTypeParams {
            references: vec![brokk_bifrost::searchtools::TypeReferenceQuery {
                path: "app.ts".to_string(),
                line: Some(3),
                column: Some(line.find("service.run").expect("receiver") + 1),
            }],
        },
    );
    result.results.remove(0)
}

#[test]
fn typescript_union_annotation_resolves_every_arm() {
    let lookup = receiver_type_lookup(
        r#"class ServiceA { run() {} }
class ServiceB { run() {} }
export function caller(service: ServiceA | ServiceB) { service.run(); }
"#,
    );
    let names = lookup
        .types
        .iter()
        .map(|item| item.fqn.clone())
        .collect::<Vec<_>>();
    assert!(
        names.iter().any(|name| name == "ServiceA") && names.iter().any(|name| name == "ServiceB"),
        "both arms of the union stay visible: {names:?} ({:?})",
        lookup.status
    );
    assert_eq!(
        lookup.status, "ambiguous",
        "a two-arm union is never one precise answer: {names:?}"
    );
}

/// A union with one indexed arm and one arm no definition backs is still not a
/// precise single type. Reporting `ServiceA` alone would erase the open arm --
/// the exact misrepresentation this work removes -- so the lookup stays
/// `ambiguous` and names the arm it could not resolve (#1477).
#[test]
fn typescript_partly_resolved_union_stays_open_about_the_unindexed_arm() {
    let lookup = receiver_type_lookup(
        r#"class ServiceA { run() {} }
class Unrelated { run() {} }
export function caller(service: ServiceA | ExternalLibService) { service.run(); }
"#,
    );
    let names = lookup
        .types
        .iter()
        .map(|item| item.fqn.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec!["ServiceA"],
        "only the indexed arm has definitions to report: {names:?}"
    );
    assert_eq!(
        lookup.status, "ambiguous",
        "one resolved arm out of two is not a precise answer: {names:?}"
    );
    assert!(
        lookup
            .diagnostics
            .iter()
            .any(|item| item.kind == "unresolved_type_arm"
                && item.message.contains("ExternalLibService")),
        "the open arm is named rather than dropped: {:?}",
        lookup.diagnostics
    );
}

/// A union whose arms are all unindexed reports no type at all, and says which
/// arms it could not resolve. It never falls back to the leading-identifier
/// text scan, which would report the first arm as one precise type (#1477).
#[test]
fn typescript_union_of_unindexed_arms_reports_no_type_not_the_first_arm() {
    let lookup = receiver_type_lookup(
        r#"class Unrelated { run() {} }
class AlsoUnrelated { run() {} }
export function caller(service: ExternalA | ExternalB) { service.run(); }
"#,
    );
    assert!(lookup.types.is_empty(), "{:?}", lookup.types);
    assert_eq!(lookup.status, "no_type", "{:?}", lookup.diagnostics);
    assert!(
        lookup
            .diagnostics
            .iter()
            .any(|item| item.kind == "unresolved_type_arm"
                && item.message.contains("ExternalA")
                && item.message.contains("ExternalB")),
        "both open arms are named: {:?}",
        lookup.diagnostics
    );
}

/// `ServiceA | null` is not open: the grammar fixes what `null` denotes, so no
/// class hides behind it and the resolved arm really is the complete answer.
/// The nullable annotation therefore keeps the precise result it always had.
#[test]
fn typescript_nullable_union_stays_precise() {
    let lookup = receiver_type_lookup(
        r#"class ServiceA { run() {} }
class Unrelated { run() {} }
export function caller(service: ServiceA | null) { service.run(); }
"#,
    );
    let names = lookup
        .types
        .iter()
        .map(|item| item.fqn.clone())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["ServiceA"], "{names:?}");
    assert_eq!(lookup.status, "resolved", "{:?}", lookup.diagnostics);
}

/// EXPECTED GAP (#1477): the receiver-analysis path does not consume the fix
/// above. `points_to` for a JS/TS receiver is answered by the JS/TS receiver
/// fact provider (`crates/bifrost-js-ts/src/graph/receiver_analysis.rs`), which
/// resolves the annotation through `ts_resolve_type_text_to_property_owners` and
/// its own copy of the leading-identifier text scan
/// (`crates/bifrost-js-ts/src/ts_owners.rs::ts_leading_type_identifier`). That
/// copy still takes the first arm, so the receiver outcome for a two-arm union
/// remains `precise` with one evidence row.
///
/// The M2 contract this fixture should meet is the one proven for a branching
/// allocation in `search/tests/details.rs`
/// (`ambiguous_receiver_keeps_both_types_as_open_evidence`): `ambiguous`/`open`
/// with one evidence row per arm. This test records the current answer so the
/// gap is stated rather than silently accepted; when the js-ts copy is fixed,
/// it must become that assertion.
#[test]
fn typescript_union_receiver_outcome_still_collapses_to_the_first_arm() {
    let files = [(
        "app.ts",
        r#"class ServiceA { run() {} }
class ServiceB { run() {} }
export function caller(service: ServiceA | ServiceB) { service.run(); }
"#,
    )];
    let receiver_query = |terminal: &str| {
        json!({
            "match": {
                "kind": "call",
                "callee": { "name": "run" },
                "receiver": { "capture": "receiver" }
            },
            "steps": [
                { "op": "points_to", "capture": "receiver" },
                { "op": terminal }
            ],
            "result_detail": "full"
        })
    };
    let outcome = serialized(&run(&files, receiver_query("receiver_outcome")));
    let evidence = serialized(&run(&files, receiver_query("receiver_evidence")));
    let arms = rows(&evidence)
        .iter()
        .filter_map(|row| row["declaration_fq_name"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        arms,
        vec!["ServiceA"],
        "expected gap: the receiver path still sees only the first arm; \
         when it is fixed this must become both arms: {evidence}"
    );
    assert_eq!(rows(&outcome)[0]["outcome"], "precise", "{outcome}");
}

/// An uninstrumented seam leaves the enrichment fields absent. Absence is
/// unattributed -- it is never depth zero, and never an owner a policy could
/// compare against. The Ruby member position has no member trace at all, so
/// whatever candidate rows it produces carry null enrichment.
#[test]
fn an_uninstrumented_seam_leaves_the_enrichment_fields_absent() {
    let files = [(
        "app.rb",
        "class Service\n  def run\n  end\nend\n\ndef caller(service)\n  service.run\nend\n",
    )];
    let candidates = candidate_rows(&files, "app.rb");
    for row in rows(&candidates) {
        assert!(
            row["owner"].is_null()
                && row["owner_id"].is_null()
                && row["hierarchy_depth"].is_null()
                && row["dispatch_tier"].is_null()
                && row["applicability"].is_null(),
            "an unattributed candidate states nothing, rather than a default: {row}"
        );
    }
}
