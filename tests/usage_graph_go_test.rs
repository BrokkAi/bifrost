//! `usage_graph` correctness on a Go fixture, exercising the behaviours the
//! whole-workspace inverted builder fixes relative to the original per-symbol
//! resolver:
//!
//! - **No over-counting of same-named methods.** `Alpha.Channel` and
//!   `Beta.Channel` share a name but never call each other; the per-symbol path
//!   cross-linked such methods into an O(n^2) false-positive cluster (observed on
//!   cockroach's generated `eventpb.*.LoggingChannel` — ~16k bogus edges). The
//!   inverted builder resolves each call to the receiver's actual type, so no edge
//!   appears between them.
//! - **Member calls resolve to the receiver's type**, so cross-file references are
//!   recovered (recall), not just bare-name matches.
//! - **Edge weights aggregate** distinct call sites, and **self-references** are
//!   dropped.

mod common;

use brokk_bifrost::SearchToolsService;
use common::InlineTestProject;
use common::usage_graph::{has_edge, usage_graph_at};
use serde_json::Value;
use std::path::PathBuf;

fn go_usage_graph() -> Value {
    go_usage_graph_with("{}")
}

fn go_usage_graph_with(args: &str) -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("usage-graph-go");
    let service = SearchToolsService::new(root).expect("failed to build searchtools service");
    let payload = service
        .call_tool_json("usage_graph", args)
        .expect("usage_graph call failed");
    serde_json::from_str(&payload).expect("usage_graph returned invalid JSON")
}

fn edge_sites<'a>(value: &'a Value, from: &str, to: &str) -> Option<&'a Vec<Value>> {
    value["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .find(|edge| edge["from"].as_str() == Some(from) && edge["to"].as_str() == Some(to))
        .and_then(|edge| edge["sites"].as_array())
}

fn edge_weight(value: &Value, from: &str, to: &str) -> Option<u64> {
    value["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .find(|edge| edge["from"].as_str() == Some(from) && edge["to"].as_str() == Some(to))
        .and_then(|edge| edge["weight"].as_u64())
}

#[test]
fn cross_package_selector_call_resolves_to_an_edge() {
    let graph = go_usage_graph();
    // `callsCrossPackage` calls `sub.Helper()` through an imported-package
    // selector; the edge must resolve to the callee in the other package.
    assert!(
        has_edge(
            &graph,
            "example.com/app.callsCrossPackage",
            "example.com/app/sub.Helper"
        ),
        "cross-package selector call should produce an edge; edges: {:?}",
        graph["edges"]
    );
}

#[test]
fn member_call_resolves_to_the_receivers_type() {
    let graph = go_usage_graph();
    // `describeAlpha` calls `a.Channel()` where `a` is typed `*Alpha`.
    assert!(
        has_edge(
            &graph,
            "example.com/app.describeAlpha",
            "example.com/app.Alpha.Channel"
        ),
        "member call on a *Alpha receiver should resolve to Alpha.Channel; edges: {:?}",
        graph["edges"]
    );
}

#[test]
fn constructor_returned_receiver_call_resolves_to_an_edge() {
    let graph = go_usage_graph();
    assert!(
        has_edge(
            &graph,
            "example.com/app.runService",
            "example.com/app.Service.Execute"
        ),
        "member call on a constructor-returned receiver should resolve to Service.Execute; edges: {:?}",
        graph["edges"]
    );
}

#[test]
fn object_sensitive_factory_receiver_resolves_only_constructed_type() {
    let project = InlineTestProject::with_language(brokk_bifrost::Language::Go)
        .file("go.mod", "module example.com/app\n\ngo 1.22\n")
        .file(
            "service.go",
            r#"
package app

type Service struct{}
func (Service) Run() {}

type Other struct{}
func (Other) Run() {}

func makeService() Service {
    return Service{}
}

func caller() {
    service := makeService()
    service.Run()
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(
            &graph,
            "example.com/app.caller",
            "example.com/app.Service.Run"
        ),
        "factory-produced receiver should resolve caller -> Service.Run: {}",
        graph["edges"]
    );
    assert!(
        !has_edge(
            &graph,
            "example.com/app.caller",
            "example.com/app.Other.Run"
        ),
        "factory-produced receiver must not resolve by same member name: {}",
        graph["edges"]
    );
}

#[test]
fn embedded_promoted_methods_resolve_with_go_precedence_and_ambiguity() {
    let project = InlineTestProject::with_language(brokk_bifrost::Language::Go)
        .file("go.mod", "module example.com/app\n\ngo 1.22\n")
        .file(
            "service.go",
            r#"
package app

type Base struct{}
func (Base) Run() {}

type Service struct {
    Base
}
func (Service) Run() {}

func readOuter(service Service) {
    service.Run()
}

type C struct{}
func (C) Ping() {}

type B struct {
    C
}

type A struct{}
func (A) Ping() {}

type Wrapper struct {
    A
    B
}

func readShallow(wrapper Wrapper) {
    wrapper.Ping()
}

type Audit struct{}
func (Audit) Record() {}

type Worker struct {
    Audit
}

func readPromotedMethod(worker Worker) {
    worker.Record()
}

type Shared struct{}
func (Shared) Touch() {}

type PathA struct {
    Shared
}

type PathB struct {
    Shared
}

type SharedAmbiguous struct {
    PathA
    PathB
}

func runSharedAmbiguous(value SharedAmbiguous) {
    value.Touch()
}

type MLeft struct{}
func (MLeft) Run() {}

type MRight struct{}
func (MRight) Run() {}

type MethodAmbiguous struct {
    MLeft
    MRight
}

func runAmbiguous(value MethodAmbiguous) {
    value.Run()
}

type NamedBase struct{}
func (NamedBase) Hidden() {}

type NamedWrapper struct {
    NamedBase NamedBase
}

func runNamedWrapper(value NamedWrapper) {
    value.Hidden()
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(
            &graph,
            "example.com/app.readOuter",
            "example.com/app.Service.Run"
        ),
        "outer direct method should win: {}",
        graph["edges"]
    );
    assert!(
        !has_edge(
            &graph,
            "example.com/app.readOuter",
            "example.com/app.Base.Run"
        ),
        "outer direct method must not also count as Base.Run: {}",
        graph["edges"]
    );
    assert!(
        has_edge(
            &graph,
            "example.com/app.readShallow",
            "example.com/app.A.Ping"
        ),
        "shallower promoted method should win: {}",
        graph["edges"]
    );
    assert!(
        !has_edge(
            &graph,
            "example.com/app.readShallow",
            "example.com/app.C.Ping"
        ),
        "deeper promoted method must not count when shallower method exists: {}",
        graph["edges"]
    );
    assert!(
        has_edge(
            &graph,
            "example.com/app.readPromotedMethod",
            "example.com/app.Audit.Record"
        ),
        "unique promoted method should resolve to canonical owner: {}",
        graph["edges"]
    );

    for (from, to) in [
        (
            "example.com/app.runSharedAmbiguous",
            "example.com/app.Shared.Touch",
        ),
        ("example.com/app.runAmbiguous", "example.com/app.MLeft.Run"),
        ("example.com/app.runAmbiguous", "example.com/app.MRight.Run"),
    ] {
        assert!(
            !has_edge(&graph, from, to),
            "ambiguous promoted selector must not emit {from} -> {to}: {}",
            graph["edges"]
        );
    }
    assert!(
        !has_edge(
            &graph,
            "example.com/app.runNamedWrapper",
            "example.com/app.NamedBase.Hidden"
        ),
        "named same-name fields must not be treated as embedded promotions: {}",
        graph["edges"]
    );
}

#[test]
fn unsupported_interface_factory_receiver_emits_no_partial_edge() {
    let project = InlineTestProject::with_language(brokk_bifrost::Language::Go)
        .file("go.mod", "module example.com/app\n\ngo 1.22\n")
        .file(
            "service.go",
            r#"
package app

type Service struct{}
func (Service) Run() {}

type Other struct{}
func (Other) Run() {}

func choose(flag bool) any {
    if flag {
        return Service{}
    }
    return Other{}
}

func caller(flag bool) {
    service := choose(flag)
    service.Run()
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        !has_edge(
            &graph,
            "example.com/app.caller",
            "example.com/app.Service.Run"
        ),
        "unsupported interface receiver must not choose Service.Run: {}",
        graph["edges"]
    );
    assert!(
        !has_edge(
            &graph,
            "example.com/app.caller",
            "example.com/app.Other.Run"
        ),
        "unsupported interface receiver must not choose Other.Run: {}",
        graph["edges"]
    );
}

#[test]
fn grouped_var_shadowed_constructor_does_not_resolve_to_package_constructor() {
    let graph = go_usage_graph();
    assert!(
        !has_edge(
            &graph,
            "example.com/app.shadowedGroupedService",
            "example.com/app.Service.Execute"
        ),
        "constructor shadowed by an earlier grouped var spec must not resolve to Service.Execute"
    );
}

#[test]
fn same_named_methods_are_not_cross_linked() {
    let graph = go_usage_graph();
    // The pathology the inverted builder fixes: Alpha.Channel and Beta.Channel
    // share a method name but never reference each other.
    assert!(
        !has_edge(
            &graph,
            "example.com/app.Alpha.Channel",
            "example.com/app.Beta.Channel"
        ),
        "Alpha.Channel must not link to the unrelated same-named Beta.Channel"
    );
    assert!(
        !has_edge(
            &graph,
            "example.com/app.Beta.Channel",
            "example.com/app.Alpha.Channel"
        ),
        "Beta.Channel must not link to the unrelated same-named Alpha.Channel"
    );
}

#[test]
fn repeated_calls_aggregate_edge_weight() {
    let graph = go_usage_graph();
    // `total` calls `helper` on two distinct lines.
    assert_eq!(
        edge_weight(&graph, "example.com/app.total", "example.com/app.helper"),
        Some(2),
        "two distinct call sites should aggregate to weight 2"
    );
}

#[test]
fn edges_carry_call_site_locations() {
    // `total` calls `helper` on calls.go lines 32 and 33; the edge carries both
    // locations, and the site count matches the weight.
    let graph = go_usage_graph();
    let sites = edge_sites(&graph, "example.com/app.total", "example.com/app.helper")
        .expect("total -> helper edge with sites");
    let located: Vec<(&str, u64)> = sites
        .iter()
        .map(|site| {
            (
                site["path"].as_str().expect("site path"),
                site["line"].as_u64().expect("site line"),
            )
        })
        .collect();
    assert_eq!(
        located,
        vec![("calls.go", 32), ("calls.go", 33)],
        "sites should be the two distinct call-site locations, sorted by (path, line)"
    );
    assert_eq!(
        edge_weight(&graph, "example.com/app.total", "example.com/app.helper"),
        Some(located.len() as u64),
        "site count must equal the edge weight"
    );
}

#[test]
fn self_reference_produces_no_edge() {
    let graph = go_usage_graph();
    // `recurse` calls itself; a self-reference is not a graph edge.
    assert!(
        !has_edge(&graph, "example.com/app.recurse", "example.com/app.recurse"),
        "self-recursion must not produce a self edge"
    );
}
