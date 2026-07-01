//! `usage_graph` correctness on a TypeScript fixture. The whole-workspace
//! inverted builder resolves a reference to the exported name it binds to, so
//! cross-file calls are recovered through both named and namespace imports —
//! references the original per-symbol path missed when a symbol's importers were
//! outside its candidate set.

mod common;

use brokk_bifrost::{Language, SearchToolsService};
use common::InlineTestProject;
use common::usage_graph::{has_edge, usage_graph_at};
use serde_json::Value;
use std::path::PathBuf;

fn ts_usage_graph() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("usage-graph-ts");
    let service = SearchToolsService::new(root).expect("failed to build searchtools service");
    let payload = service
        .call_tool_json("usage_graph", "{}")
        .expect("usage_graph call failed");
    serde_json::from_str(&payload).expect("usage_graph returned invalid JSON")
}

#[test]
fn named_imports_resolve_cross_file_calls() {
    let graph = ts_usage_graph();
    // `run` imports `{ format, parse }` from ./util and calls both.
    assert!(
        has_edge(&graph, "run", "format"),
        "named import call run -> format should be an edge; edges: {:?}",
        graph["edges"]
    );
    assert!(
        has_edge(&graph, "run", "parse"),
        "named import call run -> parse should be an edge"
    );
}

#[test]
fn namespace_imports_resolve_member_calls() {
    let graph = ts_usage_graph();
    // `go` does `import * as util` and calls `util.format` / `util.parse`.
    assert!(
        has_edge(&graph, "go", "format"),
        "namespace member call go -> format should be an edge"
    );
    assert!(
        has_edge(&graph, "go", "parse"),
        "namespace member call go -> parse should be an edge"
    );
}

#[test]
fn this_receiver_call_does_not_create_usage_graph_edge() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            r#"
export class Service {
  target() {}
  caller() {
    this.target();
  }
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        !has_edge(&graph, "Service.caller", "Service.target"),
        "self-receiver calls must not appear as usage_graph edges: {}",
        graph["edges"]
    );
}

#[test]
fn ts_factory_receiver_call_edges_only_to_constructed_type() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            r#"
export class Service { run() {} }
export class Other { run() {} }
export function makeService() { return new Service(); }
export function caller() {
  const service = makeService();
  service.run();
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&graph, "caller", "Service.run"),
        "factory-produced receiver should resolve caller -> Service.run: {}",
        graph["edges"]
    );
    assert!(
        !has_edge(&graph, "caller", "Other.run"),
        "factory-produced receiver must not resolve by same member name: {}",
        graph["edges"]
    );
}

#[test]
fn ts_parameter_shadow_blocks_outer_factory_receiver_edge() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            r#"
export class Service { run() {} }
export class Other { run() {} }
export function makeService() { return new Service(); }
const service = makeService();
export function caller(service: Other) {
  service.run();
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        !has_edge(&graph, "caller", "Service.run"),
        "parameter receiver must shadow outer factory-produced local: {}",
        graph["edges"]
    );
}

#[test]
fn ts_static_factory_receiver_call_edges_only_to_constructed_type() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            r#"
export class Service {
  static create() { return new Service(); }
  run() {}
}
export class Other { run() {} }
export function caller() {
  const service = Service.create();
  service.run();
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&graph, "caller", "Service.run"),
        "static factory-produced receiver should resolve caller -> Service.run: {}",
        graph["edges"]
    );
    assert!(
        !has_edge(&graph, "caller", "Other.run"),
        "static factory-produced receiver must not resolve by same member name: {}",
        graph["edges"]
    );
}

#[test]
fn ts_ambiguous_factory_receiver_call_emits_no_partial_edge() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            r#"
export class Service { run() {} }
export class Other { run() {} }
export function make(flag: boolean) {
  if (flag) {
    return new Service();
  }
  return new Other();
}
export function caller(flag: boolean) {
  const service = make(flag);
  service.run();
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        !has_edge(&graph, "caller", "Service.run"),
        "ambiguous receiver must not pick Service.run by partial name match: {}",
        graph["edges"]
    );
    assert!(
        !has_edge(&graph, "caller", "Other.run"),
        "ambiguous receiver must not pick Other.run by partial name match: {}",
        graph["edges"]
    );
}

#[test]
fn ts_branch_assignment_receiver_emits_no_partial_edge() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            r#"
export class Service { run() {} }
export class Other { run() {} }
export function makeService() { return new Service(); }
export function makeOther() { return new Other(); }
export function caller(flag: boolean) {
  let service;
  if (flag) service = makeService();
  else service = makeOther();
  service.run();
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        !has_edge(&graph, "caller", "Service.run") && !has_edge(&graph, "caller", "Other.run"),
        "branch-assigned receiver must not be linearized to a partial edge: {}",
        graph["edges"]
    );
}

#[test]
fn ts_factory_receiver_fanout_over_cap_emits_no_partial_edge() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            r#"
export class A { run() {} }
export class B { run() {} }
export class C { run() {} }
export class D { run() {} }
export class E { run() {} }
export function make(which: number) {
  if (which === 0) return new A();
  if (which === 1) return new B();
  if (which === 2) return new C();
  if (which === 3) return new D();
  return new E();
}
export function caller(which: number) {
  const service = make(which);
  service.run();
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    for target in ["A.run", "B.run", "C.run", "D.run", "E.run"] {
        assert!(
            !has_edge(&graph, "caller", target),
            "fanout-over-cap receiver must not emit partial {target} edge: {}",
            graph["edges"]
        );
    }
}

#[test]
fn js_factory_receiver_call_edges_only_to_constructed_type() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "service.js",
            r#"
export class Service { run() {} }
export class Other { run() {} }
export function makeService() { return new Service(); }
export function caller() {
  const service = makeService();
  service.run();
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&graph, "caller", "Service.run"),
        "JS factory-produced receiver should resolve caller -> Service.run: {}",
        graph["edges"]
    );
    assert!(
        !has_edge(&graph, "caller", "Other.run"),
        "JS factory-produced receiver must not resolve by same member name: {}",
        graph["edges"]
    );
}

#[test]
fn ts_block_local_receiver_shadow_does_not_leak_to_outer_call() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            r#"
export class Service { run() {} }
export class Other { run() {} }
export function makeService() { return new Service(); }
export function makeOther() { return new Other(); }
export function caller(flag: boolean) {
  const service = makeService();
  if (flag) {
    const service = makeOther();
  }
  service.run();
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&graph, "caller", "Service.run"),
        "outer receiver should still resolve to Service.run: {}",
        graph["edges"]
    );
    assert!(
        !has_edge(&graph, "caller", "Other.run"),
        "block-local shadow must not leak to the outer receiver call: {}",
        graph["edges"]
    );
}

#[test]
fn ts_hidden_factory_declaration_does_not_type_unrelated_call() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "service.ts",
            r#"
export class Service { run() {} }
export class Other { run() {} }
function hidden() {
  function make() { return new Service(); }
  return make;
}
export function caller() {
  const service = make();
  service.run();
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        !has_edge(&graph, "caller", "Service.run") && !has_edge(&graph, "caller", "Other.run"),
        "hidden non-visible factory must not type caller's receiver: {}",
        graph["edges"]
    );
}
