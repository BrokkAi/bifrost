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

fn ts_usage_graph() -> Value {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "consumer.ts",
            r#"import { format, parse } from "./util";

export function run(input: string): string {
  const value = parse(input);
  return format(value);
}
"#,
        )
        .file(
            "nsconsumer.ts",
            r#"import * as util from "./util";

export function go(input: string): string {
  return util.format(util.parse(input));
}
"#,
        )
        .file(
            "util.ts",
            r#"export function format(x: number): string {
  return String(x);
}

export function parse(s: string): number {
  return Number(s);
}
"#,
        )
        .build();
    let service = SearchToolsService::new(project.root().to_path_buf())
        .expect("failed to build searchtools service");
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
fn qualified_type_references_create_exact_workspace_edges() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "options.ts",
            "export interface PageOptions { enabled: boolean }\n",
        )
        .file(
            "consumer.ts",
            r#"
import * as helper from "./options";

enum EntityType { SECURITY_SERVICE }
enum OtherEntityType { SECURITY_SERVICE }

export function select(value: EntityType.SECURITY_SERVICE): helper.PageOptions {
  return { enabled: true };
}

export function otherType(value: OtherEntityType.SECURITY_SERVICE): void {}
export function runtime(helper: { PageOptions: number }, value: OtherEntityType) {
  return helper.PageOptions + value.SECURITY_SERVICE;
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&graph, "select", "EntityType"),
        "same-file enum-member discriminants must resolve to their observable enum owner: {}",
        graph["edges"]
    );
    assert!(
        has_edge(&graph, "select", "PageOptions"),
        "namespace-qualified imported types must resolve through the namespace binding: {}",
        graph["edges"]
    );
    assert!(
        !has_edge(&graph, "otherType", "EntityType"),
        "a same-spelled discriminant on another enum must not match: {}",
        graph["edges"]
    );
    assert!(
        !has_edge(&graph, "runtime", "EntityType") && !has_edge(&graph, "runtime", "PageOptions"),
        "ordinary member expressions must keep receiver-based resolution: {}",
        graph["edges"]
    );
}

#[test]
fn ambient_companion_preserves_merged_workspace_type_edges() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "ambient.d.ts",
            r#"
declare namespace interop { interface StructType<T> {} }
interface Packet { value: number }
declare var Packet: interop.StructType<Packet>;
declare var PacketConstructor: { prototype: Packet };

function consume(value: Packet): Packet { return value; }

function valueShadow() {
  const Packet = 1;
  let value: Packet;
  return value;
}

function typeShadow() {
  type Packet = { local: true };
  let value: Packet;
  return value;
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&graph, "consume", "Packet"),
        "ambient companions must preserve later function type edges: {}",
        graph["edges"]
    );
    assert!(
        has_edge(&graph, "valueShadow", "Packet"),
        "a value-space shadow must not suppress the outer type-space Packet: {}",
        graph["edges"]
    );
    assert!(
        !has_edge(&graph, "typeShadow", "Packet"),
        "a genuine nested type alias must suppress the outer Packet type: {}",
        graph["edges"]
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
fn ts_static_method_call_edges_to_static_member() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "api.ts",
            r#"
export class ApiClient {
  static create(baseUrl: string): ApiClient {
    return new ApiClient(baseUrl);
  }
  constructor(readonly baseUrl: string) {}
}

export function boot() {
  return ApiClient.create("/api");
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&graph, "boot", "ApiClient.create$static"),
        "static method call should resolve to the indexed static member key: {}",
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
fn js_window_global_property_edges_from_bare_global_only() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "polyfills.js",
            r#"
window.Promise = function Promise() {};
function readGlobal() { return typeof Promise; }
function readExplicit() { return window.Promise; }
function shadowed(Promise) { return typeof Promise; }
function readOther() { return other.Promise; }
other.Promise = makeOtherPromise();
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&graph, "readGlobal", "window.Promise"),
        "bare browser global should resolve to the exact modeled window property: {}",
        graph["edges"]
    );
    assert!(
        has_edge(&graph, "readExplicit", "window.Promise"),
        "explicit browser-global member reads should share the exact edge: {}",
        graph["edges"]
    );
    assert!(
        !has_edge(&graph, "shadowed", "window.Promise"),
        "parameter shadows must not resolve to the browser global: {}",
        graph["edges"]
    );
    assert!(
        !has_edge(&graph, "readOther", "window.Promise"),
        "same-name properties on unrelated objects must not resolve to the browser global: {}",
        graph["edges"]
    );
}

#[test]
fn js_window_global_property_edges_reject_bound_declaration_receiver() {
    for (source, extra_file) in [
        (
            r#"const window = makeLocalWindow();
window.Promise = function Promise() {};
function readGlobal() { return typeof Promise; }
"#,
            None,
        ),
        (
            r#"import window from "./shim.js";
window.Promise = function Promise() {};
function readGlobal() { return typeof Promise; }
"#,
            Some("export default {};"),
        ),
        (
            r#"const holder = function* window() {
  window.Promise = function Promise() {};
  function readGlobal() { return typeof Promise; }
  return readGlobal();
};
"#,
            None,
        ),
    ] {
        let project =
            InlineTestProject::with_language(Language::JavaScript).file("polyfills.js", source);
        let project = if let Some(contents) = extra_file {
            project.file("shim.js", contents)
        } else {
            project
        }
        .build();
        let graph = usage_graph_at(project.root(), "{}");
        assert!(
            !has_edge(&graph, "readGlobal", "window.Promise"),
            "a locally or import-bound window receiver is not the browser global: {}",
            graph["edges"]
        );
    }
}

#[test]
fn js_window_global_property_edges_respect_later_lexical_bindings() {
    for (caller, body) in [
        (
            "readBeforeFileBinding",
            r#"function readBeforeFileBinding() { return typeof Promise; }
const Promise = makeLocalPromise();
"#,
        ),
        (
            "readBeforeFunctionBinding",
            r#"function readBeforeFunctionBinding() {
    const before = typeof Promise;
    var Promise;
    return before;
}
"#,
        ),
    ] {
        let project = InlineTestProject::with_language(Language::JavaScript)
            .file(
                "polyfills.js",
                format!("window.Promise = function Promise() {{}};\n{body}"),
            )
            .build();
        let graph = usage_graph_at(project.root(), "{}");
        assert!(
            !has_edge(&graph, caller, "window.Promise"),
            "TDZ and var-hoisted bindings must shadow earlier reads: {}",
            graph["edges"]
        );
    }
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

#[test]
fn ts_parameter_default_rhs_remains_an_imported_call() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "defaults.ts",
            "export function fallback(): string { return ''; }\n",
        )
        .file(
            "consumer.ts",
            r#"
import { fallback } from "./defaults";
export function caller(value: string = fallback()) {
  return value;
}
"#,
        )
        .build();

    let graph = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&graph, "caller", "fallback"),
        "a required parameter's default initializer must remain a reference rather than a local shadow: {}",
        graph["edges"]
    );
}
