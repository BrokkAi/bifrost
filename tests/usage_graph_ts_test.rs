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
