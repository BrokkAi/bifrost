mod common;

use brokk_bifrost::{Language, SearchToolsService};
use common::InlineTestProject;
use common::usage_graph::{assert_every_edge_endpoint_is_a_node, has_edge};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn usage_graph() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("usage-graph-php");
    usage_graph_at(root, "{}")
}

fn usage_graph_at(root: impl AsRef<Path>, args: &str) -> Value {
    let service = SearchToolsService::new_without_semantic_index(root.as_ref().to_path_buf())
        .expect("service");
    let payload = service
        .call_tool_json("usage_graph", args)
        .expect("usage_graph call failed");
    serde_json::from_str(&payload).expect("invalid JSON")
}

#[test]
fn resolves_free_function_instance_static_and_self_calls() {
    let value = usage_graph();

    // Free function call attributes to the enclosing class method.
    assert!(
        has_edge(
            &value,
            "App.Consumer.callsFreeFunction",
            "App.topLevelHelper"
        ),
        "expected callsFreeFunction -> topLevelHelper: {}",
        value["edges"]
    );
    // `$s->run()` where `$s = new Service()` — local type resolves the receiver.
    assert!(
        has_edge(&value, "App.Consumer.viaInstance", "App.Service.run"),
        "expected viaInstance -> Service.run: {}",
        value["edges"]
    );
    // `Service::helper()` static call resolves the type directly.
    assert!(
        has_edge(&value, "App.Consumer.viaStatic", "App.Service.helper"),
        "expected viaStatic -> Service.helper: {}",
        value["edges"]
    );
    // `$this->viaInstance()` attributes to the enclosing class.
    assert!(
        has_edge(
            &value,
            "App.Consumer.callsSelfMethod",
            "App.Consumer.viaInstance"
        ),
        "expected callsSelfMethod -> Consumer.viaInstance: {}",
        value["edges"]
    );
}

#[test]
fn type_references_edge() {
    let value = usage_graph();

    // A `new Service()` construction and the `Service` return type both resolve to
    // the class node (recorded once per construction to avoid double counting).
    assert!(
        has_edge(&value, "App.Consumer.makeService", "App.Service"),
        "expected makeService -> Service: {}",
        value["edges"]
    );
}

#[test]
fn receiver_typing_is_type_based_not_name_based() {
    let value = usage_graph();

    // `$svc->run()` on a Service-typed parameter resolves by receiver type.
    assert!(
        has_edge(&value, "App.Consumer.viaParam", "App.Service.run"),
        "expected viaParam -> Service.run: {}",
        value["edges"]
    );
    // The same `run()` on a Consumer-typed receiver must NOT resolve to
    // Service.run — proving resolution is by receiver type, not member name.
    assert!(
        !has_edge(&value, "App.Consumer.wrongReceiver", "App.Service.run"),
        "wrongReceiver must not edge to Service.run: {}",
        value["edges"]
    );
}

#[test]
fn closure_locals_do_not_leak_into_the_enclosing_scope() {
    let value = usage_graph();

    // A closure reassigns `$svc` to a Consumer in its own scope; that must not
    // clobber the outer Service-typed `$svc`, so the outer `$svc->run()` still
    // resolves to Service.run (and never to Consumer.run).
    assert!(
        has_edge(
            &value,
            "App.Consumer.closureScopeIsolation",
            "App.Service.run"
        ),
        "closure must not leak its local type to the enclosing scope: {}",
        value["edges"]
    );
}

#[test]
fn unused_member_has_no_incoming_edges_and_no_self_edges() {
    let value = usage_graph();

    assert!(
        !value["edges"]
            .as_array()
            .expect("edges array")
            .iter()
            .any(|edge| edge["to"].as_str() == Some("App.Service.unused")),
        "unused method must have no incoming edges: {}",
        value["edges"]
    );
    // `selfRecursion` calls itself; a self reference must not appear as an edge.
    assert!(
        !value["edges"]
            .as_array()
            .expect("edges array")
            .iter()
            .any(|edge| edge["from"] == edge["to"]),
        "self references must not appear as edges: {}",
        value["edges"]
    );
}

#[test]
fn every_edge_endpoint_is_a_node() {
    assert_every_edge_endpoint_is_a_node(&usage_graph());
}

#[test]
fn path_filter_only_emits_matching_php_callers() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "Service.php",
            r#"<?php
namespace App;

class Service {
    public static function helper(): void {}
}
"#,
        )
        .file(
            "Kept.php",
            r#"<?php
namespace App;

class Kept {
    public function run(): void {
        Service::helper();
    }
}
"#,
        )
        .file(
            "Ignored.php",
            r#"<?php
namespace App;

class Ignored {
    public function run(): void {
        Service::helper();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), r#"{"paths":["Kept.php"]}"#);
    assert!(
        has_edge(&value, "App.Kept.run", "App.Service.helper"),
        "kept caller should still resolve static callee nodes: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "App.Ignored.run", "App.Service.helper"),
        "path-filtered usage_graph must not emit edges from ignored callers: {}",
        value["edges"]
    );
}

#[test]
fn scoped_usage_graph_skips_unrelated_invalid_php_callers() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "Service.php",
            r#"<?php
namespace App;

class Service {
    public static function helper(): void {}
}
"#,
        )
        .file(
            "Kept.php",
            r#"<?php
namespace App;

class Kept {
    public function run(): void {
        Service::helper();
    }
}
"#,
        )
        .file(
            "Broken.php",
            r#"<?php
namespace Broken;

class Broken {
    public function nope(
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), r#"{"paths":["Kept.php"]}"#);
    assert!(
        has_edge(&value, "App.Kept.run", "App.Service.helper"),
        "filtered PHP edge graph should not require parsing unrelated callers: {}",
        value["edges"]
    );
}
