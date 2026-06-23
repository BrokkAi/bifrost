mod common;

use brokk_bifrost::Language;
use common::InlineTestProject;
use common::usage_graph::{assert_every_edge_endpoint_is_a_node, has_edge, usage_graph_at};
use serde_json::Value;
use std::path::PathBuf;

fn usage_graph() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("usage-graph-cpp");
    usage_graph_at(root, "{}")
}

#[test]
fn resolves_instance_pointer_static_and_free_calls() {
    let value = usage_graph();

    // `Service s; s.run();` — the local's type resolves the receiver.
    assert!(
        has_edge(
            &value,
            "example.Consumer.viaInstance",
            "example.Service.run"
        ),
        "expected viaInstance -> Service.run: {}",
        value["edges"]
    );
    // `p->run()` on a `Service*` parameter — the parameter's type resolves it.
    assert!(
        has_edge(&value, "example.Consumer.viaPointer", "example.Service.run"),
        "expected viaPointer -> Service.run: {}",
        value["edges"]
    );
    // `Service::helper()` static call resolves the qualifier type directly.
    assert!(
        has_edge(
            &value,
            "example.Consumer.viaStatic",
            "example.Service.helper"
        ),
        "expected viaStatic -> Service.helper: {}",
        value["edges"]
    );
    // A bare `freeHelper()` call resolves to the visible free function.
    assert!(
        has_edge(&value, "example.Consumer.viaFree", "example.freeHelper"),
        "expected viaFree -> freeHelper: {}",
        value["edges"]
    );
}

#[test]
fn unqualified_self_call_attributes_to_enclosing_class() {
    let value = usage_graph();

    // An unqualified `local()` call attributes to the enclosing class.
    assert!(
        has_edge(
            &value,
            "example.Consumer.callsLocal",
            "example.Consumer.local"
        ),
        "expected callsLocal -> Consumer.local: {}",
        value["edges"]
    );
}

#[test]
fn new_expression_and_type_reference_edge_to_the_class() {
    let value = usage_graph();

    // `new Service()` and the `Service*` return type both reference the class.
    assert!(
        has_edge(&value, "example.Consumer.makeService", "example.Service"),
        "expected makeService -> Service: {}",
        value["edges"]
    );
}

#[test]
fn namespace_free_function_return_type_edges() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "service.h",
            r#"#pragma once
namespace example {
class Service {
public:
    void execute() const {}
};
Service build_service();
}
"#,
        )
        .file(
            "main.cpp",
            r#"#include "service.h"
namespace example {
Service build_service() { return Service{}; }
}
int main() {
    auto service = example::build_service();
    service.execute();
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "main", "example.build_service"),
        "expected main -> build_service from qualified namespace call: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "main", "example.Service.execute"),
        "expected main -> Service.execute through auto return inference: {}",
        value["edges"]
    );
}

#[test]
fn receiver_typing_is_type_based_not_name_based() {
    let value = usage_graph();

    // `o->run()` on an `Other*` parameter must edge to Other.run, NOT Service.run —
    // proving resolution is by receiver type, not by the member name `run`.
    assert!(
        has_edge(
            &value,
            "example.Consumer.wrongReceiver",
            "example.Other.run"
        ),
        "expected wrongReceiver -> Other.run: {}",
        value["edges"]
    );
    assert!(
        !has_edge(
            &value,
            "example.Consumer.wrongReceiver",
            "example.Service.run"
        ),
        "wrongReceiver must not edge to Service.run: {}",
        value["edges"]
    );
}

#[test]
fn unused_member_has_no_incoming_edge_and_no_self_edges() {
    let value = usage_graph();

    assert!(
        !value["edges"]
            .as_array()
            .expect("edges array")
            .iter()
            .any(|edge| edge["to"].as_str() == Some("example.Service.unused")),
        "unused method must have no incoming edges: {}",
        value["edges"]
    );
    // `recurse()` calls itself — self references must not appear as edges.
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
fn path_filter_only_emits_matching_cpp_callers() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "service.h",
            r#"
namespace example {

class Service {
public:
    static void helper() {}
};

} // namespace example
"#,
        )
        .file(
            "kept.cpp",
            r#"
#include "service.h"

namespace example {

class Kept {
public:
    void run() {
        Service::helper();
    }
};

} // namespace example
"#,
        )
        .file(
            "ignored.cpp",
            r#"
#include "service.h"

namespace example {

class Ignored {
public:
    void run() {
        Service::helper();
    }
};

} // namespace example
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), r#"{"paths":["kept.cpp"]}"#);
    assert!(
        has_edge(&value, "example.Kept.run", "example.Service.helper"),
        "kept caller should still resolve static callee nodes: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "example.Ignored.run", "example.Service.helper"),
        "path-filtered usage_graph must not emit edges from ignored callers: {}",
        value["edges"]
    );
}

#[test]
fn scoped_usage_graph_skips_unrelated_invalid_cpp_callers() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "service.h",
            r#"
namespace example {

class Service {
public:
    static void helper() {}
};

} // namespace example
"#,
        )
        .file(
            "kept.cpp",
            r#"
#include "service.h"

namespace example {

class Kept {
public:
    void run() {
        Service::helper();
    }
};

} // namespace example
"#,
        )
        .file(
            "broken.cpp",
            r#"
namespace broken {

class Broken {
    void nope(
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), r#"{"paths":["kept.cpp"]}"#);
    assert!(
        has_edge(&value, "example.Kept.run", "example.Service.helper"),
        "filtered C++ edge graph should not require parsing unrelated callers: {}",
        value["edges"]
    );
}
