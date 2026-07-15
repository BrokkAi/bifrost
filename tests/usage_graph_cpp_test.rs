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
fn unqualified_self_call_does_not_create_usage_graph_edge() {
    let value = usage_graph();

    // An unqualified `local()` call is an implicit self-receiver reference. It
    // belongs to editor references, not the external usage_graph edge surface.
    assert!(
        !has_edge(
            &value,
            "example.Consumer.callsLocal",
            "example.Consumer.local"
        ),
        "self-receiver calls must not appear as usage_graph edges: {}",
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
fn out_of_line_member_definition_qualifiers_edge_to_class() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "include/parity.h",
            r#"#pragma once
#include <string>
namespace parity {
struct Sink {};
class ConsoleHandler {
public:
    explicit ConsoleHandler(Sink& s);
    std::string handle(const std::string& value);
    std::string alias_handle(const std::string& value);
};
using HandlerAlias = ConsoleHandler;
}
namespace other {
struct OtherSink {};
class ConsoleHandler {
public:
    explicit ConsoleHandler(OtherSink& s);
    std::string handle(const std::string& value);
};
}
"#,
        )
        .file(
            "src/parity.cpp",
            r#"#include "../include/parity.h"
namespace parity {
ConsoleHandler::ConsoleHandler(Sink& s) {}
std::string ConsoleHandler::handle(const std::string& value) { return value; }
std::string HandlerAlias::alias_handle(const std::string& value) { return value; }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(
            &value,
            "parity.ConsoleHandler.ConsoleHandler",
            "parity.ConsoleHandler"
        ),
        "expected constructor definition qualifier to edge to ConsoleHandler: {}",
        value["edges"]
    );
    assert!(
        has_edge(
            &value,
            "parity.ConsoleHandler.handle",
            "parity.ConsoleHandler"
        ),
        "expected method definition qualifier to edge to ConsoleHandler: {}",
        value["edges"]
    );
    assert!(
        has_edge(
            &value,
            "parity.HandlerAlias.alias_handle",
            "parity.ConsoleHandler"
        ),
        "expected alias-qualified method definition qualifier to edge to ConsoleHandler: {}",
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
fn object_sensitive_factory_receiver_resolves_only_constructed_type() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "service.h",
            r#"#pragma once
namespace example {
class Service {
public:
    void run() {}
    static Service create();
};
class Other {
public:
    void run() {}
};
Service make_service();
}
"#,
        )
        .file(
            "service.cpp",
            r#"#include "service.h"
namespace example {
Service make_service() { return Service{}; }
Service Service::create() { return Service{}; }
}
"#,
        )
        .file(
            "main.cpp",
            r#"#include "service.h"
namespace example {
void via_factory() {
    auto service = make_service();
    service.run();
}
void via_static_factory() {
    auto service = Service::create();
    service.run();
}
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    for caller in ["example.via_factory", "example.via_static_factory"] {
        assert!(
            has_edge(&value, caller, "example.Service.run"),
            "{caller} should edge to Service.run: {}",
            value["edges"]
        );
        assert!(
            !has_edge(&value, caller, "example.Other.run"),
            "{caller} must not edge to Other.run by member name: {}",
            value["edges"]
        );
    }
}

#[test]
fn static_factory_return_resolves_in_method_namespace() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "service.h",
            r#"#pragma once
namespace lib {
class Service {
public:
    void run() {}
};
class Factory {
public:
    static Service create();
};
}
namespace app {
class Service {
public:
    void run() {}
};
void caller();
}
"#,
        )
        .file(
            "service.cpp",
            r#"#include "service.h"
namespace lib {
Service Factory::create() { return Service{}; }
}
"#,
        )
        .file(
            "main.cpp",
            r#"#include "service.h"
namespace app {
void caller() {
    auto service = lib::Factory::create();
    service.run();
}
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "app.caller", "lib.Service.run"),
        "static factory return should resolve in the method namespace: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.caller", "app.Service.run"),
        "static factory return must not resolve Service in the caller namespace: {}",
        value["edges"]
    );
}

#[test]
fn unsupported_conditional_receiver_emits_no_partial_edge() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "service.h",
            r#"#pragma once
namespace example {
class Service { public: void run() {} };
class Other { public: void run() {} };
void caller(bool flag);
}
"#,
        )
        .file(
            "main.cpp",
            r#"#include "service.h"
namespace example {
void caller(bool flag) {
    auto service = flag ? Service{} : Other{};
    service.run();
}
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        !has_edge(&value, "example.caller", "example.Service.run"),
        "unsupported conditional receiver must not choose Service.run: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "example.caller", "example.Other.run"),
        "unsupported conditional receiver must not choose Other.run: {}",
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

#[test]
fn qualified_method_values_create_exact_owner_usage_graph_edges() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "worker.h",
            r#"#pragma once
namespace demo {
class Worker {
public:
    void OnDone();
    void Arm();
};
class Other {
public:
    void OnDone();
    void Arm();
};
}
"#,
        )
        .file(
            "worker.cc",
            r#"#include "worker.h"
namespace demo {
void Worker::OnDone() {}
void Other::OnDone() {}
void Worker::Arm() {
    auto callback = &::demo::Worker::OnDone;
}
void Other::Arm() {
    auto callback = &Other::OnDone;
}
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "demo.Worker.Arm", "demo.Worker.OnDone"),
        "expected Worker::Arm -> Worker::OnDone method-value edge: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "demo.Other.Arm", "demo.Other.OnDone"),
        "expected Other::Arm -> Other::OnDone method-value edge: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "demo.Worker.Arm", "demo.Other.OnDone"),
        "Worker method value must not cross over to Other::OnDone: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "demo.Other.Arm", "demo.Worker.OnDone"),
        "Other method value must not cross over to Worker::OnDone: {}",
        value["edges"]
    );
}

#[test]
fn qualified_callable_values_follow_cpp_lexical_owner_tiers() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "worker.h",
            r#"#pragma once
namespace Worker {
void OnDone();
}
namespace other {
class Worker {
public:
    void OnDone();
};
}
namespace outer {
namespace inner {
void helper();
class Worker {
public:
    void OnDone();
};
}
class Worker {
public:
    void OnDone();
    void Arm();
};
}
"#,
        )
        .file(
            "worker.cc",
            r#"#include "worker.h"
namespace Worker {
void OnDone() {}
}
namespace other {
void Worker::OnDone() {}
}
namespace outer {
namespace inner {
void helper() {}
void Worker::OnDone() {}
}
void Worker::OnDone() {}
void Worker::Arm() {
    auto nearest_type = &Worker::OnDone;
    auto relative_type = &inner::Worker::OnDone;
    auto relative_function = &inner::helper;
}
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "outer.Worker.Arm", "outer.Worker.OnDone"),
        "short owner must resolve at the nearest lexical tier: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "outer.Worker.Arm", "outer::inner.Worker.OnDone"),
        "relative multi-component owner must retain its lexical namespace prefix: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "outer.Worker.Arm", "outer::inner.helper"),
        "relative namespace function must resolve through the same lexical tiers: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "outer.Worker.Arm", "Worker.OnDone")
            && !has_edge(&value, "outer.Worker.Arm", "other.Worker.OnDone"),
        "nearer lexical owners must block global namespace and unrelated visible types: {}",
        value["edges"]
    );
}

#[test]
fn qualified_namespace_function_and_data_member_values_keep_exact_graph_targets() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "worker.h",
            r#"#pragma once
namespace demo {
void OnDone();
void state();
class Worker {
public:
    int state;
    void Arm();
};
class Other {
public:
    int state;
    void Arm();
};
}
"#,
        )
        .file(
            "worker.cc",
            r#"#include "worker.h"
namespace demo {
void OnDone() {}
void state() {}
void Worker::Arm() {
    auto function_value = &demo::OnDone;
    auto field_value = &Worker::state;
}
void Other::Arm() {
    auto field_value = &Other::state;
}
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "demo.Worker.Arm", "demo.OnDone"),
        "qualified namespace function value should resolve exactly: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "demo.Worker.Arm", "demo.state")
            && !has_edge(&value, "demo.Other.Arm", "demo.state"),
        "pointer-to-data-member values must not fan out to a callable namesake: {}",
        value["edges"]
    );
}
