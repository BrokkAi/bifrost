mod common;

use brokk_bifrost::Language;
use common::InlineTestProject;
use common::usage_graph::{assert_every_edge_endpoint_is_a_node, usage_graph_at};
use serde_json::Value;
use std::path::PathBuf;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("usage-graph-java")
}

fn usage_graph() -> Value {
    usage_graph_at(fixture_root(), "{}")
}

fn find_edge<'a>(value: &'a Value, from_suffix: &str, to: &str) -> Option<&'a Value> {
    value["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .find(|edge| {
            edge["from"]
                .as_str()
                .is_some_and(|from| from.ends_with(from_suffix))
                && edge["to"].as_str() == Some(to)
        })
}

#[test]
fn resolves_instance_static_and_constructor_calls() {
    let value = usage_graph();

    // `s.run()` where `Service s = new Service()` — the local's type resolves the
    // receiver to `com.example.Service.run`.
    assert!(
        find_edge(&value, "viaInstance", "com.example.Service.run").is_some(),
        "expected viaInstance -> Service.run: {}",
        value["edges"]
    );
    // `Service.helper()` — static call resolves the type directly.
    assert!(
        find_edge(&value, "viaStatic", "com.example.Service.helper").is_some(),
        "expected viaStatic -> Service.helper: {}",
        value["edges"]
    );
    // `new Service()` / `Service` return type resolve to the class node.
    assert!(
        find_edge(&value, "makeService", "com.example.Service").is_some(),
        "expected makeService -> Service: {}",
        value["edges"]
    );
}

#[test]
fn receiver_typing_is_type_based_not_name_based() {
    let value = usage_graph();

    // A `run()` call on a Service-typed parameter resolves (the parameter name
    // shadowing the method is irrelevant — resolution is by receiver type).
    assert!(
        find_edge(&value, "shadowed", "com.example.Service.run").is_some(),
        "expected shadowed -> Service.run: {}",
        value["edges"]
    );
    // The same method name on a Consumer-typed receiver must NOT resolve to
    // Service.run — proving resolution is by receiver type, not method name.
    assert!(
        find_edge(&value, "wrongReceiver", "com.example.Service.run").is_none(),
        "wrongReceiver must not edge to Service.run: {}",
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
            .any(|edge| edge["to"].as_str() == Some("com.example.Service.unused")),
        "unused method must have no incoming edges: {}",
        value["edges"]
    );
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
fn nested_class_calls_attribute_to_the_nested_fqn() {
    let value = usage_graph();

    // An unqualified call inside `Outer.Inner` must attribute to the nested
    // class's fqn (`com.example.Outer.Inner.helper`), built from AST nesting —
    // not to a simple-name lookup that could hit a same-named top-level type.
    assert!(
        find_edge(
            &value,
            "com.example.Outer.Inner.compute",
            "com.example.Outer.Inner.helper"
        )
        .is_some(),
        "expected Outer.Inner.compute -> Outer.Inner.helper: {}",
        value["edges"]
    );
}

#[test]
fn untyped_local_named_like_a_type_produces_no_static_edge() {
    let value = usage_graph();

    // `shadowFallback` has an untyped local `Service`; `Service.run()` must not
    // be reinterpreted as a static call resolving to `com.example.Service.run`.
    assert!(
        find_edge(&value, "shadowFallback", "com.example.Service.run").is_none(),
        "an untyped local must not fall back to static type resolution: {}",
        value["edges"]
    );
}

#[test]
fn path_filter_only_emits_matching_java_callers() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "com/example/Util.java",
            r#"
package com.example;

public class Util {
    public static void helper() {}
}
"#,
        )
        .file(
            "com/example/Kept.java",
            r#"
package com.example;

public class Kept {
    void run() {
        Util.helper();
    }
}
"#,
        )
        .file(
            "com/example/Ignored.java",
            r#"
package com.example;

public class Ignored {
    void run() {
        Util.helper();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), r#"{"paths":["com/example/Kept.java"]}"#);
    assert!(
        find_edge(&value, "com.example.Kept.run", "com.example.Util.helper").is_some(),
        "kept caller should still resolve static callee nodes: {}",
        value["edges"]
    );
    assert!(
        find_edge(&value, "com.example.Ignored.run", "com.example.Util.helper").is_none(),
        "path-filtered usage_graph must not emit edges from ignored callers: {}",
        value["edges"]
    );
}

#[test]
fn include_tests_false_excludes_java_test_callers() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "com/example/Util.java",
            r#"
package com.example;

public class Util {
    public static void helper() {}
}
"#,
        )
        .file(
            "com/example/Prod.java",
            r#"
package com.example;

public class Prod {
    void run() {
        Util.helper();
    }
}
"#,
        )
        .file(
            "com/example/ProdTest.java",
            r#"
package com.example;

public class ProdTest {
    @Test
    void testRun() {
        Util.helper();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), r#"{"include_tests":false}"#);
    assert!(
        find_edge(&value, "com.example.Prod.run", "com.example.Util.helper").is_some(),
        "production caller should remain in the graph: {}",
        value["edges"]
    );
    assert!(
        find_edge(
            &value,
            "com.example.ProdTest.testRun",
            "com.example.Util.helper"
        )
        .is_none(),
        "test callers should be excluded when include_tests is false: {}",
        value["edges"]
    );
}

#[test]
fn object_sensitive_factory_receiver_resolves_only_constructed_type() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "com/example/Service.java",
            r#"
package com.example;

class Service {
    void run() {}

    static Service create() {
        return new Service();
    }
}
"#,
        )
        .file(
            "com/example/Other.java",
            r#"
package com.example;

class Other {
    void run() {}
}
"#,
        )
        .file(
            "com/example/Controller.java",
            r#"
package com.example;

class Controller {
    Service makeService() {
        return new Service();
    }

    void viaFactory() {
        var service = makeService();
        service.run();
    }

    void viaStaticFactory() {
        var service = Service.create();
        service.run();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    for caller in [
        "com.example.Controller.viaFactory",
        "com.example.Controller.viaStaticFactory",
    ] {
        assert!(
            find_edge(&value, caller, "com.example.Service.run").is_some(),
            "{caller} should edge to Service.run: {}",
            value["edges"]
        );
        assert!(
            find_edge(&value, caller, "com.example.Other.run").is_none(),
            "{caller} must not edge to Other.run by method name: {}",
            value["edges"]
        );
    }
}

#[test]
fn ambiguous_factory_receiver_emits_no_partial_edge() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "com/example/Service.java",
            "package com.example;\nclass Service { void run() {} }\n",
        )
        .file(
            "com/example/Other.java",
            "package com.example;\nclass Other { void run() {} }\n",
        )
        .file(
            "com/example/Controller.java",
            r#"
package com.example;

class Controller {
    Object choose(boolean flag) {
        if (flag) {
            return new Service();
        }
        return new Other();
    }

    void caller(boolean flag) {
        var service = choose(flag);
        service.run();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        find_edge(
            &value,
            "com.example.Controller.caller",
            "com.example.Service.run"
        )
        .is_none(),
        "ambiguous receiver must not choose Service.run: {}",
        value["edges"]
    );
    assert!(
        find_edge(
            &value,
            "com.example.Controller.caller",
            "com.example.Other.run"
        )
        .is_none(),
        "ambiguous receiver must not choose Other.run: {}",
        value["edges"]
    );
}

#[test]
fn factory_body_identifier_does_not_use_caller_bindings() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "com/example/Service.java",
            "package com.example;\nclass Service { void run() {} }\n",
        )
        .file(
            "com/example/Other.java",
            "package com.example;\nclass Other { void run() {} }\n",
        )
        .file(
            "com/example/Factory.java",
            r#"
package com.example;

class Factory {
    Other create() {
        return value;
    }
}
"#,
        )
        .file(
            "com/example/Controller.java",
            r#"
package com.example;

class Controller {
    void caller(Factory factory) {
        Service value = new Service();
        var receiver = factory.create();
        receiver.run();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        find_edge(
            &value,
            "com.example.Controller.caller",
            "com.example.Other.run"
        )
        .is_some(),
        "declared factory return type should resolve receiver to Other.run: {}",
        value["edges"]
    );
    assert!(
        find_edge(
            &value,
            "com.example.Controller.caller",
            "com.example.Service.run"
        )
        .is_none(),
        "callee return identifiers must not resolve through caller locals: {}",
        value["edges"]
    );
}

#[test]
fn recursive_factory_summary_uses_declared_return_without_body_recursion() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "com/example/Service.java",
            "package com.example;\nclass Service { void run() {} }\n",
        )
        .file(
            "com/example/Controller.java",
            r#"
package com.example;

class Controller {
    Service create() {
        return create();
    }

    void caller() {
        var receiver = create();
        receiver.run();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        find_edge(
            &value,
            "com.example.Controller.caller",
            "com.example.Service.run"
        )
        .is_some(),
        "recursive factory should use declared return type without recursing through the body: {}",
        value["edges"]
    );
}

#[test]
fn scoped_usage_graph_skips_unrelated_invalid_java_callers() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "com/example/Util.java",
            r#"
package com.example;

public class Util {
    public static void helper() {}
}
"#,
        )
        .file(
            "com/example/Kept.java",
            r#"
package com.example;

public class Kept {
    void run() {
        Util.helper();
    }
}
"#,
        )
        .file(
            "broken/Broken.java",
            r#"
package broken;

public class Broken {
    void nope(
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), r#"{"paths":["com/example/Kept.java"]}"#);
    assert!(
        find_edge(&value, "com.example.Kept.run", "com.example.Util.helper").is_some(),
        "filtered Java edge graph should not require parsing unrelated callers: {}",
        value["edges"]
    );
}
