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
        .join("usage-graph-csharp");
    usage_graph_at(root, "{}")
}

#[test]
fn resolves_instance_static_and_unqualified_calls() {
    let value = usage_graph();

    // `s.Run()` where `Service s = new Service()` — local type resolves the receiver.
    assert!(
        has_edge(
            &value,
            "Example.Consumer.ViaInstance",
            "Example.Service.Run"
        ),
        "expected ViaInstance -> Service.Run: {}",
        value["edges"]
    );
    // `Service.Helper()` static call resolves the type directly.
    assert!(
        has_edge(
            &value,
            "Example.Consumer.ViaStatic",
            "Example.Service.Helper"
        ),
        "expected ViaStatic -> Service.Helper: {}",
        value["edges"]
    );
    // Unqualified `Local()` attributes to the enclosing class.
    assert!(
        has_edge(
            &value,
            "Example.Consumer.CallsLocal",
            "Example.Consumer.Local"
        ),
        "expected CallsLocal -> Consumer.Local: {}",
        value["edges"]
    );
}

#[test]
fn receiver_typing_is_type_based_not_name_based() {
    let value = usage_graph();

    // A `Run()` call on a Service-typed parameter resolves (the parameter name
    // shadowing the member is irrelevant — resolution is by receiver type).
    assert!(
        has_edge(&value, "Example.Consumer.Shadowed", "Example.Service.Run"),
        "expected Shadowed -> Service.Run: {}",
        value["edges"]
    );
    // The same member name on a Consumer-typed receiver must NOT resolve to
    // Service.Run — proving resolution is by receiver type, not member name.
    assert!(
        !has_edge(
            &value,
            "Example.Consumer.WrongReceiver",
            "Example.Service.Run"
        ),
        "WrongReceiver must not edge to Service.Run: {}",
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
            .any(|edge| edge["to"].as_str() == Some("Example.Service.Unused")),
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
fn nested_class_unqualified_calls_attribute_to_the_nested_fqn() {
    let value = usage_graph();

    // An unqualified call inside `Outer.Inner` attributes to the nested class's
    // own fqn (`$`-separated, as the analyzer emits it), not to `Outer`.
    assert!(
        has_edge(
            &value,
            "Example.Outer$Inner.Compute",
            "Example.Outer$Inner.Helper"
        ),
        "expected Outer$Inner.Compute -> Outer$Inner.Helper: {}",
        value["edges"]
    );
}

#[test]
fn path_filter_only_emits_matching_csharp_callers() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Util.cs",
            r#"
namespace Example;

public class Util {
    public static void Helper() {}
}
"#,
        )
        .file(
            "Kept.cs",
            r#"
namespace Example;

public class Kept {
    void Run() {
        Util.Helper();
    }
}
"#,
        )
        .file(
            "Ignored.cs",
            r#"
namespace Example;

public class Ignored {
    void Run() {
        Util.Helper();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), r#"{"paths":["Kept.cs"]}"#);
    assert!(
        has_edge(&value, "Kept.Run", "Util.Helper"),
        "kept caller should still resolve static callee nodes: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "Ignored.Run", "Util.Helper"),
        "path-filtered usage_graph must not emit edges from ignored callers: {}",
        value["edges"]
    );
}

#[test]
fn include_tests_false_excludes_csharp_test_callers() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Util.cs",
            r#"
namespace Example;

public class Util {
    public static void Helper() {}
}
"#,
        )
        .file(
            "Prod.cs",
            r#"
namespace Example;

public class Prod {
    void Run() {
        Util.Helper();
    }
}
"#,
        )
        .file(
            "ProdTests.cs",
            r#"
using Xunit;

namespace Example;

public class ProdTests {
    [Fact]
    void TestRun() {
        Util.Helper();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), r#"{"include_tests":false}"#);
    assert!(
        has_edge(&value, "Prod.Run", "Util.Helper"),
        "production caller should remain in the graph: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "ProdTests.TestRun", "Util.Helper"),
        "test callers should be excluded when include_tests is false: {}",
        value["edges"]
    );
}

#[test]
fn scoped_usage_graph_skips_unrelated_invalid_csharp_callers() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Util.cs",
            r#"
namespace Example;

public class Util {
    public static void Helper() {}
}
"#,
        )
        .file(
            "Kept.cs",
            r#"
namespace Example;

public class Kept {
    void Run() {
        Util.Helper();
    }
}
"#,
        )
        .file(
            "Broken.cs",
            r#"
namespace Broken;

public class Broken {
    void Nope(
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), r#"{"paths":["Kept.cs"]}"#);
    assert!(
        has_edge(&value, "Kept.Run", "Util.Helper"),
        "filtered C# edge graph should not require parsing unrelated callers: {}",
        value["edges"]
    );
}
