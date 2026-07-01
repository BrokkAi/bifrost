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
        has_edge(&value, "Example.Kept.Run", "Example.Util.Helper"),
        "kept caller should still resolve static callee nodes: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "Example.Ignored.Run", "Example.Util.Helper"),
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
        has_edge(&value, "Example.Prod.Run", "Example.Util.Helper"),
        "production caller should remain in the graph: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "Example.ProdTests.TestRun", "Example.Util.Helper"),
        "test callers should be excluded when include_tests is false: {}",
        value["edges"]
    );
}

#[test]
fn object_sensitive_factory_receiver_resolves_only_constructed_type() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Service.cs",
            r#"
namespace Example;

public class Service {
    public void Run() {}
    public static Service Create() {
        return new Service();
    }
}

public class Other {
    public void Run() {}
}
"#,
        )
        .file(
            "Consumer.cs",
            r#"
namespace Example;

public class Consumer {
    Service MakeService() {
        return new Service();
    }

    public void ViaFactory() {
        var service = MakeService();
        service.Run();
    }

    public void ViaStaticFactory() {
        var service = Service.Create();
        service.Run();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    for caller in [
        "Example.Consumer.ViaFactory",
        "Example.Consumer.ViaStaticFactory",
    ] {
        assert!(
            has_edge(&value, caller, "Example.Service.Run"),
            "{caller} should edge to Service.Run: {}",
            value["edges"]
        );
        assert!(
            !has_edge(&value, caller, "Example.Other.Run"),
            "{caller} must not edge to Other.Run by member name: {}",
            value["edges"]
        );
    }
}

#[test]
fn factory_return_resolves_in_callee_namespace() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Lib.cs",
            r#"
namespace Lib;

public class Service {
    public void Run() {}
}

public class Factory {
    public Service Make() {
        return new Service();
    }
}
"#,
        )
        .file(
            "App.cs",
            r#"
using Lib;

namespace App;

public class Service {
    public void Run() {}
}

public class Consumer {
    public void Call(Factory factory) {
        var service = factory.Make();
        service.Run();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "App.Consumer.Call", "Lib.Service.Run"),
        "factory return should resolve in the callee namespace: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "App.Consumer.Call", "App.Service.Run"),
        "factory return must not resolve Service in the caller namespace: {}",
        value["edges"]
    );
}

#[test]
fn inherited_factory_receiver_resolves_from_base_method() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App.cs",
            r#"
namespace App;

public class Service {
    public void Run() {}
}

public class Base {
    public Service Make() {
        return new Service();
    }
}

public class Consumer : Base {
    public void Call() {
        var service = Make();
        service.Run();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "App.Consumer.Call", "App.Service.Run"),
        "inherited factory should seed the receiver type: {}",
        value["edges"]
    );
}

#[test]
fn ambiguous_factory_receiver_emits_no_partial_edge() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Service.cs",
            "namespace Example;\npublic class Service { public void Run() {} }\n",
        )
        .file(
            "Other.cs",
            "namespace Example;\npublic class Other { public void Run() {} }\n",
        )
        .file(
            "Consumer.cs",
            r#"
namespace Example;

public class Consumer {
    object Choose(bool flag) {
        if (flag) {
            return new Service();
        }
        return new Other();
    }

    public void Caller(bool flag) {
        var service = Choose(flag);
        service.Run();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        !has_edge(&value, "Example.Consumer.Caller", "Example.Service.Run"),
        "ambiguous receiver must not choose Service.Run: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "Example.Consumer.Caller", "Example.Other.Run"),
        "ambiguous receiver must not choose Other.Run: {}",
        value["edges"]
    );
}

#[test]
fn overloaded_factory_receiver_emits_no_partial_edge() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Service.cs",
            "namespace Example;\npublic class Service { public void Run() {} }\n",
        )
        .file(
            "Other.cs",
            "namespace Example;\npublic class Other { public void Run() {} }\n",
        )
        .file(
            "Consumer.cs",
            r#"
namespace Example;

public class Factory {
    public Service Make(int value) {
        return new Service();
    }

    public Other Make(string value) {
        return new Other();
    }
}

public class Consumer {
    public void Caller(Factory factory) {
        var service = factory.Make(1);
        service.Run();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        !has_edge(&value, "Example.Consumer.Caller", "Example.Service.Run")
            && !has_edge(&value, "Example.Consumer.Caller", "Example.Other.Run"),
        "overloaded factory receiver must not choose a same-arity return type by declaration order: {}",
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
        has_edge(&value, "Example.Kept.Run", "Example.Util.Helper"),
        "filtered C# edge graph should not require parsing unrelated callers: {}",
        value["edges"]
    );
}
