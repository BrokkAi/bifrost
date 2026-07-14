mod common;

use brokk_bifrost::Language;
use common::usage_graph::{assert_every_edge_endpoint_is_a_node, has_edge, usage_graph_at};
use common::{InlineTestProject, csharp_nested_partial_cacheinfo_project};
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
fn inverted_graph_resolves_unique_method_group_and_respects_shadowing() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Demo.cs",
            r#"
namespace Demo;

public delegate void Handler(int value);

public sealed class Command {
    private void onDefault(int value) {}
    private void Accept(int marker, Handler callback, object state) {}

    public void Run() {
        Accept(1, onDefault, this);
    }

    public void RunShadowed(Handler onDefault) {
        Accept(1, onDefault, this);
    }
}

public class BaseCommand {
    protected void inherited(int value) {}
}

public sealed class HiddenCommand : BaseCommand {
    private Handler inherited;
    private void Accept(Handler callback) {}

    public void Run() {
        Accept(inherited);
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "Demo.Command.Run", "Demo.Command.onDefault"),
        "unique method group should produce an inverted edge: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "Demo.Command.RunShadowed", "Demo.Command.onDefault"),
        "same-named parameter must shadow the member method group: {}",
        value["edges"]
    );
    assert!(
        !has_edge(
            &value,
            "Demo.HiddenCommand.Run",
            "Demo.BaseCommand.inherited"
        ),
        "a nearer delegate field must hide the base method group: {}",
        value["edges"]
    );
}

#[test]
fn inverted_graph_resolves_inherited_members_at_the_nearest_declaring_type() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Demo.cs",
            r#"
namespace Demo;

public class Base {
    protected void Report(int value) {}
}

public class Intermediate : Base {}

public sealed class Consumer : Intermediate {
    public void RunQualified() {
        this.Report(1);
    }

    public void RunUnqualified() {
        Report(2);
    }

    public void RunParameter(System.Action<int> Report) {
        Report(4);
    }

    public void RunLocal() {
        void Report(int value) {}
        Report(5);
    }
}

public sealed class HiddenConsumer : Intermediate {
    private void Report(int value) {}

    public void Run() {
        this.Report(3);
    }
}

public class Box {
    protected void Read() {}
}

public class Box<T> {
    protected void Read() {}
}

public sealed class GenericConsumer : Box<int> {
    public void Run() {
        this.Read();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "Demo.Consumer.RunQualified", "Demo.Base.Report"),
        "qualified inherited call should edge to the declaring base member: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "Demo.Consumer.RunUnqualified", "Demo.Base.Report"),
        "unqualified inherited call should edge to the declaring base member: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "Demo.Consumer.RunParameter", "Demo.Base.Report"),
        "delegate parameter must shadow the inherited member: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "Demo.Consumer.RunLocal", "Demo.Base.Report"),
        "local function must shadow the inherited member: {}",
        value["edges"]
    );
    assert!(
        has_edge(
            &value,
            "Demo.HiddenConsumer.Run",
            "Demo.HiddenConsumer.Report"
        ),
        "nearer member should receive the hidden call edge: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "Demo.HiddenConsumer.Run", "Demo.Base.Report"),
        "nearer declaration must hide the base member: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "Demo.GenericConsumer.Run", "Demo.Box`1.Read"),
        "generic inherited call should retain the exact metadata-arity owner: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "Demo.GenericConsumer.Run", "Demo.Box.Read"),
        "generic inherited call must not normalize to the nongeneric owner: {}",
        value["edges"]
    );
}

#[test]
fn inverted_graph_resolves_explicit_generic_calls_and_their_return_types() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Demo.cs",
            r#"
using Imported;

namespace Demo;

public sealed class Source {}

public sealed class BlockedSource {
    public void Filter<T>(T value) {}
}

public sealed class GenericResult {
    public void GenericOnly() {}
}

public sealed class Box<T> {
    public void BoxOnly() {}
}

public sealed class PlainResult {}

public static class Factory {
    public static T Create<T>() => default(T);
    public static T[] CreateArray<T>() => new T[0];
    public static Box<T> CreateBox<T>() => new Box<T>();
    public static GenericResult? CreateNullable() => new GenericResult();
    public static PlainResult Create() => new PlainResult();
}

public class BaseFactory {
    public sealed class NestedResult {
        public void NestedOnly() {}
    }

    protected NestedResult Build<T>() => new NestedResult();
}

public class Base {
    protected void Pick<T>(int value) {}
}

public sealed class Consumer : Base {
    private void Pick(int value) {}

    public void Run(Demo.Source source, Demo.BlockedSource blocked) {
        source.Select<int>(1);
        blocked.Filter<int>(1);
        Factory.Create<GenericResult>().GenericOnly();
        Pick<int>(1);
    }

    public void RunWrapped() {
        Factory.CreateArray<GenericResult>().GenericOnly();
    }

    public void RunBoxed() {
        Factory.CreateBox<GenericResult>().BoxOnly();
    }

    public void RunNullable() {
        Factory.CreateNullable().GenericOnly();
    }

    public void RunWrongArityOnly() {
        Missing<int>(1);
    }

    private void Missing(int value) {}
}

public sealed class DerivedFactory : BaseFactory {
    public void Run() {
        Build<int>().NestedOnly();
    }
}
"#,
        )
        .file(
            "Extensions.cs",
            r#"
namespace Imported {
    public static class Extensions {
        public static T Select<T>(this Demo.Source source, T value) => value;
        public static T Filter<T>(this Demo.BlockedSource source, T value) => value;
    }
}

namespace Other {
    public static class Extensions {
        public static T Select<T>(this Demo.Source source, T value) => value;
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(
            &value,
            "Demo.DerivedFactory.Run",
            "Demo.BaseFactory$NestedResult.NestedOnly"
        ),
        "inherited generic return types should resolve nested types from the declaring owner: {}",
        value["edges"]
    );
    assert!(
        !has_edge(
            &value,
            "Demo.Consumer.RunWrapped",
            "Demo.GenericResult.GenericOnly"
        ),
        "an array-wrapped method type parameter must not seed the bare result type: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "Demo.Consumer.RunBoxed", "Demo.Box`1.BoxOnly"),
        "constructed generic return facts should retain the generic owner: {}",
        value["edges"]
    );
    assert!(
        has_edge(
            &value,
            "Demo.Consumer.RunNullable",
            "Demo.GenericResult.GenericOnly"
        ),
        "nullable concrete return facts should retain the underlying owner: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "Demo.Consumer.Run", "Imported.Extensions.Select"),
        "generic extension calls should edge to the visible imported declaration: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "Demo.Consumer.Run", "Other.Extensions.Select"),
        "a nonvisible competing extension must not receive an edge: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "Demo.Consumer.Run", "Demo.BlockedSource.Filter"),
        "an applicable generic instance method should receive the call edge: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "Demo.Consumer.Run", "Imported.Extensions.Filter"),
        "an applicable instance method must suppress extension fallback: {}",
        value["edges"]
    );
    assert!(
        has_edge(
            &value,
            "Demo.Consumer.Run",
            "Demo.GenericResult.GenericOnly"
        ),
        "generic return-type inference should preserve the selected overload: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "Demo.Consumer.Run", "Demo.Base.Pick"),
        "wrong generic arity on the derived member must not hide the base call: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "Demo.Consumer.Run", "Demo.Consumer.Pick"),
        "the explicit generic call must not edge to the nongeneric sibling: {}",
        value["edges"]
    );
    assert!(
        !has_edge(
            &value,
            "Demo.Consumer.RunWrongArityOnly",
            "Demo.Consumer.Missing"
        ),
        "a call with incompatible explicit generic arity must not synthesize an edge: {}",
        value["edges"]
    );
}

#[test]
fn inverted_graph_scopes_extensions_to_the_call_site_namespace() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Declarations.cs",
            r#"
namespace Demo {
    public sealed class Source {}
}

namespace Imported {
    public static class Extensions {
        public static T Select<T>(this Demo.Source source, T value) => value;
    }
}
"#,
        )
        .file(
            "Consumers.cs",
            r#"
namespace Shared {
    using Imported;

    public sealed class ImportedConsumer {
        public void Run(Demo.Source source) {
            source.Select<int>(1);
        }
    }
}

namespace Shared {
    public sealed class SiblingConsumer {
        public void Run(Demo.Source source) {
            source.Select<int>(2);
        }
    }
}

namespace Other {
    public sealed class OtherConsumer {
        public void Run(Demo.Source source) {
            source.Select<int>(3);
        }
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(
            &value,
            "Shared.ImportedConsumer.Run",
            "Imported.Extensions.Select"
        ),
        "the namespace containing the using should resolve the extension: {}",
        value["edges"]
    );
    for caller in ["Shared.SiblingConsumer.Run", "Other.OtherConsumer.Run"] {
        assert!(
            !has_edge(&value, caller, "Imported.Extensions.Select"),
            "a namespace-scoped using must not leak into {caller}: {}",
            value["edges"]
        );
    }
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
fn nested_partial_type_references_edge_to_nested_type() {
    let project = csharp_nested_partial_cacheinfo_project().build();

    let value = usage_graph_at(project.root(), "{}");

    assert!(
        has_edge(
            &value,
            "Dapper.SqlMapper.GetCacheInfo",
            "Dapper.SqlMapper$CacheInfo"
        ),
        "bare nested type references in a partial sibling file should edge to CacheInfo: {}",
        value["edges"]
    );
}

#[test]
fn attribute_reference_edges_to_attribute_type() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "System/Attribute.cs",
            "namespace System { public class Attribute { } }\n",
        )
        .file(
            "Attributes/MarkerAttribute.cs",
            "namespace Demo.Attributes { public class MarkerAttribute : System.Attribute { } }\n",
        )
        .file(
            "Consumer.cs",
            r#"
using Demo.Attributes;

namespace Demo {
    [Marker]
    public sealed class Consumer { }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "Demo.Consumer", "Demo.Attributes.MarkerAttribute"),
        "expected Consumer -> MarkerAttribute: {}",
        value["edges"]
    );
}

#[test]
fn nested_type_references_do_not_edge_through_type_parameter_shadow() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Mapper.CacheInfo.cs",
            r#"
namespace Dapper {
    public static partial class SqlMapper {
        private sealed class CacheInfo {}
    }
}
"#,
        )
        .file(
            "Mapper.cs",
            r#"
namespace Dapper {
    public static partial class SqlMapper {
        private static CacheInfo M<CacheInfo>(CacheInfo value) {
            CacheInfo? local = value;
            return default;
        }
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");

    assert!(
        !has_edge(&value, "Dapper.SqlMapper.M", "Dapper.SqlMapper$CacheInfo"),
        "type parameter CacheInfo should shadow the nested type in usage_graph: {}",
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
fn receiver_return_type_chaining_uses_keyed_lookup_with_unrelated_declarations() {
    let mut unrelated = String::from("namespace Noise;\n");
    for index in 0..80 {
        unrelated.push_str(&format!(
            "public class Unrelated{index} {{ public void Use() {{}} public Unrelated{index} Create() => this; }}\n"
        ));
    }

    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Noise.cs", unrelated)
        .file(
            "App.cs",
            r#"
namespace App;

public class Product {
    public void Use() {}
}

public class Factory {
    public Product Create() {
        return new Product();
    }
}

public class Consumer {
    public void Run(Factory factory) {
        var product = factory.Create();
        product.Use();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "App.Consumer.Run", "App.Product.Use"),
        "factory return receiver should resolve through keyed declarations: {}",
        value["edges"]
    );
}

#[test]
fn optional_factory_return_type_seeds_inverted_receiver_edge() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App.cs",
            r#"
namespace App;

public sealed class Product {
    public void Use() {}
}

public sealed class Factory {
    public Product Create(string label = "") => new Product();
}

public sealed class Consumer {
    public void Run(Factory factory) {
        var product = factory.Create();
        product.Use();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "App.Consumer.Run", "App.Product.Use"),
        "optional factory return should type the inverted receiver edge: {}",
        value["edges"]
    );
}

#[test]
fn inverted_factory_return_keeps_overlapping_arity_untyped() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "App.cs",
            r#"
namespace App;

public sealed class ExactProduct { public void Use() {} }
public sealed class OptionalProduct { public void Use() {} }
public sealed class FixedProduct { public void Use() {} }
public sealed class ParamsProduct { public void Use() {} }

public sealed class Factory {
    public ExactProduct Create() => new ExactProduct();
    public OptionalProduct Create(int count = 0) => new OptionalProduct();
    public FixedProduct Make(string head, object tail) => new FixedProduct();
    public ParamsProduct Make(string head, params object[] tail) => new ParamsProduct();
}

public sealed class Consumer {
    public void Exact(Factory factory) {
        var product = factory.Create();
        product.Use();
    }
    public void Fixed(Factory factory) {
        var product = factory.Make("head", "tail");
        product.Use();
    }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        !has_edge(&value, "App.Consumer.Exact", "App.ExactProduct.Use"),
        "overlapping exact and optional overloads need argument-type evidence: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "App.Consumer.Exact", "App.OptionalProduct.Use"),
        "overlapping exact and optional overloads must remain conservatively untyped: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "App.Consumer.Fixed", "App.FixedProduct.Use"),
        "equal-total fixed and params overloads need argument-type evidence: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "App.Consumer.Fixed", "App.ParamsProduct.Use"),
        "equal-total fixed and params overloads must remain conservatively untyped: {}",
        value["edges"]
    );
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
