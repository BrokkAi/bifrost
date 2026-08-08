use crate::common::{assert_code_eq, csharp_fixture_project};
use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::analyzer::DispatchExtensibility;
use brokk_bifrost::{
    CSharpAnalyzer, CodeUnit, CodeUnitType, Language, ProjectFile, TestProject,
    TypeHierarchyProvider,
};
use tempfile::tempdir;

fn fixture_analyzer() -> CSharpAnalyzer {
    CSharpAnalyzer::from_project(csharp_fixture_project())
}

fn inline_csharp_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    for (path, contents) in files {
        ProjectFile::new(temp.path().to_path_buf(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(temp.keep(), Language::CSharp)
}

#[test]
fn test_csharp_initialization_and_skeletons() {
    let analyzer = fixture_analyzer();
    assert!(!analyzer.is_empty());

    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "A.cs");
    let class_a = CodeUnit::new(file.clone(), CodeUnitType::Class, "TestNamespace", "A");
    assert!(analyzer.declarations(&file).contains(&class_a));

    let skeletons = analyzer.get_skeletons(&file);
    assert!(skeletons.contains_key(&class_a));
    let class_skeleton = skeletons.get(&class_a).unwrap();
    assert!(
        class_skeleton.trim().starts_with("public class A {")
            || class_skeleton.trim().starts_with("public class A\n{")
    );
    assert_code_eq(
        r#"
        public class A {
          public int MyField;
          public string MyProperty { get; set; }
          public void MethodA() { … }
          public void MethodA(int param) { … }
          public A() { … }
        }
        "#,
        class_skeleton,
    );
    assert!(analyzer.get_skeleton(&class_a).is_some());
}

#[test]
fn test_csharp_mixed_scopes_and_nested_namespaces() {
    let analyzer = fixture_analyzer();

    let mixed = ProjectFile::new(analyzer.project().root().to_path_buf(), "MixedScope.cs");
    let mixed_skeletons = analyzer.get_skeletons(&mixed);
    assert!(!mixed_skeletons.is_empty());
    for code_unit in [
        CodeUnit::new(mixed.clone(), CodeUnitType::Class, "", "TopLevelClass"),
        CodeUnit::new(mixed.clone(), CodeUnitType::Class, "", "MyTestAttribute"),
        CodeUnit::new(mixed.clone(), CodeUnitType::Class, "NS1", "NamespacedClass"),
        CodeUnit::new(
            mixed.clone(),
            CodeUnitType::Class,
            "NS1",
            "INamespacedInterface",
        ),
        CodeUnit::new(mixed.clone(), CodeUnitType::Class, "", "TopLevelStruct"),
    ] {
        assert!(mixed_skeletons.contains_key(&code_unit));
        assert!(analyzer.declarations(&mixed).contains(&code_unit));
    }

    let nested = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "NestedNamespaces.cs",
    );
    let nested_skeletons = analyzer.get_skeletons(&nested);
    for code_unit in [
        CodeUnit::new(
            nested.clone(),
            CodeUnitType::Class,
            "Outer.Inner",
            "MyNestedClass",
        ),
        CodeUnit::new(
            nested.clone(),
            CodeUnitType::Class,
            "Outer.Inner",
            "IMyNestedInterface",
        ),
        CodeUnit::new(nested.clone(), CodeUnitType::Class, "Outer", "OuterClass"),
        CodeUnit::new(
            nested.clone(),
            CodeUnitType::Class,
            "AnotherTopLevelNs",
            "AnotherClass",
        ),
    ] {
        assert!(nested_skeletons.contains_key(&code_unit));
        assert!(analyzer.declarations(&nested).contains(&code_unit));
    }
}

#[test]
fn test_csharp_get_method_sources() {
    let analyzer = fixture_analyzer();

    let ctor = analyzer.get_definitions("TestNamespace.A.A");
    assert!(!ctor.is_empty());
    let ctor_source = analyzer.get_source(&ctor[0], true).unwrap();
    assert_code_eq(
        r#"
        // Constructor
        public A() 
        {
            MyField = 0;
            MyProperty = "default";
        }
        "#,
        &ctor_source,
    );

    let method = analyzer
        .get_definitions("TestNamespace.A.MethodA")
        .into_iter()
        .next()
        .unwrap();
    let method_sources = analyzer.get_source(&method, true).unwrap();
    assert_code_eq(
        r#"
        // Method
        public void MethodA() 
        {
            // Method body
        }

        // Overloaded Method
        public void MethodA(int param)
        {
            // Overloaded method body
            int x = param + 1;
        }
        "#,
        &method_sources,
    );

    let nested = analyzer
        .get_definitions("Outer.Inner.MyNestedClass.NestedMethod")
        .into_iter()
        .next()
        .unwrap();
    assert_code_eq(
        "public void NestedMethod() {}",
        &analyzer.get_source(&nested, true).unwrap(),
    );
}

#[test]
fn test_csharp_resolves_direct_ancestors() {
    let project = inline_csharp_project(&[(
        "Inheritance.cs",
        r#"
namespace Demo
{
    public class BaseType {}
    public interface IService {}
    public class ChildType : BaseType, IService {}
}
"#,
    )]);
    let analyzer = CSharpAnalyzer::from_project(project);

    let child = analyzer
        .get_definitions("Demo.ChildType")
        .into_iter()
        .find(|unit| unit.kind() == CodeUnitType::Class)
        .expect("child type");

    let ancestors = analyzer
        .get_direct_ancestors(&child)
        .into_iter()
        .map(|unit| unit.fq_name().to_string())
        .collect::<Vec<_>>();

    assert_eq!(ancestors, vec!["Demo.BaseType", "Demo.IService"]);
}

fn direct_ancestor_fq_names(analyzer: &CSharpAnalyzer, fq_name: &str) -> Vec<String> {
    let owner = analyzer
        .get_definitions(fq_name)
        .into_iter()
        .find(|unit| unit.kind() == CodeUnitType::Class)
        .unwrap_or_else(|| panic!("{fq_name} must be indexed as a class"));
    analyzer
        .get_direct_ancestors(&owner)
        .into_iter()
        .map(|unit| unit.fq_name().to_string())
        .collect()
}

/// #1801: supertype resolution searched only the declaring file's namespace,
/// `using` and alias scopes, so a base type that is itself nested and spelled
/// by its simple name resolved to nothing and the derived type reported no
/// ancestors at all. C# looks in the enclosing type chain first, so `Base`
/// written inside `Outer` names `Outer`'s own nested `Base`.
///
/// `Other.Base` is the near miss: an unrelated type with the same short name
/// in another namespace must not become the ancestor.
#[test]
fn test_csharp_nested_base_by_simple_name_resolves_to_the_sibling_nested_type() {
    let project = inline_csharp_project(&[
        (
            "P.cs",
            "namespace N\n{\n    public class Outer\n    {\n        private abstract class Base\n        {\n            protected static string Helper(object a, int b) { return \"x\"; }\n        }\n\n        private sealed class Derived : Base\n        {\n            public void Use(object a, int b) { var s = Helper(a, b); }\n        }\n    }\n}\n",
        ),
        (
            "Other.cs",
            "namespace Other\n{\n    public class Base { }\n}\n",
        ),
    ]);
    let analyzer = CSharpAnalyzer::from_project(project);

    assert_eq!(
        direct_ancestor_fq_names(&analyzer, "N.Outer$Derived"),
        vec!["N.Outer$Base"]
    );

    // The descendant index and everything built on it (type hierarchy,
    // polymorphic matching) is derived from the same ancestor walk, so the
    // nested relationship has to show up in the inverse direction too.
    let base = analyzer
        .get_definitions("N.Outer$Base")
        .into_iter()
        .find(|unit| unit.kind() == CodeUnitType::Class)
        .expect("nested base type");
    let descendants = analyzer
        .get_direct_descendants(&base)
        .into_iter()
        .map(|unit| unit.fq_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(descendants, vec!["N.Outer$Derived"]);
}

/// The #1801 matrix's namespace-free cell: the file-keyed search has no
/// namespace to compose with at all there, so the enclosing type chain is the
/// only scope that can name the base.
#[test]
fn test_csharp_nested_base_by_simple_name_resolves_without_a_namespace() {
    let project = inline_csharp_project(&[(
        "P.cs",
        "public class Outer\n{\n    private abstract class Base { }\n\n    private sealed class Derived : Base { }\n}\n",
    )]);
    let analyzer = CSharpAnalyzer::from_project(project);

    assert_eq!(
        direct_ancestor_fq_names(&analyzer, "Outer$Derived"),
        vec!["Outer$Base"]
    );
}

/// The controls from the #1801 matrix: a nested type whose base is spelled
/// with its enclosing type (`Outer.Base`), and a nested type whose base is a
/// top-level type, both already resolved and must keep resolving.
#[test]
fn test_csharp_qualified_and_top_level_bases_resolve_from_a_nested_type() {
    let project = inline_csharp_project(&[(
        "P.cs",
        "namespace N\n{\n    public class TopLevelBase { }\n\n    public class Outer\n    {\n        private abstract class Base { }\n\n        private sealed class Qualified : Outer.Base { }\n\n        private sealed class FromTopLevel : TopLevelBase { }\n    }\n}\n",
    )]);
    let analyzer = CSharpAnalyzer::from_project(project);

    assert_eq!(
        direct_ancestor_fq_names(&analyzer, "N.Outer$Qualified"),
        vec!["N.Outer$Base"]
    );
    assert_eq!(
        direct_ancestor_fq_names(&analyzer, "N.Outer$FromTopLevel"),
        vec!["N.TopLevelBase"]
    );
}

#[test]
fn test_csharp_interface_skeleton_and_sources() {
    let analyzer = fixture_analyzer();
    let file = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "AssetRegistrySA.cs",
    );
    let interface_cu = CodeUnit::new(
        file.clone(),
        CodeUnitType::Class,
        "ConsumerCentricityPermission.Core.ISA",
        "IAssetRegistrySA",
    );
    let validate_cu = analyzer
        .get_definitions(
            "ConsumerCentricityPermission.Core.ISA.IAssetRegistrySA.ValidateExistenceAsync",
        )
        .into_iter()
        .next()
        .unwrap();
    let can_connect_cu = analyzer
        .get_definitions("ConsumerCentricityPermission.Core.ISA.IAssetRegistrySA.CanConnectAsync")
        .into_iter()
        .next()
        .unwrap();
    let get_desc_cu = analyzer
        .get_definitions("ConsumerCentricityPermission.Core.ISA.IAssetRegistrySA.GetDeliveryPointDescriptionAsync")
        .into_iter()
        .next()
        .unwrap();

    let declarations = analyzer.declarations(&file);
    assert!(declarations.contains(&interface_cu));
    assert!(declarations.contains(&validate_cu));
    assert!(declarations.contains(&can_connect_cu));
    assert!(declarations.contains(&get_desc_cu));

    let skeleton = analyzer
        .get_skeletons(&file)
        .get(&interface_cu)
        .cloned()
        .unwrap();
    assert_code_eq(
        r#"
        public interface IAssetRegistrySA {
          public Task<Message> ValidateExistenceAsync(Guid assetId) { … }
          public Task<bool> CanConnectAsync() { … }
          public Task<string> GetDeliveryPointDescriptionAsync(Guid deliveryPointId) { … }
        }
        "#,
        &skeleton,
    );

    assert_code_eq(
        "public Task<Message> ValidateExistenceAsync(Guid assetId);",
        &analyzer.get_source(&validate_cu, true).unwrap(),
    );
    assert_code_eq(
        "public Task<bool> CanConnectAsync();",
        &analyzer.get_source(&can_connect_cu, true).unwrap(),
    );
    assert_code_eq(
        "public Task<string> GetDeliveryPointDescriptionAsync(Guid deliveryPointId);",
        &analyzer.get_source(&get_desc_cu, true).unwrap(),
    );
}

#[test]
fn test_utf8_byte_offset_handling() {
    let analyzer = fixture_analyzer();
    let file = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "GetTerminationRecordByIdHandler.cs",
    );
    let handler = analyzer
        .get_definitions("ConsumerCentricityPermission.Core.Business.Handlers.TerminationRecordHandlers.Queries.GetTerminationRecordByIdHandler")
        .into_iter()
        .next()
        .unwrap();
    let request = analyzer
        .get_definitions("ConsumerCentricityPermission.Core.Business.Handlers.TerminationRecordHandlers.Queries.GetTerminationRecordByIdRequest")
        .into_iter()
        .next()
        .unwrap();

    let declarations = analyzer.declarations(&file);
    assert!(declarations.contains(&handler));
    assert!(declarations.contains(&request));
    assert_eq!(handler.source(), &file);
    assert_eq!(request.source(), &file);

    let definition = analyzer
        .get_definitions(&handler.fq_name())
        .into_iter()
        .next()
        .unwrap();
    assert_eq!(
        "ConsumerCentricityPermission.Core.Business.Handlers.TerminationRecordHandlers.Queries.GetTerminationRecordByIdHandler",
        definition.fq_name()
    );
    assert!(
        analyzer
            .get_skeleton(&handler)
            .unwrap()
            .contains("public class GetTerminationRecordByIdHandler")
    );
}

#[test]
fn test_csharp_multi_assignment_and_complex_initializer_parity() {
    let project = inline_csharp_project(&[(
        "MultiField.cs",
        r#"
        public class MultiField {
            public int x = 1, y = 2;
        }
        "#,
    )]);
    let analyzer = CSharpAnalyzer::from_project(project);
    let x = analyzer
        .get_definitions("MultiField.x")
        .into_iter()
        .next()
        .unwrap();
    let y = analyzer
        .get_definitions("MultiField.y")
        .into_iter()
        .next()
        .unwrap();
    assert_code_eq("public int x = 1;", &analyzer.get_skeleton(&x).unwrap());
    assert_code_eq("public int y = 2;", &analyzer.get_skeleton(&y).unwrap());

    let project = inline_csharp_project(&[(
        "C.cs",
        r#"
        public class C {
          [NonSerialized] public int x = 1, y = 2;
        }
        "#,
    )]);
    let analyzer = CSharpAnalyzer::from_project(project);
    let x = analyzer.get_definitions("C.x").into_iter().next().unwrap();
    let y = analyzer.get_definitions("C.y").into_iter().next().unwrap();
    assert_code_eq("public int x = 1;", &analyzer.get_skeleton(&x).unwrap());
    assert_code_eq("public int y = 2;", &analyzer.get_skeleton(&y).unwrap());

    let project = inline_csharp_project(&[(
        "ComplexFields.cs",
        r#"
        public class ComplexFields {
            public object o = new object();
            public int literal = 42;
            public string s = "hello";
            public int calculated = 1 + 1;
        }
        "#,
    )]);
    let analyzer = CSharpAnalyzer::from_project(project);
    let o = analyzer
        .get_definitions("ComplexFields.o")
        .into_iter()
        .next()
        .unwrap();
    let literal = analyzer
        .get_definitions("ComplexFields.literal")
        .into_iter()
        .next()
        .unwrap();
    let s = analyzer
        .get_definitions("ComplexFields.s")
        .into_iter()
        .next()
        .unwrap();
    let calculated = analyzer
        .get_definitions("ComplexFields.calculated")
        .into_iter()
        .next()
        .unwrap();
    assert_code_eq("public object o;", &analyzer.get_skeleton(&o).unwrap());
    assert_code_eq(
        "public int literal = 42;",
        &analyzer.get_skeleton(&literal).unwrap(),
    );
    assert_code_eq(
        "public string s = \"hello\";",
        &analyzer.get_skeleton(&s).unwrap(),
    );
    assert_code_eq(
        "public int calculated;",
        &analyzer.get_skeleton(&calculated).unwrap(),
    );

    let project = inline_csharp_project(&[(
        "ExprField.cs",
        r#"
        public class ExprField {
            public int x = 1 + 1;
            public string s = "a" + "b";
        }
        "#,
    )]);
    let analyzer = CSharpAnalyzer::from_project(project);
    let x = analyzer
        .get_definitions("ExprField.x")
        .into_iter()
        .next()
        .unwrap();
    let s = analyzer
        .get_definitions("ExprField.s")
        .into_iter()
        .next()
        .unwrap();
    assert_code_eq("public int x;", &analyzer.get_skeleton(&x).unwrap());
    assert_code_eq("public string s;", &analyzer.get_skeleton(&s).unwrap());
}

#[test]
fn csharp_signature_metadata_classifies_member_dispatch_extensibility() {
    let project = inline_csharp_project(&[(
        "Dispatch.cs",
        r#"
public interface IContract
{
    int Count { get; }
}

public class Base
{
    public int Plain { get; }
    public virtual int Virtual { get; }
    private protected virtual int RestrictedVirtual { get; }
    public int Field;
}

public sealed class Final : Base
{
    public sealed override int Virtual => 1;
}

public enum Kind
{
    First
}
"#,
    )]);
    let analyzer = CSharpAnalyzer::from_project(project);

    let dispatch = |fqn: &str| {
        let unit = analyzer
            .get_definitions(fqn)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("missing declaration {fqn}"));
        analyzer
            .signature_metadata(&unit)
            .into_iter()
            .next()
            .and_then(|metadata| metadata.dispatch_extensibility())
    };

    assert_eq!(dispatch("Base.Plain"), Some(DispatchExtensibility::Closed));
    assert_eq!(dispatch("Base.Field"), Some(DispatchExtensibility::Closed));
    assert_eq!(dispatch("Kind.First"), Some(DispatchExtensibility::Closed));
    assert_eq!(
        dispatch("IContract.Count"),
        Some(DispatchExtensibility::Open)
    );
    assert_eq!(dispatch("Base.Virtual"), Some(DispatchExtensibility::Open));
    assert_eq!(
        dispatch("Base.RestrictedVirtual"),
        Some(DispatchExtensibility::Open)
    );
    assert_eq!(
        dispatch("Final.Virtual"),
        Some(DispatchExtensibility::Closed)
    );
}
