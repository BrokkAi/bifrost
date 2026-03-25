mod common;

use brokk_analyzer::{
    CSharpAnalyzer, CodeUnit, CodeUnitType, IAnalyzer, Language, ProjectFile, TestProject,
};
use common::{assert_code_eq, csharp_fixture_project};
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
    assert!(analyzer.get_declarations(&file).contains(&class_a));

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
        assert!(analyzer.get_declarations(&mixed).contains(&code_unit));
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
        assert!(analyzer.get_declarations(&nested).contains(&code_unit));
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

    let declarations = analyzer.get_declarations(&file);
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
    let handler = CodeUnit::new(
        file.clone(),
        CodeUnitType::Class,
        "ConsumerCentricityPermission.Core.Business.Handlers.TerminationRecordHandlers.Queries",
        "GetTerminationRecordByIdHandler",
    );
    let request = CodeUnit::new(
        file.clone(),
        CodeUnitType::Class,
        "ConsumerCentricityPermission.Core.Business.Handlers.TerminationRecordHandlers.Queries",
        "GetTerminationRecordByIdRequest",
    );

    let declarations = analyzer.get_declarations(&file);
    assert!(declarations.contains(&handler));
    assert!(declarations.contains(&request));

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
