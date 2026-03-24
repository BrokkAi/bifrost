use brokk_analyzer::{IAnalyzer, JavaAnalyzer, Language, TestProject};

fn fixture_analyzer() -> JavaAnalyzer {
    let root = std::env::current_dir()
        .unwrap()
        .join("tests/fixtures/testcode-java")
        .canonicalize()
        .unwrap();
    let project = TestProject::new(root, Language::Java);
    JavaAnalyzer::from_project(project)
}

#[test]
fn returns_overload_sources_in_file_order() {
    let analyzer = fixture_analyzer();
    let method = analyzer
        .get_definitions("A.method2")
        .into_iter()
        .next()
        .unwrap();
    let source = analyzer.get_source(&method, true).unwrap();

    assert!(source.contains("public String method2(String input)"));
    assert!(source.contains("public String method2(String input, int otherInput)"));
    assert!(source.find("method2(String input)").unwrap() < source.find("method2(String input, int otherInput)").unwrap());
}

#[test]
fn returns_nested_class_source_slice() {
    let analyzer = fixture_analyzer();
    let inner = analyzer
        .get_definitions("A.AInner.AInnerInner")
        .into_iter()
        .next()
        .unwrap();
    let source = analyzer.get_source(&inner, true).unwrap();

    assert!(source.contains("public class AInnerInner"));
    assert!(source.contains("public void method7()"));
}

#[test]
fn renders_class_skeleton_with_children() {
    let analyzer = fixture_analyzer();
    let class_a = analyzer.get_definitions("A").into_iter().next().unwrap();
    let skeleton = analyzer.get_skeleton(&class_a).unwrap();

    let expected = r#"public class A {
  void method1()
  public String method2(String input)
  public String method2(String input, int otherInput)
  public Function<Integer, Integer> method3()
  public static int method4(double foo, Integer bar)
  public void method5()
  public void method6()
  public class AInner {
    public class AInnerInner {
      public void method7()
    }
  }
  public static class AInnerStatic {
  }
  private void usesInnerClass()
}"#;

    assert_eq!(expected, skeleton);
}

#[test]
fn renders_header_only_skeleton_with_fields_and_placeholder() {
    let analyzer = fixture_analyzer();
    let class_d = analyzer.get_definitions("D").into_iter().next().unwrap();
    let skeleton = analyzer.get_skeleton_header(&class_d).unwrap();

    let expected = r#"public class D {
  public static int field1;
  private String field2;
  [...]
}"#;

    assert_eq!(expected, skeleton);
}
