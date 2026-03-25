use brokk_analyzer::{CSharpAnalyzer, IAnalyzer, Language, Project, ProjectFile, TestProject};
use tempfile::tempdir;

fn inline_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    for (path, contents) in files {
        ProjectFile::new(temp.path().to_path_buf(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(temp.keep(), Language::CSharp)
}

#[test]
fn test_contains_tests_detection() {
    let project = inline_project(&[
        (
            "Services/Logic.cs",
            r#"
            using NUnit.Framework;

            public class MyTests {
                [Test]
                public void MyTestMethod() {
                    Assert.Pass();
                }

                [Fact]
                public void XunitTest() {}

                [Theory]
                public void XunitTheory(int x) {}
            }
            "#,
        ),
        (
            "Models/Data.cs",
            r#"
            public class Calculator {
                public int Add(int a, int b) => a + b;
            }
            "#,
        ),
    ]);

    let analyzer = CSharpAnalyzer::from_project(project.clone()).update_all();
    let test_file = ProjectFile::new(project.root().to_path_buf(), "Services/Logic.cs");
    let non_test_file = ProjectFile::new(project.root().to_path_buf(), "Models/Data.cs");
    assert!(analyzer.contains_tests(&test_file));
    assert!(!analyzer.contains_tests(&non_test_file));
}

#[test]
fn test_specific_attribute_variants() {
    let project = inline_project(&[
        (
            "Tests/VariantTests.cs",
            r#"
            using NUnit.Framework;

            public class VariantTests {
                [NUnit.Framework.Test]
                public void FullyQualified() {}

                [Test]
                public void Simple() {}

                [NotATest]
                public void IgnoreMe() {}
            }
            "#,
        ),
        (
            "Tests/IgnoreTests.cs",
            r#"
            public class OnlyIgnore {
                [NotATest]
                public void Method() {}
            }
            "#,
        ),
    ]);

    let analyzer = CSharpAnalyzer::from_project(project.clone()).update_all();
    assert!(analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "Tests/VariantTests.cs",
    )));
    assert!(!analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "Tests/IgnoreTests.cs",
    )));
}

#[test]
fn test_attribute_suffix_handling() {
    let project = inline_project(&[(
        "Tests/SuffixTests.cs",
        r#"
        using NUnit.Framework;
        public class SuffixTests {
            [TestAttribute]
            public void MyTest() {}

            [NUnit.Framework.FactAttribute]
            public void QualifiedSuffix() {}
        }
        "#,
    )]);
    let analyzer = CSharpAnalyzer::from_project(project.clone()).update_all();
    assert!(analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "Tests/SuffixTests.cs",
    )));
}

#[test]
fn test_non_test_attributes_do_not_trigger_detection() {
    let project = inline_project(&[(
        "Logic/Service.cs",
        r#"
        public class MyClass {
            [Obsolete("Use NewMethod instead")]
            public void OldMethod() {}

            [Serializable]
            public void OtherMethod() {}
        }
        "#,
    )]);
    let analyzer = CSharpAnalyzer::from_project(project.clone()).update_all();
    assert!(!analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "Logic/Service.cs",
    )));
}
