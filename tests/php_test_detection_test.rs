use brokk_analyzer::{IAnalyzer, Language, PhpAnalyzer, Project, ProjectFile, TestProject};
use tempfile::tempdir;

fn inline_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    for (path, contents) in files {
        ProjectFile::new(temp.path().to_path_buf(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(temp.keep(), Language::Php)
}

#[test]
fn test_name_based_detection() {
    let project = inline_project(&[(
        "Test.php",
        r#"
        <?php
        function testFoo() { }
        "#,
    )]);
    let analyzer = PhpAnalyzer::from_project(project.clone()).update_all();
    assert!(analyzer.contains_tests(&ProjectFile::new(project.root().to_path_buf(), "Test.php",)));
}

#[test]
fn test_docblock_based_detection() {
    let project = inline_project(&[(
        "Test.php",
        r#"
        <?php
        /** @test */
        function foo() { }
        "#,
    )]);
    let analyzer = PhpAnalyzer::from_project(project.clone()).update_all();
    assert!(analyzer.contains_tests(&ProjectFile::new(project.root().to_path_buf(), "Test.php",)));
}

#[test]
fn test_negative_detection() {
    let project = inline_project(&[(
        "Normal.php",
        r#"
        <?php
        function normalFunction() { }
        class NormalClass {
            public function normalMethod() { }
        }
        "#,
    )]);
    let analyzer = PhpAnalyzer::from_project(project.clone()).update_all();
    assert!(!analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "Normal.php",
    )));
}

#[test]
fn test_name_based_detection_is_case_insensitive() {
    let project = inline_project(&[(
        "CaseInsensitive.php",
        r#"
        <?php
        function TestFoo() { }
        function TESTBar() { }
        "#,
    )]);
    let analyzer = PhpAnalyzer::from_project(project.clone()).update_all();
    assert!(analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "CaseInsensitive.php",
    )));
}

#[test]
fn test_context_manager_equivalent_detection() {
    let project = inline_project(&[(
        "Integration.php",
        r#"
        <?php
        function testFoo() { }
        "#,
    )]);
    let analyzer = PhpAnalyzer::from_project(project.clone()).update_all();
    assert!(analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "Integration.php",
    )));
}

#[test]
fn test_non_adjacent_docblock_detection() {
    let project = inline_project(&[(
        "MyService.php",
        r#"
        <?php
        /**
         * @test
         * File header
         */

        class MyService {
            /**
             * @test
             */

            // Intermediate comment breaks adjacency
            public function notATest() { }
        }
        "#,
    )]);
    let analyzer = PhpAnalyzer::from_project(project.clone()).update_all();
    assert!(!analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "MyService.php",
    )));
}

#[test]
fn test_boundary_matches() {
    let project = inline_project(&[(
        "Boundary.php",
        r#"
        <?php
        class TestSuffix {
            public function testingSetup() { }
            public function atest() { }
        }
        "#,
    )]);
    let analyzer = PhpAnalyzer::from_project(project.clone()).update_all();
    assert!(analyzer.contains_tests(&ProjectFile::new(
        project.root().to_path_buf(),
        "Boundary.php",
    )));
}
