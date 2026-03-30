use brokk_analyzer::{
    AnalyzerDelegate, CSharpAnalyzer, CppAnalyzer, GoAnalyzer, IAnalyzer, JavaAnalyzer,
    JavascriptAnalyzer, Language, MultiAnalyzer, PhpAnalyzer, PythonAnalyzer, RustAnalyzer,
    ScalaAnalyzer, TestProject, TypescriptAnalyzer,
};
use std::collections::BTreeMap;
use tempfile::tempdir;

fn fixture_project() -> TestProject {
    let temp = tempdir().unwrap();
    let root = temp.keep();
    let files = [
        ("A.java", "class A {}"),
        ("a.py", "class A: pass\n"),
        ("main.go", "package main\nfunc main() {}\n"),
        ("a.js", "export function a() {}\n"),
        ("a.ts", "export function a(): void {}\n"),
        ("lib.rs", "fn main() {}\n"),
        ("a.cpp", "int main() { return 0; }\n"),
        ("a.cs", "class A {}\n"),
        ("a.php", "<?php function a() {}\n"),
        ("A.scala", "class A\n"),
    ];

    for (path, contents) in files {
        std::fs::write(root.join(path), contents).unwrap();
    }

    TestProject::new(root, Language::Java)
}

#[test]
fn direct_analyzers_match_brokk_capability_matrix() {
    let project = fixture_project();

    let java = JavaAnalyzer::from_project(project.clone());
    let python = PythonAnalyzer::from_project(project.clone());
    let go = GoAnalyzer::from_project(project.clone());
    let javascript = JavascriptAnalyzer::from_project(project.clone());
    let typescript = TypescriptAnalyzer::from_project(project.clone());
    let rust = RustAnalyzer::from_project(project.clone());
    let cpp = CppAnalyzer::from_project(project.clone());
    let csharp = CSharpAnalyzer::from_project(project.clone());
    let php = PhpAnalyzer::from_project(project.clone());
    let scala = ScalaAnalyzer::from_project(project.clone());

    assert!(java.import_analysis_provider().is_some());
    assert!(python.import_analysis_provider().is_some());
    assert!(go.import_analysis_provider().is_some());
    assert!(javascript.import_analysis_provider().is_some());
    assert!(typescript.import_analysis_provider().is_some());
    assert!(rust.import_analysis_provider().is_some());
    assert!(cpp.import_analysis_provider().is_some());
    assert!(csharp.import_analysis_provider().is_none());
    assert!(php.import_analysis_provider().is_none());
    assert!(scala.import_analysis_provider().is_none());

    assert!(java.type_hierarchy_provider().is_some());
    assert!(python.type_hierarchy_provider().is_some());
    assert!(go.type_hierarchy_provider().is_none());
    assert!(javascript.type_hierarchy_provider().is_none());
    assert!(typescript.type_hierarchy_provider().is_none());
    assert!(rust.type_hierarchy_provider().is_none());
    assert!(cpp.type_hierarchy_provider().is_none());
    assert!(csharp.type_hierarchy_provider().is_none());
    assert!(php.type_hierarchy_provider().is_none());
    assert!(scala.type_hierarchy_provider().is_none());
}

#[test]
fn multi_analyzer_matches_brokk_capability_matrix() {
    let project = fixture_project();
    let multi = MultiAnalyzer::new(BTreeMap::from([
        (
            Language::Java,
            AnalyzerDelegate::Java(JavaAnalyzer::from_project(project.clone())),
        ),
        (
            Language::Python,
            AnalyzerDelegate::Python(PythonAnalyzer::from_project(project.clone())),
        ),
        (
            Language::Go,
            AnalyzerDelegate::Go(GoAnalyzer::from_project(project.clone())),
        ),
        (
            Language::JavaScript,
            AnalyzerDelegate::JavaScript(JavascriptAnalyzer::from_project(project.clone())),
        ),
        (
            Language::TypeScript,
            AnalyzerDelegate::TypeScript(TypescriptAnalyzer::from_project(project.clone())),
        ),
        (
            Language::Rust,
            AnalyzerDelegate::Rust(RustAnalyzer::from_project(project.clone())),
        ),
        (
            Language::Cpp,
            AnalyzerDelegate::Cpp(CppAnalyzer::from_project(project.clone())),
        ),
        (
            Language::CSharp,
            AnalyzerDelegate::CSharp(CSharpAnalyzer::from_project(project.clone())),
        ),
        (
            Language::Php,
            AnalyzerDelegate::Php(PhpAnalyzer::from_project(project.clone())),
        ),
        (
            Language::Scala,
            AnalyzerDelegate::Scala(ScalaAnalyzer::from_project(project)),
        ),
    ]));

    assert!(multi.import_analysis_provider().is_some());
    assert!(multi.type_hierarchy_provider().is_some());
}
