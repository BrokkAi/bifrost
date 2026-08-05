//! The analyzer-bound fixtures for [`brokk_bifrost_cpp::diagnostics`].
//!
//! The pass itself moved with the language knowledge; what it needs from this
//! side is a `CppAnalyzer` built over a real compile database, which the C++
//! crate cannot construct because it names no analyzer type.

use crate::analyzer::{CppAnalyzer, Language, ProjectFile, TestProject};
use brokk_bifrost_cpp::diagnostics::{CPP_UNRECOGNIZED_SYMBOL, collect_cpp_semantic_diagnostics};

fn analyzer_fixture(files: &[(&str, &str)]) -> (tempfile::TempDir, CppAnalyzer, ProjectFile) {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = temp.path().canonicalize().expect("canonical root");
    for (path, source) in files {
        ProjectFile::new(root.clone(), path)
            .write(source)
            .expect("fixture file");
    }
    let project = TestProject::new(root.clone(), Language::Cpp);
    let analyzer = CppAnalyzer::from_project(project);
    let file = ProjectFile::new(root, "src/main.cpp");
    (temp, analyzer, file)
}

#[test]
fn no_compile_context_means_no_semantic_diagnostics() {
    let (_temp, analyzer, file) = analyzer_fixture(&[("src/main.cpp", "MissingType value;")]);
    assert!(collect_cpp_semantic_diagnostics(&analyzer, &file, "MissingType value;").is_empty());
}

#[test]
fn matching_context_reports_a_clear_unknown_type() {
    let (_temp, analyzer, file) = analyzer_fixture(&[
        ("src/main.cpp", "MissingType value;"),
        (
            "compile_commands.json",
            r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-c","src/main.cpp"]}]"#,
        ),
    ]);
    let diagnostics = collect_cpp_semantic_diagnostics(&analyzer, &file, "MissingType value;");
    assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
    assert_eq!(CPP_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
}

#[test]
fn included_project_type_is_not_diagnosed() {
    let (_temp, analyzer, file) = analyzer_fixture(&[
        ("include/project_type.hpp", "struct ProjectType {};"),
        (
            "src/main.cpp",
            "#include \"project_type.hpp\"\nProjectType value;",
        ),
        (
            "compile_commands.json",
            r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-I","include","-c","src/main.cpp"]}]"#,
        ),
    ]);
    let source = "#include \"project_type.hpp\"\nProjectType value;";
    assert!(collect_cpp_semantic_diagnostics(&analyzer, &file, source).is_empty());
}

#[test]
fn preprocessing_and_templates_remain_silent() {
    let (_temp, analyzer, file) = analyzer_fixture(&[
        (
            "src/main.cpp",
            "FEATURE value;\ntemplate <typename T> T value_for();",
        ),
        (
            "compile_commands.json",
            r#"[{"directory":".","file":"src/main.cpp","arguments":["clang++","-D","FEATURE","-c","src/main.cpp"]}]"#,
        ),
    ]);
    let source = "FEATURE value;\ntemplate <typename T> T value_for();";
    assert!(collect_cpp_semantic_diagnostics(&analyzer, &file, source).is_empty());
}
