use brokk_analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, TestProject};
use pretty_assertions::assert_eq;
use std::path::Path;

#[allow(dead_code)]
pub fn js_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-js").unwrap(),
        Language::JavaScript,
    )
}

#[allow(dead_code)]
pub fn ts_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-ts").unwrap(),
        Language::TypeScript,
    )
}

#[allow(dead_code)]
pub fn py_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-py").unwrap(),
        Language::Python,
    )
}

#[allow(dead_code)]
pub fn cpp_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-cpp").unwrap(),
        Language::Cpp,
    )
}

#[allow(dead_code)]
pub fn csharp_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-cs").unwrap(),
        Language::CSharp,
    )
}

#[allow(dead_code)]
pub fn php_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-php").unwrap(),
        Language::Php,
    )
}

#[allow(dead_code)]
pub fn go_fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-go").unwrap(),
        Language::Go,
    )
}

#[allow(dead_code)]
pub fn assert_code_eq(expected: &str, actual: &str) {
    assert_eq!(normalize_code(expected), normalize_code(actual));
}

#[allow(dead_code)]
pub fn assert_linewise_eq(expected: &str, actual: &str) {
    assert_eq!(
        normalize_nonempty_lines(expected),
        normalize_nonempty_lines(actual)
    );
}

#[allow(dead_code)]
pub fn normalize_code(value: &str) -> String {
    let normalized = value.replace("\r\n", "\n");
    let lines: Vec<_> = normalized.lines().collect();
    let start = lines
        .iter()
        .position(|line| !line.trim().is_empty())
        .unwrap_or(0);
    let end = lines
        .iter()
        .rposition(|line| !line.trim().is_empty())
        .map(|index| index + 1)
        .unwrap_or(start);
    let slice = &lines[start..end];
    let indent = slice
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.chars()
                .take_while(|ch| *ch == ' ' || *ch == '\t')
                .count()
        })
        .min()
        .unwrap_or(0);
    slice
        .iter()
        .map(|line| line.chars().skip(indent).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

#[allow(dead_code)]
pub fn normalize_nonempty_lines(value: &str) -> String {
    value
        .replace("\r\n", "\n")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

#[allow(dead_code)]
pub fn write_file(root: &Path, rel_path: &str, contents: &str) -> ProjectFile {
    let file = ProjectFile::new(root.to_path_buf(), rel_path);
    file.write(contents).unwrap();
    file
}

#[allow(dead_code)]
pub fn definition<A: IAnalyzer>(analyzer: &A, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}
