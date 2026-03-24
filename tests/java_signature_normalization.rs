use brokk_analyzer::{IAnalyzer, JavaAnalyzer, Language, ProjectFile, TestProject};

#[test]
fn normalizes_callable_signatures_to_parameter_types() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    ProjectFile::new(root.clone(), "VarargsTest.java")
        .write(
            r#"
public class VarargsTest {
    public void noArgs() {}
    public void oneArg(String s) {}
    public void varargs(String... args) {}
    public void mixedVarargs(int x, String... args) {}
}
"#,
        )
        .unwrap();

    let project = TestProject::new(root, Language::Java);
    let analyzer = JavaAnalyzer::from_project(project);

    assert_eq!(
        Some("()"),
        analyzer
            .get_definitions("VarargsTest.noArgs")
            .first()
            .and_then(|code_unit| code_unit.signature())
    );
    assert_eq!(
        Some("(String)"),
        analyzer
            .get_definitions("VarargsTest.oneArg")
            .first()
            .and_then(|code_unit| code_unit.signature())
    );
    assert_eq!(
        Some("(String[])"),
        analyzer
            .get_definitions("VarargsTest.varargs")
            .first()
            .and_then(|code_unit| code_unit.signature())
    );
    assert_eq!(
        Some("(int, String[])"),
        analyzer
            .get_definitions("VarargsTest.mixedVarargs")
            .first()
            .and_then(|code_unit| code_unit.signature())
    );
}
