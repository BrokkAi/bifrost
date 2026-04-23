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

#[test]
fn normalize_full_name_handles_non_ascii_before_anonymous_marker() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let project = TestProject::new(root, Language::Java);
    let analyzer = JavaAnalyzer::from_project(project);

    assert_eq!(
        "org.elasticsearch.xpack.idp.saml.idp.SamlIdentityProviderBuilderTests.testCreateMetadataSigningCredentialFromΚeystoreWithSingleEntry$anon$479:78",
        analyzer.normalize_full_name(
            "org.elasticsearch.xpack.idp.saml.idp.SamlIdentityProviderBuilderTests.testCreateMetadataSigningCredentialFromΚeystoreWithSingleEntry$anon$479:78",
        )
    );
    assert_eq!(
        "pkg.Outer.Κeeper$anon$479:78",
        analyzer.normalize_full_name("pkg.Outer$Κeeper$anon$479:78")
    );
}
