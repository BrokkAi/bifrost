#[cfg(test)]
mod python_extraction_tests {

    use brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::multi_analyzer::AnalyzerDelegate;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

    use brokk_bifrost_analysis::analyzer::java::JavaAnalyzer;

    use brokk_bifrost_core::analyzer::config::JvmExternalDependencies;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_python_analysis::analyzer::PythonAnalyzer;

    use brokk_bifrost_core::analyzer::query_token::QueryScope;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
    use std::collections::{BTreeMap, BTreeSet};

    use brokk_bifrost_analysis::analyzer::jvm::external::python_test_support::ExternalJarFixture;

    #[test]
    fn java_dependency_discovery_routes_manifest_changes_through_multi_analyzer() {
        let Some(fixture) = ExternalJarFixture::new(false) else {
            return;
        };
        let app = ProjectFile::new(fixture.project_root().to_path_buf(), "src/App.java");
        app.write(
            "package app; import com.example.dep.ExternalService; class App { ExternalService service; }",
        )
        .unwrap();
        ProjectFile::new(fixture.project_root().to_path_buf(), "tool.py")
            .write("def tool():\n    pass\n")
            .unwrap();
        let pom = ProjectFile::new(fixture.project_root().to_path_buf(), "pom.xml");
        pom.write("<project/>").unwrap();
        let project = TestProject::with_languages(
            fixture.project_root().to_path_buf(),
            BTreeSet::from([Language::Java, Language::Python]),
        );
        let config = AnalyzerConfig {
            jvm: JvmAnalyzerConfig {
                external_dependencies: JvmExternalDependencies {
                    repository_roots: vec![fixture.maven_repository_root()],
                    ..JvmExternalDependencies::default()
                },
                ..JvmAnalyzerConfig::default()
            },
            ..AnalyzerConfig::default()
        };
        let multi = MultiAnalyzer::new(BTreeMap::from([
            (
                Language::Java,
                AnalyzerDelegate::new(JavaAnalyzer::from_project_with_config(
                    project.clone(),
                    config,
                )),
            ),
            (
                Language::Python,
                AnalyzerDelegate::new(PythonAnalyzer::from_project(project)),
            ),
        ]));
        let java = resolve_analyzer::<JavaAnalyzer>(&multi).unwrap();
        let scope = AnalyzerQueryScope::new(&multi);
        let token = scope.token();
        assert!(!java.is_known_type_name_in_file(token, None, &app, "ExternalService"));

        pom.write("<project><dependencies><dependency><groupId>com.example</groupId><artifactId>external-lib</artifactId><version>1.2.3</version></dependency></dependencies></project>")
            .unwrap();
        let updated = multi.update(&BTreeSet::from([pom]));
        let java = resolve_analyzer::<JavaAnalyzer>(&updated).unwrap();
        assert!(java.is_known_type_name_in_file(token, None, &app, "ExternalService"));
    }
}
