#[cfg(test)]
mod jvm_registry_tests {

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::workspace::DependencyPackEcosystem;

    use brokk_bifrost_core::analyzer::model::Language;

    use std::path::PathBuf;

    use brokk_bifrost_analysis::analyzer::packs_document::WorkspaceActivationSources;

    use brokk_bifrost_analysis::analyzer::packs_document::activate_workspace_semantic_sources;

    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("ab2e2f61ff4d: source-bound JVM models suppressed discovery of configured host JDKs")]
    fn activation_keeps_host_discovery_and_workspace_source_toolchains() {
        let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("src/Main.java", "class Main {}")
            .file(".bifrost/jvm-toolchains.json", r#"{"schema_version":1,"source_toolchains":[{"source_root":"src","jdk_home":"bound-jdk"}]}"#)
            .file("bound-jdk/release", "JAVA_VERSION=\"21.0.2\"\n")
            .file("activation-jdk/release", "JAVA_VERSION=\"22.0.2\"\n")
            .build();
        let mut config = AnalyzerConfig::default();
        config.jvm.standard_library_discovery.discover_java_home = false;
        let workspace = project.workspace_analyzer(config.clone());
        config
            .jvm
            .standard_library_discovery
            .jdk_homes
            .push(PathBuf::from("activation-jdk"));
        let activation = activate_workspace_semantic_sources(
            &workspace,
            &config,
            WorkspaceActivationSources {
                catalog_root: project.root(),
                workspace_model_root: None,
                config: None,
                intrinsic_shipped_models: false,
            },
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        )
        .unwrap()
        .expect("Java activation");
        let jvm = activation
            .outcome
            .ecosystems
            .iter()
            .find(|outcome| outcome.ecosystem == DependencyPackEcosystem::Jvm)
            .expect("JVM discovery");
        let mut ids = jvm
            .discovery
            .dependencies
            .iter()
            .map(|dependency| dependency.id.as_str())
            .collect::<Vec<_>>();
        ids.sort_unstable();
        assert_eq!(ids, ["jdk:21.0.2", "jdk:22.0.2"], "{jvm:#?}");
    }
}
