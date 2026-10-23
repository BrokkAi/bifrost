#[cfg(test)]
mod jvm_extraction_tests {

    use crate::engine_tests::store_jvm_package_context::tests::POM;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId;

    use crate::engine_tests::store_jvm_package_context::tests::members;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::ephemeral_store_context;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

    use std::collections::BTreeSet;
    use std::sync::Arc;

    #[test]
    fn java_analyzer_build_and_updates_publish_selected_contexts() {
        let fixture = InlineTestProject::with_language(Language::Java)
            .file("pom.xml", POM)
            .file("src/main/java/App.java", "class App {}")
            .build();
        let project = fixture.project_dyn();
        let context = ephemeral_store_context(project.as_ref()).unwrap();
        let store = Arc::clone(&context.store);
        let first = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavaAdapter,
            AnalyzerConfig::default(),
            context,
            None,
        )
        .unwrap();
        let initial = first.selected_workspace_snapshots()["java"].clone();
        let context_for = |snapshot: &WorkspaceSnapshotId| {
            let snapshot = snapshot.clone();
            store.conn.execute(move |connection| connection.query_row(
                "SELECT context_id FROM jvm_context_revisions WHERE workspace_id=?1 AND lang='java' AND generation=?2 AND revision=?3",
                params![snapshot.workspace_id.as_str(),snapshot.generation.get(),snapshot.revision], |row| row.get::<_,i64>(0),
            )).unwrap()
        };
        let initial_context = context_for(&initial);
        assert_eq!(members(&store, initial_context).len(), 1);
        let source = fixture.file("src/main/java/App.java");
        source.write("class App { int changed; }").unwrap();
        let updated = first.update(&BTreeSet::from([source]));
        let changed = updated.selected_workspace_snapshots()["java"].clone();
        assert_ne!(context_for(&changed), initial_context);
        let pom = fixture.file("pom.xml");
        pom.write("<project><groupId>example</groupId><artifactId>renamed</artifactId><version>2</version></project>").unwrap();
        let configured = updated.update(&BTreeSet::from([pom]));
        let configuration = configured.selected_workspace_snapshots()["java"].clone();
        assert_ne!(context_for(&configuration), context_for(&changed));
        let rebuilt = configured.update_all();
        assert_eq!(
            context_for(&rebuilt.selected_workspace_snapshots()["java"]),
            context_for(&configuration)
        );
    }

    use rusqlite::params;
}
