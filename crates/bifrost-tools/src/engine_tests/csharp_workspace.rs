#[cfg(test)]
mod csharp_extraction_tests {
    use brokk_bifrost_analysis::analyzer::{
        AnalyzerConfig, Language, OverlayProject, Project, WorkspaceAnalyzer,
    };
    use brokk_bifrost_analysis::inline_project::InlineTestProject;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    #[test]
    fn index_warm_clone_freezes_source_and_publishes_every_generation_warm_cell() {
        let fixture = InlineTestProject::new()
            .file(
                "src/lib.rs",
                "pub trait Runnable {}\npub struct Worker;\nimpl Runnable for Worker {}\n",
            )
            .file("src/JavaWorker.java", "class JavaWorker {}\n")
            .file("src/KotlinWorker.kt", "class KotlinWorker\n")
            .file("src/ScalaWorker.scala", "class ScalaWorker\n")
            .file("src/CSharpWorker.cs", "class CSharpWorker {}\n")
            .build();
        assert_eq!(
            fixture.languages(),
            BTreeSet::from([
                Language::CSharp,
                Language::Java,
                Language::Kotlin,
                Language::Rust,
                Language::Scala,
            ])
        );

        let rust_file = fixture.file("src/lib.rs");
        let scheduled_source =
            "pub trait Scheduled {}\npub struct Worker;\nimpl Scheduled for Worker {}\n";
        let live_project = Arc::new(OverlayProject::new(fixture.project_dyn()));
        assert!(live_project.set(rust_file.abs_path(), scheduled_source.to_owned()));
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::clone(&live_project) as Arc<dyn Project>,
            AnalyzerConfig::default(),
        )
        .expect("mixed ephemeral workspace should build");
        assert!(!workspace.query_indexes_warm());

        let frozen_project: Arc<dyn Project> = Arc::new(live_project.snapshot());
        let warm_snapshot = workspace.clone_for_index_warm(frozen_project);
        assert!(!warm_snapshot.query_indexes_warm());
        warm_snapshot.warm_query_indexes();
        assert!(warm_snapshot.query_indexes_warm());
        assert!(
            workspace.query_indexes_warm(),
            "warming the frozen clone must publish into every live generation-owned cell"
        );

        assert!(live_project.set(
            rust_file.abs_path(),
            "pub trait Later {}\npub struct Worker;\nimpl Later for Worker {}\n".to_owned(),
        ));
        assert_eq!(
            warm_snapshot
                .analyzer()
                .project()
                .read_source(&rust_file)
                .unwrap(),
            scheduled_source
        );
        let WorkspaceAnalyzer::Multi(multi) = &warm_snapshot else {
            panic!("five-language workspace must have delegates");
        };
        assert_eq!(
            multi
                .build_context()
                .expect("workspace build context")
                .project()
                .read_source(&rust_file)
                .unwrap(),
            scheduled_source,
            "future delegate construction must retain the frozen source view"
        );
    }
}
