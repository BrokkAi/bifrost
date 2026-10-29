#[cfg(test)]
mod csharp_extraction_tests {
    use brokk_bifrost_analysis::analyzer::{
        AnalyzerConfig, Language, OverlayProject, Project, WorkspaceAnalyzer,
    };
    use brokk_bifrost_analysis::inline_project::InlineTestProject;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    #[brokk_bifrost_test_macros::hardwon(
        "#6729: C# membership-scoped scans queried through a cloned analyzer whose request caches reset on every nested scope"
    )]
    #[test]
    fn csharp_warm_usage_scan_reuses_request_reads_across_membership_scopes() {
        use crate::searchtools::{ScanUsagesByReferenceParams, scan_usages_by_reference};
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::{
            begin_production_selected_sql_trace, finish_production_selected_sql_trace,
        };
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::single_connection_store_context_for_test;

        let fixture = InlineTestProject::new()
            .file("Base.cs", "namespace Example; public class Base { public virtual int Run() { return 1; } }")
            .file("Service.cs", "namespace Example; public class Service : Base { public override int Run() { return 2; } }")
            .file("Consumer.cs", "namespace Example; public class Consumer { public Service Make(Service service) { service.Run(); return new Service(); } public int Call(Base value) { return value.Run(); } }")
            .build();
        let project = fixture.project_dyn();
        let context = single_connection_store_context_for_test(project.as_ref()).unwrap();
        let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
            project,
            AnalyzerConfig::default(),
            context,
        )
        .unwrap();
        let scan = || {
            scan_usages_by_reference(
                workspace.analyzer(),
                ScanUsagesByReferenceParams {
                    symbols: vec!["Example.Service".to_owned()],
                    include_tests: true,
                    paths: None,
                    include_same_owner: true,
                },
            )
        };
        let warm = scan();
        assert_eq!(warm.summary.found, 1, "{warm:#?}");
        assert!(warm.results[0].total_hits.unwrap() > 0, "{warm:#?}");
        let store = workspace.store().unwrap();
        begin_production_selected_sql_trace(store);
        let measured = scan();
        let cost = finish_production_selected_sql_trace(store);
        assert_eq!(
            serde_json::to_value(&warm).unwrap(),
            serde_json::to_value(&measured).unwrap()
        );
        eprintln!(
            "warm C# usage scan: {} statements, {} decoded rows",
            cost.statement_count(),
            cost.decoded_rows
        );
        // Bound request work rather than elapsed time. Nested per-file scopes
        // must retain the outer scan's definition and source read caches.
        // With the fix this scan runs 166 statements; when each per-file scope
        // queried through a cloned analyzer, every nested scope reset the
        // request caches and the scan ran 279. The fixture is small, so a rise
        // of about 35 statements is the whole regression; on Dapper the same
        // defect took a warm scan from 26,849 to 630,115 statements.
        assert!(cost.statement_count() < 200, "{cost:#?}");
    }
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
