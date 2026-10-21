#[cfg(test)]
mod rust_departing_tests_tests {

    use brokk_bifrost_analysis::analyzer::index_warmer::IndexWarmer;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
    use brokk_bifrost_test_macros::hardwon;

    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    #[test]
    #[hardwon(
        "c5c11b710c78: a background warm panic left the index warmer permanently unavailable"
    )]
    fn background_warm_panic_resets_for_the_next_schedule() {
        let project = InlineTestProject::new()
            .file(
                "src/lib.rs",
                "pub trait Runnable {}\npub struct Worker;\nimpl Runnable for Worker {}\n",
            )
            .build();
        let snapshot = Arc::new(project.workspace_analyzer(AnalyzerConfig::default()));
        assert!(!snapshot.query_indexes_warm());

        let warmer = IndexWarmer::new();
        warmer.panic_before_next_warm.store(true, Ordering::Release);
        warmer.schedule(Arc::clone(&snapshot));
        warmer.wait_until_idle();
        assert!(
            !snapshot.query_indexes_warm(),
            "a failed warm must not publish a completed lazy index"
        );

        warmer.schedule(Arc::clone(&snapshot));
        warmer.wait_until_idle();
        assert!(
            snapshot.query_indexes_warm(),
            "the next schedule must retry and publish the lazy index"
        );
    }
}
