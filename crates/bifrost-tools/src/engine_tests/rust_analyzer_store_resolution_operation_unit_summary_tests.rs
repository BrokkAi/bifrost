#[cfg(test)]
mod rust_departing_root_tests {

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
    /// The comparison point for the writer hold: build a Rust workspace and let the
    /// existing crate reconcile run. Run it with `BIFROST_TIMING=1 --no-capture` and
    /// read the `rust_crates.reconcile.*` scopes. `BIFROST_UNIT_SUMMARY_RUST_CORPUS`
    /// names a Rust repository copy.
    #[test]
    #[ignore = "operator measurement: needs BIFROST_UNIT_SUMMARY_RUST_CORPUS, a Rust repository"]
    fn measure_rust_crate_reconcile_on_a_corpus() {
        let root = std::path::PathBuf::from(
            std::env::var("BIFROST_UNIT_SUMMARY_RUST_CORPUS")
                .expect("BIFROST_UNIT_SUMMARY_RUST_CORPUS names a Rust repository"),
        )
        .canonicalize()
        .unwrap();
        let project: std::sync::Arc<dyn brokk_bifrost_core::analyzer::project::Project> =
            std::sync::Arc::new(brokk_bifrost_core::analyzer::project::TestProject::new(
                root,
                Language::Rust,
            ));
        let started = std::time::Instant::now();
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("build the Rust corpus workspace");
        eprintln!("MEASURE rust build {:?}", started.elapsed());
        let conn = workspace.store().unwrap().read_conn().unwrap();
        for table in [
            "rust_crate_topologies",
            "rust_crate_versions",
            "rust_crate_exports",
            "rust_crate_imports",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            eprintln!("MEASURE rust {table} {count}");
        }
    }
}
