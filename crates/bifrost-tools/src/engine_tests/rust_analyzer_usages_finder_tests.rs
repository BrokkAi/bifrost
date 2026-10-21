#[cfg(test)]
mod rust_departing_tests_tests {
    use brokk_bifrost_analysis::CodeUnitIndex;

    use brokk_bifrost_analysis::analyzer::usages::finder::DEFAULT_MAX_USAGES;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::usages::finder::UsageFinder;

    use brokk_bifrost_analysis::analyzer::usages::finder::UsageQueryCompletion;

    use brokk_bifrost_analysis::analyzer::usages::finder::test_support::default_route_candidates;

    use brokk_bifrost_analysis::analyzer::usages::finder::test_support::write_fixture;

    use brokk_bifrost_core::analyzer::model::ProjectFile;
    #[test]
    fn a_protected_augmentation_survives_the_file_count_budget() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonicalize temp dir");
        write_fixture(
            &root,
            &[
                (
                    "Cargo.toml",
                    "[package]\nname = \"pinned\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
                ),
                (
                    "src/lib.rs",
                    "pub mod aapp;\npub mod reexport;\npub mod target;\n",
                ),
                ("src/target.rs", "pub fn collect_it() -> i32 {\n    1\n}\n"),
                ("src/reexport.rs", "pub use crate::target::collect_it;\n"),
                ("src/aapp/mod.rs", "pub mod caller;\n"),
                (
                    "src/aapp/caller.rs",
                    "use crate::reexport::collect_it;\n\npub fn call_it() -> i32 {\n    collect_it()\n}\n",
                ),
            ],
        );

        let analyzer = brokk_bifrost_rust_analysis::RustAnalyzer::from_project(
            brokk_bifrost_core::analyzer::project::TestProject::new(root.clone(), Language::Rust),
        );
        let target = analyzer
            .declarations(&ProjectFile::new(root.clone(), "src/target.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "collect_it")
            .expect("fixture declares collect_it");

        let routed = default_route_candidates(&analyzer, &target);
        let caller = ProjectFile::new(root, "src/aapp/caller.rs");
        assert!(
            !routed.contains(&caller),
            "the fixture must require Rust's binding graph: routed={routed:?}"
        );

        let result = UsageFinder::new().query(
            &analyzer,
            std::slice::from_ref(&target),
            routed.len(),
            DEFAULT_MAX_USAGES,
        );

        assert_eq!(
            result.completion,
            UsageQueryCompletion::CandidateFilesBudgetExhausted
        );
        assert_eq!(result.candidate_files.len(), routed.len());
        assert!(
            result.candidate_files.contains(&caller),
            "{caller:?} was dropped although it is protected: {:?}",
            result.candidate_files
        );
    }
}
