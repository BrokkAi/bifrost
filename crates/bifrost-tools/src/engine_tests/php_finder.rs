#[cfg(test)]
mod php_extraction_tests {

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_analysis::analyzer::usages::finder::DEFAULT_MAX_FILES;

    use brokk_bifrost_analysis::analyzer::usages::finder::DEFAULT_MAX_USAGES;

    use brokk_bifrost_core::hash::HashSet;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::usages::finder::UsageFinder;

    use brokk_bifrost_analysis::analyzer::usages::finder::UsageQueryCompletion;

    use brokk_bifrost_analysis::analyzer::usages::finder::test_support::augmentation_of;

    use brokk_bifrost_analysis::analyzer::usages::finder::test_support::default_route_candidates;

    use brokk_bifrost_analysis::analyzer::usages::finder::test_support::write_fixture;

    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
    fn php_composer_fixture() -> (
        tempfile::TempDir,
        brokk_bifrost_php_analysis::PhpAnalyzer,
        CodeUnit,
    ) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonicalize temp dir");
        let mut files = vec![
        (
            "composer.json".to_string(),
            r#"{"autoload":{"psr-4":{"App\\":"src/"}}}"#.to_string(),
        ),
        (
            "src/Domain/Service.php".to_string(),
            "<?php\nnamespace App\\Domain;\n\nclass Service {\n    public function run(): void {}\n}\n".to_string(),
        ),
        (
            "src/Http/Controller.php".to_string(),
            "<?php\nnamespace App\\Http;\n\nuse App\\Domain\\Service;\n\nclass Controller {\n    public function handle(Service $service): void {\n        $service->run();\n    }\n}\n".to_string(),
        ),
    ];
        for index in 0..6 {
            files.push((
            format!("src/Unrelated/Widget{index}.php"),
            format!(
                "<?php\nnamespace App\\Unrelated;\n\nclass Widget{index} {{\n    public function tick(): void {{}}\n}}\n"
            ),
        ));
        }
        let borrowed: Vec<(&str, &str)> = files
            .iter()
            .map(|(rel, content)| (rel.as_str(), content.as_str()))
            .collect();
        write_fixture(&root, &borrowed);

        let analyzer = brokk_bifrost_php_analysis::PhpAnalyzer::from_project(
            brokk_bifrost_core::analyzer::project::TestProject::new(root.clone(), Language::Php),
        );
        let target = analyzer
            .declarations(&ProjectFile::new(root, "src/Domain/Service.php"))
            .into_iter()
            .find(|unit| unit.is_class())
            .expect("fixture declares the Service class");
        (temp, analyzer, target)
    }

    #[test]
    fn b_a_supplemental_augmentation_is_dropped_first_by_the_file_count_budget() {
        let (_temp, analyzer, target) = php_composer_fixture();

        let routed = default_route_candidates(&analyzer, &target);
        let augmentation = augmentation_of(&analyzer, &target);
        assert!(augmentation.protected.is_empty());
        let supplemental_only: HashSet<ProjectFile> = augmentation
            .supplemental
            .difference(&routed)
            .cloned()
            .collect();
        assert!(
            supplemental_only
                .iter()
                .any(|file| file.rel_path().starts_with("src/Unrelated")),
            "composer autoload visibility must expand to the unrelated files: {:?}",
            augmentation.supplemental
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
        assert_eq!(
            result.candidate_files, routed,
            "the budget must keep exactly the protected set"
        );
        for file in &supplemental_only {
            assert!(!result.candidate_files.contains(file), "{file:?} survived");
        }
    }

    #[test]
    fn c_cancellation_during_a_supplemental_augmentation_abandons_the_query() {
        let (_temp, analyzer, target) = php_composer_fixture();

        let complete = UsageFinder::new().query(
            &analyzer,
            std::slice::from_ref(&target),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_USAGES,
        );
        assert_eq!(complete.completion, UsageQueryCompletion::Complete);
        assert!(!complete.candidate_files.is_empty());

        let mut cancelled = 0usize;
        for checks in 1..=400 {
            let result = UsageFinder::new()
                .with_cancellation(CancellationToken::cancel_after_checks_for_test(checks))
                .query(
                    &analyzer,
                    std::slice::from_ref(&target),
                    DEFAULT_MAX_FILES,
                    DEFAULT_MAX_USAGES,
                );
            if result.completion != UsageQueryCompletion::Cancelled {
                continue;
            }
            if result.candidate_files.is_empty() {
                cancelled += 1;
                assert!(!result.candidate_files_truncated);
                assert!(result.result.all_hits_including_imports().is_empty());
                continue;
            }
            assert_eq!(
                result.candidate_files, complete.candidate_files,
                "a cancelled query reported a half-expanded scope at checks={checks}"
            );
        }
        assert!(
            cancelled > 0,
            "the sweep must reach the discovery-time cancellation window"
        );
    }
}

#[test]
fn php_incomplete_descendants_skip_alias_augmentation() {
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::languages::{CandidateCtx, LanguageSupport};
    use brokk_bifrost_analysis::analyzer::{
        AnalyzerQueryScope, IAnalyzer, QueryReadIncomplete, capture_query_reads,
    };
    use brokk_bifrost_core::analyzer::capabilities::HierarchyOpenReason;
    use brokk_bifrost_core::analyzer::{CodeUnitIndex, Language};
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_php::graph_support::php_import_alias_candidates;
    use brokk_bifrost_php_analysis::PhpAnalyzer;
    let project = InlineTestProject::with_language(Language::Php)
        .file("Base.php", "<?php namespace Demo; class Base {}")
        .file(
            "Alias.php",
            "<?php namespace Client; use Demo\\Base as Alias;",
        )
        .build();
    let analyzer = PhpAnalyzer::new(project.project_dyn());
    let owner = analyzer
        .declarations(&project.file("Base.php"))
        .into_iter()
        .find(|unit| unit.identifier() == "Base")
        .unwrap();
    let (_, reads) = capture_query_reads(&analyzer, || {
        let _query = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
        analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
            "refused alias hierarchy".into(),
        ));
        let failure =
            php_import_alias_candidates(&owner, &analyzer, Some(&analyzer), &analyzer, &|| {
                panic!("incomplete hierarchy must skip alias files")
            })
            .unwrap_err();
        assert!(
            failure
                .open
                .iter()
                .any(|reason| matches!(reason, HierarchyOpenReason::DescendantIndexUnavailable)),
            "{failure:?}"
        );
        let token = CancellationToken::default();
        let augmentation = brokk_bifrost_php_analysis::analyzer::php::PhpSupport
            .candidate_augmentation(&CandidateCtx {
                analyzer: &analyzer,
                target: &owner,
                cancellation: &token,
            });
        assert!(
            augmentation
                .is_none_or(|value| value.supplemental.is_empty() && value.protected.is_empty())
        );
    });
    assert!(reads.unattributed_reads() > 0, "{reads:?}");
}
