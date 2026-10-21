#[cfg(test)]
mod ruby_extraction_tests {

    use brokk_bifrost_analysis::analyzer::usages::finder::AdmittedUsageQuery;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_analysis::analyzer::usages::finder::DEFAULT_MAX_USAGES;

    use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer;

    use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;

    use brokk_bifrost_core::hash::HashSet;

    use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::usages::model::UsageProofAuthority;

    use brokk_bifrost_analysis::analyzer::usages::finder::UsageQueryCompletion;

    use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

    use brokk_bifrost_analysis::analyzer::usages::finder::finalize_graph_usage_query;

    use brokk_bifrost_analysis::analyzer::usages::finder::graph_strategy_find_usages;

    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_ruby_analysis::RubyAnalyzer;

    struct CancellingRubyGraphStrategy {
        delegate: brokk_bifrost_ruby_analysis::analyzer::usages::ruby_graph::RubyUsageGraphStrategy,
        cancellation: CancellationToken,
    }
    impl GraphUsageAnalyzer for CancellingRubyGraphStrategy {
        fn find_graph_usages(
            &self,
            analyzer: &dyn IAnalyzer,
            overloads: &[CodeUnit],
            scan_scope: &UsageScanScope<'_>,
            max_usages: usize,
        ) -> GraphUsageOutcome {
            let outcome = self
                .delegate
                .find_graph_usages(analyzer, overloads, scan_scope, max_usages);
            self.cancellation.cancel();
            outcome
        }
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "5258690d40b2: graph cancellation discarded proven hits already found in the admitted scope"
    )]
    fn graph_cancellation_preserves_proven_hits_and_the_admitted_scope() {
        let fixture = InlineTestProject::with_language(Language::Ruby)
            .file(
                "Gemfile",
                "source \"https://rubygems.org\"\ngem \"rails\"\n",
            )
            .file(
                "app/models/user.rb",
                "class User\n  def self.build\n    new\n  end\nend\n",
            )
            .file(
                "app/controllers/caller_controller.rb",
                "class CallerController\n  def show\n    User.build\n  end\nend\n",
            )
            .build();
        let analyzer = RubyAnalyzer::from_project(fixture.project().clone());
        let target_file = fixture.file("app/models/user.rb");
        let target = analyzer
            .declarations(&target_file)
            .into_iter()
            .find(|unit| unit.identifier() == "build")
            .expect("fixture declares User.build");
        let candidate_files = HashSet::from_iter(analyzer.analyzed_files());
        let strategy =
            brokk_bifrost_ruby_analysis::analyzer::usages::ruby_graph::RubyUsageGraphStrategy::new(
            );
        let complete_cancellation = CancellationToken::new();

        let complete_outcome = graph_strategy_find_usages(
            &strategy,
            &analyzer,
            std::slice::from_ref(&target),
            &UsageScanScope::with_cancellation(&candidate_files, &complete_cancellation),
            None,
            DEFAULT_MAX_USAGES,
        );
        let complete_hits = match &complete_outcome {
            GraphUsageOutcome::Resolved(result) => result.all_hits_including_imports(),
            other => panic!("uncancelled production resolver failed: {other:?}"),
        };
        assert!(
            !complete_hits.is_empty(),
            "fixture must prove User.build usage"
        );
        assert!(complete_hits.iter().all(
            |hit| hit.proof == brokk_bifrost_core::analyzer::usages::model::UsageProof::Proven
        ));
        let complete = finalize_graph_usage_query(
            complete_outcome,
            &complete_cancellation,
            AdmittedUsageQuery {
                candidate_files: candidate_files.clone(),
                candidate_files_truncated: false,
                candidate_files_budget_exhausted: false,
                source_bytes_truncated: false,
                scanned_source_bytes: 0,
                candidate_files_sample: None,
            },
            Some(&strategy),
        );
        assert_eq!(complete.completion, UsageQueryCompletion::Complete);
        assert_eq!(complete.proof_authority, UsageProofAuthority::Legacy);

        let cancellation = CancellationToken::new();
        let cancelling_strategy = CancellingRubyGraphStrategy {
            delegate: strategy,
            cancellation: cancellation.clone(),
        };
        let outcome = graph_strategy_find_usages(
            &cancelling_strategy,
            &analyzer,
            std::slice::from_ref(&target),
            &UsageScanScope::with_cancellation(&candidate_files, &cancellation),
            None,
            DEFAULT_MAX_USAGES,
        );
        let result = finalize_graph_usage_query(
            outcome,
            &cancellation,
            AdmittedUsageQuery {
                candidate_files: candidate_files.clone(),
                candidate_files_truncated: false,
                candidate_files_budget_exhausted: false,
                source_bytes_truncated: false,
                scanned_source_bytes: 0,
                candidate_files_sample: None,
            },
            Some(&cancelling_strategy),
        );

        assert_eq!(result.completion, UsageQueryCompletion::Cancelled);
        assert_eq!(result.candidate_files, candidate_files);
        assert_eq!(result.result.all_hits_including_imports(), complete_hits);
        assert_eq!(result.proof_authority, UsageProofAuthority::Legacy);
    }
}
