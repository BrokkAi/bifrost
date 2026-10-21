#[cfg(test)]
mod php_extraction_tests {
    use brokk_bifrost_analysis::analyzer::QueryScope;
    use brokk_bifrost_analysis::analyzer::usages::call_relations::test_support::{
        call_span, generous_limits,
    };

    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationService;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::ExactCallLocation;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::canonical_external_callee;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
    #[brokk_bifrost_test_macros::hardwon(
        "#3017: PHP integration ensures external identity derives from resolver output rather than the textual receiver expression"
    )]
    #[test]
    fn php_external_identity_comes_from_the_resolver_not_expression_text() {
        let source = r#"<?php
namespace App;

function caller(string $input): string {
    return PHP_EOL . substr(...[$input, 0, 1]);
}
"#;
        let call = "substr(...[$input, 0, 1])";
        let fixture = AnalyzerFixture::new_for_language(Language::Php, &[("App.php", source)]);
        let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "App.php"),
                call_span: call_span(source, call),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert!(lookup.targets.is_empty(), "{lookup:#?}");
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::External {
                callee_text: None,
                normalized_static_owner: None,
                external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
                    Language::Php,
                    brokk_bifrost_php_analysis::analyzer::php::PHP_GLOBAL_NAMESPACE,
                    "substr",
                )),
            }],
            "the resolver-owned global identity must replace expression text without minting a target: {lookup:#?}"
        );
        assert_eq!(
            canonical_external_callee(".PHP_EOL.substr", Language::Php, None, false),
            None,
            "a PHP expression spelling is never a bindable identity"
        );
    }
}
