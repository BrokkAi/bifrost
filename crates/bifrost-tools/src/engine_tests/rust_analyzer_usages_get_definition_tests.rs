#[cfg(test)]
mod rust_departing_tests_tests {
    use brokk_bifrost_analysis::analyzer::QueryScope;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use std::sync::Arc;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionBatchContext;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupDiagnostic;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::navigation::NavigationOperation;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::navigation_lookup_outcome;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::resolve_definition_batch_with_source_and_cancellation;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::resolve_definition_requests;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;
    #[test]
    fn navigation_keeps_incomplete_candidates_without_singleton_proof() {
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", "")]);
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let scope = AnalyzerQueryScope::new(analyzer);
        let mut context = DefinitionBatchContext::new(analyzer, scope.token());
        let candidate = CodeUnit::file_scope(file.clone());
        let outcome = DefinitionLookupOutcome {
            modeled_definitions: Vec::new(),
            status: DefinitionLookupStatus::Incomplete,
            reference: None,
            definitions: vec![candidate],
            lexical_definition: None,
            diagnostics: vec![DefinitionLookupDiagnostic {
                claim: None,
                kind: "analysis_incomplete".to_string(),
                message: "candidate set is partial".to_string(),
            }],
        };

        let navigation = navigation_lookup_outcome(
            analyzer,
            scope.token(),
            &mut context,
            &file,
            outcome.into(),
            Language::Rust,
            NavigationOperation::Definition,
        );

        assert_eq!(navigation.status, DefinitionLookupStatus::Incomplete);
        assert_eq!(navigation.targets.len(), 1);
        assert_ne!(navigation.status, DefinitionLookupStatus::Resolved);
    }

    #[test]
    #[hardwon(
        "d6fe0c806939: cancelled definition batches used to lose their terminal status or return partial targets"
    )]
    fn cancelled_definition_batch_returns_terminal_outcomes_without_targets() {
        let source = "fn target() {}\nfn caller() { target(); }\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", source)]);
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let requests = ["target", "caller"]
            .into_iter()
            .map(|name| {
                let start_byte = source.find(name).expect("request token");
                DefinitionLookupRequest {
                    file: file.clone(),
                    line: None,
                    column: None,
                    start_byte: Some(start_byte),
                    end_byte: Some(start_byte + name.len()),
                }
            })
            .collect();

        let outcomes = resolve_definition_batch_with_source_and_cancellation(
            fixture.analyzer.analyzer(),
            requests,
            file,
            Arc::from(source),
            &cancellation,
        );

        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|outcome| {
            outcome.status == DefinitionLookupStatus::Cancelled
                && outcome.status.as_str() == "cancelled"
                && outcome.definitions.is_empty()
                && outcome.lexical_definition.is_none()
        }));
    }

    #[test]
    #[hardwon("d6fe0c806939: cancelled navigation exposed a partial candidate prefix")]
    fn navigation_with_cancelled_status_discards_partial_candidates() {
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("lib.rs", "")]);
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), "lib.rs");
        let scope = AnalyzerQueryScope::new(analyzer);
        let mut context = DefinitionBatchContext::new(analyzer, scope.token());
        let outcome = DefinitionLookupOutcome {
            modeled_definitions: Vec::new(),
            status: DefinitionLookupStatus::Cancelled,
            reference: None,
            definitions: vec![CodeUnit::file_scope(file.clone())],
            lexical_definition: None,
            diagnostics: vec![DefinitionLookupDiagnostic {
                claim: None,
                kind: "cancelled".to_string(),
                message: "resolution was cancelled".to_string(),
            }],
        };

        let navigation = navigation_lookup_outcome(
            analyzer,
            scope.token(),
            &mut context,
            &file,
            outcome.into(),
            Language::Rust,
            NavigationOperation::Definition,
        );

        assert_eq!(navigation.status, DefinitionLookupStatus::Cancelled);
        assert!(navigation.targets.is_empty());
    }

    #[test]
    #[ignore = "finds real bug: a two-step Rust member chain answers with the right definition but reports Incomplete. `outer.inner` resolves to `Outer.inner` and `outer.inner.value` returns `Inner.value`, yet the terminal keeps one UnsupportedSemantic reason that the same read one step shorter (`inner.value` on a parameter) does not, and a two-step chain whose terminal field has a named type exceeds the summary-expansion budget instead. Owned by lane B R2.B Rust reference lowering"]
    fn rust_batch_context_reuses_supplied_syntax_for_repeated_field_lookups() {
        let source = "struct Inner { value: i32 }\nstruct Outer { inner: Inner }\nfn first(outer: Outer) -> i32 { outer.inner.value }\nfn second(outer: Outer) -> i32 { outer.inner.value }\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("src/lib.rs", source)]);
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let analyzer = fixture.analyzer.analyzer();
        let scope = AnalyzerQueryScope::new(analyzer);
        let mut context = DefinitionBatchContext::new(analyzer, scope.token());
        let requests = source
            .match_indices("value")
            .skip(1)
            .map(|(start_byte, reference)| DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(start_byte),
                end_byte: Some(start_byte + reference.len()),
            })
            .collect();

        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let outcomes =
            resolve_definition_requests(analyzer, token, &mut context, requests, None, None);

        assert!(outcomes.iter().all(|outcome| {
            outcome.status == DefinitionLookupStatus::Resolved
                && outcome
                    .definitions
                    .iter()
                    .any(|unit| unit.fq_name() == "Inner.value")
        }));
    }
}
