#[cfg(test)]
mod js_ts_extraction_tests {
    use brokk_bifrost_analysis::analyzer::semantic::DispatchOracle;
    use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapability;
    use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
    use brokk_bifrost_analysis::analyzer::semantic::ir::artifact::CallSiteHandle;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::DispatchResult;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::DispatchBoundaryKind;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::CandidateCoverage;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticWork;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::source::SourceDispatchObservation;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::source::SourceDispatchResult;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::source::SourceOutcomeQuality;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::source::procedure_dispatch_answer_digest;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::source::procedure_dispatch_boundary_digest;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::source::procedure_dispatch_candidate_digest;
    use brokk_bifrost_core::analyzer::model::Range;
    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::exact_call_range;

    use brokk_bifrost_analysis::analyzer::semantic::ir::EvidenceCompleteness;

    use brokk_bifrost_analysis::analyzer::semantic::ir::ProofStatus;

    use brokk_bifrost_analysis::analyzer::semantic::SemanticBudget;

    use brokk_bifrost_analysis::analyzer::semantic::SemanticBudgetDimension;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_test_macros::hardwon;
    const CALL_SOURCE: &str = "function target() {}\nexport function caller() { target(); }\n";
    const BATCH_CALL_SOURCE: &str = "import { open } from \"third-party\";\nexport function caller() { open(\"a\"); open(\"b\"); }\n";
    const DISTINCT_CALL_SOURCE: &str = "function first() {}\nfunction second() {}\nexport function caller() { first(); second(); }\n";
    /// The durable, arena-independent shape of one dispatch answer. Relation
    /// provenance handles are query-local (they compare by arena identity), so
    /// two runs of the same query are compared through the observable target,
    /// quality, boundary, and coverage vocabulary instead.
    #[derive(Debug, PartialEq, Eq)]
    struct DispatchShape {
        targets: Vec<(String, String, String)>,
        boundaries: Vec<String>,
        coverage: CandidateCoverage,
    }
    fn dispatch_shape(result: &DispatchResult) -> DispatchShape {
        DispatchShape {
            targets: result
                .candidates()
                .iter()
                .map(|candidate| {
                    (
                        format!("{:?}", candidate.target().semantics().locator()),
                        format!("{:?}", candidate.proof()),
                        format!("{:?}", candidate.completeness()),
                    )
                })
                .collect(),
            boundaries: result
                .boundaries()
                .iter()
                .map(|boundary| format!("{:?}", boundary.kind))
                .collect(),
            coverage: result.coverage(),
        }
    }
    fn outcome_label<T>(outcome: &SemanticOutcome<T>) -> &'static str {
        outcome.label()
    }
    fn typescript_fixture(files: &[(&str, &str)]) -> AnalyzerFixture {
        AnalyzerFixture::new_for_language(Language::TypeScript, files)
    }
    fn artifact_for(
        fixture: &AnalyzerFixture,
        file: &ProjectFile,
    ) -> Arc<brokk_bifrost_analysis::analyzer::semantic::SemanticArtifact> {
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        fixture
            .analyzer
            .materialize_program_semantics(
                file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("TypeScript semantic materialization")
            .available_value()
            .cloned()
            .expect("TypeScript semantic artifact")
    }
    /// The only call site in `CALL_SOURCE`, with the exact source range its
    /// semantic mapping anchors.
    fn only_call_site(
        artifact: &Arc<brokk_bifrost_analysis::analyzer::semantic::SemanticArtifact>,
    ) -> (CallSiteHandle, Range) {
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| !procedure.call_sites().is_empty())
            .expect("caller procedure");
        let call = &procedure.call_sites()[0];
        let handle = artifact
            .procedure_handle(procedure.id())
            .and_then(|procedure| procedure.call_site_handle(call.id))
            .expect("scoped call handle");
        let range = exact_call_range(&handle).expect("call source mapping");
        (handle, range)
    }
    fn all_call_sites(
        artifact: &Arc<brokk_bifrost_analysis::analyzer::semantic::SemanticArtifact>,
    ) -> Vec<(CallSiteHandle, Range)> {
        artifact
            .procedures()
            .iter()
            .flat_map(|procedure| {
                procedure.call_sites().iter().map(|call| {
                    let handle = artifact
                        .procedure_handle(procedure.id())
                        .and_then(|procedure| procedure.call_site_handle(call.id))
                        .expect("scoped call handle");
                    let range = exact_call_range(&handle).expect("call source mapping");
                    (handle, range)
                })
            })
            .collect()
    }
    fn complete_materialization(
        artifact: &Arc<brokk_bifrost_analysis::analyzer::semantic::SemanticArtifact>,
    ) -> SemanticOutcome<Arc<brokk_bifrost_analysis::analyzer::semantic::SemanticArtifact>> {
        complete_materialization_with_work(artifact, SemanticWork::default())
    }
    fn complete_materialization_with_work(
        artifact: &Arc<brokk_bifrost_analysis::analyzer::semantic::SemanticArtifact>,
        work: SemanticWork,
    ) -> SemanticOutcome<Arc<brokk_bifrost_analysis::analyzer::semantic::SemanticArtifact>> {
        SemanticOutcome::Complete {
            value: Arc::clone(artifact),
            work,
        }
    }
    #[test]
    fn prepared_source_dispatch_session_shares_one_parse_and_matches_serial_results() {
        let fixture = typescript_fixture(&[("batch.ts", BATCH_CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "batch.ts");
        let artifact = artifact_for(&fixture, &file);
        let calls = all_call_sites(&artifact);
        assert_eq!(calls.len(), 2, "the fixture has two external calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut session_budget = SemanticBudget::default();
        let mut session_request = SemanticRequest::new(&mut session_budget, &cancellation);
        let mut session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));

        let mut session_outcomes = Vec::new();
        for (call, range) in &calls {
            let outcome = session
                .resolve_at_source(*range, &mut session_request)
                .expect("prepared source dispatch");
            let result = outcome
                .available_value()
                .expect("external call retains a dispatch result");
            assert_eq!(result.observations().len(), 1);
            assert_eq!(result.observations()[0].call(), call);
            session_outcomes.push(outcome);
        }
        assert_eq!(
            session_outcomes[0].work().source_bytes,
            BATCH_CALL_SOURCE.len()
        );
        assert_eq!(session_outcomes[1].work().source_bytes, 0);
        assert_eq!(
            session_request.budget.used().source_bytes,
            2 * BATCH_CALL_SOURCE.len()
        );

        for ((_, range), session_outcome) in calls.iter().zip(&session_outcomes) {
            let mut serial_budget = SemanticBudget::default();
            let serial = oracle
                .dispatch_at_source_in_artifact(
                    complete_materialization(&artifact),
                    *range,
                    &mut SemanticRequest::new(&mut serial_budget, &cancellation),
                )
                .expect("serial source dispatch");
            assert_eq!(outcome_label(session_outcome), outcome_label(&serial));
            let session_result = session_outcome
                .available_value()
                .expect("session dispatch result");
            let serial_result = serial.available_value().expect("serial dispatch result");
            assert_eq!(session_result.coverage(), serial_result.coverage());
            assert_eq!(session_result.observations().len(), 1);
            assert_eq!(serial_result.observations().len(), 1);
            assert_eq!(
                dispatch_shape(session_result.observations()[0].dispatch()),
                dispatch_shape(serial_result.observations()[0].dispatch())
            );
        }

        let mut limits = SemanticBudget::default().limits();
        limits.source_bytes = BATCH_CALL_SOURCE.len();
        let mut capped_session_budget =
            SemanticBudget::new(limits).expect("positive source budget");
        let mut capped_session_request =
            SemanticRequest::new(&mut capped_session_budget, &cancellation);
        let mut capped_session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));
        for (_, range) in &calls {
            let outcome = capped_session
                .resolve_at_source(*range, &mut capped_session_request)
                .expect("prepared source dispatch");
            assert!(
                outcome.available_value().is_some(),
                "the shared parse keeps both calls inside one source budget: {outcome:?}"
            );
        }
        assert_eq!(
            capped_session_request.budget.used().source_bytes,
            2 * BATCH_CALL_SOURCE.len()
        );

        let mut serial_budget = SemanticBudget::new(limits).expect("positive source budget");
        let first = oracle
            .dispatch_at_source_in_artifact(
                complete_materialization(&artifact),
                calls[0].1,
                &mut SemanticRequest::new(&mut serial_budget, &cancellation),
            )
            .expect("first serial source dispatch");
        assert!(first.available_value().is_some(), "{first:?}");
        let second = oracle
            .dispatch_at_source_in_artifact(
                complete_materialization(&artifact),
                calls[1].1,
                &mut SemanticRequest::new(&mut serial_budget, &cancellation),
            )
            .expect("second serial source dispatch");
        assert!(
            second.available_value().is_some(),
            "released serial parses reuse the resident source grant: {second:?}"
        );
    }
    #[test]
    #[hardwon("#5113: dispatch result refusal rolled back scan telemetry")]
    fn prepared_source_dispatch_drops_a_parse_whose_source_charge_rolled_back() {
        let fixture = typescript_fixture(&[("batch.ts", BATCH_CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "batch.ts");
        let artifact = artifact_for(&fixture, &file);
        let calls = all_call_sites(&artifact);
        assert_eq!(calls.len(), 2, "the fixture has two external calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut first_budget = SemanticBudget::default();
        let nested_limit = first_budget.limits().nested_entries;
        // Leave one retained entry for selecting the call, so result admission fails after the
        // source was parsed. Traversal work cannot cause this refusal.
        first_budget
            .admit(SemanticWork {
                nested_entries: nested_limit - 1,
                ..SemanticWork::default()
            })
            .expect("occupy retained-entry grant");
        let mut session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));

        let first = session
            .resolve_at_source(
                calls[0].1,
                &mut SemanticRequest::new(&mut first_budget, &cancellation),
            )
            .expect("post-parse budget refusal remains a typed source outcome");
        let SemanticOutcome::ExceededBudget { exceeded, work, .. } = first else {
            panic!("the retained result must exceed the resident grant: {first:?}");
        };
        assert_eq!(exceeded.dimension(), SemanticBudgetDimension::NestedEntries);
        assert_eq!(work.source_bytes, BATCH_CALL_SOURCE.len());
        assert_eq!(
            first_budget.used().source_bytes,
            2 * BATCH_CALL_SOURCE.len()
        );
        assert_eq!(first_budget.resident().source_bytes, 0);
        assert_eq!(
            session.retained_bytes(),
            0,
            "a released source admission cannot leave reusable parsed syntax"
        );

        let first_scope = first_budget.scope_snapshot();
        let mut retry_budget =
            SemanticBudget::new_child(SemanticBudget::default().limits(), &first_scope);
        let second = session
            .resolve_at_source(
                calls[1].1,
                &mut SemanticRequest::new(&mut retry_budget, &cancellation),
            )
            .expect("a same-scope retry reparses after the unpaid syntax was dropped");
        assert!(second.available_value().is_some(), "{second:?}");
        assert_eq!(second.work().source_bytes, BATCH_CALL_SOURCE.len());
        assert_eq!(
            retry_budget.used().source_bytes,
            2 * BATCH_CALL_SOURCE.len()
        );
        assert_eq!(
            retry_budget.root_work_peak().source_bytes,
            BATCH_CALL_SOURCE.len()
        );
        assert_eq!(
            retry_budget.resident().source_bytes,
            BATCH_CALL_SOURCE.len()
        );
        assert!(session.retained_bytes() > 0);
    }
    #[test]
    fn source_dispatch_session_cancellation_does_not_reclassify_prior_calls() {
        let fixture = typescript_fixture(&[("batch.ts", BATCH_CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "batch.ts");
        let artifact = artifact_for(&fixture, &file);
        let calls = all_call_sites(&artifact);
        assert_eq!(calls.len(), 2, "the fixture has two external calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let mut session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));

        let first = session
            .resolve_at_source(calls[0].1, &mut request)
            .expect("first requested dispatch");
        assert!(!matches!(first, SemanticOutcome::Cancelled { .. }));
        assert_eq!(first.work().source_bytes, BATCH_CALL_SOURCE.len());

        cancellation.cancel();
        let second = session
            .resolve_at_source(calls[1].1, &mut request)
            .expect("second requested dispatch");
        let SemanticOutcome::Cancelled { work, .. } = second else {
            panic!("only the call requested after cancellation is cancelled: {second:?}");
        };
        assert_eq!(work.source_bytes, 0);
        assert_eq!(work.call_sites, 0);
        assert_eq!(work.nested_entries, 0);
    }
    #[test]
    #[hardwon(
        "bc14f106eeaa: repeated source dispatch reparsed the same caller and duplicated materialization work"
    )]
    fn prepared_source_dispatch_session_reports_materialization_work_once() {
        let fixture = typescript_fixture(&[("batch.ts", BATCH_CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "batch.ts");
        let artifact = artifact_for(&fixture, &file);
        let calls = all_call_sites(&artifact);
        assert_eq!(calls.len(), 2, "the fixture has two external calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut baseline_budget = SemanticBudget::default();
        let mut baseline_request = SemanticRequest::new(&mut baseline_budget, &cancellation);
        let mut baseline_session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));
        let baseline_first = baseline_session
            .resolve_at_source(calls[0].1, &mut baseline_request)
            .expect("baseline first source dispatch");
        let baseline_second = baseline_session
            .resolve_at_source(calls[1].1, &mut baseline_request)
            .expect("baseline second source dispatch");

        let materialization_work = SemanticWork {
            owned_text_bytes: 37,
            ..SemanticWork::default()
        };
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let mut session = oracle.prepare_source_dispatch_session_in_artifact(
            complete_materialization_with_work(&artifact, materialization_work),
        );

        let first = session
            .resolve_at_source(calls[0].1, &mut request)
            .expect("first source dispatch");
        let second = session
            .resolve_at_source(calls[1].1, &mut request)
            .expect("second source dispatch");

        assert_eq!(
            first.work(),
            baseline_first.work().conservative_add(materialization_work)
        );
        assert_eq!(second.work(), baseline_second.work());
    }
    /// Every call-site projection walked and charged every procedure of its
    /// file, so a file of N functions cost N procedures per range. A range now
    /// charges only the procedures whose call-site mappings can contain it.
    #[test]
    #[hardwon("6287e19f0597: a source range charged every procedure of its file")]
    fn source_projection_charges_only_the_procedures_that_contain_the_range() {
        let mut source = String::from("import { open } from \"third-party\";\n");
        for index in 0..32 {
            source.push_str(&format!(
                "export function f{index}() {{ open(\"{index}\"); }}\n"
            ));
        }
        let fixture = typescript_fixture(&[("many.ts", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "many.ts");
        let artifact = artifact_for(&fixture, &file);
        assert!(
            artifact.procedures().len() >= 32,
            "the fixture must have one procedure per function"
        );
        let calls = all_call_sites(&artifact);
        assert_eq!(
            calls.len(),
            32,
            "the fixture has one external call per function"
        );
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let mut session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));
        for (call, range) in &calls {
            let outcome = session
                .resolve_at_source(*range, &mut request)
                .expect("prepared source dispatch");
            assert_eq!(
                outcome.work().procedures,
                1,
                "a range inside one function examines only that function, not the {} procedures of the file",
                artifact.procedures().len()
            );
            let result = outcome
                .available_value()
                .expect("external call retains a dispatch result");
            assert_eq!(result.observations()[0].call(), call);
        }
    }
    #[test]
    #[hardwon("bc14f106eeaa: prepared syntax reuse must stay bound to its logical budget scope")]
    fn prepared_source_dispatch_session_rejects_an_unrelated_budget_scope() {
        let fixture = typescript_fixture(&[("batch.ts", BATCH_CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "batch.ts");
        let artifact = artifact_for(&fixture, &file);
        let calls = all_call_sites(&artifact);
        assert_eq!(calls.len(), 2, "the fixture has two external calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));

        let mut first_budget = SemanticBudget::default();
        session
            .resolve_at_source(
                calls[0].1,
                &mut SemanticRequest::new(&mut first_budget, &cancellation),
            )
            .expect("first logical budget scope binds the prepared session");

        let first_scope = first_budget.scope_snapshot();
        let mut same_scope_child =
            SemanticBudget::new_child(SemanticBudget::default().limits(), &first_scope);
        let same_scope = session
            .resolve_at_source(
                calls[1].1,
                &mut SemanticRequest::new(&mut same_scope_child, &cancellation),
            )
            .expect("a child ledger in the same logical scope can reuse the session");
        assert!(same_scope.available_value().is_some(), "{same_scope:?}");
        assert_eq!(same_scope.work().source_bytes, 0);

        let mut unrelated_budget = SemanticBudget::default();
        let error = session
            .resolve_at_source(
                calls[0].1,
                &mut SemanticRequest::new(&mut unrelated_budget, &cancellation),
            )
            .expect_err("fresh budget scope cannot inherit a retained parse charge");
        assert!(
            error.to_string().contains("semantic budget scopes"),
            "{error}"
        );
        assert_eq!(unrelated_budget.used(), SemanticWork::default());
    }
    #[test]
    #[hardwon(
        "bc14f106eeaa: prepared dispatch must preserve requested result order for distinct callees"
    )]
    fn source_dispatch_session_preserves_reverse_order_for_distinct_targets() {
        let fixture = typescript_fixture(&[("ordered.ts", DISTINCT_CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "ordered.ts");
        let artifact = artifact_for(&fixture, &file);
        let mut calls = all_call_sites(&artifact);
        calls.sort_by_key(|(_, range)| (range.start_byte, range.end_byte));
        assert_eq!(calls.len(), 2, "the fixture has two distinct local calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut serial_outcomes = Vec::new();
        let mut serial_shapes = Vec::new();
        for (_, range) in &calls {
            let mut serial_budget = SemanticBudget::default();
            let serial = oracle
                .dispatch_at_source_in_artifact(
                    complete_materialization(&artifact),
                    *range,
                    &mut SemanticRequest::new(&mut serial_budget, &cancellation),
                )
                .expect("serial source dispatch baseline");
            let result = serial.available_value().expect("serial target is resolved");
            assert_eq!(result.observations().len(), 1);
            serial_shapes.push(dispatch_shape(result.observations()[0].dispatch()));
            serial_outcomes.push(outcome_label(&serial));
        }
        assert_ne!(
            serial_shapes[0], serial_shapes[1],
            "the regression requires distinguishable target answers"
        );

        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let mut session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));
        assert_eq!(session.retained_bytes(), 0);

        let second = session
            .resolve_at_source(calls[1].1, &mut request)
            .expect("second row can be the first row actually requested");
        let second_result = second.available_value().expect("second dispatch result");
        assert_eq!(second_result.observations()[0].call(), &calls[1].0);
        assert_eq!(outcome_label(&second), serial_outcomes[1]);
        assert_eq!(
            dispatch_shape(second_result.observations()[0].dispatch()),
            serial_shapes[1]
        );
        assert_eq!(second.work().source_bytes, DISTINCT_CALL_SOURCE.len());

        let first = session
            .resolve_at_source(calls[0].1, &mut request)
            .expect("an earlier skipped row does not desynchronize the session");
        let first_result = first.available_value().expect("first dispatch result");
        assert_eq!(first_result.observations()[0].call(), &calls[0].0);
        assert_eq!(outcome_label(&first), serial_outcomes[0]);
        assert_eq!(
            dispatch_shape(first_result.observations()[0].dispatch()),
            serial_shapes[0]
        );
        assert_eq!(first.work().source_bytes, 0);
    }
    #[test]
    #[hardwon(
        "bc14f106eeaa: non-call ranges must not eagerly parse or charge source before dispatch is requested"
    )]
    fn source_dispatch_session_defers_parse_until_a_range_contains_a_call() {
        let fixture = typescript_fixture(&[("batch.ts", BATCH_CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "batch.ts");
        let artifact = artifact_for(&fixture, &file);
        let calls = all_call_sites(&artifact);
        assert_eq!(calls.len(), 2, "the fixture has two external calls");
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let mut session =
            oracle.prepare_source_dispatch_session_in_artifact(complete_materialization(&artifact));

        let no_call = session
            .resolve_at_source(
                Range {
                    start_byte: 0,
                    end_byte: "import".len(),
                    start_line: 0,
                    end_line: 0,
                },
                &mut request,
            )
            .expect("a non-call range remains a typed source answer");
        assert!(matches!(&no_call, SemanticOutcome::Unknown { .. }));
        assert_eq!(no_call.work().source_bytes, 0);
        assert_eq!(session.retained_bytes(), 0);

        let first_call = session
            .resolve_at_source(calls[0].1, &mut request)
            .expect("the first real call initializes exact dispatch");
        assert_eq!(first_call.work().source_bytes, BATCH_CALL_SOURCE.len());
        assert_eq!(
            session.retained_bytes(),
            brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::prepared_syntax_retained_bytes(
                BATCH_CALL_SOURCE.len()
            )
            .saturating_add(file.retained_bytes())
        );
    }
    #[test]
    fn dispatch_at_source_agrees_with_the_call_site_handle_path() {
        let fixture = typescript_fixture(&[("call.ts", CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "call.ts");
        let artifact = artifact_for(&fixture, &file);
        let (call, range) = only_call_site(&artifact);
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();

        let mut handle_budget = SemanticBudget::default();
        let by_handle = oracle
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut handle_budget, &cancellation),
            )
            .expect("handle dispatch");
        let by_handle_result = by_handle
            .available_value()
            .expect("handle dispatch retains a result");

        let mut source_budget = SemanticBudget::default();
        let by_source = oracle
            .dispatch_at_source(
                &file,
                range,
                &mut SemanticRequest::new(&mut source_budget, &cancellation),
            )
            .expect("source dispatch");
        assert_eq!(
            outcome_label(&by_source),
            outcome_label(&by_handle),
            "source and handle dispatch must classify the same call identically: \
             {by_source:?} vs {by_handle:?}"
        );
        let by_source_result = by_source
            .available_value()
            .expect("source dispatch retains a result");
        assert_eq!(
            by_source_result.observations().len(),
            1,
            "one call site occupies this range: {by_source_result:?}"
        );
        let observation = &by_source_result.observations()[0];
        assert_eq!(
            observation.call().id(),
            call.id(),
            "the seam must address the same semantic call site"
        );
        assert_eq!(
            dispatch_shape(observation.dispatch()),
            dispatch_shape(by_handle_result),
            "the seam must not alter targets, quality, boundaries, or coverage"
        );
        assert_eq!(by_source_result.coverage(), by_handle_result.coverage());
        assert_eq!(
            by_source_result.target_candidates().count(),
            by_handle_result.candidates().len()
        );
    }
    #[test]
    #[hardwon(
        "840fffe45997: dispatch certificates omitted candidate and boundary evidence axes, allowing stale reuse"
    )]
    fn procedure_dispatch_v2_rotates_candidate_and_boundary_evidence_axes() {
        let fixture =
            typescript_fixture(&[("call.ts", CALL_SOURCE), ("external.ts", BATCH_CALL_SOURCE)]);
        let call_file = ProjectFile::new(fixture.project_root(), "call.ts");
        let call_artifact = artifact_for(&fixture, &call_file);
        let (call, _) = only_call_site(&call_artifact);
        let oracle = fixture.analyzer.semantic_oracle_provider();
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = oracle
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("workspace call dispatch");
        let dispatch = outcome
            .available_value()
            .expect("workspace call retains dispatch");
        let candidate = dispatch
            .candidates()
            .first()
            .expect("workspace call has one target");
        let candidate_digest = procedure_dispatch_candidate_digest(candidate);

        let mut changed_proof = candidate.clone();
        changed_proof.proof = ProofStatus::Unproven("changed proof".into());
        assert_ne!(
            candidate_digest,
            procedure_dispatch_candidate_digest(&changed_proof)
        );
        let mut changed_completeness = candidate.clone();
        changed_completeness.completeness =
            EvidenceCompleteness::Partial("changed completeness".into());
        assert_ne!(
            candidate_digest,
            procedure_dispatch_candidate_digest(&changed_completeness)
        );
        let excluded = call_artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.id() != candidate.target().id())
            .and_then(|procedure| call_artifact.procedure_handle(procedure.id()))
            .expect("the caller is a distinct exclusion identity");
        let mut changed_exclusions = candidate.clone();
        changed_exclusions.excluded_targets = Box::new([excluded]);
        assert_ne!(
            candidate_digest,
            procedure_dispatch_candidate_digest(&changed_exclusions)
        );

        let external_file = ProjectFile::new(fixture.project_root(), "external.ts");
        let external_artifact = artifact_for(&fixture, &external_file);
        let (external_call, _) = all_call_sites(&external_artifact)
            .into_iter()
            .next()
            .expect("external fixture call");
        let mut external_budget = SemanticBudget::default();
        let external = oracle
            .resolve_call(
                &external_call,
                &mut SemanticRequest::new(&mut external_budget, &cancellation),
            )
            .expect("external call dispatch");
        let boundary = external
            .available_value()
            .and_then(|dispatch| dispatch.boundaries().first())
            .expect("external call retains a boundary");
        let boundary_digest = procedure_dispatch_boundary_digest(boundary);
        let mut changed_boundary = boundary.clone();
        changed_boundary.kind = DispatchBoundaryKind::Unresolved;
        assert_ne!(
            boundary_digest,
            procedure_dispatch_boundary_digest(&changed_boundary),
            "same empty target set and coverage with a different boundary must rotate"
        );
        let mut changed_boundary_proof = boundary.clone();
        changed_boundary_proof.proof = ProofStatus::Unproven("changed boundary proof".into());
        assert_ne!(
            boundary_digest,
            procedure_dispatch_boundary_digest(&changed_boundary_proof)
        );
        let mut changed_boundary_completeness = boundary.clone();
        changed_boundary_completeness.completeness =
            EvidenceCompleteness::Partial("changed boundary completeness".into());
        assert_ne!(
            boundary_digest,
            procedure_dispatch_boundary_digest(&changed_boundary_completeness)
        );
    }
    #[test]
    #[hardwon(
        "840fffe45997: dispatch certificates omitted answer quality and v1 identity, allowing stale reuse"
    )]
    fn procedure_dispatch_v2_rotates_quality_and_cannot_equal_a_v1_answer() {
        let fixture = typescript_fixture(&[("call.ts", CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "call.ts");
        let artifact = artifact_for(&fixture, &file);
        let (call, _) = only_call_site(&artifact);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .semantic_oracle_provider()
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("workspace dispatch");
        let result = SourceDispatchResult {
            observations: Box::new([SourceDispatchObservation {
                call,
                dispatch: outcome
                    .available_value()
                    .expect("workspace call retains dispatch")
                    .clone(),
            }]),
            coverage: CandidateCoverage::Exhaustive,
        };
        let complete =
            procedure_dispatch_answer_digest(SourceOutcomeQuality::Complete, Some(&result));
        assert_ne!(
            complete,
            procedure_dispatch_answer_digest(SourceOutcomeQuality::Ambiguous, Some(&result)),
            "outcome quality changes direct-call binding status"
        );

        let mut legacy = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
            b"bifrost-read-ledger:procedure-dispatch-answer:v1",
        );
        legacy.field("coverage", result.coverage().label().as_bytes());
        let mut targets = result
            .target_candidates()
            .map(|candidate| {
                let target = candidate.target();
                target
                    .artifact()
                    .key()
                    .procedure_lineage_fingerprint(target.semantics().locator().declaration())
            })
            .collect::<Vec<_>>();
        targets.sort_unstable();
        targets.dedup();
        for target in targets {
            legacy.value(target.as_bytes());
        }
        assert_ne!(
            complete,
            StableDigest::from_array(legacy.finish()),
            "the v2 domain must invalidate every persisted v1 read answer"
        );
    }
    #[test]
    fn dispatch_at_source_without_a_call_site_is_unknown() {
        let fixture = typescript_fixture(&[("call.ts", CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "call.ts");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        // The `function` keyword of the callee declaration: inside the file,
        // outside every call expression.
        let outcome = fixture
            .analyzer
            .semantic_oracle_provider()
            .dispatch_at_source(
                &file,
                Range {
                    start_byte: 0,
                    end_byte: "function".len(),
                    start_line: 0,
                    end_line: 0,
                },
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("source dispatch");
        let SemanticOutcome::Unknown { partial, .. } = &outcome else {
            panic!("a position with no call site must be Unknown: {outcome:?}");
        };
        assert!(
            partial.is_none(),
            "no call site means no dispatch answer at all: {partial:?}"
        );
    }
    #[test]
    fn dispatch_at_source_in_an_unsupported_file_is_unsupported() {
        let fixture =
            typescript_fixture(&[("call.ts", CALL_SOURCE), ("notes.txt", "plain prose\n")]);
        let file = ProjectFile::new(fixture.project_root(), "notes.txt");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .semantic_oracle_provider()
            .dispatch_at_source(
                &file,
                Range {
                    start_byte: 0,
                    end_byte: 5,
                    start_line: 0,
                    end_line: 0,
                },
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("source dispatch");
        let SemanticOutcome::Unsupported {
            capability,
            partial,
            ..
        } = &outcome
        else {
            panic!("an unsupported file must report Unsupported: {outcome:?}");
        };
        assert_eq!(*capability, SemanticCapability::Procedures);
        assert!(partial.is_none(), "{partial:?}");
    }
    #[test]
    fn dispatch_at_source_reports_cancellation() {
        let fixture = typescript_fixture(&[("call.ts", CALL_SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "call.ts");
        let artifact = artifact_for(&fixture, &file);
        let (_, range) = only_call_site(&artifact);
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let mut budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .semantic_oracle_provider()
            .dispatch_at_source(
                &file,
                range,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("source dispatch");
        assert!(
            matches!(outcome, SemanticOutcome::Cancelled { .. }),
            "{outcome:?}"
        );
    }
}
