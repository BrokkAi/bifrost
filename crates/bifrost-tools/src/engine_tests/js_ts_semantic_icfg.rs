#[cfg(test)]
mod js_ts_extraction_tests {
    use brokk_bifrost_analysis::analyzer::semantic::DispatchOracle;

    use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapability;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::CallBoundary;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::CallToReturnModel;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::CallTransfer;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::DispatchReadAttribution;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::DispatchReadUnattributedReason;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::IcfgBoundaryKind;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::IcfgEdgeKind;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::IcfgExitProfile;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::IcfgSnapshotLimits;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::MatchedReturnProjection;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::ReturnTransferKind;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::SnapshotBuilder;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::SnapshotQuality;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::call_evaluation_gap_applies;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::dispatch_read_attribution_for_exact_range;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::dispatch_read_attribution_with_range;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::invoked_call_at;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::is_call_scaffolding;
    use brokk_bifrost_analysis::analyzer::semantic::icfg::materialize_exit_profile;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::validate_call_transfer_set;
    use brokk_bifrost_analysis::analyzer::semantic::ids::CallSiteId;
    use brokk_bifrost_analysis::analyzer::semantic::ids::ProgramPointId;
    use brokk_bifrost_analysis::analyzer::semantic::ir::artifact::ProcedureHandle;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallContinuationKind;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ControlContinuation;

    use brokk_bifrost_analysis::analyzer::semantic::ir::model::EvidenceCompleteness;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProofStatus;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGap;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapDischarge;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapImpact;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapKind;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapSubject;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::DispatchBoundary;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::DispatchResult;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::limits::OracleLimits;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::DispatchBoundaryKind;

    use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::CandidateCoverage;

    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticProviderError;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticWork;
    use brokk_bifrost_analysis::analyzer::semantic::read_ledger::LookupKind;
    use brokk_bifrost_analysis::analyzer::semantic::read_ledger::ReadKey;

    use brokk_bifrost_core::hash::HashMap;
    use std::sync::Arc;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::*;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::retain_dispatch_candidate;

    use brokk_bifrost_analysis::analyzer::semantic::ids::DeclarationSegment;

    use brokk_bifrost_analysis::analyzer::semantic::DispatchCandidate;

    use brokk_bifrost_analysis::analyzer::semantic::SemanticBudget;

    use brokk_bifrost_analysis::analyzer::semantic::SemanticExecutionBudget;

    use brokk_bifrost_analysis::analyzer::semantic::SemanticGapId;

    use brokk_bifrost_analysis::analyzer::semantic::SemanticGapImpacts;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    #[test]
    fn unnameable_dispatch_range_is_typed_unattributed() {
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::TypeScript,
            &[(
                "dispatch-read.ts",
                "function target() {}\nexport function caller() { target(); }\n",
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "dispatch-read.ts");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("TypeScript semantic materialization")
            .available_value()
            .cloned()
            .expect("TypeScript semantic artifact");
        let call = artifact
            .procedures()
            .iter()
            .find(|procedure| !procedure.call_sites().is_empty())
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .and_then(|procedure| procedure.call_site_handle(CallSiteId::new(0)))
            .expect("fixture call site");
        let outcome = SemanticOutcome::<DispatchResult>::Unknown {
            partial: None,
            work: SemanticWork::default(),
        };

        let attribution = dispatch_read_attribution_with_range(
            &call,
            &outcome,
            Err(SemanticProviderError::internal(
                "synthetic missing source range",
            )),
        );

        assert_eq!(
            attribution,
            DispatchReadAttribution::Unattributed(
                DispatchReadUnattributedReason::SourceRangeUnavailable
            )
        );
    }
    #[test]
    fn duplicate_span_dispatch_is_typed_ambiguous() {
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::TypeScript,
            &[(
                "dispatch-read.ts",
                "function target() {}\nexport function caller() { target(); }\n",
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "dispatch-read.ts");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("TypeScript semantic materialization")
            .available_value()
            .cloned()
            .expect("TypeScript semantic artifact");
        let call = artifact
            .procedures()
            .iter()
            .find(|procedure| !procedure.call_sites().is_empty())
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .and_then(|procedure| procedure.call_site_handle(CallSiteId::new(0)))
            .expect("fixture call site");
        let range = brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::exact_call_range(&call)
            .expect("fixture call has an exact range");
        let outcome = SemanticOutcome::<DispatchResult>::Unknown {
            partial: None,
            work: SemanticWork::default(),
        };

        assert_eq!(
            dispatch_read_attribution_for_exact_range(&call, &outcome, range, 2),
            DispatchReadAttribution::Unattributed(
                DispatchReadUnattributedReason::SourceRangeAmbiguous
            )
        );
    }
    #[test]
    fn call_evaluation_gap_scope_covers_procedure_point_and_call_site() {
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::TypeScript,
            &[(
                "scope.ts",
                "function target() {}\nexport function caller() { target(); }\n",
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "scope.ts");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("TypeScript semantic materialization")
            .available_value()
            .cloned()
            .expect("TypeScript semantic artifact");
        let call = artifact
            .procedures()
            .iter()
            .find_map(|procedure| procedure.call_sites().first().cloned())
            .expect("semantic call site");
        let different_point = ProgramPointId::new(call.point.get().saturating_add(1));
        let gap = |subject, point, impacts| SemanticGap {
            id: SemanticGapId::new(0),
            point,
            subject,
            capability: SemanticCapability::Calls,
            impacts,
            kind: SemanticGapKind::Unproven,
            budget: None,
            discharge: SemanticGapDischarge::None,
            detail: "caller-side evaluation is incomplete".into(),
            source: call.source,
            evidence: call.evidence,
        };

        assert!(call_evaluation_gap_applies(
            &gap(
                SemanticGapSubject::Procedure,
                different_point,
                SemanticGapImpacts::single(SemanticGapImpact::CallEvaluation),
            ),
            &call,
        ));
        assert!(call_evaluation_gap_applies(
            &gap(
                SemanticGapSubject::Point,
                call.point,
                SemanticGapImpacts::single(SemanticGapImpact::CallEvaluation),
            ),
            &call,
        ));
        assert!(!call_evaluation_gap_applies(
            &gap(
                SemanticGapSubject::Point,
                different_point,
                SemanticGapImpacts::single(SemanticGapImpact::CallEvaluation),
            ),
            &call,
        ));
        assert!(call_evaluation_gap_applies(
            &gap(
                SemanticGapSubject::CallSite(call.id),
                call.point,
                SemanticGapImpacts::single(SemanticGapImpact::CallEvaluation),
            ),
            &call,
        ));
        assert!(!call_evaluation_gap_applies(
            &gap(
                SemanticGapSubject::CallSite(CallSiteId::new(call.id.get().saturating_add(1),)),
                call.point,
                SemanticGapImpacts::single(SemanticGapImpact::CallEvaluation),
            ),
            &call,
        ));
        assert!(!call_evaluation_gap_applies(
            &gap(
                SemanticGapSubject::Procedure,
                call.point,
                SemanticGapImpacts::NONE,
            ),
            &call,
        ));
    }
    #[test]
    fn exit_profiles_are_scoped_to_distinct_artifact_instances() {
        fn materialize_handle() -> ProcedureHandle {
            let fixture = AnalyzerFixture::new_for_language(
                brokk_bifrost_core::analyzer::model::Language::TypeScript,
                &[(
                    "artifact-scope.ts",
                    "export function target(flag: boolean) {\n\
                     if (flag) { return; }\n\
                     return;\n\
                     const unreachable = 1;\n\
                     }\n",
                )],
            );
            let file = ProjectFile::new(fixture.project_root(), "artifact-scope.ts");
            let cancellation = CancellationToken::default();
            let mut budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("TypeScript semantic materialization")
                .available_value()
                .cloned()
                .expect("complete TypeScript semantic artifact");
            let procedure = artifact
                .procedures()
                .first()
                .expect("one TypeScript procedure");
            artifact
                .procedure_handle(procedure.id())
                .expect("procedure handle")
        }

        let first = materialize_handle();
        let second = materialize_handle();
        assert_eq!(first.id(), second.id());
        assert!(!std::sync::Arc::ptr_eq(first.artifact(), second.artifact()));
        assert_ne!(first, second);

        let mut builder = SnapshotBuilder::new(IcfgSnapshotLimits::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        for procedure in [&first, &second] {
            let entry = procedure
                .point_handle(procedure.semantics().entry_point())
                .expect("entry point handle");
            let exit = procedure
                .point_handle(procedure.semantics().normal_exit_point())
                .expect("normal exit point handle");
            let outcome = materialize_exit_profile(&entry, &exit, &mut request)
                .expect("exit profile")
                .map(Arc::new);
            assert!(
                builder
                    .exit_profiles
                    .insert((procedure.clone(), entry.id(), exit.id()), outcome,)
                    .is_none()
            );
        }

        assert_eq!(builder.exit_profiles.len(), 2);
        assert!(builder.exit_profiles.contains_key(&(
            first.clone(),
            first.semantics().entry_point(),
            first.semantics().normal_exit_point(),
        )));
        assert!(builder.exit_profiles.contains_key(&(
            second.clone(),
            second.semantics().entry_point(),
            second.semantics().normal_exit_point(),
        )));
    }
    #[test]
    fn typescript_imported_target_does_not_admit_unrelated_same_name_body() {
        let target = "export function target(value: number) { return value + 1; }\n";
        let unrelated = "export function target(value: number) { return value + 2; }\n";
        let caller = concat!(
            "import { target } from './target';\n",
            "export function caller() { return target(1); }\n",
        );
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::TypeScript,
            &[
                ("target.ts", target),
                ("unrelated.ts", unrelated),
                ("caller.ts", caller),
            ],
        );
        let caller_file = ProjectFile::new(fixture.project_root(), "caller.ts");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &caller_file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("TypeScript caller materialization")
            .available_value()
            .cloned()
            .expect("TypeScript caller artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(DeclarationSegment::name)
                    == Some("caller")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("caller procedure");
        let call = caller
            .semantics()
            .call_sites()
            .first()
            .and_then(|call| caller.call_site_handle(call.id))
            .expect("target call site");

        let mut dispatch_budget = SemanticBudget::default();
        let outcome = fixture
            .analyzer
            .icfg_provider()
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
            )
            .expect("TypeScript exact dispatch");
        let dispatch = outcome.available_value().expect("dispatch payload");

        // The resolver proved the imported target as the complete receiverless
        // target set, which discharges the adapter's blanket rebinding gap
        // (#1952): the outcome is complete, and no unresolved boundary remains.
        assert!(matches!(&outcome, SemanticOutcome::Complete { .. }));
        assert_eq!(dispatch.coverage(), CandidateCoverage::Exhaustive);
        assert_eq!(dispatch.candidates().len(), 1, "{dispatch:#?}");
        assert!(matches!(
            &dispatch.candidates()[0].proof,
            ProofStatus::Proven
        ));
        assert!(matches!(
            &dispatch.candidates()[0].completeness,
            EvidenceCompleteness::Complete
        ));
        assert_eq!(
            dispatch.candidates()[0]
                .target
                .artifact()
                .key()
                .path()
                .as_str(),
            "target.ts"
        );
        assert!(dispatch.boundaries().is_empty(), "{dispatch:#?}");
    }
    #[test]
    fn final_dispatch_limit_counts_unique_materialized_procedures() {
        let source = concat!(
            "export function first() { return 1; }\n",
            "export function second() { return 2; }\n",
        );
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::TypeScript,
            &[("targets.ts", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "targets.ts");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("TypeScript materialization")
            .available_value()
            .cloned()
            .expect("TypeScript artifact");
        let mut procedures = artifact
            .procedures()
            .iter()
            .filter_map(|procedure| artifact.procedure_handle(procedure.id()))
            .collect::<Vec<_>>();
        procedures
            .sort_by(|left, right| left.semantics().locator().cmp(right.semantics().locator()));
        assert_eq!(procedures.len(), 2);

        let candidate = |target: ProcedureHandle| {
            DispatchCandidate::new(
                target,
                ProofStatus::Proven,
                EvidenceCompleteness::Complete,
                std::iter::empty(),
                OracleLimits::default(),
            )
            .expect("an empty dispatch draft fits every positive provenance limit")
        };
        let mut retained = Vec::new();
        let mut indexes = HashMap::default();
        assert!(!retain_dispatch_candidate(
            &mut retained,
            &mut indexes,
            candidate(procedures[0].clone()),
            1,
        ));
        assert!(!retain_dispatch_candidate(
            &mut retained,
            &mut indexes,
            candidate(procedures[0].clone()),
            1,
        ));
        assert!(retain_dispatch_candidate(
            &mut retained,
            &mut indexes,
            candidate(procedures[1].clone()),
            1,
        ));
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].target, procedures[0]);
    }
    #[test]
    fn workspace_icfg_provider_parses_one_artifact_once_across_clones_and_retry_budgets() {
        let source = concat!(
            "function first() {}\n",
            "function second() {}\n",
            "export function caller() { first(); second(); }\n",
        );
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::TypeScript,
            &[("calls.ts", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "calls.ts");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("TypeScript semantic materialization")
            .available_value()
            .cloned()
            .expect("TypeScript semantic artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.call_sites().len() == 2)
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("caller with two calls");
        let calls = caller.semantics().call_sites();
        let read_ledger =
            Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
        let _read_scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::with_read_ledger(
                fixture.analyzer.analyzer(),
                Arc::clone(&read_ledger),
            );
        let provider = fixture.analyzer.icfg_provider();

        let mut first_budget = SemanticBudget::default();
        let first = provider
            .call_transfers(
                &caller,
                calls[0].id,
                &mut SemanticRequest::new(&mut first_budget, &cancellation),
            )
            .expect("first call transfer");
        assert!(first.available_value().is_some(), "{first:#?}");
        assert_eq!(first.work().source_bytes, source.len());
        assert_eq!(first_budget.used().source_bytes, 2 * source.len());
        assert_eq!(first_budget.root_work_peak().source_bytes, source.len());
        assert_eq!(first_budget.resident().source_bytes, source.len());

        // A restarted trial owns a fresh scalar ledger in the same logical
        // query and uses a provider clone. It reuses the parser, but takes
        // over no source admission from the snapshot: the live source is
        // admitted in this child without repeating the scan work.
        let mut retry_budget = SemanticBudget::new_child(
            SemanticBudget::default().limits(),
            &first_budget.scope_snapshot(),
        );
        let second = provider
            .clone()
            .call_transfers(
                &caller,
                calls[1].id,
                &mut SemanticRequest::new(&mut retry_budget, &cancellation),
            )
            .expect("second call transfer through cloned provider");
        assert!(second.available_value().is_some(), "{second:#?}");
        assert_eq!(second.work().source_bytes, 0);
        assert_eq!(retry_budget.used().source_bytes, source.len());
        assert_eq!(retry_budget.root_work_peak().source_bytes, 0);
        assert_eq!(retry_budget.resident().source_bytes, source.len());
        assert_eq!(
            provider
                .outcome_cache
                .dispatch_sessions
                .lock()
                .expect("query-local dispatch session cache is not poisoned")
                .len(),
            1,
        );
        assert_eq!(
            read_ledger
                .keys()
                .iter()
                .filter(|key| matches!(
                    key,
                    ReadKey::Lookup {
                        kind: LookupKind::ProcedureDispatch,
                        ..
                    }
                ))
                .count(),
            2,
            "parser reuse must still attribute each distinct dispatch answer",
        );
    }
    #[test]
    fn workspace_icfg_direct_dispatch_is_one_shot_and_preserves_read_attribution() {
        let source = concat!(
            "function first() {}\n",
            "function second() {}\n",
            "export function caller() { first(); second(); }\n",
        );
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::TypeScript,
            &[("calls.ts", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "calls.ts");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("TypeScript semantic materialization")
            .available_value()
            .cloned()
            .expect("TypeScript semantic artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.call_sites().len() == 2)
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("caller with two calls");
        let calls = caller
            .semantics()
            .call_sites()
            .iter()
            .map(|call| caller.call_site_handle(call.id).expect("call handle"))
            .collect::<Vec<_>>();
        let read_ledger =
            Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
        let _read_scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::with_read_ledger(
                fixture.analyzer.analyzer(),
                Arc::clone(&read_ledger),
            );
        let provider = fixture.analyzer.icfg_provider();

        let mut first_budget = SemanticBudget::default();
        let first = provider
            .resolve_call(
                &calls[0],
                &mut SemanticRequest::new(&mut first_budget, &cancellation),
            )
            .expect("first direct dispatch");
        assert!(first.available_value().is_some(), "{first:#?}");
        assert_eq!(first.work().source_bytes, source.len());

        let mut second_budget = SemanticBudget::default();
        let second = provider
            .clone()
            .resolve_call(
                &calls[1],
                &mut SemanticRequest::new(&mut second_budget, &cancellation),
            )
            .expect("second direct dispatch through provider clone");
        assert!(second.available_value().is_some(), "{second:#?}");
        assert_eq!(second.work().source_bytes, source.len());
        assert_eq!(second_budget.used().source_bytes, 2 * source.len());
        assert_eq!(second_budget.root_work_peak().source_bytes, source.len());
        assert_eq!(second_budget.resident().source_bytes, 0);
        assert!(
            provider
                .outcome_cache
                .dispatch_sessions
                .lock()
                .expect("query-local dispatch session cache is not poisoned")
                .is_empty(),
            "direct dispatch has no enclosing transaction that could safely publish syntax",
        );
        assert_eq!(
            read_ledger
                .keys()
                .iter()
                .filter(|key| matches!(
                    key,
                    ReadKey::Lookup {
                        kind: LookupKind::ProcedureDispatch,
                        ..
                    }
                ))
                .count(),
            2,
        );
    }
    #[test]
    fn failed_snapshot_transaction_does_not_publish_transfer_work() {
        let source = concat!(
            "function first() {}\n",
            "function second() {}\n",
            "export function root() { first(); }\n",
            "export function other() { second(); }\n",
        );
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::TypeScript,
            &[("calls.ts", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "calls.ts");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("TypeScript semantic materialization")
            .available_value()
            .cloned()
            .expect("TypeScript semantic artifact");
        let mut callers = artifact
            .procedures()
            .iter()
            .filter(|procedure| procedure.call_sites().len() == 1)
            .filter_map(|procedure| artifact.procedure_handle(procedure.id()))
            .collect::<Vec<_>>();
        callers.sort_by(|left, right| left.semantics().locator().cmp(right.semantics().locator()));
        assert_eq!(callers.len(), 2);
        let provider = fixture.analyzer.icfg_provider();
        let mut outer_budget = SemanticBudget::default();

        let failed: Result<(), SemanticProviderError> = provider.with_snapshot_transaction(
            &mut SemanticRequest::new(&mut outer_budget, &cancellation),
            |snapshot_provider, snapshot_request| {
                let outcome = snapshot_provider.call_transfers(
                    &callers[0],
                    callers[0].semantics().call_sites()[0].id,
                    snapshot_request,
                )?;
                assert!(outcome.available_value().is_some(), "{outcome:#?}");
                assert_eq!(outcome.work().source_bytes, source.len());
                assert_eq!(
                    snapshot_request.budget.used().source_bytes,
                    2 * source.len()
                );
                assert_eq!(
                    snapshot_request.budget.root_work_peak().source_bytes,
                    source.len()
                );
                assert_eq!(
                    snapshot_request.budget.resident().source_bytes,
                    source.len()
                );
                assert!(
                    provider
                        .outcome_cache
                        .call_transfers
                        .lock()
                        .expect("shared call-transfer cache is not poisoned")
                        .is_empty(),
                    "a transfer remains private until the outer snapshot commits",
                );
                assert!(
                    provider
                        .outcome_cache
                        .dispatch_sessions
                        .lock()
                        .expect("shared dispatch-session cache is not poisoned")
                        .is_empty(),
                    "parsed source remains private until the outer snapshot commits",
                );
                Err(SemanticProviderError::internal(
                    "synthetic post-transfer snapshot failure",
                ))
            },
        );
        assert!(failed.is_err());
        assert_eq!(outer_budget.resident(), SemanticWork::default());
        assert_ne!(
            outer_budget.used(),
            SemanticWork::default(),
            "performed work survives the failed snapshot transaction"
        );
        assert!(
            provider
                .outcome_cache
                .call_transfers
                .lock()
                .expect("shared call-transfer cache is not poisoned")
                .is_empty(),
        );
        assert!(
            provider
                .outcome_cache
                .dispatch_sessions
                .lock()
                .expect("shared dispatch-session cache is not poisoned")
                .is_empty(),
        );

        let mut retry_budget = SemanticBudget::default();
        let retry = provider
            .call_transfers(
                &callers[1],
                callers[1].semantics().call_sites()[0].id,
                &mut SemanticRequest::new(&mut retry_budget, &cancellation),
            )
            .expect("retry after rolled-back snapshot transaction");
        assert!(retry.available_value().is_some(), "{retry:#?}");
        assert_eq!(retry.work().source_bytes, source.len());
        assert_eq!(retry_budget.used().source_bytes, 2 * source.len());
        assert_eq!(retry_budget.root_work_peak().source_bytes, source.len());
        assert_eq!(retry_budget.resident().source_bytes, source.len());
    }
    #[test]
    fn successful_snapshot_publishes_prepared_dispatch_for_later_procedures() {
        let source = concat!(
            "function first() {}\n",
            "function second() {}\n",
            "export function root() { first(); }\n",
            "export function other() { second(); }\n",
        );
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::TypeScript,
            &[("calls.ts", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "calls.ts");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("TypeScript semantic materialization")
            .available_value()
            .cloned()
            .expect("TypeScript semantic artifact");
        let mut callers = artifact
            .procedures()
            .iter()
            .filter(|procedure| procedure.call_sites().len() == 1)
            .filter_map(|procedure| artifact.procedure_handle(procedure.id()))
            .collect::<Vec<_>>();
        callers.sort_by(|left, right| left.semantics().locator().cmp(right.semantics().locator()));
        assert_eq!(callers.len(), 2);
        let provider = fixture.analyzer.icfg_provider();
        let mut snapshot_budget = SemanticBudget::default();
        let snapshot = provider
            .snapshot(
                &callers[1],
                IcfgSnapshotLimits::default(),
                &mut SemanticRequest::new(&mut snapshot_budget, &cancellation),
            )
            .expect("successful ICFG snapshot");
        assert!(snapshot.available_value().is_some(), "{snapshot:#?}");
        assert!(
            provider
                .outcome_cache
                .dispatch_sessions
                .lock()
                .expect("shared dispatch-session cache is not poisoned")
                .values()
                .any(|session| session
                    .lock()
                    .expect("prepared dispatch session is not poisoned")
                    .retains_exact_source()),
            "a committed snapshot publishes its paid exact-source session",
        );

        let mut later_budget = SemanticBudget::default();
        let later = provider
            .call_transfers(
                &callers[0],
                callers[0].semantics().call_sites()[0].id,
                &mut SemanticRequest::new(&mut later_budget, &cancellation),
            )
            .expect("call in an unvisited procedure reuses the snapshot session");
        assert!(later.available_value().is_some(), "{later:#?}");
        assert_eq!(later.work().source_bytes, 0);
        assert_eq!(later_budget.used().source_bytes, source.len());
        assert_eq!(later_budget.root_work_peak().source_bytes, 0);
        assert_eq!(later_budget.resident().source_bytes, source.len());
    }
    #[test]
    fn snapshot_overlay_reads_parent_outcomes_without_copying_them() {
        let source = "function target() {}\nexport function caller() { target(); }\n";
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::TypeScript,
            &[("call.ts", source)],
        );
        let file = ProjectFile::new(fixture.project_root(), "call.ts");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("TypeScript semantic materialization")
            .available_value()
            .cloned()
            .expect("TypeScript semantic artifact");
        let caller = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.call_sites().len() == 1)
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("caller procedure");
        let call = caller.semantics().call_sites()[0].id;
        let provider = fixture.analyzer.icfg_provider();

        let mut transfer_budget = SemanticBudget::default();
        let transfer = provider
            .call_transfers(
                &caller,
                call,
                &mut SemanticRequest::new(&mut transfer_budget, &cancellation),
            )
            .expect("parent call transfer")
            .available_value()
            .and_then(|transfers| transfers.transfers.first())
            .cloned()
            .expect("resolved target transfer");
        let exit = transfer
            .callee
            .point_handle(transfer.callee.semantics().normal_exit_point())
            .expect("target normal exit");
        let mut profile_budget = SemanticBudget::default();
        provider
            .exit_profile(
                &transfer.callee_entry,
                &exit,
                &mut SemanticRequest::new(&mut profile_budget, &cancellation),
            )
            .expect("parent exit profile");

        let mut snapshot_budget = SemanticBudget::default();
        provider
            .with_snapshot_transaction(
                &mut SemanticRequest::new(&mut snapshot_budget, &cancellation),
                |snapshot_provider, snapshot_request| {
                    let replayed_transfer =
                        snapshot_provider.call_transfers(&caller, call, snapshot_request)?;
                    let replayed_profile = snapshot_provider.exit_profile(
                        &transfer.callee_entry,
                        &exit,
                        snapshot_request,
                    )?;
                    assert_eq!(replayed_transfer.work(), SemanticWork::default());
                    assert_eq!(replayed_profile.work(), SemanticWork::default());
                    assert!(
                        snapshot_provider
                            .outcome_cache
                            .call_transfers
                            .lock()
                            .expect("snapshot call-transfer cache is not poisoned")
                            .is_empty(),
                        "a parent hit must not be copied into the snapshot write layer",
                    );
                    assert!(
                        snapshot_provider
                            .outcome_cache
                            .exit_profiles
                            .lock()
                            .expect("snapshot exit-profile cache is not poisoned")
                            .is_empty(),
                        "a parent hit must not be copied into the snapshot write layer",
                    );
                    Ok(())
                },
            )
            .expect("snapshot transaction replays parent outcomes");
        assert_eq!(snapshot_budget.used(), SemanticWork::default());
        assert_eq!(
            provider
                .outcome_cache
                .call_transfers
                .lock()
                .expect("parent call-transfer cache is not poisoned")
                .len(),
            1,
        );
        assert_eq!(
            provider
                .outcome_cache
                .exit_profiles
                .lock()
                .expect("parent exit-profile cache is not poisoned")
                .len(),
            1,
        );
    }
    #[test]
    fn exit_profile_projects_exact_returns_and_owns_one_topology_scan() {
        let fixture = AnalyzerFixture::new_for_language(
            brokk_bifrost_core::analyzer::model::Language::TypeScript,
            &[(
                "returns.ts",
                concat!(
                    "function target(): number { return 1; }\n",
                    "function other(): number { return target(); }\n",
                    "export function caller(): number { return target(); }\n",
                ),
            )],
        );
        let file = ProjectFile::new(fixture.project_root(), "returns.ts");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("TypeScript materialization")
            .available_value()
            .cloned()
            .expect("TypeScript artifact");
        let find_procedure = |name| {
            artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(DeclarationSegment::name)
                        == Some(name)
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .unwrap_or_else(|| panic!("missing {name} procedure"))
        };
        let target = find_procedure("target");
        let other = find_procedure("other");
        let caller = find_procedure("caller");
        let semantic_call = caller
            .semantics()
            .call_sites()
            .first()
            .expect("target call");
        let call_point = caller
            .point_handle(semantic_call.point)
            .expect("target call point");
        let other_call = other
            .semantics()
            .call_sites()
            .first()
            .and_then(|call| other.call_site_handle(call.id))
            .expect("other target call");
        assert_eq!(
            invoked_call_at(&call_point).expect("valid invocation point"),
            Some(semantic_call.id)
        );
        assert!(
            caller
                .semantics()
                .successor_edges(semantic_call.point)
                .any(|(_, edge)| is_call_scaffolding(edge, semantic_call))
        );

        let provider = fixture.analyzer.icfg_provider();
        let mut transfer_budget = SemanticBudget::default();
        let transfer_outcome = provider
            .call_transfers(
                &caller,
                semantic_call.id,
                &mut SemanticRequest::new(&mut transfer_budget, &cancellation),
            )
            .expect("target call transfer");
        assert_ne!(transfer_outcome.work(), SemanticWork::default());
        assert_eq!(
            transfer_budget.root_work_peak().source_bytes,
            transfer_outcome.work().source_bytes,
            "the transfer owns one topology scan"
        );
        let transfer_set = transfer_outcome
            .available_value()
            .expect("target transfer payload");
        validate_call_transfer_set(&caller, semantic_call, transfer_set)
            .expect("valid target transfer set");
        let incoming = transfer_set
            .transfers
            .iter()
            .find(|transfer| transfer.callee == target)
            .expect("target transfer")
            .clone();
        let caller_entry = caller
            .point_handle(caller.semantics().entry_point())
            .expect("caller entry");
        let mut mismatched_origin = transfer_set.clone();
        mismatched_origin.transfers[0].origin = other_call.clone();
        assert!(
            validate_call_transfer_set(&caller, semantic_call, &mismatched_origin).is_err(),
            "transfer origins must identify the requested call"
        );
        let mut mismatched_entry_owner = transfer_set.clone();
        mismatched_entry_owner.transfers[0].callee_entry = caller_entry.clone();
        assert!(
            validate_call_transfer_set(&caller, semantic_call, &mismatched_entry_owner).is_err(),
            "callee entries must belong to their declared callees"
        );
        let mut mismatched_normal = transfer_set.clone();
        mismatched_normal.transfers[0].normal_continuation =
            if semantic_call.normal_continuation == ControlContinuation::Unknown {
                ControlContinuation::Absent
            } else {
                ControlContinuation::Unknown
            };
        assert!(
            validate_call_transfer_set(&caller, semantic_call, &mismatched_normal).is_err(),
            "normal continuations must match the semantic call"
        );
        let mut mismatched_exceptional = transfer_set.clone();
        mismatched_exceptional.transfers[0].exceptional_continuation =
            if semantic_call.exceptional_continuation == ControlContinuation::Unknown {
                ControlContinuation::Absent
            } else {
                ControlContinuation::Unknown
            };
        assert!(
            validate_call_transfer_set(&caller, semantic_call, &mismatched_exceptional).is_err(),
            "exceptional continuations must match the semantic call"
        );
        // The resolved receiverless call retains no boundary of its own since
        // the resolver-proven target set discharges the blanket rebinding gap
        // (#1952), so fabricate one with a foreign origin to prove the
        // validator still rejects boundary origins from another call.
        assert!(transfer_set.boundaries.is_empty(), "{transfer_set:#?}");
        let mut mismatched_boundary = transfer_set.clone();
        mismatched_boundary.boundaries = vec![CallBoundary {
            origin: other_call,
            dispatch: DispatchBoundary {
                kind: DispatchBoundaryKind::Unresolved,
                external_callee_identity: None,
                exact_external_target: None,
                unmaterialized_external_target: None,
                proof: ProofStatus::Unproven("fabricated foreign-origin boundary".into()),
                completeness: EvidenceCompleteness::Partial(
                    "fabricated foreign-origin boundary".into(),
                ),
                provenance: Box::new([]),
            },
            model: CallToReturnModel::NormalAndExceptional,
        }]
        .into_boxed_slice();
        assert!(
            validate_call_transfer_set(&caller, semantic_call, &mismatched_boundary).is_err(),
            "boundary origins must identify the requested call"
        );
        let exit = target
            .point_handle(target.semantics().normal_exit_point())
            .expect("target normal exit");
        let expected_work = SemanticWork {
            program_points: target.semantics().points().len().saturating_mul(2),
            control_edges: target.semantics().control_edges().len().saturating_mul(2),
            gaps: target.semantics().gaps().len(),
            nested_entries: target
                .semantics()
                .points()
                .len()
                .saturating_mul(2)
                .saturating_add(target.semantics().control_edges().len().saturating_mul(2))
                .saturating_add(target.semantics().gaps().len()),
            ..SemanticWork::default()
        };
        let mut exit_budget = SemanticBudget::default();
        let exit_outcome = provider
            .exit_profile(
                &incoming.callee_entry,
                &exit,
                &mut SemanticRequest::new(&mut exit_budget, &cancellation),
            )
            .expect("target exit profile");
        assert!(matches!(&exit_outcome, SemanticOutcome::Complete { .. }));
        assert_eq!(exit_outcome.work(), expected_work);
        assert_eq!(exit_budget.used(), expected_work);
        let profile = exit_outcome.available_value().expect("target exit payload");
        assert_eq!(profile.callee_entry(), &incoming.callee_entry);
        assert_eq!(profile.kind(), ReturnTransferKind::Normal);
        assert!(!profile.has_aggregate_return_affecting_gaps());

        let replay_provider = provider.clone();
        let mut replay_transfer_budget = SemanticBudget::default();
        let replay_transfer_outcome = replay_provider
            .call_transfers(
                &caller,
                semantic_call.id,
                &mut SemanticRequest::new(&mut replay_transfer_budget, &cancellation),
            )
            .expect("cached target call transfer");
        let mut replay_exit_budget = SemanticBudget::default();
        let replay_exit_outcome = replay_provider
            .exit_profile(
                &incoming.callee_entry,
                &exit,
                &mut SemanticRequest::new(&mut replay_exit_budget, &cancellation),
            )
            .expect("cached target exit profile");
        assert_eq!(
            transfer_outcome.available_value(),
            replay_transfer_outcome.available_value(),
            "a restarted trial receives the exact call transfer result"
        );
        assert_eq!(
            exit_outcome.available_value(),
            replay_exit_outcome.available_value(),
            "a restarted trial receives the exact exit profile result"
        );
        assert_eq!(replay_transfer_outcome.work(), SemanticWork::default());
        assert_eq!(replay_exit_outcome.work(), SemanticWork::default());
        assert_eq!(replay_transfer_budget.used(), SemanticWork::default());
        assert_eq!(replay_exit_budget.used(), SemanticWork::default());
        assert_eq!(
            provider
                .outcome_cache
                .call_transfers
                .lock()
                .expect("query-local ICFG cache mutex is not poisoned")
                .len(),
            1,
            "both trials materialize one call-transfer outcome for the exact key"
        );
        assert_eq!(
            provider
                .outcome_cache
                .exit_profiles
                .lock()
                .expect("query-local ICFG cache mutex is not poisoned")
                .len(),
            1,
            "both trials materialize one exit-profile outcome for the exact key"
        );

        let other_exit = other
            .point_handle(other.semantics().normal_exit_point())
            .expect("other normal exit");
        assert_eq!(
            other_exit.id(),
            exit.id(),
            "fixture procedures reuse local point IDs"
        );
        let mut cross_procedure_budget = SemanticBudget::default();
        assert!(
            replay_provider
                .exit_profile(
                    &incoming.callee_entry,
                    &other_exit,
                    &mut SemanticRequest::new(&mut cross_procedure_budget, &cancellation),
                )
                .is_err(),
            "an exact-handle cache key must not alias an exit from another procedure"
        );
        assert_eq!(cross_procedure_budget.used(), SemanticWork::default());

        let enriched_provider = fixture.analyzer.icfg_provider();
        let enriched_execution = SemanticExecutionBudget::new(16);
        let mut enriched_transfer_budget = SemanticBudget::default();
        let enriched_transfer = enriched_provider
            .call_transfers(
                &caller,
                semantic_call.id,
                &mut SemanticRequest::with_execution_budget(
                    &mut enriched_transfer_budget,
                    &cancellation,
                    &enriched_execution,
                ),
            )
            .expect("execution-budgeted call transfer");
        let enriched_incoming = enriched_transfer
            .available_value()
            .and_then(|transfers| {
                transfers
                    .transfers
                    .iter()
                    .find(|transfer| transfer.callee == target)
            })
            .expect("execution-budgeted target transfer")
            .clone();
        let mut enriched_exit_budget = SemanticBudget::default();
        let enriched_exit = enriched_provider
            .exit_profile(
                &enriched_incoming.callee_entry,
                &exit,
                &mut SemanticRequest::with_execution_budget(
                    &mut enriched_exit_budget,
                    &cancellation,
                    &enriched_execution,
                ),
            )
            .expect("execution-budgeted exit profile");
        assert_ne!(enriched_transfer.work(), SemanticWork::default());
        assert_ne!(enriched_exit.work(), SemanticWork::default());
        assert!(
            enriched_provider
                .outcome_cache
                .call_transfers
                .lock()
                .expect("query-local ICFG cache mutex is not poisoned")
                .is_empty(),
            "an enriched request must not populate the bare-request cache"
        );
        assert!(
            enriched_provider
                .outcome_cache
                .exit_profiles
                .lock()
                .expect("query-local ICFG cache mutex is not poisoned")
                .is_empty(),
            "an enriched request must not populate the bare-request cache"
        );

        let mut bare_transfer_budget = SemanticBudget::default();
        let bare_transfer = enriched_provider
            .call_transfers(
                &caller,
                semantic_call.id,
                &mut SemanticRequest::new(&mut bare_transfer_budget, &cancellation),
            )
            .expect("bare call transfer after enriched request");
        let mut bare_exit_budget = SemanticBudget::default();
        let bare_exit = enriched_provider
            .exit_profile(
                &incoming.callee_entry,
                &exit,
                &mut SemanticRequest::new(&mut bare_exit_budget, &cancellation),
            )
            .expect("bare exit profile after enriched request");
        assert_ne!(bare_transfer.work(), SemanticWork::default());
        assert_ne!(bare_exit.work(), SemanticWork::default());
        assert_eq!(
            enriched_transfer.available_value(),
            bare_transfer.available_value()
        );
        assert_eq!(enriched_exit.available_value(), bare_exit.available_value());

        let replay_execution = SemanticExecutionBudget::new(16);
        let mut enriched_replay_transfer_budget = SemanticBudget::default();
        let enriched_replay_transfer = enriched_provider
            .call_transfers(
                &caller,
                semantic_call.id,
                &mut SemanticRequest::with_execution_budget(
                    &mut enriched_replay_transfer_budget,
                    &cancellation,
                    &replay_execution,
                ),
            )
            .expect("enriched call transfer after bare cache population");
        let mut enriched_replay_exit_budget = SemanticBudget::default();
        let enriched_replay_exit = enriched_provider
            .exit_profile(
                &incoming.callee_entry,
                &exit,
                &mut SemanticRequest::with_execution_budget(
                    &mut enriched_replay_exit_budget,
                    &cancellation,
                    &replay_execution,
                ),
            )
            .expect("enriched exit profile after bare cache population");
        assert_ne!(enriched_replay_transfer.work(), SemanticWork::default());
        assert_ne!(enriched_replay_exit.work(), SemanticWork::default());

        let mut mismatched_profile_budget = SemanticBudget::default();
        assert!(
            provider
                .exit_profile(
                    &caller_entry,
                    &exit,
                    &mut SemanticRequest::new(&mut mismatched_profile_budget, &cancellation),
                )
                .is_err(),
            "profile entry and exit must belong to one procedure"
        );
        assert_eq!(
            mismatched_profile_budget.used(),
            SemanticWork::default(),
            "invalid profile topology must not own semantic work"
        );

        let MatchedReturnProjection::Edge {
            edge: return_edge, ..
        } = profile
            .project_matched_return(&incoming)
            .expect("matched target return")
        else {
            panic!("target normal exit must project a return edge");
        };
        assert_eq!(return_edge.source, exit);
        assert_eq!(return_edge.target.procedure(), &caller);
        assert_eq!(return_edge.kind, IcfgEdgeKind::NormalReturn);
        assert_eq!(return_edge.origin.as_ref(), Some(&incoming.origin));
        assert_eq!(return_edge.proof, incoming.proof);
        assert_eq!(return_edge.completeness, incoming.completeness);

        let exceptional_exit = target
            .point_handle(target.semantics().exceptional_exit_point())
            .expect("target exceptional exit");
        let abort_profile = IcfgExitProfile {
            callee_entry: incoming.callee_entry.clone(),
            callee_exit: exceptional_exit,
            kind: ReturnTransferKind::Exceptional,
            gap_reason: Some("unsupported exceptional_control_flow: implicit abort".into()),
            matched_return_has_gaps: true,
            matched_return_gap_reason: Some(
                "unsupported exceptional_control_flow: implicit abort".into(),
            ),
            matched_return_gaps_are_implicit_abort_only: true,
            quality: SnapshotQuality::Unsupported(SemanticCapability::ExceptionalControlFlow),
        };
        let projection_is_abort_only = |incoming: &CallTransfer| {
            let MatchedReturnProjection::Edge {
                implicit_abort_only,
                ..
            } = abort_profile
                .project_matched_return(incoming)
                .expect("implicit-abort exceptional return")
            else {
                panic!("target exceptional exit must project a return edge");
            };
            implicit_abort_only
        };
        assert!(
            projection_is_abort_only(&incoming),
            "a proven complete incoming transfer leaves only the implicit-abort weakening"
        );
        let mut unproven_incoming = incoming.clone();
        unproven_incoming.proof = ProofStatus::Unproven("independent dispatch uncertainty".into());
        assert!(
            !projection_is_abort_only(&unproven_incoming),
            "independently unproven incoming evidence must remain distinct"
        );
        let mut partial_incoming = incoming.clone();
        partial_incoming.completeness =
            EvidenceCompleteness::Partial("independent call-transfer gap".into());
        assert!(
            !projection_is_abort_only(&partial_incoming),
            "independently partial incoming evidence must remain distinct"
        );

        let mut mismatched_entry = incoming.clone();
        mismatched_entry.callee_entry = exit.clone();
        assert!(
            profile.project_matched_return(&mismatched_entry).is_err(),
            "matched returns require the exact profiled entry"
        );

        let mut unknown_continuation = incoming;
        unknown_continuation.normal_continuation = ControlContinuation::Unknown;
        let MatchedReturnProjection::Boundary(boundary) = profile
            .project_matched_return(&unknown_continuation)
            .expect("unknown return continuation")
        else {
            panic!("unknown continuation must remain a typed boundary");
        };
        assert_eq!(boundary.at, exit);
        assert_eq!(boundary.origin.as_ref(), Some(&unknown_continuation.origin));
        assert_eq!(
            boundary.kind,
            IcfgBoundaryKind::Continuation {
                kind: CallContinuationKind::Normal,
                state: ControlContinuation::Unknown,
            }
        );
    }
}
