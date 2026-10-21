#[cfg(test)]
mod cpp_semantic_extraction {
    mod icfg {
        use brokk_bifrost_analysis::analyzer::semantic::DispatchOracle;

        use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::CandidateCoverage;

        use brokk_bifrost_analysis::analyzer::semantic::oracle::model::DispatchBoundaryKind;

        use brokk_bifrost_analysis::analyzer::semantic::ir::model::EvidenceCompleteness;

        use brokk_bifrost_analysis::analyzer::semantic::icfg::IcfgEdgeKind;

        use brokk_bifrost_analysis::analyzer::semantic::icfg::IcfgSnapshotLimits;

        use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProofStatus;

        use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapability;

        use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapImpact;
        use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapKind;
        use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapSubject;

        use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;

        use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
        use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticWork;

        use brokk_bifrost_core::analyzer::model::ProjectFile;

        use brokk_bifrost_analysis::analyzer::semantic::icfg::*;

        use brokk_bifrost_analysis::analyzer::semantic::ids::DeclarationSegment;

        use crate::analyzer::semantic::SemanticBudget;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::test_support::AnalyzerFixture;
        use brokk_bifrost_test_macros::hardwon;
        #[test]
        #[hardwon("#1372: a bodyless C/C++ declaration lost its unresolved call boundary")]
        fn cpp_bodyless_callable_identity_emits_one_unresolved_boundary() {
            let header = "#pragma once\nint target(int value);\n";
            let caller = "#include \"target.h\"\nint caller() { return target(1); }\n";
            let fixture = AnalyzerFixture::new_for_language(
                brokk_bifrost_core::analyzer::model::Language::Cpp,
                &[("target.h", header), ("caller.cpp", caller)],
            );
            let caller_file = ProjectFile::new(fixture.project_root(), "caller.cpp");
            let cancellation = CancellationToken::default();
            let mut materialization_budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &caller_file,
                    &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                )
                .expect("C++ caller materialization")
                .available_value()
                .cloned()
                .expect("C++ caller artifact");
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
                .expect("C++ exact dispatch");
            let dispatch = outcome.available_value().expect("dispatch payload");

            assert!(!matches!(&outcome, SemanticOutcome::Complete { .. }));
            assert!(dispatch.candidates().is_empty(), "{dispatch:#?}");
            assert_eq!(dispatch.boundaries().len(), 1, "{dispatch:#?}");
            assert_eq!(
                dispatch.boundaries()[0].kind,
                DispatchBoundaryKind::Unresolved,
                "{dispatch:#?}"
            );
            assert!(matches!(
                dispatch.boundaries()[0].proof,
                ProofStatus::Unproven(_)
            ));
            assert!(matches!(
                dispatch.boundaries()[0].completeness,
                EvidenceCompleteness::Partial(_)
            ));
        }
        #[test]
        fn cpp_conditional_noexcept_gap_downgrades_exceptional_return() {
            let source = r#"
void conditional_target() noexcept(sizeof(int) == 4) {
    throw 1;
}

void conditional_caller() {
    conditional_target();
}
"#;
            let fixture = AnalyzerFixture::new_for_language(
                brokk_bifrost_core::analyzer::model::Language::Cpp,
                &[("conditional_noexcept.cpp", source)],
            );
            let file = ProjectFile::new(fixture.project_root(), "conditional_noexcept.cpp");
            let cancellation = CancellationToken::default();
            let mut materialization_budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                )
                .expect("conditional-noexcept materialization")
                .available_value()
                .cloned()
                .expect("conditional-noexcept artifact");
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
                        == Some("conditional_caller")
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .expect("conditional caller procedure");

            let mut snapshot_budget = SemanticBudget::default();
            let outcome = fixture
                .analyzer
                .icfg_provider()
                .snapshot(
                    &caller,
                    IcfgSnapshotLimits::default(),
                    &mut SemanticRequest::new(&mut snapshot_budget, &cancellation),
                )
                .expect("conditional-noexcept ICFG snapshot");
            assert!(matches!(&outcome, SemanticOutcome::Unproven { .. }));
            let snapshot = outcome
                .available_value()
                .expect("conditional-noexcept partial snapshot");
            let exceptional_returns = snapshot
                .edges()
                .iter()
                .filter(|edge| edge.kind == IcfgEdgeKind::ExceptionalReturn)
                .collect::<Vec<_>>();
            assert_eq!(exceptional_returns.len(), 1, "{snapshot:#?}");
            assert!(matches!(
                exceptional_returns[0].proof,
                ProofStatus::Unproven(_)
            ));
            assert!(matches!(
                exceptional_returns[0].completeness,
                EvidenceCompleteness::Partial(_)
            ));
        }
        #[test]
        fn cpp_dynamic_dispatch_gap_adds_an_open_target_arm_only_to_virtual_stitch() {
            let source = r#"
struct Base {
    virtual int dynamic_call(int value) { return value; }
    int direct_call(int value) { return value + 1; }
};

int invoke_dynamic(Base* receiver) {
    return receiver->dynamic_call(1);
}

int invoke_direct(Base* receiver) {
    return receiver->Base::direct_call(1);
}
"#;
            let fixture = AnalyzerFixture::new_for_language(
                brokk_bifrost_core::analyzer::model::Language::Cpp,
                &[("dispatch.cpp", source)],
            );
            let file = ProjectFile::new(fixture.project_root(), "dispatch.cpp");
            let cancellation = CancellationToken::default();
            let mut materialization_budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                )
                .expect("C++ dispatch materialization")
                .available_value()
                .cloned()
                .expect("C++ dispatch artifact");
            let procedure = |name: &str| {
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
            let dynamic_caller = procedure("invoke_dynamic");
            let direct_caller = procedure("invoke_direct");
            let dynamic_call = dynamic_caller
                .semantics()
                .call_sites()
                .first()
                .expect("dynamic call site");
            let direct_call = direct_caller
                .semantics()
                .call_sites()
                .first()
                .expect("direct call site");

            assert!(dynamic_caller.semantics().gaps().iter().any(|gap| {
                gap.point == dynamic_call.point
                    && gap.capability == SemanticCapability::DynamicDispatch
                    && gap.impacts.contains(SemanticGapImpact::DispatchCoverage)
                    && (gap.subject == SemanticGapSubject::Point
                        || gap.subject == SemanticGapSubject::CallSite(dynamic_call.id))
            }));
            assert!(!direct_caller.semantics().gaps().iter().any(|gap| {
                gap.point == direct_call.point
                    && gap.capability == SemanticCapability::DynamicDispatch
                    && (gap.subject == SemanticGapSubject::Point
                        || gap.subject == SemanticGapSubject::CallSite(direct_call.id))
            }));
            assert!(!direct_caller.semantics().gaps().iter().any(|gap| {
                gap.point == direct_call.point
                    && gap.subject == SemanticGapSubject::CallSite(direct_call.id)
                    && (gap.impacts.contains(SemanticGapImpact::CallEvaluation)
                        || gap.impacts.contains(SemanticGapImpact::DispatchCoverage))
            }));

            let provider = fixture.analyzer.icfg_provider();
            let dynamic_call_handle = dynamic_caller
                .call_site_handle(dynamic_call.id)
                .expect("dynamic call handle");
            let direct_call_handle = direct_caller
                .call_site_handle(direct_call.id)
                .expect("direct call handle");
            let mut dynamic_dispatch_budget = SemanticBudget::default();
            let dynamic_dispatch = provider
                .resolve_call(
                    &dynamic_call_handle,
                    &mut SemanticRequest::new(&mut dynamic_dispatch_budget, &cancellation),
                )
                .expect("virtual C++ dispatch")
                .available_value()
                .cloned()
                .expect("virtual C++ dispatch payload");
            assert_eq!(dynamic_dispatch.coverage(), CandidateCoverage::Open);

            let mut direct_dispatch_budget = SemanticBudget::default();
            let direct_dispatch_outcome = provider
                .resolve_call(
                    &direct_call_handle,
                    &mut SemanticRequest::new(&mut direct_dispatch_budget, &cancellation),
                )
                .expect("qualified C++ dispatch");
            assert!(matches!(
                &direct_dispatch_outcome,
                SemanticOutcome::Complete { .. }
            ));
            let direct_dispatch = direct_dispatch_outcome
                .available_value()
                .cloned()
                .expect("qualified C++ dispatch payload");
            assert_eq!(direct_dispatch.coverage(), CandidateCoverage::Exhaustive);
            assert_eq!(
                direct_dispatch.candidates().len(),
                1,
                "{direct_dispatch:#?}"
            );
            assert!(matches!(
                direct_dispatch.candidates()[0].proof,
                ProofStatus::Proven
            ));
            assert!(matches!(
                direct_dispatch.candidates()[0].completeness,
                EvidenceCompleteness::Complete
            ));
            let direct_dispatch_work = direct_dispatch_outcome.work();
            let mut projection_limits = SemanticBudget::default().limits();
            let retained_nested = direct_dispatch_budget.resident_peak().nested_entries;
            assert!(retained_nested > 0);
            projection_limits.nested_entries = retained_nested - 1;
            let mut projection_budget = SemanticBudget::new_child(
                projection_limits,
                &SemanticBudget::default().scope_snapshot(),
            );
            let projection_limited = provider
                .resolve_call(
                    &direct_call_handle,
                    &mut SemanticRequest::new(&mut projection_budget, &cancellation),
                )
                .expect("projection-limited dispatch");
            assert!(matches!(
                projection_limited,
                SemanticOutcome::ExceededBudget {
                    partial: None,
                    work,
                    ..
                } if work.nested_entries == direct_dispatch_work.nested_entries
            ));
            assert_eq!(projection_budget.resident(), SemanticWork::default());

            let mut dynamic_budget = SemanticBudget::default();
            let dynamic_outcome = provider
                .call_transfers(
                    &dynamic_caller,
                    dynamic_call.id,
                    &mut SemanticRequest::new(&mut dynamic_budget, &cancellation),
                )
                .expect("virtual C++ call transfers");
            assert!(matches!(&dynamic_outcome, SemanticOutcome::Unproven { .. }));
            let dynamic = dynamic_outcome
                .available_value()
                .expect("virtual dispatch transfers");
            assert_eq!(dynamic.transfers.len(), 1, "{dynamic:#?}");
            assert!(matches!(&dynamic.transfers[0].proof, ProofStatus::Proven));
            // The open virtual target set does not weaken this retained
            // candidate's proof or its represented normal call mechanics.
            assert_eq!(
                dynamic.transfers[0].completeness,
                EvidenceCompleteness::Complete
            );
            assert!(dynamic.boundaries.iter().any(|boundary| {
                boundary.dispatch.kind == DispatchBoundaryKind::Unresolved
                    && matches!(&boundary.dispatch.proof, ProofStatus::Unproven(_))
                    && matches!(
                        &boundary.dispatch.completeness,
                        EvidenceCompleteness::Partial(_)
                    )
            }));

            let mut direct_budget = SemanticBudget::default();
            let direct_outcome = provider
                .call_transfers(
                    &direct_caller,
                    direct_call.id,
                    &mut SemanticRequest::new(&mut direct_budget, &cancellation),
                )
                .expect("explicitly qualified C++ call transfers");
            assert!(matches!(&direct_outcome, SemanticOutcome::Complete { .. }));
            let direct = direct_outcome
                .available_value()
                .expect("non-virtual dispatch transfers");
            assert_eq!(direct.transfers.len(), 1, "{direct:#?}");
            assert!(matches!(&direct.transfers[0].proof, ProofStatus::Proven));
            assert_eq!(
                direct.transfers[0].completeness,
                EvidenceCompleteness::Complete
            );
            assert!(direct.boundaries.is_empty(), "{direct:#?}");
            // This fresh ledger also admits source retained by an earlier
            // dispatch session, outside this transfer's incremental census.
            assert_eq!(
                direct_budget.used(),
                direct_outcome.work().conservative_add(SemanticWork {
                    source_bytes: source.len(),
                    ..SemanticWork::default()
                })
            );
            assert_eq!(direct_budget.resident().source_bytes, source.len());
        }
        #[test]
        #[hardwon("#1372: header declarations acquired false C/C++ value-flow targets")]
        fn cpp_header_definition_coalescing_is_proven_and_excludes_unrelated_link_unit() {
            let header = "#pragma once\nnamespace api { int target(int value); }\n";
            let definition = concat!(
                "#include \"target.h\"\n",
                "namespace api { int target(int value) { return value + 1; } }\n",
            );
            let unrelated_header = "#pragma once\nnamespace api { int target(int value); }\n";
            let unrelated = concat!(
                "#include \"target.h\"\n",
                "namespace api { int target(int value) { return value + 2; } }\n",
            );
            let caller = concat!(
                "#include \"target.h\"\n",
                "int caller() { return api::target(1); }\n",
            );
            let fixture = AnalyzerFixture::new_for_language(
                brokk_bifrost_core::analyzer::model::Language::Cpp,
                &[
                    ("target.h", header),
                    ("target.cpp", definition),
                    ("other/target.h", unrelated_header),
                    ("other/target.cpp", unrelated),
                    ("caller.cpp", caller),
                ],
            );
            let caller_file = ProjectFile::new(fixture.project_root(), "caller.cpp");
            let cancellation = CancellationToken::default();
            let mut materialization_budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &caller_file,
                    &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                )
                .expect("C++ caller materialization")
                .available_value()
                .cloned()
                .expect("C++ caller artifact");
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
                .expect("C++ exact dispatch");
            let dispatch = outcome.available_value().expect("dispatch payload");

            assert!(matches!(&outcome, SemanticOutcome::Complete { .. }));
            assert_eq!(dispatch.candidates().len(), 1, "{dispatch:#?}");
            assert_eq!(dispatch.candidates()[0].proof, ProofStatus::Proven);
            assert_eq!(
                dispatch.candidates()[0].completeness,
                EvidenceCompleteness::Complete
            );
            assert_eq!(
                dispatch.candidates()[0]
                    .target
                    .artifact()
                    .key()
                    .path()
                    .as_str(),
                "target.cpp"
            );
            assert!(dispatch.boundaries().is_empty(), "{dispatch:#?}");

            let pre_cancelled = CancellationToken::default();
            pre_cancelled.cancel();
            let mut cancelled_budget = SemanticBudget::default();
            let cancelled = fixture
                .analyzer
                .icfg_provider()
                .resolve_call(
                    &call,
                    &mut SemanticRequest::new(&mut cancelled_budget, &pre_cancelled),
                )
                .expect("pre-cancelled dispatch");
            assert!(matches!(
                cancelled,
                SemanticOutcome::Cancelled {
                    partial: None,
                    work
                } if work == SemanticWork::default()
            ));
            assert_eq!(cancelled_budget.used(), SemanticWork::default());
        }
        #[test]
        fn cpp_preprocessor_call_gap_opens_the_set_without_weakening_retained_candidates() {
            let source = r#"
int enabled_target(int value) { return value + 1; }
int disabled_target(int value) { return value + 2; }

int configured_caller(int value) {
#if FEATURE_ENABLED
    return enabled_target(value);
#else
    return disabled_target(value);
#endif
}
"#;
            let fixture = AnalyzerFixture::new_for_language(
                brokk_bifrost_core::analyzer::model::Language::Cpp,
                &[("configured.cpp", source)],
            );
            let file = ProjectFile::new(fixture.project_root(), "configured.cpp");
            let cancellation = CancellationToken::default();
            let mut materialization_budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                )
                .expect("C++ preprocessor materialization")
                .available_value()
                .cloned()
                .expect("C++ preprocessor artifact");
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
                        == Some("configured_caller")
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .expect("configured caller procedure");
            assert!(caller.semantics().gaps().iter().any(|gap| {
                gap.subject == SemanticGapSubject::Procedure
                    && gap.capability == SemanticCapability::Calls
                    && gap.kind == SemanticGapKind::Unsupported
                    && gap.impacts.contains(SemanticGapImpact::DispatchCoverage)
            }));
            let call = caller
                .semantics()
                .call_sites()
                .first()
                .and_then(|call| caller.call_site_handle(call.id))
                .expect("conditionally compiled call site");

            let mut dispatch_budget = SemanticBudget::default();
            let outcome = fixture
                .analyzer
                .icfg_provider()
                .resolve_call(
                    &call,
                    &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
                )
                .expect("preprocessor call dispatch");
            let dispatch = outcome.available_value().expect("dispatch payload");

            assert!(matches!(&outcome, SemanticOutcome::Unproven { .. }));
            assert_eq!(dispatch.coverage(), CandidateCoverage::Open);
            assert_eq!(dispatch.candidates().len(), 1, "{dispatch:#?}");
            assert!(matches!(
                &dispatch.candidates()[0].proof,
                ProofStatus::Proven
            ));
            assert!(matches!(
                &dispatch.candidates()[0].completeness,
                EvidenceCompleteness::Complete
            ));
            assert!(dispatch.boundaries().iter().any(|boundary| {
                boundary.kind == DispatchBoundaryKind::Unresolved
                    && matches!(&boundary.proof, ProofStatus::Unproven(_))
                    && matches!(&boundary.completeness, EvidenceCompleteness::Partial(_))
            }));
        }
        #[test]
        fn cpp_raii_exit_gap_downgrades_normal_return() {
            let source = r#"
struct Guard {
    Guard();
    ~Guard();
};

Guard make_guard();

void temporary_target() {
    make_guard();
}

Guard *pointer_target(Guard *value) {
    Guard *copy = value;
    return copy;
}

void raii_target() {
    Guard guard;
}

void raii_caller() {
    raii_target();
}
"#;
            let fixture = AnalyzerFixture::new_for_language(
                brokk_bifrost_core::analyzer::model::Language::Cpp,
                &[("raii_return.cpp", source)],
            );
            let file = ProjectFile::new(fixture.project_root(), "raii_return.cpp");
            let cancellation = CancellationToken::default();
            let mut materialization_budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                )
                .expect("RAII materialization")
                .available_value()
                .cloned()
                .expect("RAII artifact");
            let procedure = |name: &str| {
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
            let caller = procedure("raii_caller");
            let temporary_target = procedure("temporary_target");
            let pointer_target = procedure("pointer_target");
            assert!(temporary_target.semantics().gaps().iter().any(|gap| {
                gap.point == temporary_target.semantics().normal_exit_point()
                    && gap.capability == SemanticCapability::ResourceManagement
            }));
            assert!(!pointer_target.semantics().gaps().iter().any(|gap| {
                gap.point == pointer_target.semantics().normal_exit_point()
                    && gap.capability == SemanticCapability::ResourceManagement
            }));

            let mut snapshot_budget = SemanticBudget::default();
            let outcome = fixture
                .analyzer
                .icfg_provider()
                .snapshot(
                    &caller,
                    IcfgSnapshotLimits::default(),
                    &mut SemanticRequest::new(&mut snapshot_budget, &cancellation),
                )
                .expect("RAII ICFG snapshot");
            assert!(matches!(&outcome, SemanticOutcome::Unproven { .. }));
            let snapshot = outcome.available_value().expect("RAII partial snapshot");
            let normal_returns = snapshot
                .edges()
                .iter()
                .filter(|edge| edge.kind == IcfgEdgeKind::NormalReturn)
                .collect::<Vec<_>>();
            assert_eq!(normal_returns.len(), 1, "{snapshot:#?}");
            assert!(matches!(normal_returns[0].proof, ProofStatus::Unproven(_)));
            assert!(matches!(
                normal_returns[0].completeness,
                EvidenceCompleteness::Partial(_)
            ));
        }
        #[test]
        fn cpp_syntax_error_elsewhere_does_not_weaken_an_exact_call_dispatch() {
            let source = r#"
int exact_target() { return 1; }

int caller_with_error() {
    int malformed = ;
    return exact_target();
}
"#;
            let fixture = AnalyzerFixture::new_for_language(
                brokk_bifrost_core::analyzer::model::Language::Cpp,
                &[("syntax_error.cpp", source)],
            );
            let file = ProjectFile::new(fixture.project_root(), "syntax_error.cpp");
            let cancellation = CancellationToken::default();
            let mut materialization_budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                )
                .expect("C++ syntax-error materialization")
                .available_value()
                .cloned()
                .expect("C++ syntax-error artifact");
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
                        == Some("caller_with_error")
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .expect("caller procedure");
            let call = caller
                .semantics()
                .call_sites()
                .first()
                .and_then(|call| caller.call_site_handle(call.id))
                .expect("exact target call site");

            assert!(caller.semantics().gaps().iter().any(|gap| {
                gap.subject == SemanticGapSubject::Procedure
                    && gap.capability == SemanticCapability::Calls
                    && gap.kind == SemanticGapKind::Unsupported
                    && !gap.impacts.contains(SemanticGapImpact::DispatchCoverage)
            }));

            let mut dispatch_budget = SemanticBudget::default();
            let outcome = fixture
                .analyzer
                .icfg_provider()
                .resolve_call(
                    &call,
                    &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
                )
                .expect("exact C++ dispatch despite unrelated syntax error");
            assert!(matches!(&outcome, SemanticOutcome::Complete { .. }));
            let dispatch = outcome.available_value().expect("exact dispatch payload");
            assert_eq!(dispatch.coverage(), CandidateCoverage::Exhaustive);
            assert_eq!(dispatch.candidates().len(), 1, "{dispatch:#?}");
        }
    }

    mod workspace_oracle_dispatch {

        pub (super) use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::assert_proven_local_dispatch as assert_proven_local_dispatch;

        pub (super) use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::calls_in_source_order as calls_in_source_order;

        pub (super) use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::external_call_identities as external_call_identities;

        pub (super) use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::semantic_call_fixture_for_language as semantic_call_fixture_for_language;
use std::sync::Arc;
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;
use brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind;
use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind;
use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLookup;

        use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableTarget;
        use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableTargetResolution;

        use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::CandidateCoverage;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;

        use brokk_bifrost_core::analyzer::model::LanguageDialect;

        use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::PreparedCallDispatch;

        use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProofStatus;

        use brokk_bifrost_core::analyzer::model::LanguageDialect as SemanticLanguage;

        use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;

        use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;

        use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::resolver_proven_external_static_boundary;
        use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::scoped_call_dispatch_gap;

        use crate::analyzer::semantic::SemanticBudget;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_core::analyzer::model::ProjectFile;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::test_support::AnalyzerFixture;

        /// The C++ fixture behind the #2606 acceptance. It holds one external call
        /// per qualification shape plus the two workspace-defined controls that
        /// must keep resolving in the workspace.
        const CPP_EXTERNAL_CALL_SOURCE: &str = r#"namespace app {

struct Local {
    static int stat(const char* p) { return 1; }
};

int helper(const char* p) { return 2; }

int run(const char* p) {
    return std::filesystem::exists(p)
        + ns::Type::method(p)
        + ns::f(p)
        + app::Local::stat(p)
        + app::helper(p);
}

}
"#;
        /// #2606: a `::`-qualified C++ callee with no workspace definition
        /// publishes the dot-joined canonical identity an authored
        /// `std.filesystem.exists` summary is posted under.
        ///
        /// The cut takes the last separator, so `ns::Type::method` is owner
        /// `ns.Type` and member `method`, never owner `ns` and member
        /// `Type::method`.
        ///
        /// `has_receiver` is `false` for all of them: C++ lowers a call receiver
        /// only for a `field_expression` target (`obj.method()`), never for a
        /// `qualified_identifier`, so an authored C++ summary for a qualified
        /// callee must declare `"has_receiver": false`.
        ///
        /// A single-segment owner (`ns::f`) names no identity. C++ does not
        /// publish single-segment external owners (#2598) and has no import binder
        /// that could expand one, so such a call keeps the boundary it had.
        #[test]
        fn a_qualified_cpp_callee_publishes_a_dot_joined_external_identity() {
            let identities =
                external_call_identities(Language::Cpp, "app.cpp", CPP_EXTERNAL_CALL_SOURCE);
            assert_eq!(
                identities,
                vec![
                    // Defined in this workspace, so it resolves rather than
                    // minting an external identity.
                    ("app::Local::stat(p)".to_owned(), None),
                    ("app::helper(p)".to_owned(), None),
                    (
                        "ns::Type::method(p)".to_owned(),
                        Some(("ns.Type".to_owned(), "method".to_owned(), 1, false))
                    ),
                    // A single-segment owner is out of scope for the same reason
                    // Rust's prelude spelling is.
                    ("ns::f(p)".to_owned(), None),
                    (
                        "std::filesystem::exists(p)".to_owned(),
                        Some(("std.filesystem".to_owned(), "exists".to_owned(), 1, false))
                    ),
                ]
            );
        }
        #[test]
        fn c_header_function_proof_closes_static_dispatch_gap() {
            let source = "void caller() { getenv(\"X\"); }\n";
            let (fixture, call) =
                semantic_call_fixture_for_language(Language::Cpp, "caller.c", source);
            assert_eq!(
                call.procedure().artifact().key().language(),
                LanguageDialect::CppC
            );
            let semantic_call = call
                .procedure()
                .semantics()
                .call_site(call.id())
                .expect("call belongs to its procedure");
            assert!(
                scoped_call_dispatch_gap(call.procedure().semantics(), semantic_call).is_none(),
                "a direct C function call has no receiver dispatch gap"
            );

            let proof = ExactExternalCallProof::c_header_function("stdlib", "getenv", 1);
            let oracle = fixture.analyzer.semantic_oracle_provider();
            let cancellation = CancellationToken::default();
            let mut budget = SemanticBudget::default();
            let outcome = oracle
                .resolve_prepared_call(
                    &call,
                    PreparedCallDispatch {
                        lookup: CallDispatchLookup {
                            status: Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                            boundary: Some(BoundaryStatus::ExternalIndexed),
                            boundaries: vec![CallDispatchBoundaryKind::External {
                                callee_text: Some(proof.canonical_callee().into()),
                                normalized_static_owner: None,
                                external_callee_identity: None,
                            }],
                            call_application: CallApplicationKind::PackageFunction,
                            exact_external_call: Some(proof),
                            ..CallDispatchLookup::default()
                        },
                    },
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("C header dispatch");
            let SemanticOutcome::Complete { value, .. } = outcome else {
                panic!("an exact C header function proof must close dispatch: {outcome:#?}");
            };
            assert_eq!(value.coverage(), CandidateCoverage::Exhaustive);
            let [boundary] = value.boundaries() else {
                panic!("one external C header boundary: {value:#?}");
            };
            let target = boundary
                .unmaterialized_external_target
                .as_ref()
                .expect("C header function external identity");
            assert_eq!(target.owner_fqn(), "stdlib");
            assert_eq!(target.member(), "getenv");
            assert_eq!(target.arity(), 1);
            assert!(!target.has_receiver());
            assert_eq!(target.language(), SemanticLanguage::Standard(Language::Cpp));
            assert!(target.resolver_proves_static_call());
            assert_eq!(boundary.proof, ProofStatus::Proven);
            assert!(resolver_proven_external_static_boundary(
                Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                &[],
                std::slice::from_ref(boundary),
            ));
        }
        #[test]
        fn cpp_adapter_proven_local_function_pointer_bypasses_source_rediscovery() {
            let source =
                "void target() {}\nvoid caller() { void (*callback)() = &target; callback(); }\n";
            let fixture =
                AnalyzerFixture::new_for_language(Language::Cpp, &[("callback.cpp", source)]);
            let file = ProjectFile::new(fixture.project_root(), "callback.cpp");
            let cancellation = CancellationToken::default();
            let mut materialization_budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                )
                .expect("C++ semantic materialization")
                .available_value()
                .cloned()
                .expect("C++ semantic artifact");
            let proven_calls = calls_in_source_order(&artifact)
                .into_iter()
                .filter(|call| {
                    matches!(
                        call.procedure()
                            .semantics()
                            .call_site(call.id())
                            .expect("call belongs to its procedure")
                            .declared_targets,
                        CallableTargetResolution::Proven(CallableTarget::Local(_))
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(
                proven_calls.len(),
                1,
                "the stable pointer invocation is the sole exact local call: {:#?}",
                calls_in_source_order(&artifact)
                    .iter()
                    .map(|call| call
                        .procedure()
                        .semantics()
                        .call_site(call.id())
                        .expect("call belongs to its procedure"))
                    .collect::<Vec<_>>()
            );

            let call = &proven_calls[0];
            let declared_target = match call
                .procedure()
                .semantics()
                .call_site(call.id())
                .expect("call belongs to its procedure")
                .declared_targets
            {
                CallableTargetResolution::Proven(CallableTarget::Local(target)) => target,
                ref other => panic!("expected one C++ local target, got {other:?}"),
            };
            let mut session = fixture
                .analyzer
                .semantic_oracle_provider()
                .prepare_call_dispatch_session(Arc::clone(call.procedure().artifact()));
            let mut dispatch_budget = SemanticBudget::default();
            let outcome = session
                .resolve_call(
                    call,
                    &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
                )
                .expect("adapter-proven C++ pointer dispatch");
            let SemanticOutcome::Complete { value, .. } = outcome else {
                panic!("adapter-proven C++ local dispatch must be complete: {outcome:?}");
            };

            assert_proven_local_dispatch(&value, declared_target);
        }
        #[test]
        fn unsafe_cpp_function_pointer_bindings_retain_no_initializer_target() {
            for (name, source) in [
                (
                    "reassigned.cpp",
                    "void first() {}\nvoid second() {}\nvoid caller() { void (*callback)() = &first; callback = &second; callback(); }\n",
                ),
                (
                    "copied.cpp",
                    "void target() {}\nvoid caller() { void (*callback)() = &target; auto escaped = callback; callback(); }\n",
                ),
                (
                    "address_escaped.cpp",
                    "void target() {}\nvoid caller() { void (*callback)() = &target; auto escaped = &callback; callback(); }\n",
                ),
                (
                    "passed.cpp",
                    "void target() {}\nvoid consume(void (*)()) {}\nvoid caller() { void (*callback)() = &target; consume(callback); callback(); }\n",
                ),
                (
                    "nonempty_signature.cpp",
                    "void target(int) {}\nvoid caller() { void (*callback)(int) = &target; callback(1); }\n",
                ),
            ] {
                let fixture = AnalyzerFixture::new_for_language(Language::Cpp, &[(name, source)]);
                let file = ProjectFile::new(fixture.project_root(), name);
                let cancellation = CancellationToken::default();
                let mut budget = SemanticBudget::default();
                let artifact = fixture
                    .analyzer
                    .materialize_program_semantics(
                        &file,
                        &mut SemanticRequest::new(&mut budget, &cancellation),
                    )
                    .expect("C++ semantic materialization")
                    .available_value()
                    .cloned()
                    .expect("C++ semantic artifact");

                assert!(
                    calls_in_source_order(&artifact).into_iter().all(|call| {
                        !matches!(
                            call.procedure()
                                .semantics()
                                .call_site(call.id())
                                .expect("call belongs to its procedure")
                                .declared_targets,
                            CallableTargetResolution::Proven(CallableTarget::Local(_))
                        )
                    }),
                    "{name} must not retain an initializer target"
                );
            }
        }
    }

    mod workspace_oracle_value_flow {
        use brokk_bifrost_analysis::analyzer::semantic::ValueFlowOracle;

        use brokk_bifrost_analysis::analyzer::semantic::oracle::model::OracleCallContext;

        use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapability;

        use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
        use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;

        use brokk_bifrost_analysis::analyzer::semantic::oracle::value_flow::ValueFlowSnapshot;

        use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

        use brokk_bifrost_core::analyzer::model::Language;

        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_core::cancellation::CancellationToken;
        use brokk_bifrost_test_macros::hardwon;
        #[test]
        #[hardwon("#2835: unproven relation evidence masked typed value-flow incompleteness")]
        fn issue_2835_balanced_templates_preserve_their_typed_quality_bound() {
            fn assert_run_outcomes(
                language: Language,
                path: &str,
                source: &str,
                assert_outcome: impl Fn(&SemanticOutcome<ValueFlowSnapshot>),
            ) {
                let project = InlineTestProject::with_language(language)
                    .file(path, source)
                    .build();
                let file = project.file(path);
                let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
                let cancellation = CancellationToken::default();
                let mut materialization_budget =
                    crate::analyzer::semantic::SemanticBudget::default();
                let artifact = analyzer
                    .materialize_program_semantics(
                        &file,
                        &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                    )
                    .expect("semantic materialization runs")
                    .available_value()
                    .cloned()
                    .expect("semantic artifact is available");
                let oracle = analyzer.semantic_oracle_provider();

                for name in ["positive", "negative"] {
                    let procedure = artifact
                        .procedures()
                        .iter()
                        .find(|procedure| {
                            procedure
                                .locator()
                                .declaration()
                                .segments()
                                .last()
                                .and_then(|segment| segment.name())
                                == Some(name)
                        })
                        .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                        .unwrap_or_else(|| panic!("missing {name} procedure"));
                    let mut budget = crate::analyzer::semantic::SemanticBudget::default();
                    let outcome = oracle
                        .procedure_relations(
                            &procedure,
                            &OracleCallContext::empty(),
                            &mut SemanticRequest::new(&mut budget, &cancellation),
                        )
                        .expect("value-flow relation query runs");
                    assert_outcome(&outcome);
                    assert!(
                        outcome.available_value().is_some(),
                        "{name} must retain its partial relation artifact: {outcome:#?}"
                    );
                }
            }

            assert_run_outcomes(
                Language::Cpp,
                "kernel.c",
                r#"#include <string.h>
struct Record { const char *key; int value; };
int source(void) { return 1; }
void sink(int value) {}
void positive(void) {
    struct Record records[2];
    records[0].key = "record";
    records[0].value = source();
    for (int index = 0; index < 2; index++) {
        if (strcmp(records[index].key, "record") == 0) sink(records[index].value);
    }
}
void negative(void) {
    struct Record records[2];
    struct Record others[2];
    records[0].value = source();
    others[0].key = "record";
    others[0].value = 0;
    for (int index = 0; index < 2; index++) {
        if (strcmp(others[index].key, "record") == 0) sink(others[index].value);
    }
}
"#,
                |outcome| {
                    assert!(
                        matches!(outcome, SemanticOutcome::Unknown { .. }),
                        "dynamic-index evidence must not hide C's unknown call resolution: {outcome:#?}"
                    );
                },
            );

            assert_run_outcomes(
                Language::Cpp,
                "kernel.cpp",
                r#"struct FlowException { int value; };
int source() { return 1; }
void sink(int value) {}
void positive() {
    try {
        FlowException flow;
        flow.value = source();
        throw flow;
    } catch (FlowException &caught) {
        sink(caught.value);
    }
}
void negative() {
    try {
        FlowException flow;
        int ignored = source();
        flow.value = 0;
        throw flow;
    } catch (FlowException &caught) {
        sink(caught.value);
    }
}
"#,
                |outcome| {
                    assert!(
                        matches!(
                            outcome,
                            SemanticOutcome::Unsupported {
                                capability: SemanticCapability::ExceptionalControlFlow,
                                ..
                            }
                        ),
                        "unproven catch relations must retain C++'s typed handler-selection boundary: {outcome:#?}"
                    );
                },
            );
        }
    }

    mod structural_materialization_rows {

        use brokk_bifrost_analysis::analyzer::structural::materialization_rows::test_support::Fixture;

        use brokk_bifrost_core::analyzer::structural::materialization::GenerationKind;

        use brokk_bifrost_core::analyzer::structural::materialization::MaterializationAxis;

        use brokk_bifrost_core::analyzer::model::Language;

        /// C++ configuration gating: declarations inside a preprocessor
        /// conditional are gated, the axis reports that no active configuration
        /// is known, and a `#define` is a generation site producing its macro
        /// unit.
        #[test]
        fn cpp_config_gated_declarations_report_unknown_configuration() {
            let fixture = Fixture::new(
                Language::Cpp,
                "config.h",
                concat!(
                    "#define WIDGET_MAX 8\n",
                    "#ifdef USE_FAST\n",
                    "int fast_path();\n",
                    "#else\n",
                    "int slow_path();\n",
                    "#endif\n",
                    "int always();\n",
                ),
            );
            let rows = fixture.rows();

            let macro_site = rows
                .sites
                .iter()
                .find(|row| row.kind == GenerationKind::PreprocessorDefinition)
                .expect("macro generation site");
            assert_eq!(macro_site.generated.len(), 1);
            assert_eq!(macro_site.generated[0].0.fq_name(), "WIDGET_MAX");

            let gated: Vec<_> = rows
                .states
                .iter()
                .filter(|row| row.config_gated)
                .map(|row| row.unit.fq_name().to_string())
                .collect();
            assert!(
                gated.contains(&"fast_path".to_string())
                    && gated.contains(&"slow_path".to_string()),
                "gated: {gated:?}, states: {:?}",
                rows.states
            );
            let always = rows
                .states
                .iter()
                .find(|row| row.unit.fq_name() == "always")
                .expect("ungated declaration");
            assert!(!always.config_gated);

            assert!(
                !rows
                    .completeness
                    .covers(MaterializationAxis::ConfigurationGating),
                "no active configuration is known: {:?}",
                rows.completeness
            );
            assert!(rows.completeness.covers(MaterializationAxis::GeneratedSets));
        }
    }

    mod symbol_lookup {

        use brokk_bifrost_analysis::analyzer::symbol_lookup::FuzzyResolveBudget;

        use brokk_bifrost_analysis::analyzer::symbol_lookup::FuzzyResolveStop;

        use brokk_bifrost_analysis::analyzer::symbol_lookup::resolve_codeunit_fuzzy_bounded;

        #[test]
        fn nested_duplicate_candidates_count_toward_resolution_budget() {
            let project = crate::inline_project::InlineTestProject::new()
                .file("first.cpp", "struct Outer { struct Inner {}; };")
                .file("second.cpp", "struct Outer { struct Inner {}; };")
                .build();
            let workspace = project.workspace_analyzer(
                brokk_bifrost_core::analyzer::config::AnalyzerConfig::default(),
            );
            let keep_going = || true;
            let result = resolve_codeunit_fuzzy_bounded(
                workspace.analyzer(),
                "Outer$Inner",
                FuzzyResolveBudget::new(&keep_going, 1),
            );
            assert!(
                matches!(
                    result,
                    Err(FuzzyResolveStop::TooManyCandidates { total: 2, limit: 1 })
                ),
                "duplicate names are two candidates, repeated index hits are not: {result:?}"
            );
        }
    }

    mod usages_get_definition_call_sites {

        use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::test_support::byte_range;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::test_support::file;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::call_reference_ranges_in_tree;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::parse_tree_for_language;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::cpp_test_support::CPP_CALL_SITE_SOURCE as CPP_CALL_SITE_SOURCE;

        #[test]
        fn cpp_call_candidates_exclude_receivers_qualifiers_and_template_arguments() {
            let source = CPP_CALL_SITE_SOURCE;
            let file = file("calls.cpp");
            let tree =
                parse_tree_for_language(&file, Language::Cpp, source).expect("C++ syntax tree");
            let body = byte_range(
                source,
                "void caller(ns::Widget& receiver) {\n  ns::make<int>(1);\n  receiver.run<int>(1);\n  new ns::Box<int>();\n  receiver.operator+(1);\n  receiver.~Widget();\n}",
            );

            let references = call_reference_ranges_in_tree(&tree, Language::Cpp, &body, 20);
            let names = references
                .iter()
                .map(|range| &source[range.start_byte..range.end_byte])
                .collect::<Vec<_>>();

            assert_eq!(names, vec!["make", "run", "Box", "operator+", "~Widget"]);
        }
    }

    mod usages_call_relations {

        use std::sync::Arc;

        use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind;

        use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationService;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

        use brokk_bifrost_analysis::analyzer::usages::call_relations::ExactCallLocation;

        use brokk_bifrost_core::analyzer::model::ProjectFile;

        use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity;

        use brokk_bifrost_core::analyzer::usages::model::UsageProof;

        use brokk_bifrost_analysis::analyzer::usages::call_relations::test_support::call_span;

        use brokk_bifrost_analysis::analyzer::usages::call_relations::test_support::generous_limits;

        use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

        use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

        use brokk_bifrost_core::analyzer::query_token::QueryScope;

        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_core::analyzer::project::TestProject;

        use brokk_bifrost_analysis::test_support::AnalyzerFixture;

        #[test]
        fn exact_dispatch_keeps_cpp_function_pointer_calls_as_a_typed_boundary() {
            let source = r#"
void target() {}
void caller() {
  void (*callable)() = &target;
  callable();
}
"#;
            let fixture =
                AnalyzerFixture::new_for_language(Language::Cpp, &[("calls.cpp", source)]);
            let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
            let token = scope.token();
            let lookup = CallRelationService::dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                token,
                &ExactCallLocation {
                    file: ProjectFile::new(fixture.project_root(), "calls.cpp"),
                    call_span: call_span(source, "callable()"),
                },
                Arc::from(source),
                generous_limits(),
                None,
            );

            assert_eq!(lookup.status, Some(DefinitionLookupStatus::NoDefinition));
            assert!(lookup.targets.is_empty(), "{lookup:#?}");
            assert_eq!(
                lookup.boundaries,
                vec![CallDispatchBoundaryKind::Unresolved(
                    DefinitionLookupStatus::NoDefinition
                )]
            );
            assert!(
                lookup
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.contains("no_indexed_definition")),
                "{lookup:#?}"
            );
        }
        #[test]
        fn exact_dispatch_keeps_cpp_internal_linkage_in_its_translation_unit() {
            let caller_source = r#"
static int local_target(int value) { return value + 1; }
int caller() { return local_target(1); }
"#;
            let unrelated_source = "static int local_target(int value) { return value + 2; }\n";
            let fixture = AnalyzerFixture::new_for_language(
                Language::Cpp,
                &[
                    ("caller.c", caller_source),
                    ("unrelated.c", unrelated_source),
                ],
            );
            let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
            let token = scope.token();
            let lookup = CallRelationService::dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                token,
                &ExactCallLocation {
                    file: ProjectFile::new(fixture.project_root(), "caller.c"),
                    call_span: call_span(caller_source, "local_target(1)"),
                },
                Arc::from(caller_source),
                generous_limits(),
                None,
            );

            assert_eq!(lookup.status, Some(DefinitionLookupStatus::Resolved));
            assert_eq!(lookup.targets.len(), 1, "{lookup:#?}");
            assert_eq!(
                lookup.targets[0].definition.source().rel_path(),
                std::path::Path::new("caller.c")
            );
            assert!(lookup.boundaries.is_empty(), "{lookup:#?}");
        }
        #[brokk_bifrost_test_macros::hardwon(
            "#1372: Checks multiple candidate C++ bodies remain ambiguous and unproven instead of choosing one"
        )]
        #[test]
        fn exact_dispatch_keeps_multiple_cpp_bodies_unproven() {
            let header_source = "int relay(int value);\n";
            let first_body = "#include \"relay.h\"\nint relay(int value) { return value + 1; }\n";
            let second_body = "#include \"relay.h\"\nint relay(int value) { return value + 2; }\n";
            let caller_source =
                "#include \"relay.h\"\nint caller(int value) { return relay(value); }\n";
            let fixture = AnalyzerFixture::new_for_language(
                Language::Cpp,
                &[
                    ("relay.h", header_source),
                    ("first.cpp", first_body),
                    ("second.cpp", second_body),
                    ("caller.cpp", caller_source),
                ],
            );

            let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
            let token = scope.token();
            let lookup = CallRelationService::dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                token,
                &ExactCallLocation {
                    file: ProjectFile::new(fixture.project_root(), "caller.cpp"),
                    call_span: call_span(caller_source, "relay(value)"),
                },
                Arc::from(caller_source),
                generous_limits(),
                None,
            );

            // Since #1440 the two candidate bodies survive as Unproven targets;
            // ambiguity is expressed by the status and the per-target proof, and the
            // Unresolved(Ambiguous) boundary is reserved for lookups that surface no
            // targets at all.
            assert_eq!(lookup.status, Some(DefinitionLookupStatus::Ambiguous));
            let mut target_paths: Vec<_> = lookup
                .targets
                .iter()
                .map(|target| target.definition.source().rel_path().to_path_buf())
                .collect();
            target_paths.sort();
            assert_eq!(
                target_paths,
                vec![
                    std::path::PathBuf::from("first.cpp"),
                    std::path::PathBuf::from("second.cpp"),
                ],
                "{lookup:#?}"
            );
            assert!(
                lookup
                    .targets
                    .iter()
                    .all(|target| target.proof == UsageProof::Unproven),
                "{lookup:#?}"
            );
            assert!(
                lookup
                    .boundaries
                    .contains(&CallDispatchBoundaryKind::UnprovenTargetIdentity),
                "{lookup:#?}"
            );
            assert!(
                !lookup
                    .boundaries
                    .contains(&CallDispatchBoundaryKind::Unresolved(
                        DefinitionLookupStatus::Ambiguous
                    )),
                "{lookup:#?}"
            );
        }
        #[brokk_bifrost_test_macros::hardwon(
            "#1372: C++ header/body integration fixture checks a unique implementation body is selected with proven identity"
        )]
        #[test]
        fn exact_dispatch_projects_cpp_header_declarations_to_the_unique_body() {
            let header_source = "int relay(int value);\n";
            let body_source = "#include \"relay.h\"\nint relay(int value) { return value; }\n";
            let caller_source =
                "#include \"relay.h\"\nint caller(int value) { return relay(value); }\n";
            let fixture = AnalyzerFixture::new_for_language(
                Language::Cpp,
                &[
                    ("relay.h", header_source),
                    ("relay.cpp", body_source),
                    ("caller.cpp", caller_source),
                ],
            );

            let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
            let token = scope.token();
            let lookup = CallRelationService::dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                token,
                &ExactCallLocation {
                    file: ProjectFile::new(fixture.project_root(), "caller.cpp"),
                    call_span: call_span(caller_source, "relay(value)"),
                },
                Arc::from(caller_source),
                generous_limits(),
                None,
            );

            assert_eq!(lookup.status, Some(DefinitionLookupStatus::Resolved));
            assert_eq!(lookup.targets.len(), 1, "{lookup:#?}");
            assert_eq!(
                lookup.targets[0].definition.source().rel_path(),
                std::path::Path::new("relay.cpp")
            );
            assert_eq!(lookup.targets[0].proof, UsageProof::Proven);
            assert!(lookup.boundaries.is_empty(), "{lookup:#?}");
        }
        #[test]
        fn exact_dispatch_publishes_c_header_proof_and_identity() {
            use crate::analyzer::semantic_model::CatalogOptions;

            use crate::analyzer::semantic_model::DependencyPackLimits;

            use crate::analyzer::semantic_model::SemanticModelActivationControl;

            use crate::analyzer::semantic_model::SemanticModelActivationRequest;

            use crate::analyzer::semantic_model::SemanticModelControlAction;

            use crate::analyzer::semantic_model::SemanticModelControlScope;

            use crate::analyzer::semantic_model::SemanticModelPackSelector;

            use crate::analyzer::semantic_model::SemanticModelRuntimeLimits;

            use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelRuntimeOutcome;

            use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

            use brokk_bifrost_analysis::analyzer::workspace::DependencyPackEcosystem;

            use brokk_bifrost_analysis::analyzer::workspace::DependencyPackWorkspaceContext;

            let source = "#include <stdlib.h>\nvoid caller(void) { system(getenv(\"X\")); }\n";
            let temp = tempfile::tempdir().expect("temp root");
            let root = temp.path().canonicalize().expect("canonical temp root");
            let app = root.join("app");
            std::fs::create_dir_all(&app).expect("app directory");
            ProjectFile::new(app.clone(), "probe.c")
                .write(source)
                .expect("source");
            ProjectFile::new(root, "stubs/include/stdlib.h")
                .write("char *getenv(const char *name);\nint system(const char *command);\n")
                .expect("header");
            ProjectFile::new(app.clone(), "compile_commands.json")
            .write(r#"[{"directory":".","file":"probe.c","arguments":["clang","-I","../stubs/include","-c","probe.c"]}]"#)
            .expect("compile database");
            let analyzer = WorkspaceAnalyzer::build_ephemeral_footgun(
                Arc::new(TestProject::new(app.clone(), Language::Cpp)),
                AnalyzerConfig::default(),
            )
            .expect("C analyzer");
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
                .expect("semantic-pack catalog");
            let cancellation = CancellationToken::new();
            let activation = SemanticModelActivationRequest {
                bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                    .expect("crate version"),
                evidence: Vec::new(),
                controls: vec![SemanticModelActivationControl {
                    scope: SemanticModelControlScope::Workspace,
                    action: SemanticModelControlAction::Enable,
                    selector: SemanticModelPackSelector {
                        pack_id: "bifrost.external.cpp-headers".to_owned(),
                        version: None,
                        manifest_digest: None,
                    },
                }],
                limits: SemanticModelRuntimeLimits::default(),
            };
            let activation_outcome = analyzer.activate_dependency_packs(
                &AnalyzerConfig::default(),
                &[DependencyPackEcosystem::Cpp],
                DependencyPackWorkspaceContext {
                    catalog: &catalog,
                    persistence: None,
                    activation: &activation,
                    limits: DependencyPackLimits::default(),
                    cancellation: &cancellation,
                },
            );
            assert!(activation_outcome.complete(), "{activation_outcome:#?}");
            assert!(matches!(
                activation_outcome.runtime,
                Some(SemanticModelRuntimeOutcome::Ready { .. })
            ));
            let file = ProjectFile::new(app, "probe.c");
            let scope = AnalyzerQueryScope::new(analyzer.analyzer());

            for (call, member, arity) in [
                ("getenv(\"X\")", "getenv", 1),
                ("system(getenv(\"X\"))", "system", 1),
            ] {
                let lookup = CallRelationService::dispatch_at_bounded(
                    analyzer.analyzer(),
                    scope.token(),
                    &ExactCallLocation {
                        file: file.clone(),
                        call_span: call_span(source, call),
                    },
                    Arc::from(source),
                    generous_limits(),
                    None,
                );

                assert_eq!(
                    lookup.status,
                    Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                    "{call}: {lookup:#?}"
                );
                assert!(lookup.targets.is_empty(), "{call}: {lookup:#?}");
                let proof = lookup.exact_external_call.as_ref().unwrap_or_else(|| {
                    panic!("{call} must carry its exact C header proof: {lookup:#?}")
                });
                assert_eq!(proof.canonical_callee(), format!("stdlib::{member}"));
                assert_eq!(proof.parameter_count(), arity);
                assert!(
                    !proof.has_receiver(),
                    "C header functions are receiverless: {lookup:#?}"
                );
                assert_eq!(
                    lookup.boundaries,
                    vec![CallDispatchBoundaryKind::External {
                        callee_text: Some(proof.canonical_callee().into()),
                        normalized_static_owner: None,
                        external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
                            Language::Cpp,
                            "stdlib",
                            member,
                        )),
                    }],
                    "{call}: resolver-owned proof and identity must survive call dispatch",
                );
            }
        }
        #[test]
        fn exact_dispatch_resolves_cpp_template_operator_and_destructor_names() {
            let source = r#"
namespace ns {
template <typename T> void make(T) {}
template <typename T> struct Box { Box() {} };
struct Widget {
  template <typename T> void run(T) {}
  Widget& operator+(int) { return *this; }
  ~Widget() {}
};
}
void caller(ns::Widget& receiver) {
  ns::make<int>(1);
  new ns::Box<int>();
  receiver.run<int>(1);
  receiver.operator+(1);
  receiver.~Widget();
}
"#;
            let fixture =
                AnalyzerFixture::new_for_language(Language::Cpp, &[("calls.cpp", source)]);

            for (call, identifier) in [
                ("ns::make<int>(1)", "make"),
                ("new ns::Box<int>()", "Box"),
                ("receiver.run<int>(1)", "run"),
                ("receiver.operator+(1)", "operator+"),
                ("receiver.~Widget()", "~Widget"),
            ] {
                let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
                let token = scope.token();
                let lookup = CallRelationService::dispatch_at_bounded(
                    fixture.analyzer.analyzer(),
                    token,
                    &ExactCallLocation {
                        file: ProjectFile::new(fixture.project_root(), "calls.cpp"),
                        call_span: call_span(source, call),
                    },
                    Arc::from(source),
                    generous_limits(),
                    None,
                );

                assert_eq!(
                    lookup.status,
                    Some(DefinitionLookupStatus::Resolved),
                    "{call}: {lookup:#?}"
                );
                assert_eq!(lookup.targets.len(), 1, "{call}: {lookup:#?}");
                assert_eq!(lookup.targets[0].definition.identifier(), identifier);
                assert!(lookup.boundaries.is_empty(), "{call}: {lookup:#?}");
            }
        }
    }

    mod usages_get_definition_trace {

        use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::BoundaryFixture;

        use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::assert_boundary_route_joins_occurrence;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::external_routes;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::test_support::route_names;

        use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_test_macros::hardwon;

        /// C APIs are not required to use lowercase names. Keep a capitalized
        /// file-scope call on the same unresolved-include boundary as `getenv`;
        /// the C++ construction-shape guard must not reject a C source file.
        #[test]
        fn a_c_capitalized_free_function_call_across_an_unindexed_include_publishes_one_row() {
            let fixture = BoundaryFixture::new(
                Language::Cpp,
                "main.c",
                "#include <openssl/evp.h>\nint main(void) { return EVP_des_cbc() != 0; }\n",
            );
            let (outcome, trace) = fixture.trace("EVP_des_cbc");
            assert_eq!(
                outcome.status,
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "the unresolved `<openssl/evp.h>` above the call makes the C API a boundary: {:?}",
                outcome.diagnostics
            );
            assert_eq!(
                outcome.resolved_reference_target(),
                Some("EVP_des_cbc"),
                "the boundary names the written capitalized C callee: {:?}",
                outcome.diagnostics
            );
            assert_eq!(
                route_names(&trace),
                vec!["EVP_des_cbc".to_string()],
                "the trace publishes one route row for the capitalized C callee: {:#?}",
                trace.candidates
            );
            assert_boundary_route_joins_occurrence(
                &fixture,
                "EVP_des_cbc",
                OccurrenceRole::ValueReference,
            );
        }
        /// #3466: a C free function called across an unresolved include. Two
        /// defects used to hide the boundary: the adapter classified no occurrence
        /// at the callee token, leaving the traced route nothing to join against,
        /// and the identifier call arm had no include-boundary decision. Both
        /// halves now publish one `getenv` row.
        #[test]
        #[hardwon(
            "#3466: A C call through an unindexed system include publishes one route and the occurrence row joins it"
        )]
        fn a_c_free_function_call_across_an_unindexed_include_publishes_one_row() {
            let fixture = BoundaryFixture::new(
                Language::Cpp,
                "main.c",
                "#include <stdlib.h>\nint main(void) { return getenv(\"PATH\") != 0; }\n",
            );
            let (outcome, trace) = fixture.trace("getenv");
            assert_eq!(
                outcome.status,
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "the unresolved `<stdlib.h>` above the call makes the callee a boundary: {:?}",
                outcome.diagnostics
            );
            assert_eq!(
                outcome.resolved_reference_target(),
                Some("getenv"),
                "the boundary names the written callee: {:?}",
                outcome.diagnostics
            );
            assert_eq!(
                route_names(&trace),
                vec!["getenv".to_string()],
                "the trace publishes one route row: {:#?}",
                trace.candidates
            );
            assert_eq!(
                external_routes(&trace),
                vec![(BoundaryStatus::ExternalUnknown, None)],
                "no header pack is activated, so the row names the boundary without sharpening it"
            );
            assert_boundary_route_joins_occurrence(
                &fixture,
                "getenv",
                OccurrenceRole::ValueReference,
            );
        }
        #[hardwon(
            "#3466: lowercase C++ free-function calls across unresolved includes published no candidate row"
        )]
        #[test]
        fn a_cpp_free_function_call_across_an_unindexed_include_publishes_one_row() {
            let fixture = BoundaryFixture::new(
                Language::Cpp,
                "main.cpp",
                "#include <cstdlib>\nint main() { return getenv(\"PATH\") != nullptr; }\n",
            );
            let (outcome, trace) = fixture.trace("getenv");
            assert_eq!(
                outcome.status,
                DefinitionLookupStatus::UnresolvableImportBoundary,
                "the unresolved `<cstdlib>` above the call makes the callee a boundary: {:?}",
                outcome.diagnostics
            );
            assert_eq!(
                route_names(&trace),
                vec!["getenv".to_string()],
                "the trace publishes one route row: {:#?}",
                trace.candidates
            );
            assert_boundary_route_joins_occurrence(
                &fixture,
                "getenv",
                OccurrenceRole::ValueReference,
            );
        }
    }

    mod usages_workspace_graph {

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::CatalogDeclaration;

        use brokk_bifrost_core::analyzer::model::DeclarationId;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageCatalog;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageNodeKey;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::is_graph_declaration;

        use brokk_bifrost_analysis::analyzer::usages::common::language_for_target;

        use brokk_bifrost_test_macros::hardwon;
        use std::collections::BTreeMap;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::cpp_test_support::CatalogNodeFields;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::cpp_test_support::catalog_node_fields;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::cpp_test_support::parity_inventory;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::cpp_test_support::persisted_multilanguage_analyzer;

        #[test]
        #[hardwon(
            "2d6e0d05e77f: A persisted fixture compares identities, duplicates, primary ranges, and order with an independent reference grouping"
        )]
        fn catalog_grouping_matches_the_ordered_map_reference_grouping() {
            let _guard = brokk_bifrost_analysis::analyzer::usages::workspace_graph::cpp_test_support::CATALOG_TEST_LOCK.lock().unwrap();
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            let analyzer = persisted_multilanguage_analyzer(root.clone());
            let declarations = parity_inventory(&analyzer, &root);
            assert!(
                declarations.len() > 8,
                "the parity fixture must carry enough rows to exercise grouping: {declarations:?}"
            );

            let expected = reference_catalog_nodes(declarations.clone());
            let actual = WorkspaceUsageCatalog::from_declarations(
                declarations,
                &CancellationToken::default(),
            )
            .expect("uncancelled catalog");

            assert_eq!(
                catalog_node_fields(&actual),
                expected,
                "the grouping rewrite must reproduce the ordered-map grouping exactly: identity, \
             primary, primary range, duplicate files, duplicate identities, and node order"
            );

            // The C++ redeclarations are one node whose primary is the header, and
            // the node is reachable by either declaration identity.
            let merged = actual
                .nodes
                .iter()
                .find(|node| node.declaration_files.len() == 2)
                .expect("the C++ redeclaration pair must group into one node");
            assert_eq!(
                merged.primary.source().rel_path(),
                std::path::Path::new("lib/widget.cpp"),
                "primary selection must take the first declaration in source order, not enumeration \
             order: {files:?}",
                files = merged.declaration_files
            );
            assert_eq!(merged.declaration_ids.len(), 2, "{:?}", merged.primary);
            for id in &merged.declaration_ids {
                assert_eq!(
                    actual.index_for_id(id),
                    actual.index_for_id(&merged.key.id),
                    "every identity in a merged node must index that node"
                );
            }
        }
        /// The grouping this file replaced, written out as an independent oracle.
        ///
        /// This is the sequential `BTreeMap` walk `from_declarations` used before
        /// #2935: one ordered map keyed by ecosystem, rendered name, kind,
        /// signature, and exact declaration identity; each group sorted by source
        /// file, primary start line, and signature; the head of that sort as the
        /// node's primary; nodes ordered by declaration identity.
        fn reference_catalog_nodes(
            declarations: Vec<CatalogDeclaration>,
        ) -> Vec<CatalogNodeFields> {
            #[derive(PartialEq, Eq, PartialOrd, Ord)]
            struct ReferenceGroupKey {
                ecosystem: UsageEcosystem,
                fqn: String,
                kind: brokk_bifrost_core::analyzer::model::CodeUnitType,
                signature: Option<String>,
                exact_declaration: Option<DeclarationId>,
            }

            let mut grouped: BTreeMap<ReferenceGroupKey, Vec<CatalogDeclaration>> = BTreeMap::new();
            for (unit, range) in declarations {
                if !is_graph_declaration(&unit) {
                    continue;
                }
                let ecosystem = UsageEcosystem::of(language_for_target(&unit));
                let exact_declaration =
                    (!matches!(ecosystem, UsageEcosystem::Cpp | UsageEcosystem::CSharp))
                        .then(|| unit.declaration_id());
                grouped
                    .entry(ReferenceGroupKey {
                        ecosystem,
                        fqn: unit.fq_name(),
                        kind: unit.kind(),
                        signature: unit.signature().map(str::to_string),
                        exact_declaration,
                    })
                    .or_default()
                    .push((unit, range));
            }

            let mut nodes = Vec::with_capacity(grouped.len());
            for (_, mut declarations) in grouped {
                declarations.sort_by(|(left, left_range), (right, right_range)| {
                    left.source()
                        .cmp(right.source())
                        .then_with(|| {
                            left_range
                                .map(|range| range.start_line)
                                .cmp(&right_range.map(|range| range.start_line))
                        })
                        .then_with(|| left.signature().cmp(&right.signature()))
                });
                let (primary, primary_range) =
                    declarations.first().expect("non-empty group").clone();
                let ecosystem = UsageEcosystem::of(language_for_target(&primary));
                let key = WorkspaceUsageNodeKey {
                    id: primary.declaration_id(),
                    ecosystem,
                    fqn: primary.fq_name(),
                    defining_file: ecosystem
                        .is_module_scoped()
                        .then(|| primary.source().clone()),
                };
                let mut declaration_files: Vec<_> = declarations
                    .iter()
                    .map(|(unit, _)| unit.source().clone())
                    .collect();
                declaration_files.sort();
                declaration_files.dedup();
                let mut declaration_ids: Vec<_> = declarations
                    .iter()
                    .map(|(unit, _)| unit.declaration_id())
                    .collect();
                declaration_ids.sort();
                declaration_ids.dedup();
                nodes.push((
                    key,
                    primary,
                    primary_range,
                    declaration_files,
                    declaration_ids,
                ));
            }
            nodes.sort_by(|left, right| left.0.id.cmp(&right.0.id));
            nodes
        }
    }
}
