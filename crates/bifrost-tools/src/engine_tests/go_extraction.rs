#[cfg(test)]
#[doc(hidden)]
pub mod go_extraction_tests {
    mod go_move_0 {

        use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;

        use brokk_bifrost_analysis::analyzer::java::adapter::JavaAdapter;

        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_analysis :: analyzer :: tree_sitter_analyzer :: tree_sitter_resolution_producer_tests_go_support :: go_extraction_support_0 :: assert_native_overlay_publication ;

        use brokk_bifrost_analysis :: analyzer :: tree_sitter_analyzer :: tree_sitter_resolution_producer_tests_go_support :: go_extraction_support_0 :: assert_native_unit_projection ;

        use brokk_bifrost_analysis :: analyzer :: tree_sitter_analyzer :: tree_sitter_resolution_producer_tests_go_support :: go_extraction_support_0 :: native_type_projection ;

        #[test]
        fn hydrated_go_overlays_publish_same_and_changed_native_content() {
            use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;
            let original = "package sample; func original() {}\nfunc caller() { original() }\n";
            assert_native_overlay_publication(
                GoAdapter,
                "sample.go",
                original,
                original,
                "original",
                "original",
            );
            assert_native_overlay_publication(
                GoAdapter,
                "sample.go",
                original,
                "package sample; func changed() {}\nfunc caller() { changed() }\n",
                "changed",
                "changed",
            );
        }
        #[test]
        fn go_native_definition_projection_uses_selected_package_anchor_after_disk_change() {
            let source = "package sample; func target() {}\nfunc caller() { target() }\n";
            let fixture = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.com/original\n")
                .file("sample.go", source)
                .build();
            assert_native_unit_projection(
                &fixture,
                brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter,
                "sample.go",
                source,
                || {
                    std::fs::write(
                        fixture.file("go.mod").abs_path(),
                        "module example.com/changed\n",
                    )
                    .unwrap();
                },
            );
        }
        #[test]
        fn native_go_type_projects_bound_parameter_and_predeclared_type() {
            use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

            use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeTypes;
            let source = "package sample; func f(target int) int { return target }";
            let fixture = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/types\n\ngo 1.22\n")
                .file("source.go", source)
                .build();
            let answer = native_type_projection(&fixture, GoAdapter, "source.go", source);
            assert_eq!(
                answer.answer.binding().targets().len(),
                1,
                "{:?}",
                answer.answer
            );
            assert_eq!(
                answer.answer.binding().completion(),
                &ResolutionCompletion::Complete
            );
            assert_eq!(answer.answer.completion(), &ResolutionCompletion::Complete);
            let SelectedNativeTypes::Ready {
                nominal, intrinsic, ..
            } = answer.value_types
            else {
                panic!("the predeclared int type must project from selected Go facts");
            };
            assert!(nominal.is_empty());
            assert_eq!(intrinsic.len(), 1);
            assert_eq!(intrinsic[0].spelling(), "int");
        }
        #[test]
        fn native_java_and_go_types_project_nominal_source_identities() {
            use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeDefinition;

            use brokk_bifrost_analysis::analyzer::store::resolution_operation::native_units::SelectedNativeTypes;
            let java = "class Target {} class Use { Target f(Target target) { return target; } }";
            let java_fixture = InlineTestProject::with_language(Language::Java)
                .file("Use.java", java)
                .build();
            let go = "package sample; type Target struct {}; func f(target Target) Target { return target }";
            let go_fixture = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/types\n\ngo 1.22\n")
                .file("source.go", go)
                .build();
            for (answer, file) in [
                (
                    native_type_projection(&java_fixture, JavaAdapter, "Use.java", java),
                    java_fixture.file("Use.java"),
                ),
                (
                    native_type_projection(&go_fixture, GoAdapter, "source.go", go),
                    go_fixture.file("source.go"),
                ),
            ] {
                let SelectedNativeTypes::Ready {
                    nominal, intrinsic, ..
                } = answer.value_types
                else {
                    panic!("nominal type must project to its selected declaration");
                };
                assert!(intrinsic.is_empty());
                assert_eq!(
                    nominal.len(),
                    1,
                    "{file:?}: {:?}: {:?}",
                    answer.named_reasons,
                    answer.answer
                );
                let (identity, SelectedNativeDefinition::Unit(unit)) = &nominal[0] else {
                    panic!("nominal type must have a parser unit");
                };
                assert_eq!(unit.terminal_name(), "Target");
                assert_eq!(unit.source(), &file);
                assert!(answer.answer.projected_frontiers().iter().any(|frontier| {
                    frontier
                        .possible_values()
                        .iter()
                        .any(|value| value.ty().identity() == *identity)
                }));
            }
        }
    }
    mod go_move_1 {

        use brokk_bifrost_core::analyzer::config::GoDependencyDiscoveryMode;

        use brokk_bifrost_semantic::analyzer::semantic_model::compiler::CompilerOptions;

        use crate::analyzer::semantic_model::SemanticModelActivationEvidence;

        use crate::analyzer::semantic_model::SemanticModelRuntimeLimits;

        use crate::analyzer::semantic_model::SessionPackSource;

        use crate::analyzer::semantic_model::SessionPackSourceKind;

        use brokk_bifrost_semantic::analyzer::semantic_model::source::SourceFormat;

        use brokk_bifrost_semantic::analyzer::semantic_model::compiler::compile_source;

        use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

        use brokk_bifrost_analysis::analyzer::workspace::DependencyPackEcosystem;

        use brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits;

        use brokk_bifrost_analysis::analyzer::workspace::DependencyPackWorkspaceContext;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelActivationRequest;

        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelRuntimeOutcome;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

        use crate::inline_project::InlineTestProject;

        use brokk_bifrost_test_macros::hardwon;

        #[test]
        fn intrinsic_models_activate_when_dependency_discovery_fails() {
            let project = InlineTestProject::with_language(Language::Go)
                .file("main.go", "package main\n")
                .build();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
            let pack = compile_source(
                SourceFormat::Json,
                br#"{
              "schema_version": 2,
              "pack_id": "test.go.intrinsic",
              "version": "1.0.0",
              "producer": {"name": "test", "version": "1.0.0"},
              "language": "go",
              "ecosystem": "go",
              "compatibility": {"bifrost": ">=0.10.0, <1.0.0"},
              "provenance": {"source": "test:go-intrinsic"},
              "license": "Apache-2.0",
              "completeness": "complete",
              "safety": {"generated_code_only": false, "review_required": false},
              "shards": [{
                "id": "summaries",
                "activation": [{}],
                "payload": {
                  "kind": "procedure_summaries",
                  "summaries": [{
                    "id": "test.go.exit",
                    "target": {
                      "path": "src/os/proc.go",
                      "symbol": "os.Exit(code int)",
                      "has_receiver": false,
                      "parameter_count": 1
                    },
                    "completeness": "complete",
                    "normal_continuation_absent": true,
                    "transfers": [],
                    "effects": [{
                      "kind": "unknown_call_boundary",
                      "event": "test.go.exit-boundary"
                    }]
                  }]
                }
              }]
            }"#,
                &CompilerOptions::default(),
            )
            .unwrap_or_else(|diagnostics| panic!("intrinsic fixture failed: {diagnostics:#?}"));
            catalog
                .register_session_pack(
                    &pack,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: "test:go-intrinsic".to_owned(),
                    },
                )
                .unwrap();

            let mut config = AnalyzerConfig::default();
            config.go.dependency_discovery.mode = GoDependencyDiscoveryMode::CuratedPackEvidence;
            config.go.dependency_discovery.go_executable = Some(project.root().join("missing-go"));
            let request = SemanticModelActivationRequest {
                bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "go".to_owned(),
                    ecosystem: "go".to_owned(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            };
            let outcome = workspace.activate_dependency_packs(
                &config,
                &[DependencyPackEcosystem::Go],
                DependencyPackWorkspaceContext {
                    catalog: &catalog,
                    persistence: None,
                    activation: &request,
                    limits: DependencyPackLimits::default(),
                    cancellation: &brokk_bifrost_core::cancellation::CancellationToken::default(),
                },
            );

            assert!(!outcome.complete());
            assert!(outcome.diagnostic_refresh_required);
            assert!(!outcome.ecosystems[0].discovery.complete);
            // #2887: an incomplete discovery still prepares the dependencies it
            // did resolve. Go discovery resolved none here, so preparation has
            // nothing to select and contributes no evidence of its own.
            let preparation = outcome.ecosystems[0]
                .preparation
                .as_ref()
                .expect("incomplete discovery must still prepare its resolved set");
            assert!(preparation.complete, "{preparation:#?}");
            assert!(preparation.evidence.is_empty(), "{preparation:#?}");
            let SemanticModelRuntimeOutcome::Ready { active, .. } = outcome
                .runtime
                .expect("intrinsic activation must still run")
            else {
                panic!("intrinsic activation should be ready")
            };
            assert_eq!(active.shards().len(), 1);
            assert_eq!(active.shards()[0].manifest.pack_id, "test.go.intrinsic");
        }
        #[test]
        #[hardwon(
            "b610cdc85704: cancellation allowed later ecosystem discovery to publish a partial activation transaction"
        )]
        fn cancelled_dependency_discovery_stops_the_whole_activation_transaction() {
            let project = InlineTestProject::with_language(Language::Go)
                .file("main.go", "package main\n")
                .build();
            let mut config = AnalyzerConfig::default();
            config.go.dependency_discovery.mode = GoDependencyDiscoveryMode::CuratedPackEvidence;
            config.go.dependency_discovery.go_executable = Some(project.root().join("missing-go"));
            let workspace = project.workspace_analyzer(config.clone());
            let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
            let request = SemanticModelActivationRequest {
                bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                evidence: Vec::new(),
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            };
            // The first cancellation check is the top of Go discovery itself, so
            // discovery is cancelled before it resolves anything and before the
            // second ecosystem can start.
            let cancellation =
                brokk_bifrost_core::cancellation::CancellationToken::cancel_after_checks_for_test(
                    1,
                );
            let outcome = workspace.activate_dependency_packs(
                &config,
                &[DependencyPackEcosystem::Go, DependencyPackEcosystem::Python],
                DependencyPackWorkspaceContext {
                    catalog: &catalog,
                    persistence: None,
                    activation: &request,
                    limits: DependencyPackLimits::default(),
                    cancellation: &cancellation,
                },
            );
            assert_eq!(outcome.ecosystems.len(), 1, "{outcome:#?}");
            assert!(outcome.ecosystems[0].discovery.cancelled, "{outcome:#?}");
            assert!(outcome.ecosystems[0].preparation.is_none(), "{outcome:#?}");
            assert!(outcome.runtime.is_none(), "{outcome:#?}");
            assert!(!outcome.diagnostic_refresh_required, "{outcome:#?}");
            assert!(!outcome.complete(), "{outcome:#?}");
        }
        #[test]
        fn go_native_activation_disabled_never_invokes_configured_tool() {
            let fixture = crate::inline_project::InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/root\n")
                .file("main.go", "package main\nfunc main() {}\n")
                .build();
            let mut config = AnalyzerConfig::default();
            config.go.dependency_discovery.mode = GoDependencyDiscoveryMode::Disabled;
            config.go.dependency_discovery.go_executable =
                Some(fixture.root().join("absent-go-tool"));
            assert_eq!(
                config.go.dependency_discovery.mode,
                GoDependencyDiscoveryMode::Disabled
            );
            let workspace =
                WorkspaceAnalyzer::build_ephemeral_footgun(fixture.project_dyn(), config.clone())
                    .unwrap();
            let outcome = workspace.resolve_dependency_discovery(
                DependencyPackEcosystem::Go,
                &config,
                &DependencyPackLimits::default(),
                &brokk_bifrost_core::cancellation::CancellationToken::new(),
            );
            assert!(outcome.complete);
            assert!(outcome.diagnostics.is_empty());
            let conn = workspace.store().unwrap().read_conn().unwrap();
            let contexts: i64 = conn
                .query_row("SELECT count(*) FROM go_context_publications", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(contexts, 1);
            let (complete, gaps): (bool, String) = conn
                .query_row(
                    "SELECT complete,json(gaps) FROM go_context_publications",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert!(!complete);
            assert!(gaps.contains("build_selection_unavailable"));
        }
    }
    mod go_move_4 {

        use brokk_bifrost_core::analyzer::model::ProjectFile;

        use crate::analyzer::semantic::SemanticBudget;
        use brokk_bifrost_semantic::analyzer::semantic::ids::DeclarationSegment;

        use brokk_bifrost_analysis::analyzer::semantic::icfg::python_test_support::assert_failed_transfer_retry_pays_source;

        use brokk_bifrost_analysis::analyzer::semantic::icfg::*;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapability;

        use brokk_bifrost_analysis::analyzer::semantic::icfg::IcfgExitProfile;

        use brokk_bifrost_analysis::analyzer::semantic::ir::artifact::ProcedureHandle;

        use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapDischarge;
        use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapImpact;

        use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapSubject;
        use brokk_bifrost_analysis::analyzer::semantic::oracle::limits::OracleLimits;

        use brokk_bifrost_analysis::analyzer::semantic::oracle::model::OracleCallContext;

        use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
        use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticProviderError;
        use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
        use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticWork;

        use brokk_bifrost_analysis::test_support::AnalyzerFixture;

        #[test]
        fn contextual_callback_source_and_proof_rollback_with_snapshot() {
            let fixture = AnalyzerFixture::new_for_language(
                brokk_bifrost_core::analyzer::model::Language::Go,
                &[(
                    "main.go",
                    concat!(
                        "package pkg\n",
                        "func Invoke(cb func()) { cb() }\n",
                        "func First() { seed := 7; cb := func() { _ = seed }; Invoke(cb) }\n",
                    ),
                )],
            );
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let cancellation = CancellationToken::default();
            let mut materialization = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut materialization, &cancellation),
                )
                .expect("Go materialization")
                .available_value()
                .cloned()
                .expect("Go artifact");
            let named = |name| {
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
                    .and_then(|row| artifact.procedure_handle(row.id()))
                    .expect("named Go procedure")
            };
            let caller = named("First");
            let callee = named("Invoke");
            let entering = caller
                .call_site_handle(caller.semantics().call_sites()[0].id)
                .expect("entering call");
            let context =
                OracleCallContext::bounded(vec![entering.clone()], OracleLimits::default());
            let callback = callee.semantics().call_sites()[0].id;
            let provider = fixture.analyzer.icfg_provider();
            let mut outer = SemanticBudget::default();
            let failed: Result<(), SemanticProviderError> = provider.with_snapshot_transaction(
                &mut SemanticRequest::new(&mut outer, &cancellation),
                |snapshot_provider, request| {
                    let result = snapshot_provider
                        .call_transfers_in_context(&callee, callback, &context, request)?;
                    let transfer = &result
                        .available_value()
                        .expect("callback transfer")
                        .transfers[0];
                    let proof = transfer
                        .argument_callable
                        .as_ref()
                        .expect("exact argument proof");
                    assert_eq!(proof.entering_call(), &entering);
                    assert_eq!(proof.creation().procedure(), &caller);
                    assert!(!proof.captures().is_empty());
                    assert!(
                        matches!(
                            result,
                            SemanticOutcome::Unsupported {
                                capability: SemanticCapability::Captures,
                                ..
                            }
                        ),
                        "capture transport stays incomplete: {result:#?}"
                    );
                    assert!(request.budget.used().source_bytes > 0);
                    assert!(
                        provider
                            .outcome_cache
                            .dispatch_sessions
                            .lock()
                            .expect("sessions")
                            .is_empty()
                    );
                    Err(SemanticProviderError::internal(
                        "post-context snapshot failure",
                    ))
                },
            );
            assert!(failed.is_err());
            assert_eq!(outer.resident(), SemanticWork::default());
            assert_ne!(
                outer.used(),
                SemanticWork::default(),
                "performed work survives the failed snapshot transaction"
            );
            assert!(
                provider
                    .outcome_cache
                    .dispatch_sessions
                    .lock()
                    .expect("sessions")
                    .is_empty()
            );
            assert!(
                provider
                    .outcome_cache
                    .call_transfers
                    .lock()
                    .expect("transfers")
                    .is_empty()
            );
            let mut retry = SemanticBudget::default();
            let result = provider
                .with_snapshot_transaction(
                    &mut SemanticRequest::new(&mut retry, &cancellation),
                    |snapshot_provider, request| {
                        snapshot_provider
                            .call_transfers_in_context(&callee, callback, &context, request)
                    },
                )
                .expect("retry callback transfer");
            assert!(result.available_value().is_some());
            assert!(
                retry.used().source_bytes > 0,
                "rolled-back caller source must be paid again"
            );
            assert!(
                !provider
                    .outcome_cache
                    .dispatch_sessions
                    .lock()
                    .expect("sessions")
                    .is_empty()
            );
        }
        use brokk_bifrost_analysis::analyzer::semantic::DispatchOracle as _;
        #[test]
        fn failed_transfer_projection_discards_newly_parsed_dispatch_source() {
            let source = concat!(
                "package sample\n",
                "func first() {}\n",
                "func second() {}\n",
                "func caller() { go first(); second() }\n",
            );
            let fixture = AnalyzerFixture::new_for_language(
                brokk_bifrost_core::analyzer::model::Language::Go,
                &[("calls.go", source)],
            );
            let file = ProjectFile::new(fixture.project_root(), "calls.go");
            let cancellation = CancellationToken::default();
            let mut materialization_budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                )
                .expect("Go semantic materialization")
                .available_value()
                .cloned()
                .expect("Go semantic artifact");
            let caller = artifact
                .procedures()
                .iter()
                .find(|procedure| procedure.call_sites().len() == 2)
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .expect("caller with detached and ordinary calls");
            let calls = caller.semantics().call_sites();

            // Calibrate exactly the prepared dispatch portion. Projecting the
            // detached candidate into a call boundary owns additional retained
            // relations, so a limit at this point admits parsing and dispatch but
            // rejects the enclosing call-transfer projection atomically.
            let oracle = fixture.analyzer.semantic_oracle_provider();
            let first_call = caller
                .call_site_handle(calls[0].id)
                .expect("detached call handle");
            let mut dispatch_budget = SemanticBudget::default();
            let dispatch = oracle
                .resolve_call(
                    &first_call,
                    &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
                )
                .expect("detached call dispatch calibration");
            assert!(dispatch.available_value().is_some(), "{dispatch:#?}");
            let dispatch_nested_entries = dispatch.work().nested_entries;
            assert!(dispatch_nested_entries > 0);

            let provider = fixture.analyzer.icfg_provider();
            let mut limits = SemanticBudget::default().limits();
            limits.nested_entries = dispatch_nested_entries;
            let mut tight_budget = SemanticBudget::new(limits).expect("positive projection budget");
            let failed = provider
                .call_transfers(
                    &caller,
                    calls[0].id,
                    &mut SemanticRequest::new(&mut tight_budget, &cancellation),
                )
                .expect("call-transfer projection exhaustion is typed");
            assert!(matches!(
                failed,
                SemanticOutcome::ExceededBudget { partial: None, .. }
            ));
            assert_eq!(tight_budget.resident(), SemanticWork::default());
            assert_eq!(
                tight_budget.root_work_peak(),
                dispatch_budget.root_work_peak(),
                "a failed transfer keeps performed dispatch work",
            );
            assert_failed_transfer_retry_pays_source(
                &provider,
                &caller,
                calls[1].id,
                source.len(),
                &cancellation,
            );
        }
        #[test]
        fn go_implicit_abort_discharge_uses_the_gap_point_cleanup_scope() {
            let fixture = AnalyzerFixture::new_for_language(
                brokk_bifrost_core::analyzer::model::Language::Go,
                &[(
                    "defer_abort_scope.go",
                    concat!(
                        "package sample\n",
                        "type resource struct{ value int }\n",
                        "func cleanup(int) {}\n",
                        "func first(resource *resource) { defer cleanup(resource.value) }\n",
                        "func later(resource *resource) {\n",
                        "    defer cleanup(0)\n",
                        "    defer cleanup(resource.value)\n",
                        "}\n",
                    ),
                )],
            );
            let file = ProjectFile::new(fixture.project_root(), "defer_abort_scope.go");
            let cancellation = CancellationToken::default();
            let mut materialization_budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                )
                .expect("Go materialization")
                .available_value()
                .cloned()
                .expect("Go artifact");
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
            let selection_gap = |procedure: &ProcedureHandle| {
                procedure
                    .semantics()
                    .gaps()
                    .iter()
                    .find(|gap| gap.detail.as_ref() == "selection may panic on a nil operand")
                    .cloned()
                    .unwrap_or_else(|| panic!("missing selector abort gap in {procedure:#?}"))
            };
            let first = find_procedure("first");
            let later = find_procedure("later");
            let first_gap = selection_gap(&first);
            let later_gap = selection_gap(&later);
            assert_eq!(
                first_gap.discharge,
                SemanticGapDischarge::NonRejoiningExceptionalExit,
                "the first defer is not registered until after its field selection"
            );
            assert_eq!(
                later_gap.discharge,
                SemanticGapDischarge::ExitOnlyProcedureCompletion,
                "the earlier defer can run on panic, but cannot resume this procedure's normal body"
            );

            for procedure in [&first, &later] {
                assert!(
                    brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::value_flow::abort_paths_run_user_code(
                        procedure.semantics()
                    ),
                    "the procedure-wide fallback sees deferred user code"
                );
            }
            assert!(
                brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::value_flow::implicit_abort_gap_is_discharged(
                    &first_gap, true,
                ),
                "a later cleanup elsewhere in the procedure must not open the first selection"
            );
            assert!(
                !brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::value_flow::implicit_abort_gap_is_discharged(
                    &later_gap, true,
                ),
                "an already-active cleanup must keep the later selection open"
            );

            let provider = fixture.analyzer.icfg_provider();
            let exit_profile = |procedure: &ProcedureHandle| {
                let entry = procedure
                    .point_handle(procedure.semantics().entry_point())
                    .expect("procedure entry");
                let exit = procedure
                    .point_handle(procedure.semantics().normal_exit_point())
                    .expect("procedure normal exit");
                let mut budget = SemanticBudget::default();
                provider
                    .exit_profile(
                        &entry,
                        &exit,
                        &mut SemanticRequest::new(&mut budget, &cancellation),
                    )
                    .expect("normal exit profile")
            };
            let first_outcome = exit_profile(&first);
            assert!(
                matches!(&first_outcome, SemanticOutcome::Complete { .. }),
                "the first deferred argument's pre-registration abort must discharge: {first_outcome:#?}"
            );
            let later_outcome = exit_profile(&later);
            assert!(
                matches!(&later_outcome, SemanticOutcome::Unsupported { .. }),
                "the later field selection can abort through the earlier cleanup: {later_outcome:#?}"
            );
            assert!(
                later_outcome
                    .available_value()
                    .and_then(IcfgExitProfile::aggregate_return_affecting_gap_reason)
                    .is_some_and(|reason| reason.contains("selection may panic on a nil operand")),
                "the retained boundary must name the point-local selector gap: {later_outcome:#?}"
            );
        }
        #[test]
        fn exit_profile_scopes_point_return_gaps_from_the_requested_entry() {
            let fixture = AnalyzerFixture::new_for_language(
                brokk_bifrost_core::analyzer::model::Language::Go,
                &[(
                    "entry_scope.go",
                    "package sample\nfunc target(callback func()) { defer callback() }\n",
                )],
            );
            let file = ProjectFile::new(fixture.project_root(), "entry_scope.go");
            let cancellation = CancellationToken::default();
            let mut materialization_budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                )
                .expect("Go materialization")
                .available_value()
                .cloned()
                .expect("Go artifact");
            let target = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(DeclarationSegment::name)
                        == Some("target")
                })
                .and_then(|procedure| artifact.procedure_handle(procedure.id()))
                .expect("target procedure");
            let semantics = target.semantics();
            let return_gap = semantics
                .gaps()
                .iter()
                .find(|gap| {
                    gap.subject == SemanticGapSubject::Point
                        && gap.impacts.contains(SemanticGapImpact::ReturnTransfer)
                })
                .expect("point-scoped defer return gap");
            let canonical_entry = target
                .point_handle(semantics.entry_point())
                .expect("canonical target entry");
            let exit = target
                .point_handle(semantics.normal_exit_point())
                .expect("target normal exit");
            assert_ne!(
                return_gap.point,
                exit.id(),
                "alternate exit entry must begin after the defer gap"
            );

            let provider = fixture.analyzer.icfg_provider();
            let mut canonical_budget = SemanticBudget::default();
            let canonical_outcome = provider
                .exit_profile(
                    &canonical_entry,
                    &exit,
                    &mut SemanticRequest::new(&mut canonical_budget, &cancellation),
                )
                .expect("canonical entry profile");
            let canonical_profile = canonical_outcome
                .available_value()
                .expect("canonical entry profile payload");
            assert_eq!(canonical_profile.callee_entry(), &canonical_entry);
            assert!(
                canonical_profile.has_aggregate_return_affecting_gaps(),
                "canonical entry-to-exit topology crosses the defer gap"
            );
            let expected_reason = semantics
                .gaps()
                .iter()
                .filter(|gap| gap.impacts.contains(SemanticGapImpact::ReturnTransfer))
                .map(|gap| {
                    format!(
                        "{} {}: {}",
                        gap.kind.label(),
                        gap.capability.label(),
                        gap.detail,
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            assert_eq!(
                canonical_profile.gap_reason.as_deref(),
                Some(expected_reason.as_str()),
            );
            assert_eq!(
                canonical_outcome.work().owned_text_bytes,
                expected_reason.len(),
                "the exact retained return-gap text must be charged",
            );
            assert_eq!(canonical_budget.used(), canonical_outcome.work());

            let mut text_limited_work = SemanticBudget::default().limits();
            text_limited_work.owned_text_bytes = expected_reason
                .len()
                .checked_sub(1)
                .expect("return-gap reason is non-empty");
            let mut text_limited_budget = SemanticBudget::new(text_limited_work)
                .expect("all semantic limits remain positive");
            // Measure the cold atomic charge rather than replaying the completed
            // profile from this query-local provider's memo.
            let text_limited_provider = fixture.analyzer.icfg_provider();
            let text_limited_outcome = text_limited_provider
                .exit_profile(
                    &canonical_entry,
                    &exit,
                    &mut SemanticRequest::new(&mut text_limited_budget, &cancellation),
                )
                .expect("owned-text boundary is a typed semantic outcome");
            let SemanticOutcome::ExceededBudget {
                partial,
                exceeded,
                work,
            } = text_limited_outcome
            else {
                panic!("the exact return-gap text must exceed the one-byte-short budget");
            };
            assert!(
                partial.is_none(),
                "a failed text charge publishes no profile"
            );
            assert_eq!(
                exceeded.dimension(),
                crate::analyzer::semantic::SemanticBudgetDimension::OwnedTextBytes,
            );
            assert_eq!(exceeded.limit(), expected_reason.len() - 1);
            assert_eq!(exceeded.attempted(), expected_reason.len());
            assert_eq!(work.owned_text_bytes, 0);
            assert_eq!(text_limited_budget.used(), work);

            let alternate_entry = exit.clone();
            let mut alternate_budget = SemanticBudget::default();
            let alternate_outcome = provider
                .exit_profile(
                    &alternate_entry,
                    &exit,
                    &mut SemanticRequest::new(&mut alternate_budget, &cancellation),
                )
                .expect("alternate entry profile");
            let alternate_profile = alternate_outcome
                .available_value()
                .expect("alternate entry profile payload");
            assert_eq!(alternate_profile.callee_entry(), &alternate_entry);
            assert!(
                !alternate_profile.has_aggregate_return_affecting_gaps(),
                "starting at the exit must exclude the earlier point-scoped defer gap"
            );
            assert!(
                matches!(alternate_outcome, SemanticOutcome::Complete { .. }),
                "no other return gap should weaken the alternate entry profile"
            );
            assert_eq!(alternate_outcome.work().owned_text_bytes, 0);
            assert_eq!(alternate_budget.used(), alternate_outcome.work());
        }
    }
    mod go_move_5 {

        use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind;

        use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLookup;

        use brokk_bifrost_analysis::analyzer::usages::call_shape::call_shape_for_call;

        use std::sync::Arc;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind;

        use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits;

        use brokk_bifrost_analysis::analyzer::usages::call_shape::CallShapeReport;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

        use brokk_bifrost_analysis::analyzer::usages::effects::ModeledCallApplication;

        use brokk_bifrost_analysis::analyzer::usages::effects::ModeledCallTargetArm;

        use brokk_bifrost_analysis::analyzer::usages::effects::ModeledCallTargetCoverage;

        use brokk_bifrost_analysis::analyzer::usages::effects::ModeledCallTargetLookup;

        use brokk_bifrost_analysis::analyzer::usages::effects::ModeledCallTargetOrigin;

        use brokk_bifrost_analysis::analyzer::usages::effects::ModeledProcedureKey;

        use brokk_bifrost_analysis::analyzer::usages::effects::modeled_call_targets_for_shape;

        use brokk_bifrost_analysis::analyzer::usages::effects::project_modeled_call_target_lookup;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_core::analyzer::model::ProjectFile;

        use brokk_bifrost_analysis::test_support::AnalyzerFixture;
        use brokk_bifrost_test_macros::hardwon;

        fn go_shape(
            fixture: &AnalyzerFixture,
            source: &str,
            call: &str,
        ) -> (CallShapeReport, Arc<str>) {
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let facts = fixture
                .analyzer
                .analyzer()
                .structural_fact_providers()
                .into_iter()
                .find_map(|provider| provider.structural_facts(&file))
                .expect("Go structural facts");
            let call_id = brokk_bifrost_analysis::analyzer::usages::test_support::call_node_id(
                source, &facts, call,
            );
            (
                call_shape_for_call(&facts, &file, call_id).expect("exact call shape"),
                Arc::from(source),
            )
        }
        fn modeled_lookup(
            fixture: &AnalyzerFixture,
            shape: &CallShapeReport,
            source: Arc<str>,
            limits: CallRelationLimits,
            cancellation: Option<&CancellationToken>,
        ) -> ModeledCallTargetLookup {
            modeled_call_targets_for_shape(
                fixture.analyzer.analyzer(),
                shape,
                source,
                limits,
                cancellation,
            )
        }
        #[test]
        #[hardwon(
            "aa501216592e: Real Go fixtures ensure external typed receiver calls stay targetless and preserve bound-receiver classification, including a call-expression receiver"
        )]
        fn external_typed_go_receiver_is_adjudicated_without_minting_a_target() {
            let source = r#"package main
import "embed"
var embedded embed.FS
func factory() embed.FS { return embedded }
func caller() {
    _, _ = embedded.Open("book.xlsx")
    _, _ = factory().Open("book.xlsx")
}
"#;
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
            let (shape, text) = go_shape(&fixture, source, "embedded.Open(\"book.xlsx\")");
            let lookup = modeled_lookup(
                &fixture,
                &shape,
                text,
                CallRelationLimits {
                    max_files: 1,
                    max_source_bytes: usize::MAX,
                    max_candidates: 100,
                },
                None,
            );
            assert!(lookup.arms.is_empty(), "{lookup:#?}");
            assert_eq!(lookup.coverage, ModeledCallTargetCoverage::Open);
            assert_eq!(
                lookup.call_application,
                ModeledCallApplication::BoundReceiver,
                "{lookup:#?}"
            );

            let (structured_shape, structured_text) =
                go_shape(&fixture, source, "factory().Open(\"book.xlsx\")");
            let structured = modeled_lookup(
                &fixture,
                &structured_shape,
                structured_text,
                CallRelationLimits {
                    max_files: 1,
                    max_source_bytes: usize::MAX,
                    max_candidates: 100,
                },
                None,
            );
            assert!(structured.arms.is_empty(), "{structured:#?}");
            assert_eq!(structured.coverage, ModeledCallTargetCoverage::Open);
            assert_eq!(
                structured.call_application,
                ModeledCallApplication::BoundReceiver,
                "the structured call-expression base is a value: {structured:#?}"
            );
        }
        #[test]
        fn lightweight_modeled_targets_preserve_go_aliases_and_typed_gaps() {
            let alias_source = r#"package main
import files "os"
func caller() { _, _ = files.Open("book.xlsx") }
"#;
            let alias_fixture =
                AnalyzerFixture::new_for_language(Language::Go, &[("main.go", alias_source)]);
            let (alias_shape, alias_text) =
                go_shape(&alias_fixture, alias_source, "files.Open(\"book.xlsx\")");
            let limits = CallRelationLimits {
                max_files: 1,
                max_source_bytes: usize::MAX,
                max_candidates: 100,
            };
            let alias = modeled_lookup(&alias_fixture, &alias_shape, alias_text, limits, None);
            // The import binder proves package-function application, not that the
            // external package publishes one callable of this exact shape. This
            // fixture activates no declaration overlay, so target coverage stays
            // open even though the canonical alias classification is retained.
            assert_eq!(alias.coverage, ModeledCallTargetCoverage::Open);
            assert!(alias.arms.is_empty(), "{alias:#?}");
            assert_eq!(
                alias.call_application,
                ModeledCallApplication::PackageFunction
            );

            let dot_source = r#"package main
import . "os"
func caller() { _, _ = Open("book.xlsx") }
"#;
            let dot_fixture =
                AnalyzerFixture::new_for_language(Language::Go, &[("main.go", dot_source)]);
            let (dot_shape, dot_text) = go_shape(&dot_fixture, dot_source, "Open(\"book.xlsx\")");
            let dot = modeled_lookup(&dot_fixture, &dot_shape, dot_text, limits, None);
            assert_eq!(dot.coverage, ModeledCallTargetCoverage::Open, "{dot:#?}");
            assert_eq!(
                dot.call_application,
                ModeledCallApplication::PackageFunction,
                "{dot:#?}"
            );
            assert!(dot.arms.is_empty(), "{dot:#?}");

            let shadowed_predeclared_source = r#"package main
import . "os"
func len(values []int) (int, error) { return 0, nil }
func caller(values []int) {
    _, _ = Open("book.xlsx")
    _, _ = len(values)
}
"#;
            let shadowed_predeclared_fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("main.go", shadowed_predeclared_source)],
            );
            let (shadowed_predeclared_shape, shadowed_predeclared_text) = go_shape(
                &shadowed_predeclared_fixture,
                shadowed_predeclared_source,
                "len(values)",
            );
            let shadowed_predeclared = modeled_lookup(
                &shadowed_predeclared_fixture,
                &shadowed_predeclared_shape,
                shadowed_predeclared_text,
                limits,
                None,
            );
            assert!(
                shadowed_predeclared
                    .arms
                    .iter()
                    .all(|arm| arm.key.owner != "os"),
                "{shadowed_predeclared:#?}"
            );
            assert!(
                !shadowed_predeclared.arms.is_empty(),
                "the shadowing package declaration must resolve to a target: {shadowed_predeclared:#?}"
            );

            let local_source = r#"package main
import os "os"
type opener struct{}
func (opener) Open(string) (int, error) { return 0, nil }
func caller(os opener) { _, _ = os.Open("book.xlsx") }
"#;
            let local_fixture =
                AnalyzerFixture::new_for_language(Language::Go, &[("main.go", local_source)]);
            let (local_shape, local_text) =
                go_shape(&local_fixture, local_source, "os.Open(\"book.xlsx\")");
            // The parameter binding shadows the package import, so the receiver is
            // the workspace `opener` value and the call binds that type's own
            // method. Since #3455 recorded Go callable modifiers the method has a
            // receiver contract and therefore a canonical key, so it resolves to a
            // workspace arm rather than staying an unkeyable residual. What must
            // not happen is the call borrowing `os.Open`'s identity.
            let local = modeled_lookup(&local_fixture, &local_shape, local_text, limits, None);
            assert_eq!(local.coverage, ModeledCallTargetCoverage::Exhaustive);
            let [local_arm] = local.arms.as_slice() else {
                panic!("one workspace arm for the local method: {local:#?}");
            };
            assert_eq!(local_arm.origin, ModeledCallTargetOrigin::WorkspaceBody);
            assert_ne!(local_arm.key.owner, "os");
            assert_eq!(local_arm.key.member, "Open");
            assert!(local_arm.key.has_receiver);
            assert_eq!(
                local.call_application,
                ModeledCallApplication::BoundReceiver,
                "the parameter binding shadows the package import: {local:#?}"
            );

            let local_callable_source = r#"package main
func caller(Open func(string) (int, error)) { _, _ = Open("book.xlsx") }
"#;
            let local_callable_fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("main.go", local_callable_source)],
            );
            let (local_callable_shape, local_callable_text) = go_shape(
                &local_callable_fixture,
                local_callable_source,
                "Open(\"book.xlsx\")",
            );
            let local_callable = modeled_lookup(
                &local_callable_fixture,
                &local_callable_shape,
                local_callable_text,
                limits,
                None,
            );
            assert!(local_callable.arms.is_empty(), "{local_callable:#?}");
            assert_eq!(
                local_callable.coverage,
                ModeledCallTargetCoverage::Unmodeled
            );

            let unresolved_source = r#"package main
func caller() { _, _ = missing.Open("book.xlsx") }
"#;
            let unresolved_fixture =
                AnalyzerFixture::new_for_language(Language::Go, &[("main.go", unresolved_source)]);
            let (unresolved_shape, unresolved_text) = go_shape(
                &unresolved_fixture,
                unresolved_source,
                "missing.Open(\"book.xlsx\")",
            );
            let unresolved = modeled_lookup(
                &unresolved_fixture,
                &unresolved_shape,
                unresolved_text,
                limits,
                None,
            );
            assert!(unresolved.arms.is_empty(), "{unresolved:#?}");
            assert_eq!(unresolved.coverage, ModeledCallTargetCoverage::Open);
            assert_eq!(unresolved.call_application, ModeledCallApplication::Unknown);

            let modeled_with_residual = project_modeled_call_target_lookup(
                alias_fixture.analyzer.analyzer(),
                &alias_shape,
                true,
                CallDispatchLookup {
                    status: Some(DefinitionLookupStatus::Ambiguous),
                    call_application: CallApplicationKind::PackageFunction,
                    exact_external_call: Some(ExactExternalCallProof::go_package_function(
                        "os.Open", 1,
                    )),
                    boundaries: vec![
                        CallDispatchBoundaryKind::External {
                            callee_text: Some("os.Open".into()),
                            normalized_static_owner: None,
                            external_callee_identity: None,
                        },
                        CallDispatchBoundaryKind::Unresolved(DefinitionLookupStatus::NoDefinition),
                    ],
                    ..CallDispatchLookup::default()
                },
            );
            assert_eq!(
                modeled_with_residual.arms,
                vec![ModeledCallTargetArm {
                    key: ModeledProcedureKey {
                        language: "go".to_owned(),
                        owner: "os".to_owned(),
                        member: "Open".to_owned(),
                        has_receiver: false,
                        parameter_count: 1,
                    },
                    origin: ModeledCallTargetOrigin::UnmaterializedExternal,
                }]
            );
            assert_eq!(
                modeled_with_residual.coverage,
                ModeledCallTargetCoverage::Open
            );

            let cancelled = CancellationToken::default();
            cancelled.cancel();
            let interrupted = modeled_lookup(
                &alias_fixture,
                &alias_shape,
                Arc::from(alias_source),
                limits,
                Some(&cancelled),
            );
            assert!(interrupted.arms.is_empty());
            assert_eq!(interrupted.coverage, ModeledCallTargetCoverage::Cancelled);

            let budgeted = modeled_lookup(
                &alias_fixture,
                &alias_shape,
                Arc::from(alias_source),
                CallRelationLimits {
                    max_source_bytes: 1,
                    ..limits
                },
                None,
            );
            assert!(budgeted.arms.is_empty());
            assert_eq!(budgeted.coverage, ModeledCallTargetCoverage::Truncated);

            let spread_source = r#"package main
import "fmt"
func caller(values []any) { fmt.Println(values...) }
"#;
            let spread_fixture =
                AnalyzerFixture::new_for_language(Language::Go, &[("main.go", spread_source)]);
            let (spread_shape, spread_text) =
                go_shape(&spread_fixture, spread_source, "fmt.Println(values...)");
            let spread = modeled_lookup(&spread_fixture, &spread_shape, spread_text, limits, None);
            assert!(spread.arms.is_empty(), "{spread:#?}\n{spread_shape:#?}");
            assert_eq!(spread.coverage, ModeledCallTargetCoverage::Unsupported);
        }
        #[test]
        fn exact_concrete_go_receiver_boundary_mints_only_a_receiver_arm() {
            let source = r#"package main
import "testing"
func caller(t *testing.T) { t.Fatal("stop") }
"#;
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
            let (shape, _) = go_shape(&fixture, source, "t.Fatal(\"stop\")");
            let dispatch = CallDispatchLookup {
                status: Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                call_application: CallApplicationKind::BoundReceiver,
                dispatch_extensibility: Some(
                    brokk_bifrost_core::analyzer::model::DispatchExtensibility::Closed,
                ),
                exact_external_call: Some(ExactExternalCallProof::go_concrete_receiver(
                    "testing.T.Fatal",
                    1,
                )),
                boundaries: vec![CallDispatchBoundaryKind::External {
                    callee_text: Some("testing.T.Fatal".into()),
                    normalized_static_owner: None,
                    external_callee_identity: None,
                }],
                ..CallDispatchLookup::default()
            };

            let exact = project_modeled_call_target_lookup(
                fixture.analyzer.analyzer(),
                &shape,
                true,
                dispatch.clone(),
            );
            assert_eq!(exact.coverage, ModeledCallTargetCoverage::Exhaustive);
            assert_eq!(
                exact.arms,
                vec![ModeledCallTargetArm {
                    key: ModeledProcedureKey {
                        language: "go".to_owned(),
                        owner: "testing.T".to_owned(),
                        member: "Fatal".to_owned(),
                        has_receiver: true,
                        parameter_count: 1,
                    },
                    origin: ModeledCallTargetOrigin::UnmaterializedExternal,
                }]
            );
            assert_eq!(
                exact.call_application,
                ModeledCallApplication::BoundReceiver
            );

            let uncertain = project_modeled_call_target_lookup(
                fixture.analyzer.analyzer(),
                &shape,
                true,
                CallDispatchLookup {
                    call_application: CallApplicationKind::ReceiverBindingUnknown,
                    exact_external_call: None,
                    ..dispatch.clone()
                },
            );
            assert!(uncertain.arms.is_empty(), "{uncertain:#?}");
            assert_eq!(uncertain.coverage, ModeledCallTargetCoverage::Open);

            for dispatch_extensibility in [
                None,
                Some(brokk_bifrost_core::analyzer::model::DispatchExtensibility::Open),
            ] {
                let open = project_modeled_call_target_lookup(
                    fixture.analyzer.analyzer(),
                    &shape,
                    true,
                    CallDispatchLookup {
                        dispatch_extensibility,
                        exact_external_call: None,
                        ..dispatch.clone()
                    },
                );
                assert!(open.arms.is_empty(), "{open:#?}");
                assert_eq!(open.coverage, ModeledCallTargetCoverage::Open);
            }

            let spread = project_modeled_call_target_lookup(
                fixture.analyzer.analyzer(),
                &shape,
                false,
                dispatch,
            );
            assert!(spread.arms.is_empty(), "{spread:#?}");
            assert_eq!(spread.coverage, ModeledCallTargetCoverage::Open);
        }
        #[test]
        fn modeled_go_target_uses_resolver_effective_arity_for_a_sole_tuple_call() {
            let source = r#"package main
import model "example.com/model"
func caller() { model.Binary(model.Pair()) }
"#;
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
            let (shape, _) = go_shape(&fixture, source, "model.Binary(model.Pair())");
            assert_eq!(
                shape.arguments.len(),
                1,
                "the structural call retains one written argument"
            );
            let lookup = project_modeled_call_target_lookup(
                fixture.analyzer.analyzer(),
                &shape,
                true,
                CallDispatchLookup {
                    status: Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                    call_application: CallApplicationKind::PackageFunction,
                    exact_external_call: Some(ExactExternalCallProof::go_package_function(
                        "example.com/model.Binary",
                        2,
                    )),
                    boundaries: vec![CallDispatchBoundaryKind::External {
                        callee_text: Some("example.com/model.Binary".into()),
                        normalized_static_owner: None,
                        external_callee_identity: None,
                    }],
                    ..CallDispatchLookup::default()
                },
            );

            assert_eq!(lookup.coverage, ModeledCallTargetCoverage::Exhaustive);
            let [arm] = lookup.arms.as_slice() else {
                panic!("one exact modeled arm: {lookup:#?}");
            };
            assert_eq!(arm.key.parameter_count, 2, "{lookup:#?}");
            assert_ne!(
                arm.key,
                ModeledProcedureKey {
                    parameter_count: 1,
                    ..arm.key.clone()
                },
                "a one-parameter summary cannot bind the two-result expansion"
            );
        }
        #[test]
        fn adjudicated_modeled_go_noncallable_is_unmodeled_not_open() {
            let source = r#"package main
import model "example.com/model"
func caller() { model.Duration(1) }
"#;
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
            let (shape, _) = go_shape(&fixture, source, "model.Duration(1)");
            let dispatch = CallDispatchLookup {
                status: Some(DefinitionLookupStatus::NoDefinition),
                call_application: CallApplicationKind::PackageFunction,
                adjudicated_no_target: true,
                boundaries: vec![CallDispatchBoundaryKind::Unresolved(
                    DefinitionLookupStatus::NoDefinition,
                )],
                ..CallDispatchLookup::default()
            };

            let adjudicated = project_modeled_call_target_lookup(
                fixture.analyzer.analyzer(),
                &shape,
                true,
                dispatch.clone(),
            );
            assert!(adjudicated.arms.is_empty(), "{adjudicated:#?}");
            assert_eq!(adjudicated.coverage, ModeledCallTargetCoverage::Unmodeled);

            let unproven = project_modeled_call_target_lookup(
                fixture.analyzer.analyzer(),
                &shape,
                true,
                CallDispatchLookup {
                    adjudicated_no_target: false,
                    ..dispatch
                },
            );
            assert!(unproven.arms.is_empty(), "{unproven:#?}");
            assert_eq!(unproven.coverage, ModeledCallTargetCoverage::Open);
        }
        #[test]
        fn external_typed_go_receiver_resolves_its_modeled_method_identity() {
            let source = r#"package main
import "embed"
var embedded embed.FS
func factory() embed.FS { return embedded }
func caller() {
    _, _ = embedded.Open("book.xlsx")
    _, _ = factory().Open("book.xlsx")
}
        "#;
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
            let overlay = brokk_bifrost_analysis::analyzer::semantic_model::overlay::go_extra_support_0::go_external_receiver_test_overlay();
            let _overlay_scope = brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::with_semantic_model_overlay(
                fixture.analyzer.analyzer(),
                Some(overlay),
            );
            let (shape, text) = go_shape(&fixture, source, "embedded.Open(\"book.xlsx\")");
            let lookup = modeled_lookup(
                &fixture,
                &shape,
                text,
                CallRelationLimits {
                    max_files: 1,
                    max_source_bytes: usize::MAX,
                    max_candidates: 100,
                },
                None,
            );
            let expected_arm = ModeledCallTargetArm {
                key: ModeledProcedureKey {
                    language: "go".to_owned(),
                    owner: "embed.FS".to_owned(),
                    member: "Open".to_owned(),
                    has_receiver: true,
                    parameter_count: 1,
                },
                origin: ModeledCallTargetOrigin::UnmaterializedExternal,
            };
            assert_eq!(lookup.arms, vec![expected_arm.clone()], "{lookup:#?}");
            assert_eq!(lookup.coverage, ModeledCallTargetCoverage::Exhaustive);
            assert_eq!(
                lookup.call_application,
                ModeledCallApplication::BoundReceiver,
                "{lookup:#?}"
            );

            let (structured_shape, structured_text) =
                go_shape(&fixture, source, "factory().Open(\"book.xlsx\")");
            let structured = modeled_lookup(
                &fixture,
                &structured_shape,
                structured_text,
                CallRelationLimits {
                    max_files: 1,
                    max_source_bytes: usize::MAX,
                    max_candidates: 100,
                },
                None,
            );
            assert_eq!(structured.arms, vec![expected_arm], "{structured:#?}");
            assert_eq!(structured.coverage, ModeledCallTargetCoverage::Exhaustive);
            assert_eq!(
                structured.call_application,
                ModeledCallApplication::BoundReceiver,
                "the structured call-expression base is a value: {structured:#?}"
            );
        }
    }
    mod go_move_6 {

        use brokk_bifrost_core::analyzer::model::Language;

        use std::sync::Arc;

        use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind;

        use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind;

        use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationService;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

        use brokk_bifrost_core::analyzer::model::DispatchExtensibility;

        use brokk_bifrost_analysis::analyzer::usages::call_relations::ExactCallLocation;

        use brokk_bifrost_core::analyzer::model::ProjectFile;

        use brokk_bifrost_core::analyzer::model::Range;

        use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity;

        use brokk_bifrost_core::analyzer::usages::model::UsageProof;

        use brokk_bifrost_analysis::analyzer::usages::call_relations::test_support::call_span;

        use brokk_bifrost_analysis::analyzer::usages::call_relations::test_support::generous_limits;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::GO_MODELED_PACKAGE_CALL_NOT_APPLICABLE_DIAGNOSTIC_KIND;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::GO_MODELED_PACKAGE_CALL_UNPROVEN_DIAGNOSTIC_KIND;

        use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

        use brokk_bifrost_core::analyzer::query_token::QueryScope;

        use brokk_bifrost_analysis::test_support::AnalyzerFixture;
        use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

        fn activate_go_declaration_payload(
            fixture: &AnalyzerFixture,
            pack_id: &str,
            import_path: &str,
            package_name: &str,
            mut types: Vec<serde_json::Value>,
            members: Vec<serde_json::Value>,
        ) {
            use crate::analyzer::semantic_model::{
                CatalogCoordinate, SemanticModelActivationControl, SemanticModelActivationEvidence,
                SemanticModelActivationRequest, SemanticModelControlAction,
                SemanticModelControlScope, SemanticModelPackSelector, SemanticModelRuntimeLimits,
            };

            let id_namespace = pack_id.replace('-', ".");
            let module_id = format!("type.{id_namespace}.module");
            types.insert(
                0,
                serde_json::json!({
                    "id": module_id,
                    "name": import_path,
                    "type_kind": "module",
                    "visibility": "package",
                    "aliases": [package_name],
                    "locator": {
                        "kind": "artifact",
                        "path": "fixture.go",
                        "symbol": import_path
                    }
                }),
            );
            let source = serde_json::to_vec(&serde_json::json!({
                "schema_version": 2,
                "pack_id": pack_id,
                "version": "1.0.0",
                "producer": { "name": "go-dispatch-fixture", "version": "1.0.0" },
                "language": "go",
                "ecosystem": "go",
                "compatibility": { "bifrost": "*", "toolchains": [] },
                "provenance": { "source": "fixture" },
                "license": "NOASSERTION",
                "completeness": "partial",
                "safety": { "generated_code_only": false, "review_required": false },
                "shards": [{
                    "id": format!("declarations.{pack_id}"),
                    "activation": [{}],
                    "payload": {
                        "kind": "declaration_facts",
                        "types": types,
                        "members": members,
                        "relations": []
                    }
                }]
            }))
            .expect("serialize Go declaration fixture");
            let request = SemanticModelActivationRequest {
                bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                    .expect("crate version"),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "go".to_owned(),
                    ecosystem: "go".to_owned(),
                    package: Some(CatalogCoordinate {
                        name: import_path.to_owned(),
                        version: None,
                    }),
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                }],
                controls: vec![SemanticModelActivationControl {
                    scope: SemanticModelControlScope::Workspace,
                    action: SemanticModelControlAction::Enable,
                    selector: SemanticModelPackSelector {
                        pack_id: pack_id.to_owned(),
                        version: None,
                        manifest_digest: None,
                    },
                }],
                limits: SemanticModelRuntimeLimits::default(),
            };
            brokk_bifrost_analysis::analyzer::usages::test_support::activate_semantic_pack(
                fixture.analyzer.analyzer(),
                pack_id,
                &source,
                &request,
            );
        }
        fn activate_go_function_declaration(
            fixture: &AnalyzerFixture,
            pack_id: &str,
            import_path: &str,
            package_name: &str,
            member: &str,
        ) {
            let id_namespace = pack_id.replace('-', ".");
            let module_id = format!("type.{id_namespace}.module");
            activate_go_declaration_payload(
                fixture,
                pack_id,
                import_path,
                package_name,
                Vec::new(),
                vec![serde_json::json!({
                    "id": format!("member.{id_namespace}.{}", member.to_ascii_lowercase()),
                    "owner": module_id,
                    "name": member,
                    "member_kind": "function",
                    "visibility": "public",
                    "is_static": true,
                    "signature": { "parameters": [] },
                    "locator": {
                        "kind": "artifact",
                        "path": "fixture.go",
                        "symbol": format!("{import_path}.{member}")
                    }
                })],
            );
        }
        #[test]
        fn exact_dispatch_preserves_canonical_go_external_package_member() {
            for (import, call) in [
                ("\"os\"", "os.Open(\"book.xlsx\")"),
                ("files \"os\"", "files.Open(\"book.xlsx\")"),
            ] {
                let source = format!(
                    "package main\n\nimport {import}\n\nfunc caller() {{ _, _ = {call} }}\n"
                );
                let fixture =
                    AnalyzerFixture::new_for_language(Language::Go, &[("main.go", &source)]);
                let file = ProjectFile::new(fixture.project_root(), "main.go");
                let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
                let lookup = CallRelationService::dispatch_at_bounded(
                    fixture.analyzer.analyzer(),
                    scope.token(),
                    &ExactCallLocation {
                        file,
                        call_span: call_span(&source, call),
                    },
                    Arc::from(source),
                    generous_limits(),
                    None,
                );

                assert_eq!(
                    lookup.status,
                    Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                    "{lookup:#?}"
                );
                assert_eq!(lookup.go_selector_member.as_deref(), None, "{lookup:#?}");
                assert!(lookup.targets.is_empty(), "{lookup:#?}");
                assert_eq!(
                    lookup.boundaries,
                    vec![CallDispatchBoundaryKind::External {
                        callee_text: Some("os.Open".into()),
                        normalized_static_owner: None,
                        external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
                            Language::Go,
                            "os",
                            "Open",
                        )),
                    }],
                    "{lookup:#?}"
                );
            }
        }
        #[test]
        fn exact_go_selector_dispatch_uses_receiver_method_sets_and_embedding() {
            let source = r#"package main

type receiver struct{}
func (receiver) Value() {}
func (*receiver) Pointer() {}

type embedded struct { receiver }
type shadow struct { receiver }
func (shadow) Value() {}

func caller() {
	var r receiver
	r.Value()
	r.Pointer()
	var e embedded
	e.Value()
	var s shadow
	s.Value()
}
"#;
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("go.mod", "module example.com/app\n"), ("main.go", source)],
            );
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
            for (call, expected) in [
                ("r.Value()", "example.com/app.receiver.Value"),
                ("r.Pointer()", "example.com/app.receiver.Pointer"),
                ("e.Value()", "example.com/app.receiver.Value"),
                ("s.Value()", "example.com/app.shadow.Value"),
            ] {
                let lookup = CallRelationService::dispatch_at_bounded(
                    fixture.analyzer.analyzer(),
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
                    Some(DefinitionLookupStatus::Resolved),
                    "{lookup:#?}"
                );
                assert_eq!(lookup.targets.len(), 1, "{lookup:#?}");
                assert_eq!(
                    lookup.targets[0].definition.fq_name(),
                    expected,
                    "{lookup:#?}"
                );
                assert_eq!(lookup.targets[0].proof, UsageProof::Proven);
                assert!(lookup.boundaries.is_empty(), "{lookup:#?}");
            }
        }
        #[test]
        fn exact_go_external_receiver_dispatch_preserves_reviewed_and_unmodeled_identity() {
            for model_level in 1..=2 {
                let modeled = model_level == 2;
                let source = r#"package main

import "time"

func caller(idleTicker *time.Ticker) { idleTicker.Stop() }
"#;
                let fixture = AnalyzerFixture::new_for_language(
                    Language::Go,
                    &[("go.mod", "module example.com/app\n"), ("main.go", source)],
                );
                let mut methods = Vec::new();
                if modeled {
                    methods.push(serde_json::json!({
                        "id": "fixture.go.time-ticker.stop",
                        "owner": "fixture.go.time-ticker.type",
                        "name": "Stop",
                        "member_kind": "method",
                        "visibility": "public",
                        "is_static": false,
                        "receiver": {"pointer": true},
                        "signature": {"parameters": []},
                        "locator": {
                            "kind": "artifact",
                            "path": "time/sleep.go",
                            "symbol": "time.Ticker.Stop"
                        }
                    }));
                }
                activate_go_declaration_payload(
                    &fixture,
                    "fixture.go.time-ticker",
                    "time",
                    "time",
                    vec![serde_json::json!({
                        "id": "fixture.go.time-ticker.type",
                        "name": "time.Ticker",
                        "type_kind": "struct",
                        "visibility": "public",
                        "locator": {
                            "kind": "artifact",
                            "path": "time/tick.go",
                            "symbol": "time.Ticker"
                        }
                    })],
                    methods,
                );
                let file = ProjectFile::new(fixture.project_root(), "main.go");
                let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
                let mut session = CallRelationService::dispatch_session(file, Arc::from(source));
                let lookup = session.dispatch_at_bounded(
                    fixture.analyzer.analyzer(),
                    scope.token(),
                    &call_span(source, "idleTicker.Stop()"),
                    generous_limits().max_candidates,
                    None,
                );

                assert_eq!(
                    lookup.status,
                    Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                    "{lookup:#?}"
                );
                assert!(lookup.targets.is_empty(), "{lookup:#?}");
                assert!(
                    lookup.boundaries.iter().any(|boundary| matches!(
                        boundary,
                        CallDispatchBoundaryKind::External {
                            callee_text: Some(callee), ..
                        } if callee.as_ref() == "time.Ticker.Stop"
                    )),
                    "{lookup:#?}"
                );
                let identity = lookup
                    .boundaries
                    .iter()
                    .find_map(|boundary| match boundary {
                        CallDispatchBoundaryKind::External {
                            external_callee_identity,
                            ..
                        } => external_callee_identity.as_ref(),
                        _ => None,
                    });
                assert_eq!(
                    identity.map(|identity| {
                        (identity.language(), identity.owner_fqn(), identity.member())
                    }),
                    (model_level > 0).then_some((Language::Go, "time.Ticker", "Stop")),
                    "only a structured external concrete type declaration proves a model key: {lookup:#?}"
                );
                let proof = lookup
                    .exact_external_call
                    .as_ref()
                    .expect("structured external receiver retains its canonical identity");
                assert_eq!(proof.canonical_callee(), "time.Ticker.Stop");
                assert_eq!(
                    proof.dispatch_extensibility(),
                    modeled.then_some(DispatchExtensibility::Closed),
                    "{lookup:#?}"
                );
            }
        }
        #[test]
        fn exact_dispatch_keeps_model_proof_external_and_canonical() {
            for (
                pack_id,
                import_path,
                package_name,
                import,
                call,
                expected_target,
                expected_owner,
                expected_member,
            ) in [
                (
                    "fixture.go.os",
                    "os",
                    "os",
                    "\"os\"",
                    "os.Open()",
                    "os.Open",
                    "os",
                    "Open",
                ),
                (
                    "fixture.go.os-alias",
                    "os",
                    "os",
                    "files \"os\"",
                    "files.Open()",
                    "os.Open",
                    "os",
                    "Open",
                ),
                (
                    "fixture.go.declared-name",
                    "example.com/m/postgres",
                    "pg",
                    "\"example.com/m/postgres\"",
                    "pg.Open()",
                    "example.com/m/postgres.Open",
                    "example.com/m/postgres",
                    "Open",
                ),
                (
                    "fixture.go.dot-import",
                    "os",
                    "os",
                    ". \"os\"",
                    "Open()",
                    "os.Open",
                    "os",
                    "Open",
                ),
            ] {
                let source = format!(
                    "package main\n\nimport {import}\n\nfunc caller() {{ _, _ = {call} }}\n"
                );
                let fixture =
                    AnalyzerFixture::new_for_language(Language::Go, &[("main.go", &source)]);
                activate_go_function_declaration(
                    &fixture,
                    pack_id,
                    import_path,
                    package_name,
                    "Open",
                );
                let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
                let lookup = CallRelationService::dispatch_at_bounded(
                    fixture.analyzer.analyzer(),
                    scope.token(),
                    &ExactCallLocation {
                        file: ProjectFile::new(fixture.project_root(), "main.go"),
                        call_span: call_span(&source, call),
                    },
                    Arc::from(source),
                    generous_limits(),
                    None,
                );

                assert_eq!(
                    lookup.status,
                    Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                    "{lookup:#?}"
                );
                assert_eq!(lookup.boundary, Some(BoundaryStatus::ExternalIndexed));
                assert_eq!(
                    lookup.boundaries,
                    vec![CallDispatchBoundaryKind::External {
                        callee_text: Some(expected_target.into()),
                        normalized_static_owner: None,
                        external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
                            Language::Go,
                            expected_owner,
                            expected_member,
                        )),
                    }],
                    "{lookup:#?}"
                );
                assert_eq!(
                    lookup.call_application,
                    CallApplicationKind::PackageFunction,
                    "{lookup:#?}"
                );
                assert_eq!(lookup.dispatch_extensibility, None, "{lookup:#?}");
            }
        }
        #[test]
        fn dot_imported_model_function_conflicts_with_package_scope_and_stays_identityless() {
            let source = r#"package main

import . "example.com/model"

func Open() {}
func caller() { Open() }
"#;
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("go.mod", "module example.com/app\n"), ("main.go", source)],
            );
            activate_go_function_declaration(
                &fixture,
                "fixture.go.dot-shadow",
                "example.com/model",
                "model",
                "Open",
            );
            let lookup = CallRelationService::dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                AnalyzerQueryScope::new(fixture.analyzer.analyzer()).token(),
                &ExactCallLocation {
                    file: ProjectFile::new(fixture.project_root(), "main.go"),
                    call_span: call_span(source, "Open()"),
                },
                Arc::from(source),
                generous_limits(),
                None,
            );
            assert_eq!(
                lookup.status,
                Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                "{lookup:#?}"
            );
            assert!(lookup.targets.is_empty(), "{lookup:#?}");
            assert_eq!(lookup.boundary, Some(BoundaryStatus::ExternalIndexed));
            assert_eq!(
                lookup.call_application,
                CallApplicationKind::PackageFunction
            );
            assert_eq!(
                lookup.boundaries,
                vec![CallDispatchBoundaryKind::External {
                    callee_text: None,
                    normalized_static_owner: None,
                    external_callee_identity: None,
                }],
                "{lookup:#?}"
            );

            let ambiguous_source = r#"package main

import (
    . "example.com/a"
    . "example.com/b"
)

func caller() { Open() }
"#;
            let ambiguous = AnalyzerFixture::new_for_language(
                Language::Go,
                &[
                    ("go.mod", "module example.com/app\n"),
                    ("main.go", ambiguous_source),
                ],
            );
            for (pack_id, import_path, package_name) in [
                ("fixture.go.dot-a", "example.com/a", "a"),
                ("fixture.go.dot-b", "example.com/b", "b"),
            ] {
                activate_go_function_declaration(
                    &ambiguous,
                    pack_id,
                    import_path,
                    package_name,
                    "Open",
                );
            }
            let lookup = CallRelationService::dispatch_at_bounded(
                ambiguous.analyzer.analyzer(),
                AnalyzerQueryScope::new(ambiguous.analyzer.analyzer()).token(),
                &ExactCallLocation {
                    file: ProjectFile::new(ambiguous.project_root(), "main.go"),
                    call_span: call_span(ambiguous_source, "Open()"),
                },
                Arc::from(ambiguous_source),
                generous_limits(),
                None,
            );
            assert_eq!(
                lookup.status,
                Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                "{lookup:#?}"
            );
            assert!(lookup.targets.is_empty(), "{lookup:#?}");
            assert!(
                lookup.boundaries.iter().all(|boundary| match boundary {
                    CallDispatchBoundaryKind::External {
                        callee_text,
                        external_callee_identity,
                        ..
                    } => callee_text.is_none() && external_callee_identity.is_none(),
                    _ => true,
                }),
                "{lookup:#?}"
            );
        }
        #[brokk_bifrost_test_macros::hardwon(
            "5c5d4e214494: Go model proof requires one public exact callable and applicable arity"
        )]
        #[test]
        fn modeled_go_package_calls_require_one_public_exact_function() {
            let import_path = "example.com/model";
            let pack_id = "fixture.go.package-calls";
            let id_namespace = pack_id.replace('-', ".");
            let module_id = format!("type.{id_namespace}.module");
            let function =
                |id: &str, name: &str, visibility: &str, parameters: Vec<serde_json::Value>| {
                    serde_json::json!({
                        "id": id,
                        "owner": module_id,
                        "name": name,
                        "member_kind": "function",
                        "visibility": visibility,
                        "is_static": true,
                        "signature": { "parameters": parameters },
                        "locator": {
                            "kind": "artifact",
                            "path": "fixture.go",
                            "symbol": format!("{import_path}.{name}")
                        }
                    })
                };
            let result_function =
                |id: &str, name: &str, returns: serde_json::Value| -> serde_json::Value {
                    let mut declaration = function(id, name, "public", Vec::new());
                    declaration["signature"]["returns"] = returns;
                    declaration
                };
            let source = r#"package main

import model "example.com/model"

func pair() (int, int) { return 1, 2 }

func caller() {
    values := []int{1, 2}
    model.Open()
    model.Open(1)
    model.Open(model.One())
    model.Open(model.Pair())
    model.Binary(model.Pair())
    model.Zero()
    model.NoResult()
    model.Zero(model.NoResult())
    model.Duration(1)
    model.Vector(1)
    model.Open[int](1)
    model.Variadic()
    model.Variadic(1)
    model.Variadic(1, 2)
    model.Variadic(model.Pair())
    model.Variadic(pair())
    model.Variadic((pair()))
    model.Variadic(values...)
    model.Flag()
    model.Conflict()
    model.Hidden()
}
"#;
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
            activate_go_declaration_payload(
                &fixture,
                pack_id,
                import_path,
                "model",
                vec![
                    serde_json::json!({
                        "id": format!("type.{id_namespace}.duration"),
                        "name": format!("{import_path}.Duration"),
                        "type_kind": "struct",
                        "visibility": "public",
                        "locator": {
                            "kind": "artifact",
                            "path": "fixture.go",
                            "symbol": format!("{import_path}.Duration")
                        }
                    }),
                    serde_json::json!({
                        "id": format!("type.{id_namespace}.vector"),
                        "name": format!("{import_path}.Vector"),
                        "type_kind": "struct",
                        "visibility": "public",
                        "locator": {
                            "kind": "artifact",
                            "path": "fixture.go",
                            "symbol": format!("{import_path}.Vector")
                        }
                    }),
                ],
                vec![
                    function(
                        "member.fixture.open",
                        "Open",
                        "public",
                        vec![serde_json::json!({
                            "name": "value",
                            "type": { "kind": "named", "name": "int" }
                        })],
                    ),
                    function(
                        "member.fixture.variadic",
                        "Variadic",
                        "public",
                        vec![serde_json::json!({
                            "name": "values",
                            "type": { "kind": "named", "name": "int" },
                            "variadic": true
                        })],
                    ),
                    function(
                        "member.fixture.binary",
                        "Binary",
                        "public",
                        vec![
                            serde_json::json!({
                                "name": "left",
                                "type": { "kind": "named", "name": "int" }
                            }),
                            serde_json::json!({
                                "name": "right",
                                "type": { "kind": "named", "name": "int" }
                            }),
                        ],
                    ),
                    function("member.fixture.zero", "Zero", "public", Vec::new()),
                    function("member.fixture.no-result", "NoResult", "public", Vec::new()),
                    result_function(
                        "member.fixture.one",
                        "One",
                        serde_json::json!({
                            "kind": "named",
                            "name": "int"
                        }),
                    ),
                    result_function(
                        "member.fixture.pair",
                        "Pair",
                        serde_json::json!({
                            "kind": "tuple",
                            "elements": [
                                { "kind": "named", "name": "int" },
                                { "kind": "named", "name": "int" }
                            ]
                        }),
                    ),
                    serde_json::json!({
                        "id": "member.fixture.flag",
                        "owner": module_id,
                        "name": "Flag",
                        "member_kind": "constant",
                        "visibility": "public",
                        "is_static": true,
                        "locator": {
                            "kind": "artifact",
                            "path": "fixture.go",
                            "symbol": format!("{import_path}.Flag")
                        }
                    }),
                    function(
                        "member.fixture.conflict.first",
                        "Conflict",
                        "public",
                        Vec::new(),
                    ),
                    function(
                        "member.fixture.conflict.second",
                        "Conflict",
                        "public",
                        Vec::new(),
                    ),
                    function("member.fixture.hidden", "Hidden", "private", Vec::new()),
                ],
            );
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
            let lookup = |call: &str| {
                CallRelationService::dispatch_at_bounded(
                    fixture.analyzer.analyzer(),
                    scope.token(),
                    &ExactCallLocation {
                        file: file.clone(),
                        call_span: call_span(source, call),
                    },
                    Arc::from(source),
                    generous_limits(),
                    None,
                )
            };

            for (call, canonical, member, effective_parameter_count) in [
                ("model.Open(1)", "example.com/model.Open", "Open", 1),
                (
                    "model.Open(model.One())",
                    "example.com/model.Open",
                    "Open",
                    1,
                ),
                (
                    "model.Binary(model.Pair())",
                    "example.com/model.Binary",
                    "Binary",
                    2,
                ),
                ("model.One()", "example.com/model.One", "One", 0),
                ("model.Pair()", "example.com/model.Pair", "Pair", 0),
                ("model.Zero()", "example.com/model.Zero", "Zero", 0),
                (
                    "model.NoResult()",
                    "example.com/model.NoResult",
                    "NoResult",
                    0,
                ),
                (
                    "model.Variadic()",
                    "example.com/model.Variadic",
                    "Variadic",
                    0,
                ),
                (
                    "model.Variadic(1)",
                    "example.com/model.Variadic",
                    "Variadic",
                    1,
                ),
                (
                    "model.Variadic(1, 2)",
                    "example.com/model.Variadic",
                    "Variadic",
                    2,
                ),
                (
                    "model.Variadic(model.Pair())",
                    "example.com/model.Variadic",
                    "Variadic",
                    2,
                ),
            ] {
                let exact = lookup(call);
                assert!(
                    scope.store_error().is_none(),
                    "modeled call store error: {:?}",
                    scope.store_error()
                );
                assert_eq!(
                    exact.status,
                    Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                    "{call}: {exact:#?}; parse errors: {:?}",
                    fixture.analyzer.analyzer().parse_errors(&file)
                );
                assert_eq!(
                    exact.boundaries,
                    vec![CallDispatchBoundaryKind::External {
                        callee_text: Some(canonical.into()),
                        normalized_static_owner: None,
                        external_callee_identity: Some(ResolverOwnedExternalCalleeIdentity::new(
                            Language::Go,
                            import_path,
                            member,
                        )),
                    }],
                    "{call}: {exact:#?}"
                );
                let proof = exact
                    .exact_external_call
                    .as_ref()
                    .unwrap_or_else(|| panic!("{call}: exact external proof: {exact:#?}"));
                assert_eq!(proof.canonical_callee(), canonical, "{call}: {exact:#?}");
                assert_eq!(
                    proof.call_application(),
                    CallApplicationKind::PackageFunction,
                    "{call}: {exact:#?}"
                );
                assert_eq!(
                    proof.parameter_count(),
                    effective_parameter_count,
                    "{call}: {exact:#?}"
                );
            }

            for (call, adjudicated_no_target) in [
                ("model.Open()", true),
                ("model.Duration(1)", true),
                ("model.Vector(1)", true),
                ("model.Open(model.Pair())", true),
                ("model.Zero(model.NoResult())", false),
                ("model.Variadic(pair())", false),
                ("model.Variadic((pair()))", false),
                ("model.Variadic(values...)", false),
                ("model.Flag()", true),
                ("model.Conflict()", false),
                ("model.Hidden()", true),
            ] {
                let rejected = lookup(call);
                assert_eq!(
                    rejected.status,
                    Some(DefinitionLookupStatus::NoDefinition),
                    "{call}: {rejected:#?}"
                );
                assert_eq!(
                    rejected.dispatch_extensibility, None,
                    "{call}: {rejected:#?}"
                );
                assert!(
                    rejected.exact_external_call.is_none(),
                    "{call}: rejected calls retain no partial external identity: {rejected:#?}"
                );
                assert_eq!(
                    rejected.adjudicated_no_target, adjudicated_no_target,
                    "{call}: {rejected:#?}"
                );
                let expected_diagnostic = if adjudicated_no_target {
                    GO_MODELED_PACKAGE_CALL_NOT_APPLICABLE_DIAGNOSTIC_KIND
                } else {
                    GO_MODELED_PACKAGE_CALL_UNPROVEN_DIAGNOSTIC_KIND
                };
                assert!(
                    rejected
                        .diagnostics
                        .iter()
                        .any(|diagnostic| diagnostic.starts_with(expected_diagnostic)),
                    "{call}: {rejected:#?}"
                );
                assert!(
                    rejected.boundaries.iter().all(|boundary| !matches!(
                        boundary,
                        CallDispatchBoundaryKind::External { .. }
                    )),
                    "{call}: {rejected:#?}"
                );
            }

            let generic = lookup("model.Open[int](1)");
            assert_eq!(
                generic.status,
                Some(DefinitionLookupStatus::InvalidLocation),
                "{generic:#?}"
            );
            assert!(!generic.adjudicated_no_target, "{generic:#?}");
            assert!(
                generic
                    .boundaries
                    .iter()
                    .all(|boundary| !matches!(boundary, CallDispatchBoundaryKind::External { .. })),
                "{generic:#?}"
            );
        }
        #[test]
        fn a_model_cannot_turn_a_workspace_go_package_miss_external() {
            for (pack_id, import_path, package_name, workspace_file) in [
                (
                    "fixture.go.workspace-collision",
                    "example.com/app/service",
                    "service",
                    "service/service.go",
                ),
                (
                    "fixture.go.vendor-collision",
                    "example.com/dep/pkg",
                    "pkg",
                    "vendor/example.com/dep/pkg/pkg.go",
                ),
            ] {
                let call = format!("{package_name}.Open()");
                let source = format!(
                    "package main\n\nimport \"{import_path}\"\n\nfunc caller() {{ {call} }}\n"
                );
                let workspace_source = format!("package {package_name}\n");
                let fixture = AnalyzerFixture::new_for_language(
                    Language::Go,
                    &[
                        ("go.mod", "module example.com/app\n"),
                        (workspace_file, &workspace_source),
                        ("main.go", &source),
                    ],
                );
                activate_go_function_declaration(
                    &fixture,
                    pack_id,
                    import_path,
                    package_name,
                    "Open",
                );
                let file = ProjectFile::new(fixture.project_root(), "main.go");
                let tree = brokk_bifrost_analysis::analyzer::usages::get_definition::parse_tree_for_language(
                    &file,
                    Language::Go,
                    &source,
                )
                .expect("Go tree");
                let focus_start_byte = source.find("Open").expect("Open reference");
                let focus_end_byte = focus_start_byte + "Open".len();
                let focus_line = source[..focus_start_byte]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count()
                    + 1;
                let site = ResolvedReferenceSite {
                    path: brokk_bifrost_core::path_utils::rel_path_string(&file),
                    text: "Open".to_owned(),
                    range: Range {
                        start_byte: focus_start_byte,
                        end_byte: focus_end_byte,
                        start_line: focus_line,
                        end_line: focus_line,
                    },
                    focus_start_byte,
                    focus_end_byte,
                };
                let go = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                    brokk_bifrost_go_analysis::GoAnalyzer,
                >(fixture.analyzer.analyzer())
                .expect("fixture Go analyzer");
                let index_builds_before = go.workspace_path_index_build_count_for_test();
                assert_eq!(
                    index_builds_before, 0,
                    "the bounded regression must exercise a cold workspace path index"
                );
                let bounded = brokk_bifrost_go_analysis::analyzer::usages::get_definition::go::resolve_go_bounded(
                fixture.analyzer.analyzer(),
                &file,
                &source,
                Some(&tree),
                &site,
                brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget::default(
                ),
                None,
            );
                let brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution::Complete {
                    value: bounded,
                    ..
                } = bounded
                else {
                    panic!(
                        "bounded Go lookup should complete without scanning the workspace: {bounded:#?}"
                    );
                };
                assert_eq!(bounded.status, DefinitionLookupStatus::NoDefinition);
                assert!(bounded.reference.is_none(), "{bounded:#?}");
                assert_eq!(
                    go.workspace_path_index_build_count_for_test(),
                    index_builds_before,
                    "bounded resolution must not initialize the whole-workspace path index"
                );

                let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
                let lookup = CallRelationService::dispatch_at_bounded(
                    fixture.analyzer.analyzer(),
                    scope.token(),
                    &ExactCallLocation {
                        file,
                        call_span: call_span(&source, &call),
                    },
                    Arc::from(source),
                    generous_limits(),
                    None,
                );

                assert_eq!(
                    lookup.status,
                    Some(DefinitionLookupStatus::NoDefinition),
                    "{import_path}: {lookup:#?}"
                );
                assert!(
                    lookup.boundaries.iter().all(|boundary| !matches!(
                        boundary,
                        CallDispatchBoundaryKind::External { .. }
                    )),
                    "{import_path}: {lookup:#?}"
                );
                assert_eq!(
                    go.workspace_path_index_build_count_for_test(),
                    index_builds_before,
                    "bounded exact dispatch must not initialize the whole-workspace path index"
                );
            }
        }
        #[test]
        fn local_go_value_named_like_package_is_not_an_external_member() {
            let source = r#"package main

type opener struct{}
func (opener) Open(string) {}

func caller(os opener) { os.Open("book.xlsx") }
"#;
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let scope = AnalyzerQueryScope::new(fixture.analyzer.analyzer());
            let lookup = CallRelationService::dispatch_at_bounded(
                fixture.analyzer.analyzer(),
                scope.token(),
                &ExactCallLocation {
                    file,
                    call_span: call_span(source, "os.Open(\"book.xlsx\")"),
                },
                Arc::from(source),
                generous_limits(),
                None,
            );

            assert!(
                !lookup.boundaries.iter().any(|boundary| matches!(
                    boundary,
                    CallDispatchBoundaryKind::External {
                        callee_text: Some(target),
                        ..
                    } if target.as_ref() == "os.Open"
                )),
                "{lookup:#?}"
            );
        }
        #[brokk_bifrost_test_macros::hardwon(
            "#2808+911caaf2b65b: Go external dispatch identity requires proven workspace-package absence"
        )]
        #[test]
        fn go_external_identity_requires_proven_absent_workspace_package() {
            let workspace_source = r#"package main

import "example.com/app/library"

func caller() { library.Open() }
"#;
            let workspace = AnalyzerFixture::new_for_language(
                Language::Go,
                &[
                    ("go.mod", "module example.com/app\n"),
                    ("library/library.go", "package library\n\nfunc Open() {}\n"),
                    ("main.go", workspace_source),
                ],
            );
            let workspace_lookup = CallRelationService::dispatch_at_bounded(
                workspace.analyzer.analyzer(),
                AnalyzerQueryScope::new(workspace.analyzer.analyzer()).token(),
                &ExactCallLocation {
                    file: ProjectFile::new(workspace.project_root(), "main.go"),
                    call_span: call_span(workspace_source, "library.Open()"),
                },
                Arc::from(workspace_source),
                generous_limits(),
                None,
            );
            assert_eq!(
                workspace_lookup.status,
                Some(DefinitionLookupStatus::Resolved),
                "{workspace_lookup:#?}"
            );
            assert_eq!(workspace_lookup.targets.len(), 1, "{workspace_lookup:#?}");
            assert!(
                workspace_lookup.boundaries.is_empty(),
                "{workspace_lookup:#?}"
            );

            let incomplete_source = r#"package main

import "os"

func caller() { _, _ = os.Open("book.xlsx") }
"#;
            let incomplete = AnalyzerFixture::new_for_language(
                Language::Go,
                &[
                    ("go.mod", "module example.com/app\n"),
                    ("main.go", incomplete_source),
                ],
            );
            let go = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                brokk_bifrost_go_analysis::GoAnalyzer,
            >(incomplete.analyzer.analyzer())
            .expect("fixture Go analyzer");
            let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
                Arc::new(incomplete.test_project().clone()),
            ));
            let incomplete_file = ProjectFile::new(incomplete.project_root(), "main.go");
            assert!(overlay.set(
                incomplete_file.abs_path().to_path_buf(),
                incomplete_source.to_owned(),
            ));
            let request_snapshot = go.clone_with_project(
                overlay as Arc<dyn brokk_bifrost_core::analyzer::project::Project>,
            );
            let incomplete_lookup = CallRelationService::dispatch_at_bounded(
                &request_snapshot,
                AnalyzerQueryScope::new(&request_snapshot).token(),
                &ExactCallLocation {
                    file: incomplete_file,
                    call_span: call_span(incomplete_source, "os.Open(\"book.xlsx\")"),
                },
                Arc::from(incomplete_source),
                generous_limits(),
                None,
            );
            assert_ne!(
                incomplete_lookup.status,
                Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                "an incomplete package inventory cannot prove absence: {incomplete_lookup:#?}"
            );
            assert!(
                incomplete_lookup
                    .boundaries
                    .iter()
                    .all(|boundary| match boundary {
                        CallDispatchBoundaryKind::External {
                            external_callee_identity,
                            ..
                        } => external_callee_identity.is_none(),
                        _ => true,
                    }),
                "an incomplete package inventory must not mint external identity: {incomplete_lookup:#?}"
            );
        }
    }

    mod go_move_8 {

        use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;

        use brokk_bifrost_go_analysis::analyzer::go::native_points::GoNativePointRequest;

        use brokk_bifrost_go_analysis::analyzer::go::native_points::GoNativePointRequestOpen;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SharedNameInterner;

        use crate::analyzer::semantic_model::DependencyPackLimits;

        use crate::analyzer::semantic_model::SemanticModelActivationRequest;

        use crate::analyzer::semantic_model::SemanticModelRuntimeLimits;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

        use brokk_bifrost_analysis::analyzer::store::PersistBatchTargets;

        use brokk_bifrost_analysis::analyzer::store::go_unit_summaries::go_unit_key;

        use brokk_bifrost_analysis::analyzer::store::go_unit_summaries::go_live_summary;

        use brokk_bifrost_analysis::analyzer::store::go_unit_summaries::go_profile_read_key;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_same_package::PACKAGE_PEER_MOUNTS;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::package_context::SelectedPackageRows;

        use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

        use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_named::GoPreparedImportContextOutcome;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedResolutionMountOrdinal;

        use brokk_bifrost_analysis::analyzer::store::unit_summaries as unit_summaries_sql;

        use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

        use brokk_bifrost_analysis::analyzer::workspace::DependencyPackEcosystem;

        use brokk_bifrost_analysis::analyzer::workspace::DependencyPackWorkspaceContext;

        use brokk_bifrost_go_analysis::GoAnalyzer;

        use brokk_bifrost_core::analyzer::config::GoAnalyzerConfig;

        use brokk_bifrost_core::analyzer::config::GoDependencyDiscoveryConfig;

        use brokk_bifrost_core::analyzer::config::GoDependencyDiscoveryMode;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

        use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
        use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
        use git2::{ObjectType, Oid};
        use rusqlite::OptionalExtension;

        const GO_FIXTURE: &[(&str, &str)] = &[
            ("go.mod", "module example.test/native\n\ngo 1.22\n"),
            (
                "util/util.go",
                "package util\n\ntype Helper struct{}\n\nfunc Public() int { return private() }\n\nfunc private() int { return 1 }\n\nconst Limit = 10\n\nvar shared = 2\n\nfunc Map[T any](x T) T { return x }\n\ntype Pair[K comparable, V any] struct{ Key K; Val V }\n",
            ),
            (
                "other/other.go",
                "package other\n\nfunc Extra() int { return 0 }\n\ntype Thing struct{}\n",
            ),
            ("blank/blank.go", "package blank\n\nfunc init() {}\n"),
            (
                "api/api.go",
                "package api\n\nimport (\n\t\"strings\"\n\n\t. \"example.test/native/other\"\n\t_ \"example.test/native/blank\"\n\tu \"example.test/native/util\"\n)\n\ntype Client struct{ name string }\ntype LocalClient = Client\ntype HelperAlias = u.Helper\ntype CommandCtx = func()\n\nfunc NewClient() *Client {\n\t_ = strings.ToUpper(\"x\")\n\t_ = u.Public()\n\t_ = Extra()\n\treturn &Client{}\n}\n",
            ),
            (
                "api/helpers.go",
                "package api\n\nvar Version = \"1\"\n\nvar (\n\tAlpha, beta = 1, 2\n)\n\nconst (\n\tfirst = iota\n\tSecond\n)\n\ntype internalState struct{}\n\nfunc helper() {}\n",
            ),
            (
                "api/platform_windows.go",
                "//go:build windows\n\npackage api\n\nfunc platform() {}\n",
            ),
            (
                "api/platform_other.go",
                "//go:build !windows\n\npackage api\n\nfunc platform() {}\n",
            ),
            (
                "api/api_internal_test.go",
                "package api\n\nimport \"testing\"\n\nfunc TestClient(t *testing.T) { helper(); _ = internalState{} }\n",
            ),
            (
                "api/api_ext_test.go",
                "package api_test\n\nimport (\n\t\"testing\"\n\n\t\"example.test/native/api\"\n\t\"example.test/native/util\"\n)\n\nfunc TestExt(t *testing.T) { _ = api.NewClient(); _ = util.Limit }\n",
            ),
            (
                "cmd/main.go",
                "package main\n\nimport \"example.test/native/api\"\n\nfunc main() { api.NewClient() }\n",
            ),
        ];
        fn go_full_production_config() -> AnalyzerConfig {
            AnalyzerConfig {
                go: GoAnalyzerConfig {
                    dependency_discovery: GoDependencyDiscoveryConfig {
                        mode: GoDependencyDiscoveryMode::FullProduction,
                        // The fixture has mutually exclusive Linux/Windows files.
                        // Pin the Go target so expected unit paths do not depend on
                        // the operating system running the test.
                        goos: Some("linux".to_owned()),
                        ..GoDependencyDiscoveryConfig::default()
                    },
                },
                ..AnalyzerConfig::default()
            }
        }
        /// Publish the Go dependency context of `workspace` through the production path,
        /// which reconciles the unit summaries after the head publication.
        fn activate_go_context(workspace: &WorkspaceAnalyzer) {
            activate_go_context_with(workspace, &go_full_production_config());
        }
        fn activate_go_context_with(workspace: &WorkspaceAnalyzer, config: &AnalyzerConfig) {
            let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
            let activation = SemanticModelActivationRequest {
                bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                evidence: Vec::new(),
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            };
            let cancellation = CancellationToken::default();
            let discovery = workspace.activate_dependency_packs(
                config,
                &[DependencyPackEcosystem::Go],
                DependencyPackWorkspaceContext {
                    catalog: &catalog,
                    persistence: None,
                    activation: &activation,
                    limits: DependencyPackLimits::default(),
                    cancellation: &cancellation,
                },
            );
            let discovery = format!("{discovery:#?}");
            assert!(!discovery.contains("go.unit_summary_failed"), "{discovery}");
        }
        fn go_toolchain_available() -> bool {
            std::process::Command::new("go")
                .arg("version")
                .output()
                .is_ok()
        }
        /// Build a Go workspace and publish its tool context. `None` when the host
        /// lacks the Go toolchain needed for this publication.
        fn published_go_workspace(
            files: &[(&str, &str)],
        ) -> Option<(BuiltInlineTestProject, WorkspaceAnalyzer)> {
            if !go_toolchain_available() {
                return None;
            }
            let mut project = InlineTestProject::with_language(Language::Go);
            for (path, source) in files {
                project = project.file(*path, *source);
            }
            let fixture = project.build();
            let workspace = fixture.workspace_analyzer(go_full_production_config());
            activate_go_context(&workspace);
            Some((fixture, workspace))
        }
        /// One member file of one unit, as the incumbent same-package reader sees it.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
        struct UnitMemberFact {
            blob_id: i64,
            rel_path: String,
        }
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
        struct ExportFact {
            blob_id: i64,
            site: u32,
            key: u32,
            namespace: String,
            identity_id: i64,
        }
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
        struct ImportFact {
            blob_id: i64,
            definition_key: u32,
            dependency_unit_key: String,
        }
        /// A dot import, which the incumbent import binding reader does not publish. The
        /// oracle is the tool's own import rows for the spelling the file declares.
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
        struct DotImportFact {
            blob_id: i64,
            import_id: i64,
            dependency_unit_key: String,
        }
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }
        fn symmetric_difference<T: Ord + Clone + std::fmt::Debug>(
            incumbent: &std::collections::BTreeSet<T>,
            summary: &std::collections::BTreeSet<T>,
        ) -> Option<String> {
            let only_incumbent: Vec<&T> = incumbent.difference(summary).collect();
            let only_summary: Vec<&T> = summary.difference(incumbent).collect();
            (!only_incumbent.is_empty() || !only_summary.is_empty()).then(|| {
        format!("only in the incumbent reader: {only_incumbent:#?}\nonly in the summary: {only_summary:#?}")
    })
        }
        /// What the differential saw, for the test to assert that it compared something.
        #[derive(Debug, Default)]
        struct DifferentialCounts {
            units: usize,
            members: usize,
            exports: usize,
            exported_visibility: usize,
            unit_visibility: usize,
            imports: usize,
            blank_imports: usize,
            dot_imports: usize,
            unresolved_imports: usize,
            dependency_keys: std::collections::BTreeSet<String>,
        }
        fn assert_summaries_match_incumbent_readers(
            workspace: &WorkspaceAnalyzer,
        ) -> DifferentialCounts {
            let go = resolve_analyzer::<GoAnalyzer>(workspace.analyzer()).expect("a Go analyzer");
            let snapshot = go
                .selected_snapshot_for_test()
                .expect("a selected Go snapshot");
            let cancellation = CancellationToken::new();
            let GoNativePointRequestOpen::Ready(request) =
                GoNativePointRequest::open(go, None, &cancellation)
                    .expect("open the Go point request")
            else {
                panic!("the Go point request is unavailable");
            };
            let (operation, context_id) = request.oracle_for_test();
            let connection = operation.ready.inventory.connection();
            let names = operation.ready.shared_names();
            let producer_epoch: String = connection
                .query_row(
                    "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang = 'go'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let profile: [u8; 32] = connection
        .query_row(
            "SELECT selections.profile_digest FROM main.go_context_publications AS publications
             JOIN main.go_context_selections AS selections ON selections.selection_id = publications.selection_id
             WHERE publications.context_id = ?1",
            [context_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .unwrap()
        .try_into()
        .unwrap();
            let mut counts = DifferentialCounts::default();

            // The incumbent's units: the package placement of every selected file under
            // the role the file declares.
            // Ignored-role memberships are build exclusions published as rows and never have a package placement; see docs/src/content/docs/design/usage-analysis.md#selected-graph-caller-admission.
            let mut files = Vec::new();
            {
                let mut statement = connection
            .prepare(
                "SELECT file_version_id, source_role, rel_path FROM main.go_context_source_files
                 WHERE context_id = ?1 AND source_role <> 'ignored' ORDER BY rel_path, source_role",
            )
            .unwrap();
                let mut rows = statement.query([context_id]).unwrap();
                while let Some(row) = rows.next().unwrap() {
                    files.push((
                        row.get::<_, i64>(0).unwrap(),
                        row.get::<_, String>(1).unwrap(),
                        row.get::<_, String>(2).unwrap(),
                    ));
                }
            }
            assert!(!files.is_empty(), "the Go context selected no files");
            let mut units: std::collections::BTreeSet<(i64, String)> =
                std::collections::BTreeSet::new();
            let mut alias_exports = std::collections::BTreeSet::new();
            for (file_version_id, role, rel_path) in &files {
                let package = connection
            .query_row(
                brokk_bifrost_analysis::analyzer::store::resolution_operation::go_same_package::CALLER_PACKAGE,
                rusqlite::params![context_id, file_version_id, role],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .unwrap();
                // A file of a role that has no placement (a `go` file listed again under a
                // test variant) is the same file seen as a peer of that variant.
                if let Some(package) = package {
                    units.insert((package, role.clone()));
                } else {
                    let listed_under_variant: bool = connection
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM main.go_context_source_files
                     WHERE context_id = ?1 AND file_version_id = ?2 AND source_role <> ?3)",
                            rusqlite::params![context_id, file_version_id, role],
                            |row| row.get(0),
                        )
                        .unwrap();
                    assert!(
                        listed_under_variant,
                        "{rel_path} [{role}] has no package placement and no other role"
                    );
                }
            }
            let instance_key = |package_id: i64, role: &str| -> [u8; 32] {
                let (path, for_test): (String, String) = connection
            .query_row(
                "SELECT tool_import_path, for_test FROM main.go_package_instances WHERE package_id = ?1",
                [package_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
                go_unit_key(&path, &for_test, role)
            };
            let unit_role_of_package = |package_id: i64| -> String {
                let for_test: String = connection
                    .query_row(
                        "SELECT for_test FROM main.go_package_instances WHERE package_id = ?1",
                        [package_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                if for_test.is_empty() {
                    return "go".to_owned();
                }
                let roles: Vec<&str> = units
                    .iter()
                    .filter(|(package, _)| *package == package_id)
                    .map(|(_, role)| role.as_str())
                    .collect();
                assert_eq!(
                    roles.len(),
                    1,
                    "a test variant instance is the unit of one role: {roles:?}"
                );
                roles[0].to_owned()
            };

            // Every incumbent unit has a live summary, and nothing else is live.
            let live_versions: i64 = connection
                .query_row(
                    "SELECT count(*) FROM main.resolution_unit_summary_versions
             WHERE workspace_id = ?1 AND lang = 'go' AND generation = ?2 AND valid_until IS NULL
               AND profile_digest = ?3",
                    rusqlite::params![
                        snapshot.workspace_id.as_str(),
                        snapshot.generation.get(),
                        profile.as_slice()
                    ],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                usize::try_from(live_versions).unwrap(),
                units.len(),
                "live version rows against the incumbent's units {units:#?}"
            );

            for (package_id, role) in &units {
                let key = instance_key(*package_id, role);
                let label = format!("package {package_id} [{role}]");
                let (summary_id, _) =
                    go_live_summary(connection, &snapshot, &producer_epoch, &key, &profile)
                        .unwrap()
                        .unwrap_or_else(|| {
                            panic!("{label} has no live summary of the selected profile")
                        });
                counts.units += 1;

                // Peers: the same-package reader's mounts.
                let mut peers = Vec::new();
                {
                    let mut statement = connection.prepare(PACKAGE_PEER_MOUNTS).unwrap();
                    let mut rows = statement
                        .query(rusqlite::params![context_id, package_id, role])
                        .unwrap();
                    while let Some(row) = rows.next().unwrap() {
                        peers.push(SelectedResolutionMountOrdinal::new(row.get(0).unwrap()));
                    }
                }
                assert!(!peers.is_empty(), "{label} has no peers");
                let mut incumbent_members = std::collections::BTreeSet::new();
                let mut incumbent_exports = std::collections::BTreeSet::new();
                for peer in &peers {
                    let record = operation
                        .ready
                        .inventory
                        .mount_record_by_ordinal(*peer)
                        .unwrap();
                    incumbent_members.insert(UnitMemberFact {
                        blob_id: record.blob_id(),
                        rel_path: record.persisted_relative_path().to_owned(),
                    });
                    let SelectedPackageRows::Ready(by_lookup) = operation
                        .selected_package_members_by_lookup(*peer, &cancellation)
                        .unwrap()
                    else {
                        panic!("not cancelled");
                    };
                    for member in by_lookup.values().flatten() {
                        incumbent_exports.insert(ExportFact {
                            blob_id: record.blob_id(),
                            site: member.source_site.get(),
                            key: member
                                .definition
                                .local_key()
                                .expect("an ordinary package member is local to its mount"),
                            namespace: member.namespace.label().to_owned(),
                            identity_id: i64::from(
                                names
                                    .to_persisted(
                                        member
                                            .lookup
                                            .shared_name_id()
                                            .expect("a package member lookup is a shared name"),
                                    )
                                    .expect("a persisted lookup name")
                                    .get(),
                            ),
                        });
                    }
                }

                let mut summary_members = std::collections::BTreeSet::new();
                {
                    let mut statement = connection
                .prepare(
                    "SELECT blob_id, rel_path FROM main.resolution_unit_summary_members WHERE summary_id = ?1",
                )
                .unwrap();
                    let mut rows = statement.query([summary_id]).unwrap();
                    while let Some(row) = rows.next().unwrap() {
                        summary_members.insert(UnitMemberFact {
                            blob_id: row.get(0).unwrap(),
                            rel_path: row.get(1).unwrap(),
                        });
                    }
                }
                if let Some(difference) = symmetric_difference(&incumbent_members, &summary_members)
                {
                    panic!("{label}: member files differ\n{difference}");
                }
                counts.members += summary_members.len();

                let mut summary_exports = std::collections::BTreeSet::new();
                {
                    let mut statement = connection
                .prepare(
                    "SELECT exports.declaration_blob_id, exports.declaration_site, exports.declaration_key,
                            exports.namespace, exports.identity_id, exports.visibility, identities.spelling,
                            exports.origin, exports.alias_dependency_ordinal, alias_identity.spelling,
                            dependencies.dependency_unit_key
                     FROM main.resolution_unit_summary_exports AS exports
                     JOIN main.resolution_identities AS identities ON identities.id = exports.identity_id
                     LEFT JOIN main.resolution_identities AS alias_identity
                       ON alias_identity.id = exports.alias_identity_id
                     LEFT JOIN main.resolution_unit_summary_dependencies AS dependencies
                       ON dependencies.summary_id = exports.summary_id
                      AND dependencies.dependency_ordinal = exports.alias_dependency_ordinal
                     WHERE exports.summary_id = ?1",
                )
                .unwrap();
                    let mut rows = statement.query([summary_id]).unwrap();
                    while let Some(row) = rows.next().unwrap() {
                        summary_exports.insert(ExportFact {
                            blob_id: row.get(0).unwrap(),
                            site: row.get(1).unwrap(),
                            key: row.get(2).unwrap(),
                            namespace: row.get(3).unwrap(),
                            identity_id: row.get(4).unwrap(),
                        });
                        // Go exports a name whose first letter is upper case; the fixture
                        // names are ASCII.
                        let visibility: String = row.get(5).unwrap();
                        let spelling: String = row.get(6).unwrap();
                        let origin: String = row.get(7).unwrap();
                        let alias_dependency_ordinal: Option<i64> = row.get(8).unwrap();
                        let alias_target: Option<String> = row.get(9).unwrap();
                        let dependency_unit_key: Option<Vec<u8>> = row.get(10).unwrap();
                        if origin == "alias" {
                            let alias_target = alias_target.unwrap_or_else(|| {
                                panic!("{label}: alias {spelling:?} has no target identity")
                            });
                            let dependency_unit_key = dependency_unit_key.map(|key| hex(&key));
                            match spelling.as_str() {
                                "LocalClient" => {
                                    assert_eq!(
                                        alias_target, "Client",
                                        "{label}: local alias target"
                                    );
                                    assert!(
                                        alias_dependency_ordinal.is_none(),
                                        "{label}: local alias has dependency ordinal"
                                    );
                                    assert!(
                                        dependency_unit_key.is_none(),
                                        "{label}: local alias has dependency row"
                                    );
                                }
                                "HelperAlias" => {
                                    assert_eq!(
                                        alias_target, "Helper",
                                        "{label}: imported alias target"
                                    );
                                    assert!(
                                        alias_dependency_ordinal.is_some(),
                                        "{label}: imported alias lacks dependency ordinal"
                                    );
                                    assert_eq!(
                                        dependency_unit_key.as_deref(),
                                        Some(
                                            hex(&go_unit_key("example.test/native/util", "", "go"))
                                                .as_str()
                                        ),
                                        "{label}: imported alias dependency"
                                    );
                                }
                                _ => panic!("{label}: unexpected alias export {spelling:?}"),
                            }
                            alias_exports.insert((
                                spelling.clone(),
                                alias_target,
                                dependency_unit_key,
                            ));
                        } else {
                            assert!(
                                alias_dependency_ordinal.is_none(),
                                "{label}: non-alias has dependency ordinal"
                            );
                            assert!(
                                alias_target.is_none(),
                                "{label}: non-alias has target identity"
                            );
                            assert!(
                                dependency_unit_key.is_none(),
                                "{label}: non-alias has dependency row"
                            );
                        }
                        let expected =
                            if spelling.starts_with(|first: char| first.is_ascii_uppercase()) {
                                "exported"
                            } else {
                                "unit"
                            };
                        assert_eq!(visibility, expected, "{label}: visibility of {spelling:?}");
                        if visibility == "exported" {
                            counts.exported_visibility += 1;
                        } else {
                            counts.unit_visibility += 1;
                        }
                    }
                }
                if let Some(difference) = symmetric_difference(&incumbent_exports, &summary_exports)
                {
                    panic!("{label}: export rows differ\n{difference}");
                }
                counts.exports += summary_exports.len();
                {
                    let mut statement = connection
                .prepare(
                    "SELECT dependency_unit_key FROM main.resolution_unit_summary_dependencies WHERE summary_id = ?1",
                )
                .unwrap();
                    let mut rows = statement.query([summary_id]).unwrap();
                    while let Some(row) = rows.next().unwrap() {
                        counts
                            .dependency_keys
                            .insert(hex(&row.get::<_, Vec<u8>>(0).unwrap()));
                    }
                }

                // Imports: only the files whose own role is the unit's role, because the
                // incumbent binds a file's imports under the role it declares.
                let covered_blobs: std::collections::BTreeSet<i64> = files
                    .iter()
                    .filter(|(_, file_role, _)| file_role == role)
                    .filter_map(|(_, _, rel_path)| {
                        incumbent_members
                            .iter()
                            .find(|member| &member.rel_path == rel_path)
                            .map(|member| member.blob_id)
                    })
                    .collect();
                let mut incumbent_imports = std::collections::BTreeSet::new();
                for (file_version_id, file_role, rel_path) in &files {
                    if file_role != role
                || connection
                    .query_row(
                        brokk_bifrost_analysis::analyzer::store::resolution_operation::go_same_package::CALLER_PACKAGE,
                        rusqlite::params![context_id, file_version_id, file_role],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()
                    .unwrap()
                    != Some(*package_id)
            {
                continue;
            }
                    let outcome = operation
                        .go_file_import_context_with_role(context_id, rel_path, role, &cancellation)
                        .unwrap();
                    let GoPreparedImportContextOutcome::Ready(prepared) = outcome else {
                        panic!("{label}: {rel_path} has no prepared import context");
                    };
                    for ((mount, definition), target_package) in &prepared.demand.import_packages {
                        let record = operation
                            .ready
                            .inventory
                            .mount_record_by_ordinal(*mount)
                            .unwrap();
                        incumbent_imports.insert(ImportFact {
                            blob_id: record.blob_id(),
                            definition_key: definition
                                .local_key()
                                .expect("an import binding definition is local to its mount"),
                            dependency_unit_key: hex(&instance_key(
                                *target_package,
                                &unit_role_of_package(*target_package),
                            )),
                        });
                    }
                }
                let mut summary_imports = std::collections::BTreeSet::new();
                let mut summary_dots = std::collections::BTreeSet::new();
                {
                    let mut statement = connection
                .prepare(
                    "SELECT imports.blob_id, imports.import_id, imports.kind, imports.import_definition_key,
                            imports.state, dependencies.dependency_unit_key
                     FROM main.resolution_unit_summary_imports AS imports
                     LEFT JOIN main.resolution_unit_summary_dependencies AS dependencies
                       ON dependencies.summary_id = imports.summary_id
                      AND dependencies.dependency_ordinal = imports.dependency_ordinal
                     WHERE imports.summary_id = ?1",
                )
                .unwrap();
                    let mut rows = statement.query([summary_id]).unwrap();
                    while let Some(row) = rows.next().unwrap() {
                        let blob_id: i64 = row.get(0).unwrap();
                        let import_id: i64 = row.get(1).unwrap();
                        let kind: String = row.get(2).unwrap();
                        let state: String = row.get(4).unwrap();
                        let dependency: Option<Vec<u8>> = row.get(5).unwrap();
                        match kind.as_str() {
                            "blank" => counts.blank_imports += 1,
                            "dot" => counts.dot_imports += 1,
                            _ => {}
                        }
                        if state == "unresolved" {
                            counts.unresolved_imports += 1;
                        }
                        if !covered_blobs.contains(&blob_id) {
                            continue;
                        }
                        match (kind.as_str(), dependency) {
                            ("named", Some(dependency)) => {
                                summary_imports.insert(ImportFact {
                                    blob_id,
                                    definition_key: row.get(3).unwrap(),
                                    dependency_unit_key: hex(&dependency),
                                });
                            }
                            ("dot", Some(dependency)) => {
                                summary_dots.insert(DotImportFact {
                                    blob_id,
                                    import_id,
                                    dependency_unit_key: hex(&dependency),
                                });
                            }
                            _ => {}
                        }
                    }
                }
                if let Some(difference) = symmetric_difference(&incumbent_imports, &summary_imports)
                {
                    panic!("{label}: import rows differ\n{difference}");
                }
                counts.imports += summary_imports.len();

                let mut incumbent_dots = std::collections::BTreeSet::new();
                for blob_id in &covered_blobs {
                    let mut statement = connection
                .prepare(
                    "SELECT imports.import_id,
                            (SELECT group_concat(segment, '/') FROM
                               (SELECT segment FROM main.source_import_segments AS segments
                                WHERE segments.blob_id = imports.blob_id AND segments.import_id = imports.import_id
                                ORDER BY ordinal))
                     FROM main.source_imports AS imports
                     WHERE imports.blob_id = ?1 AND imports.alias = '.'",
                )
                .unwrap();
                    let mut rows = statement.query([blob_id]).unwrap();
                    while let Some(row) = rows.next().unwrap() {
                        let import_id: i64 = row.get(0).unwrap();
                        let spelling: String = row.get(1).unwrap();
                        let target: Option<i64> = connection
                    .query_row(
                        "SELECT target_package_id FROM main.go_package_imports
                         WHERE importer_package_id = ?1 AND import_role = ?2 AND source_spelling = ?3",
                        rusqlite::params![package_id, role, spelling],
                        |row| row.get::<_, Option<i64>>(0),
                    )
                    .optional()
                    .unwrap()
                    .flatten();
                        if let Some(target) = target {
                            incumbent_dots.insert(DotImportFact {
                                blob_id: *blob_id,
                                import_id,
                                dependency_unit_key: hex(&instance_key(
                                    target,
                                    &unit_role_of_package(target),
                                )),
                            });
                        }
                    }
                }
                if let Some(difference) = symmetric_difference(&incumbent_dots, &summary_dots) {
                    panic!("{label}: dot import rows differ\n{difference}");
                }
            }
            assert_eq!(
                alias_exports,
                [
                    ("LocalClient".to_owned(), "Client".to_owned(), None),
                    (
                        "HelperAlias".to_owned(),
                        "Helper".to_owned(),
                        Some(hex(&go_unit_key("example.test/native/util", "", "go"))),
                    ),
                ]
                .into(),
                "summary alias targets agree with the saved target identity and dependency unit"
            );
            counts
        }
        /// One open version row of the live summaries, keyed by the unit's member paths.
        #[derive(Debug, Clone, PartialEq, Eq)]
        struct OpenUnit {
            valid_from: i64,
            summary_id: i64,
            summary_digest: Vec<u8>,
            output_digest: Vec<u8>,
        }
        fn open_units(
            workspace: &WorkspaceAnalyzer,
        ) -> std::collections::BTreeMap<String, OpenUnit> {
            let conn = workspace.store().unwrap().read_conn().unwrap();
            let mut statement = conn
        .prepare(
            "SELECT (SELECT group_concat(rel_path, ',') FROM
                       (SELECT rel_path FROM resolution_unit_summary_members AS members
                        WHERE members.summary_id = versions.summary_id ORDER BY rel_path)),
                    versions.valid_from, versions.summary_id, summaries.summary_digest, summaries.output_digest
             FROM resolution_unit_summary_versions AS versions
             JOIN resolution_unit_summaries AS summaries ON summaries.summary_id = versions.summary_id
             WHERE versions.lang = 'go' AND versions.valid_until IS NULL
               AND versions.profile_digest = ?1",
        )
        .unwrap();
            let go = resolve_analyzer::<GoAnalyzer>(workspace.analyzer()).unwrap();
            let profile = go.native_context_profile().unwrap();
            let mut rows = statement.query([profile.as_slice()]).unwrap();
            let mut units = std::collections::BTreeMap::new();
            while let Some(row) = rows.next().unwrap() {
                let label: String = row.get(0).unwrap();
                let previous = units.insert(
                    label.clone(),
                    OpenUnit {
                        valid_from: row.get(1).unwrap(),
                        summary_id: row.get(2).unwrap(),
                        summary_digest: row.get(3).unwrap(),
                        output_digest: row.get(4).unwrap(),
                    },
                );
                assert!(
                    previous.is_none(),
                    "two live units list the members {label}"
                );
            }
            units
        }
        fn units_with_a_new_summary(
            before: &std::collections::BTreeMap<String, OpenUnit>,
            after: &std::collections::BTreeMap<String, OpenUnit>,
        ) -> std::collections::BTreeSet<String> {
            assert_eq!(
                before.keys().collect::<Vec<_>>(),
                after.keys().collect::<Vec<_>>(),
                "the unit set changed"
            );
            before
                .iter()
                .filter(|(label, unit)| after[*label].summary_id != unit.summary_id)
                .map(|(label, _)| label.clone())
                .collect()
        }
        fn edit_and_republish(
            fixture: &BuiltInlineTestProject,
            workspace: &WorkspaceAnalyzer,
            path: &str,
            source: &str,
        ) -> WorkspaceAnalyzer {
            std::fs::write(fixture.root().join(path), source).unwrap();
            let file = fixture.file(path);
            let updated = workspace.update(&std::collections::BTreeSet::from([file]));
            activate_go_context(&updated);
            updated
        }
        /// How many live summaries record `profile` as the context profile they derive
        /// from, in their read ledger.
        fn live_summaries_of_profile(workspace: &WorkspaceAnalyzer, profile: [u8; 32]) -> usize {
            let conn = workspace.store().unwrap().read_conn().unwrap();
            conn.query_row(
                "SELECT count(*) FROM resolution_unit_summary_versions AS versions
         WHERE versions.lang = 'go' AND versions.valid_until IS NULL
           AND versions.profile_digest=?1
           AND EXISTS (SELECT 1 FROM resolution_unit_summary_reads AS reads
                       WHERE reads.summary_id = versions.summary_id
                         AND reads.kind = 'context_publication' AND reads.digest = ?1)",
                [profile.as_slice()],
                |row| row.get(0),
            )
            .unwrap()
        }
        #[brokk_bifrost_test_macros::hardwon(
            "800772caaffe: an alias to an anonymous Go type was misclassified as an incomplete provider"
        )]
        #[test]
        fn go_unit_summaries_equal_the_incumbent_member_and_import_readers() {
            let Some((_fixture, workspace)) = published_go_workspace(GO_FIXTURE) else {
                return;
            };
            let counts = assert_summaries_match_incumbent_readers(&workspace);
            // The fixture has plain, internal-test and external-test units, exported and
            // package-private names, dot, aliased, blank and standard-library imports.
            assert!(counts.units >= 7, "{counts:?}");
            assert!(
                counts.exported_visibility > 0 && counts.unit_visibility > 0,
                "{counts:?}"
            );
            assert!(counts.blank_imports >= 1, "{counts:?}");
            assert!(counts.dot_imports >= 1, "{counts:?}");
            // The tool context binds every import of the fixture, the standard library
            // included.
            assert_eq!(counts.unresolved_imports, 0, "{counts:?}");
            for (path, role) in [("example.test/native/other", "go"), ("strings", "go")] {
                assert!(
                    counts
                        .dependency_keys
                        .contains(&hex(&go_unit_key(path, "", role))),
                    "{path} is not a recorded dependency: {counts:?}"
                );
            }
            assert!(counts.imports >= 7, "{counts:?}");
            let connection = workspace.store().unwrap().read_conn().unwrap();
            type AliasRow = (Option<i64>, String, Option<Vec<u8>>);
            let aliases: std::collections::HashMap<String, AliasRow> = {
                let mut statement = connection
                    .prepare(
                        "SELECT exported.spelling, exports.alias_dependency_ordinal,
                        target.spelling, dependency.dependency_unit_key
                 FROM resolution_unit_summary_exports AS exports
                 JOIN resolution_unit_summaries AS summaries
                   ON summaries.summary_id=exports.summary_id
                 JOIN resolution_unit_summary_members AS members
                   ON members.summary_id=summaries.summary_id
                  AND members.rel_path='api/api.go'
                 JOIN resolution_identities AS exported ON exported.id=exports.identity_id
                 JOIN resolution_identities AS target ON target.id=exports.alias_identity_id
                 LEFT JOIN resolution_unit_summary_dependencies AS dependency
                   ON dependency.summary_id=exports.summary_id
                  AND dependency.dependency_ordinal=exports.alias_dependency_ordinal
                 WHERE exports.origin='alias'",
                    )
                    .unwrap();
                let mut rows = statement.query([]).unwrap();
                let mut aliases = std::collections::HashMap::new();
                while let Some(row) = rows.next().unwrap() {
                    aliases.insert(
                        row.get(0).unwrap(),
                        (
                            row.get(1).unwrap(),
                            row.get(2).unwrap(),
                            row.get(3).unwrap(),
                        ),
                    );
                }
                aliases
            };
            let local = aliases
                .get("LocalClient")
                .unwrap_or_else(|| panic!("same-unit Go alias target is published: {aliases:?}"));
            assert_eq!(local.0, None);
            assert_eq!(local.1, "Client");
            assert_eq!(local.2, None);
            let qualified = aliases
                .get("HelperAlias")
                .expect("qualified Go alias target is published");
            assert!(
                qualified.0.is_some(),
                "qualified alias has a dependency ordinal"
            );
            assert_eq!(qualified.1, "Helper");
            assert_eq!(
                qualified.2.as_deref(),
                Some(go_unit_key("example.test/native/util", "", "go").as_slice()),
                "qualified Go alias points to the dependency unit"
            );
            let (anonymous_origin, alias_dependency, alias_identity, alias_gap_count): (
                String,
                Option<i64>,
                Option<i64>,
                i64,
            ) = connection
                .query_row(
                    "SELECT exports.origin, exports.alias_dependency_ordinal,
                    exports.alias_identity_id,
                    (SELECT COUNT(*) FROM resolution_unit_summary_gaps AS gaps
                     WHERE gaps.summary_id=exports.summary_id
                       AND gaps.gap_kind='incomplete_provider'
                       AND json_extract(gaps.detail, '$.reason')='go_alias_target_unavailable')
             FROM resolution_unit_summary_exports AS exports
             JOIN resolution_unit_summaries AS summaries
               ON summaries.summary_id=exports.summary_id
             JOIN resolution_unit_summary_members AS members
               ON members.summary_id=summaries.summary_id
              AND members.rel_path='api/api.go'
             JOIN resolution_identities AS identity ON identity.id=exports.identity_id
             WHERE identity.spelling='CommandCtx'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
            assert_eq!(anonymous_origin, "declaration");
            assert_eq!(alias_dependency, None);
            assert_eq!(alias_identity, None);
            assert_eq!(
                alias_gap_count, 0,
                "anonymous alias targets are not provider gaps"
            );
        }
        #[brokk_bifrost_test_macros::hardwon(
            "51e2e4668128: test package summaries lost alias targets imported by ordinary Go files"
        )]
        #[test]
        fn go_test_unit_aliases_reach_imports_from_package_files() {
            let Some((_fixture, workspace)) = published_go_workspace(GO_FIXTURE) else {
                return;
            };
            let connection = workspace.store().unwrap().read_conn().unwrap();
            let profile = resolve_analyzer::<GoAnalyzer>(workspace.analyzer())
                .unwrap()
                .native_context_profile()
                .unwrap();
            let summary_id: i64 = connection
                .query_row(
                    "SELECT members.summary_id
             FROM resolution_unit_summary_members AS members
             JOIN resolution_unit_summary_versions AS versions
               ON versions.summary_id=members.summary_id AND versions.valid_until IS NULL
             WHERE members.rel_path='api/api_internal_test.go' AND versions.profile_digest=?1",
                    [profile.as_slice()],
                    |row| row.get(0),
                )
                .expect("the internal test variant has a live unit summary");
            let (origin, target, dependency_key): (String, String, Option<Vec<u8>>) = connection
                .query_row(
                    "SELECT exports.origin, target.spelling, dependency.dependency_unit_key
             FROM resolution_unit_summary_exports AS exports
             JOIN resolution_identities AS exported ON exported.id=exports.identity_id
             JOIN resolution_identities AS target ON target.id=exports.alias_identity_id
             LEFT JOIN resolution_unit_summary_dependencies AS dependency
               ON dependency.summary_id=exports.summary_id
              AND dependency.dependency_ordinal=exports.alias_dependency_ordinal
             WHERE exports.summary_id=?1 AND exported.spelling='HelperAlias'",
                    [summary_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("the test unit publishes the named alias from api/api.go");
            assert_eq!(origin, "alias");
            assert_eq!(target, "Helper");
            assert_eq!(
                dependency_key.as_deref(),
                Some(go_unit_key("example.test/native/util", "", "go").as_slice())
            );
        }
        /// Early cutoff, end to end. A body edit to a package with dependents derives
        /// exactly that package again and leaves every dependent's version row alone,
        /// because the package's output digest is unchanged. An edit that adds an
        /// exported name derives the package and its direct importers, and stops at the
        /// importers' own dependents because their output digests are unchanged.
        #[test]
        fn a_body_edit_derives_one_unit_and_stops_at_the_output_digest() {
            let Some((fixture, workspace)) = published_go_workspace(GO_FIXTURE) else {
                return;
            };
            let initial = open_units(&workspace);
            assert_eq!(
                initial.len(),
                7,
                "{:#?}",
                initial.keys().collect::<Vec<_>>()
            );
            let util_source = GO_FIXTURE
                .iter()
                .find(|(path, _)| *path == "util/util.go")
                .unwrap()
                .1;

            let body_edit = util_source.replace(
                "func private() int { return 1 }",
                "func private() int { return 2 }",
            );
            assert_ne!(body_edit, util_source);
            let after_body = edit_and_republish(&fixture, &workspace, "util/util.go", &body_edit);
            let body_units = open_units(&after_body);
            assert_eq!(
                units_with_a_new_summary(&initial, &body_units),
                ["util/util.go".to_owned()].into(),
                "a body edit derives the one unit that lists the file"
            );
            assert_eq!(
                initial["util/util.go"].output_digest, body_units["util/util.go"].output_digest,
                "a body edit leaves the output digest"
            );
            assert_ne!(
                initial["util/util.go"].summary_digest, body_units["util/util.go"].summary_digest,
                "the member oid is part of the input digest"
            );
            for (label, unit) in &initial {
                if label != "util/util.go" {
                    assert_eq!(
                        unit, &body_units[label],
                        "{label}: a dependent's version row is untouched"
                    );
                }
            }

            let surface_edit = format!("{body_edit}\nfunc Added() int {{ return 3 }}\n");
            let after_surface =
                edit_and_republish(&fixture, &after_body, "util/util.go", &surface_edit);
            let surface_units = open_units(&after_surface);
            let rederived = units_with_a_new_summary(&body_units, &surface_units);
            assert_eq!(
                rederived,
                [
                    "util/util.go",
                    "api/api.go,api/api_internal_test.go,api/helpers.go,api/platform_other.go",
                    "api/api.go,api/helpers.go,api/platform_other.go",
                    "api/api_ext_test.go",
                ]
                .map(str::to_owned)
                .into(),
                "an exported addition derives the package and its direct importers"
            );
            assert_ne!(
                body_units["util/util.go"].output_digest,
                surface_units["util/util.go"].output_digest,
                "an exported addition moves the output digest"
            );
            for importer in &rederived {
                if importer != "util/util.go" {
                    assert_eq!(
                        body_units[importer].output_digest, surface_units[importer].output_digest,
                        "{importer}: an importer's own surface is unchanged"
                    );
                }
            }
            assert_eq!(
                body_units["cmd/main.go"], surface_units["cmd/main.go"],
                "the importers' dependents stop at their unchanged output digests"
            );

            // An added import is not caller-visible (Go has no re-exports): it derives
            // the unit that gained it and no importer.
            let import_edit = surface_edit.replacen(
                "package util\n",
                "package util\n\nimport _ \"example.test/native/other\"\n",
                1,
            );
            assert_ne!(import_edit, surface_edit);
            let after_import =
                edit_and_republish(&fixture, &after_surface, "util/util.go", &import_edit);
            let import_units = open_units(&after_import);
            assert_eq!(
                units_with_a_new_summary(&surface_units, &import_units),
                ["util/util.go".to_owned()].into(),
                "an added import derives only the unit that gained it"
            );
            assert_eq!(
                surface_units["util/util.go"].output_digest,
                import_units["util/util.go"].output_digest,
                "an added import leaves the output digest"
            );
        }
        #[test]
        #[brokk_bifrost_test_macros::hardwon(
            "#4994: retained summary statistics let Go reverse completeness scan source imports"
        )]
        fn go_unit_summary_readers_seek_in_both_statistics_states() {
            use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

            use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;
            use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
            use rusqlite::types::Value;

            let Some((_fixture, workspace)) = published_go_workspace(GO_FIXTURE) else {
                return;
            };
            let store = workspace.store().unwrap();
            // The two pinned states, then the store's own ANALYZE of this fixture, whose
            // statistics describe the summary tables themselves.
            for statistics in PlannerStatisticsState::BOTH
                .into_iter()
                .map(Some)
                .chain([None])
            {
                match statistics {
                    Some(statistics) => {
                        store
                            .conn
                            .execute(move |connection| statistics.install(connection));
                        store.recycle_readers_for_new_statistics();
                    }
                    None => {
                        store.refresh_planner_statistics().unwrap();
                    }
                }
                let statistics = statistics.map_or_else(
                    || "the store's own ANALYZE".to_owned(),
                    |statistics| statistics.to_string(),
                );
                let go = resolve_analyzer::<GoAnalyzer>(workspace.analyzer()).unwrap();
                let snapshot = go.selected_snapshot_for_test().unwrap();
                let cancellation = CancellationToken::new();
                let GoNativePointRequestOpen::Ready(request) =
                    GoNativePointRequest::open(go, None, &cancellation).unwrap()
                else {
                    panic!("the Go point request is unavailable");
                };
                let (operation, inventory_context_id) = request.oracle_for_test();
                let connection = operation.ready.inventory.connection();
                brokk_bifrost_analysis::analyzer::store::go_unit_summaries::register_go_summary_sql_functions(
                    connection,
                )
                .unwrap();
                let epoch: String = connection
                    .query_row(
                        "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang = 'go'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                // The unit with the most dependents and exports in the fixture is the
                // util package, so its rows are the realistic bindings.
                let profile = go.native_context_profile().unwrap().to_vec();
                let (summary_id, unit_key): (i64, Vec<u8>) = connection
            .query_row(
                "SELECT versions.summary_id, versions.unit_key
                 FROM resolution_unit_summary_versions AS versions
                 JOIN resolution_unit_summary_members AS members ON members.summary_id = versions.summary_id
                 WHERE versions.valid_until IS NULL AND members.rel_path = 'util/util.go'
                   AND versions.profile_digest = ?1",
                [profile.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
                let unit_key_array: [u8; 32] = unit_key.clone().try_into().unwrap();
                let (namespace, identity_id): (String, i64) = connection
                    .query_row(
                        "SELECT namespace, identity_id FROM resolution_unit_summary_exports
                 WHERE summary_id = ?1 AND visibility = 'exported' ORDER BY identity_id LIMIT 1",
                        [summary_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                let (blob_oid, lang): (String, String) = connection
            .query_row(
                "SELECT blobs.blob_oid, blobs.lang FROM resolution_unit_summary_members AS members
                 JOIN blobs ON blobs.id = members.blob_id WHERE members.summary_id = ?1 LIMIT 1",
                [summary_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
                let workspace_id = snapshot.workspace_id.as_str().to_owned();
                let (
                    caller_blob_id,
                    caller_summary_id,
                    caller_unit_key,
                    caller_reference,
                    source_lookup,
                ): (i64, i64, Vec<u8>, i64, i64) = connection
                    .query_row(
                        "SELECT route.blob_id,versions.summary_id,versions.unit_key,
                        route.reference,route.source_lookup
                 FROM main.resolution_qualified_routes AS route
                 JOIN temp.selected_resolution_mounts AS mount
                   ON mount.blob_id=route.blob_id AND mount.storage_language='go'
                 JOIN main.resolution_unit_summary_members AS member
                   ON member.blob_id=route.blob_id
                 JOIN main.resolution_unit_summary_versions AS versions
                   ON versions.summary_id=member.summary_id
                 WHERE versions.workspace_id=?1 AND versions.lang='go'
                   AND versions.generation=?2 AND versions.valid_from<=?3
                   AND (versions.valid_until IS NULL OR ?3<versions.valid_until)
                   AND versions.profile_digest=?4
                 LIMIT 1",
                        rusqlite::params![
                            workspace_id,
                            snapshot.generation.get(),
                            snapshot.revision,
                            profile.as_slice()
                        ],
                        |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                            ))
                        },
                    )
                    .unwrap();
                let caller_unit_key: [u8; 32] = caller_unit_key.try_into().unwrap();
                let (caller_package_id, caller_summary_role): (i64, String) = connection
                    .query_row(
                        "SELECT package.package_id,
                        CASE WHEN package.for_test='' THEN 'go'
                             WHEN EXISTS(SELECT 1 FROM main.go_package_files AS tests
                                         WHERE tests.package_id=package.package_id
                                           AND tests.source_role='xtest') THEN 'xtest'
                             ELSE 'test' END
                 FROM main.go_context_source_files AS source
                 JOIN temp.selected_resolution_mounts AS mount
                   ON mount.file_version_id=source.file_version_id
                 JOIN main.go_package_instances AS package
                   ON package.context_id=source.context_id
                  AND package.package_id=source.package_id
                 WHERE source.context_id=?1 AND mount.blob_id=?2 LIMIT 1",
                        rusqlite::params![inventory_context_id, caller_blob_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                let inventory_file_version: i64 = connection
                    .query_row(
                        "SELECT file_version_id FROM main.workspace_file_versions
                 WHERE workspace_id=?1 AND lang='go' AND generation=?2
                   AND rel_path='util/util.go' LIMIT 1",
                        rusqlite::params![workspace_id, snapshot.generation.get()],
                        |row| row.get(0),
                    )
                    .unwrap();
                let demand_json =
                    serde_json::to_string(&[(identity_id, namespace.as_str())]).unwrap();
                let qualified_demand_json =
                    serde_json::to_string(&[(source_lookup, "type")]).unwrap();

                let bind = |name: &str, params: Vec<Value>| {
                    let mut pin = pinned(name);
                    pin.params = params;
                    let plan = explain_pin(connection, &pin);
                    eprintln!("UNIT SUMMARY PLAN {statistics} {name}: {plan:#?}");
                    let allowed = |detail: &&String| {
                        let bounded_path_walk = name == "reference_local_path_evidence";
                        let bounded_qualifier_spellings = name == "go_reverse_qualified_import";
                        let bounded_import_segment_walk = [
                            "go_reverse_inventory_complete",
                            "go_reverse_qualified_import",
                            "go_reverse_dot_export_rows",
                            "go_reverse_transient_alias_exports",
                        ]
                        .contains(&name)
                            && (detail.starts_with("CO-ROUTINE (subquery-")
                                || detail.starts_with("SCAN (subquery-"));
                        // The path CTEs follow one keyed (blob_id, site) request. The
                        // qualifier CTE contains only that request's scope spellings.
                        // The import-segment subqueries seek one selected source
                        // import before walking its bounded path segments.
                        let bounded_cte_scan = [
                            "SCAN CONSTANT ROW",
                            "SCAN target_packages",
                            "SCAN target_units",
                            "SCAN test_units",
                            "SCAN target_keys",
                            "SCAN target ",
                            "SCAN dependent_units",
                            "SCAN visible",
                            "SCAN live_summaries",
                            "SCAN prefix",
                            "SCAN prefix_site_paths",
                            "SCAN prefix_matched_bindings",
                            "SCAN nearest",
                            // Candidate-local relation materialized from the one
                            // keyed qualifier path read above.
                            "SCAN prefix_definition_row",
                        ]
                        .iter()
                        .any(|prefix| detail.starts_with(prefix))
                            || (bounded_path_walk
                                && ["SCAN paths LEFT-JOIN", "SCAN site_paths", "SCAN walk"]
                                    .iter()
                                    .any(|prefix| detail.starts_with(prefix)))
                            || (bounded_qualifier_spellings && detail.starts_with("SCAN scope"));
                        let bounded_cte_scan = bounded_cte_scan
                            || (bounded_import_segment_walk
                                && detail.starts_with("SCAN (subquery-"));
                        let unindexed_table_scan = detail.starts_with("SCAN ")
                            && !detail.contains("VIRTUAL TABLE")
                            && !bounded_cte_scan;
                        let bounded_cte_index = detail
                    .starts_with("SEARCH target_packages USING AUTOMATIC")
                    || detail.starts_with("SEARCH visible USING AUTOMATIC")
                    || (bounded_path_walk
                        && (detail.starts_with("SEARCH walk USING AUTOMATIC COVERING INDEX")
                            || detail
                                .starts_with("SEARCH binding USING AUTOMATIC COVERING INDEX")
                            || detail.starts_with(
                                "SEARCH prefix_definition USING AUTOMATIC PARTIAL COVERING INDEX",
                            )
                            || detail.starts_with(
                                "SEARCH prefix_scope USING AUTOMATIC PARTIAL COVERING INDEX",
                            )));
                        let bounded_path_temp_btree = bounded_path_walk
                            && [
                                "USE TEMP B-TREE FOR GROUP BY",
                                "USE TEMP B-TREE FOR count(DISTINCT)",
                                "USE TEMP B-TREE FOR ORDER BY",
                                "USE TEMP B-TREE FOR DISTINCT",
                            ]
                            .iter()
                            .any(|prefix| detail.starts_with(prefix));
                        let bounded_qualifier_temp_btree = bounded_qualifier_spellings
                            && detail.starts_with("USE TEMP B-TREE FOR DISTINCT");
                        let bounded_qualifier_co_routine = bounded_qualifier_spellings
                            && detail.starts_with("CO-ROUTINE scope_spellings");
                        !unindexed_table_scan
                            && (!detail.contains("AUTOMATIC") || bounded_cte_index)
                            && (!detail.contains("TEMP B-TREE")
                                || bounded_path_temp_btree
                                || bounded_qualifier_temp_btree)
                            && (!detail.contains("CO-ROUTINE")
                                || bounded_qualifier_co_routine
                                || bounded_import_segment_walk)
                            && (!detail.starts_with("SCAN (subquery-")
                                || bounded_import_segment_walk)
                    };
                    let violations: Vec<_> =
                        plan.iter().filter(|detail| !allowed(detail)).collect();
                    assert!(
                        violations.is_empty(),
                        "{name} with {statistics} has forbidden plan entries {violations:?}: {plan:?}"
                    );
                    plan
                };
                let uses = |plan: &[String], needle: &str, name: &str| {
                    assert!(
                        plan.iter()
                            .any(|detail| detail.starts_with("SEARCH") && detail.contains(needle)),
                        "{name} with {statistics} must seek {needle}: {plan:?}"
                    );
                };

                let plan = bind(
                    "unit_summary_live_version",
                    vec![
                Value::Text(workspace_id.clone()),
                Value::Text("go".into()),
                Value::Integer(snapshot.generation.get()),
                Value::Blob(unit_key.clone()),
                Value::Integer(snapshot.revision),
                Value::Text(epoch.clone()),
                Value::Integer(
                    brokk_bifrost_analysis::analyzer::store::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION,
                ),
                Value::Blob(go_profile_read_key(&unit_key_array).to_vec()),
                Value::Blob(profile.clone()),
            ],
                );
                uses(&plan, "versions USING PRIMARY KEY", "live version");
                uses(&plan, "profile EXISTS USING INDEX", "live version");
                uses(&plan, "summaries USING INTEGER PRIMARY KEY", "live version");

                connection
                    .execute_batch(
                        "CREATE TEMP TABLE IF NOT EXISTS unit_summary_order(
               ordinal INTEGER PRIMARY KEY, unit_id INTEGER NOT NULL UNIQUE, unit_key BLOB UNIQUE
             ) STRICT;",
                    )
                    .unwrap();
                for name in [
                    "unit_summary_open_version",
                    "unit_summary_close_version",
                    "unit_summary_withdraw_version",
                    "unit_summary_withdraw_unsettled",
                    "unit_summary_close_unsettled",
                    "unit_summary_later_open_version",
                ] {
                    let mut values = vec![
                        Value::Text(workspace_id.clone()),
                        Value::Text("go".into()),
                        Value::Integer(snapshot.generation.get()),
                    ];
                    if matches!(
                        name,
                        "unit_summary_open_version"
                            | "unit_summary_close_version"
                            | "unit_summary_withdraw_version"
                    ) {
                        values.push(Value::Blob(unit_key.clone()));
                    }
                    if name != "unit_summary_open_version" {
                        values.push(Value::Integer(snapshot.revision));
                    }
                    values.push(Value::Blob(profile.clone()));
                    let plan = bind(name, values);
                    uses(&plan, "resolution_unit_summary_versions USING", name);
                    assert!(
                        plan.iter().any(|step| step.contains("profile_digest=?")),
                        "{name} with {statistics} must seek its profile: {plan:?}"
                    );
                }

                let plan = bind(
                    "unit_summary_export_point",
                    vec![
                        Value::Integer(summary_id),
                        Value::Text(namespace.clone()),
                        Value::Integer(identity_id),
                    ],
                );
                uses(&plan, "resolution_unit_summary_exports", "export point");

                let plan = bind(
                    "unit_summary_dependents",
                    vec![
                        Value::Blob(unit_key),
                        Value::Text(workspace_id.clone()),
                        Value::Text("go".into()),
                        Value::Integer(snapshot.generation.get()),
                        Value::Blob(profile.clone()),
                    ],
                );
                assert!(
                    plan[0].starts_with("SEARCH dependencies USING")
                        && plan[0].contains("resolution_unit_summary_dependencies_unit"),
                    "dependents with {statistics} must start from the dependency index: {plan:?}"
                );
                uses(&plan, "versions USING", "dependents");

                let plan = bind("unit_summary_graph_join", vec![Value::Integer(summary_id)]);
                uses(&plan, "members USING", "graph join");
                let position = |needle: &str| {
                    plan.iter()
                        .position(|detail| detail.starts_with("SEARCH") && detail.contains(needle))
                        .unwrap_or_else(|| {
                            panic!("graph join with {statistics} must seek {needle}: {plan:?}")
                        })
                };
                assert!(
                    position(
                        "paths USING COVERING INDEX resolution_paths_root_terminal (blob_id=?"
                    ) < position("exports USING PRIMARY KEY (summary_id=? AND identity_id=?"),
                    "graph join with {statistics} must probe the exports once per root path: {plan:?}"
                );

                let plan = bind(
                    "unit_summary_withdraw_replaced_blob",
                    vec![Value::Text(blob_oid), Value::Text(lang)],
                );
                uses(&plan, "blobs USING", "withdraw replaced blob");
                uses(&plan, "members USING", "withdraw replaced blob");
                uses(
                    &plan,
                    "resolution_unit_summary_versions USING",
                    "withdraw replaced blob",
                );

                let plan = bind(
                    "reference_local_path_evidence",
                    vec![
                        Value::Integer(caller_blob_id),
                        Value::Integer(caller_reference),
                    ],
                );
                uses(
                    &plan,
                    "resolution_paths_forward (blob_id=? AND start_node=?",
                    "keyed local path evidence",
                );

                let plan = bind(
                    "go_reverse_summary_export_rows",
                    vec![
                Value::Integer(caller_summary_id),
                Value::Text(demand_json.clone()),
                Value::Integer(1),
                Value::Integer(1),
                Value::Text(workspace_id.clone()),
                Value::Integer(snapshot.generation.get()),
                Value::Integer(snapshot.revision),
                Value::Text(epoch.clone()),
                Value::Integer(
                    brokk_bifrost_analysis::analyzer::store::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION,
                ),
                Value::Blob(go_profile_read_key(&caller_unit_key).to_vec()),
                Value::Text("[]".into()),
                Value::Integer(1),
            ],
                );
                uses(&plan, "export USING PRIMARY KEY", "reverse export rows");

                for (name, params) in [
            (
                "go_reverse_transient_target_exports",
                vec![
                    Value::Integer(caller_summary_id),
                    Value::Text("[]".into()),
                    Value::Text(demand_json.clone()),
                ],
            ),
            (
                "go_reverse_transient_alias_exports",
                vec![
                    Value::Integer(caller_summary_id),
                    Value::Text(demand_json.clone()),
                    Value::Integer(caller_package_id),
                    Value::Text(caller_summary_role.clone()),
                    Value::Integer(inventory_context_id),
                    Value::Text(workspace_id.clone()),
                    Value::Integer(snapshot.generation.get()),
                    Value::Integer(snapshot.revision),
                    Value::Text(epoch.clone()),
                    Value::Integer(
                        brokk_bifrost_analysis::analyzer::store::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION,
                    ),
                    Value::Blob(go_profile_read_key(&caller_unit_key).to_vec()),
                    Value::Text("[]".into()),
                ],
            ),
        ] {
            bind(name, params);
        }

                let plan = bind(
                    "go_reverse_qualified_import",
                    vec![
                        Value::Integer(caller_summary_id),
                        Value::Integer(caller_blob_id),
                        Value::Integer(caller_reference),
                        Value::Text(qualified_demand_json),
                        Value::Integer(caller_package_id),
                        Value::Text(caller_summary_role.clone()),
                        Value::Integer(1),
                    ],
                );
                uses(
                    &plan,
                    "resolution_go_package_imports_scope (blob_id=? AND file_scope_key=?)",
                    "qualified import binder",
                );

                let plan = bind(
                    "go_reverse_dot_export_rows",
                    vec![
                Value::Integer(caller_summary_id),
                Value::Integer(caller_blob_id),
                Value::Text(demand_json.clone()),
                Value::Text(workspace_id.clone()),
                Value::Integer(snapshot.generation.get()),
                Value::Integer(snapshot.revision),
                Value::Text(epoch.clone()),
                Value::Integer(
                    brokk_bifrost_analysis::analyzer::store::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION,
                ),
                Value::Blob(go_profile_read_key(&caller_unit_key).to_vec()),
                Value::Text("[]".into()),
                Value::Integer(inventory_context_id),
                Value::Integer(caller_package_id),
                Value::Text(caller_summary_role),
                Value::Integer(1),
            ],
                );
                uses(&plan, "export USING PRIMARY KEY", "dot reverse exports");

                let target_surfaces = serde_json::to_string(&[(identity_id, "type")]).unwrap();
                let plan = bind(
                    "go_reverse_inventory_complete",
                    vec![
                Value::Integer(inventory_context_id),
                Value::Integer(inventory_file_version),
                Value::Integer(1),
                Value::Integer(1),
                Value::Text(target_surfaces),
                Value::Text(workspace_id.clone()),
                Value::Integer(snapshot.generation.get()),
                Value::Integer(snapshot.revision),
                Value::Text(epoch.clone()),
                Value::Blob(profile.clone()),
                Value::Integer(
                    brokk_bifrost_analysis::analyzer::store::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION,
                ),
                Value::Text("[]".into()),
            ],
                );
                uses(
                    &plan,
                    "resolution_unit_summary_dependencies_unit",
                    "reverse inventory dependents",
                );
                uses(
                    &plan,
                    "resolution_unit_summary_versions",
                    "reverse inventory live versions",
                );
                uses(
                    &plan,
                    "main.source_import_segments USING PRIMARY KEY (blob_id=? AND import_id=?)",
                    "unresolved dot-import path",
                );
            }
        }
        /// Operator measurement of the reconcile on a real repository.
        ///
        /// `BIFROST_UNIT_SUMMARY_CORPUS` names a writable copy of a Go repository whose
        /// `go list` works offline (the test appends a comment to a file when
        /// `BIFROST_UNIT_SUMMARY_EDIT` names one). Run it with `BIFROST_TIMING=1 --no-capture`:
        /// each reconcile prints its `UnitSummaryReconciliation` (units derived, rows,
        /// statements, writer hold times), and the test prints the table row counts.
        /// Build and activation use `CuratedPackEvidence`, which publishes the same tool
        /// context as `FullProduction` without preparing dependency packs.
        #[test]
        #[ignore = "operator measurement: needs BIFROST_UNIT_SUMMARY_CORPUS, a writable copy of a Go repository"]
        fn measure_go_unit_summary_reconcile_on_a_corpus() {
            use std::sync::Arc;
            use std::sync::atomic::AtomicUsize;
            use std::time::Instant;

            let root = std::path::PathBuf::from(
                std::env::var("BIFROST_UNIT_SUMMARY_CORPUS")
                    .expect("BIFROST_UNIT_SUMMARY_CORPUS names a Go repository copy"),
            )
            .canonicalize()
            .unwrap();
            let mut config = go_full_production_config();
            config.go.dependency_discovery.mode = GoDependencyDiscoveryMode::CuratedPackEvidence;
            let project: Arc<dyn brokk_bifrost_core::analyzer::project::Project> = Arc::new(
                brokk_bifrost_core::analyzer::project::TestProject::new(root.clone(), Language::Go),
            );
            let started = Instant::now();
            let workspace =
                WorkspaceAnalyzer::build_ephemeral_footgun(Arc::clone(&project), config.clone())
                    .expect("build the corpus workspace");
            eprintln!("MEASURE build {:?}", started.elapsed());
            let store = workspace.store().unwrap();
            let counter = Arc::new(AtomicUsize::new(0));
            *store.crate_statement_counter.lock().unwrap() = Some(counter.clone());

            // `BIFROST_UNIT_SUMMARY_PROFILE=inventory` measures the production default:
            // the source-inventory context the build already published and reconciled.
            // Its first pass ran before the counter existed, so the pass is withdrawn and
            // derived again through an unchanged update of `BIFROST_UNIT_SUMMARY_EDIT`.
            let inventory =
                std::env::var("BIFROST_UNIT_SUMMARY_PROFILE").as_deref() == Ok("inventory");
            let touched = std::env::var("BIFROST_UNIT_SUMMARY_EDIT").ok().map(|edit| {
                brokk_bifrost_core::analyzer::model::ProjectFile::new(root.clone(), edit)
            });
            let reconcile_again = |workspace: &WorkspaceAnalyzer| -> Option<WorkspaceAnalyzer> {
                if inventory {
                    let file = touched
                        .clone()
                        .expect("inventory mode names a file to touch");
                    Some(workspace.update(&std::collections::BTreeSet::from([file])))
                } else {
                    activate_go_context_with(workspace, &config);
                    None
                }
            };
            let started = Instant::now();
            if inventory {
                store
                    .conn
                    .execute(
                        |conn| -> brokk_bifrost_analysis::analyzer::store::Result<()> {
                            conn.execute(unit_summaries_sql::DELETE_LANGUAGE_VERSIONS_SQL, ["go"])?;
                            conn.execute(
                                brokk_bifrost_core::cache_gc::DELETE_UNBOUND_SUMMARIES_SQL,
                                [],
                            )?;
                            Ok(())
                        },
                    )
                    .unwrap();
            }
            let _ = reconcile_again(&workspace);
            eprintln!(
                "MEASURE fresh pass ({}) {:?}",
                if inventory {
                    "source inventory, derived again"
                } else {
                    "tool context, no dependency packs"
                },
                started.elapsed()
            );
            let table_counts = |label: &str| {
                let conn = store.read_conn().unwrap();
                for table in [
                    "resolution_unit_summaries",
                    "resolution_unit_summary_versions",
                    "resolution_unit_summary_members",
                    "resolution_unit_summary_dependencies",
                    "resolution_unit_summary_reads",
                    "resolution_unit_summary_exports",
                    "resolution_unit_summary_imports",
                    "resolution_unit_summary_gaps",
                ] {
                    let count: i64 = conn
                        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                            row.get(0)
                        })
                        .unwrap();
                    eprintln!("MEASURE {label} {table} {count}");
                }
            };
            let dump = |label: &str| {
                let Ok(directory) = std::env::var("BIFROST_UNIT_SUMMARY_DUMP") else {
                    return;
                };
                let conn = store.read_conn().unwrap();
                let profile = resolve_analyzer::<GoAnalyzer>(workspace.analyzer())
                    .unwrap()
                    .native_context_profile()
                    .unwrap();
                let mut lines = Vec::new();
                let mut statement = conn
            .prepare(
                "SELECT hex(versions.unit_key),
                        (SELECT group_concat(rel_path, ',') FROM
                           (SELECT rel_path FROM resolution_unit_summary_members AS members
                            WHERE members.summary_id = versions.summary_id ORDER BY rel_path)),
                        hex(summaries.summary_digest), hex(summaries.output_digest), summaries.complete,
                        (SELECT group_concat(hex(dependency_unit_key) || '=' || hex(consumed_output_digest) || '=' || boundary, ' ')
                         FROM (SELECT * FROM resolution_unit_summary_dependencies AS deps
                               WHERE deps.summary_id = versions.summary_id ORDER BY dependency_ordinal)),
                        (SELECT group_concat(gap_kind || ':' || subject || ':' || json(detail), ' | ')
                         FROM (SELECT * FROM resolution_unit_summary_gaps AS gaps
                               WHERE gaps.summary_id = versions.summary_id ORDER BY gap_kind, subject)),
                        (SELECT group_concat(hex(key_digest) || '=' || hex(digest), ' ')
                         FROM (SELECT * FROM resolution_unit_summary_reads AS reads
                               WHERE reads.summary_id = versions.summary_id ORDER BY read_ordinal))
                 FROM resolution_unit_summary_versions AS versions
                 JOIN resolution_unit_summaries AS summaries ON summaries.summary_id = versions.summary_id
                 WHERE versions.lang = 'go' AND versions.valid_until IS NULL
                   AND versions.profile_digest=?1
                 ORDER BY 2, 1",
            )
            .unwrap();
                let mut rows = statement.query([profile.as_slice()]).unwrap();
                while let Some(row) = rows.next().unwrap() {
                    let columns: Vec<String> = (0..8)
                        .map(|index| {
                            row.get::<_, Option<rusqlite::types::Value>>(index)
                                .unwrap()
                                .map_or_else(String::new, |value| match value {
                                    rusqlite::types::Value::Integer(value) => value.to_string(),
                                    rusqlite::types::Value::Text(value) => value,
                                    other => format!("{other:?}"),
                                })
                        })
                        .collect();
                    lines.push(columns.join("\t"));
                }
                std::fs::write(
                    std::path::Path::new(&directory).join(format!("units-{label}.tsv")),
                    lines.join("\n"),
                )
                .unwrap();
            };
            if std::env::var_os("BIFROST_UNIT_SUMMARY_DIFFERENTIAL").is_some() {
                // The differential on a real repository store: the summaries against the
                // incumbent readers, for every unit of the corpus.
                let started = Instant::now();
                let counts = assert_summaries_match_incumbent_readers(&workspace);
                eprintln!(
                    "MEASURE differential equal in {:?}: units {} members {} exports {} imports {} blank {} dot {} unresolved {}",
                    started.elapsed(),
                    counts.units,
                    counts.members,
                    counts.exports,
                    counts.imports,
                    counts.blank_imports,
                    counts.dot_imports,
                    counts.unresolved_imports
                );
            }
            dump("fresh");
            table_counts("fresh");

            let started = Instant::now();
            let _ = reconcile_again(&workspace);
            eprintln!(
                "MEASURE pass again, nothing changed {:?}",
                started.elapsed()
            );
            dump("again");

            if let Ok(edit) = std::env::var("BIFROST_UNIT_SUMMARY_EDIT") {
                let path = root.join(&edit);
                let mut source = std::fs::read_to_string(&path).unwrap();
                source.push_str("\n// unit summary measurement edit\n");
                std::fs::write(&path, source).unwrap();
                let file =
                    brokk_bifrost_core::analyzer::model::ProjectFile::new(root.clone(), edit);
                let started = Instant::now();
                let updated = workspace.update(&std::collections::BTreeSet::from([file]));
                eprintln!("MEASURE update after the edit {:?}", started.elapsed());
                let started = Instant::now();
                if !inventory {
                    activate_go_context_with(&updated, &config);
                }
                eprintln!("MEASURE pass after the edit {:?}", started.elapsed());
                table_counts("edited");
            }
        }
        /// Blob replacement. Persisting a blob that already exists deletes its row and
        /// inserts a new one, and the unit summary rows that reference the old row
        /// cascade away. The persist path withdraws the version rows of every summary
        /// that listed the blob in the same transaction, so a reader finds no live
        /// summary for the unit (it falls back) instead of a complete summary whose rows
        /// are gone. The next reconcile rebuilds the header in place and rebinds the
        /// unit, and the rebuilt rows equal the incumbent readers' again.
        #[test]
        fn a_replaced_blob_withdraws_its_summaries_until_the_next_reconcile() {
            let Some((fixture, workspace)) = published_go_workspace(GO_FIXTURE) else {
                return;
            };
            let before = open_units(&workspace);
            let store = workspace.store().unwrap();
            let go = resolve_analyzer::<GoAnalyzer>(workspace.analyzer()).unwrap();
            let generation = go.selected_snapshot_for_test().unwrap().generation;
            let source = GO_FIXTURE
                .iter()
                .find(|(path, _)| *path == "util/util.go")
                .unwrap()
                .1;
            let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
            let (state, _) = crate::engine_tests::go_extraction::go_extraction_tests::go_move_11::parsed_go_state(fixture.root(), "util/util.go", source);
            let prepared =
                AnalyzerStore::prepare_parsed_blob(oid, "go", generation, &GoAdapter, state)
                    .unwrap();
            let (outcomes, _) =
                store.persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
            assert!(
                outcomes.iter().all(|outcome| outcome.error.is_none()),
                "{:#?}",
                outcomes
                    .iter()
                    .map(|outcome| &outcome.error)
                    .collect::<Vec<_>>()
            );

            let hollow = open_units(&workspace);
            let missing: Vec<&String> = before
                .keys()
                .filter(|label| !hollow.contains_key(*label))
                .collect();
            assert_eq!(
                missing,
                ["util/util.go"],
                "exactly the units that listed the replaced blob lose their live summary"
            );
            for (label, unit) in &hollow {
                assert_eq!(
                    &before[label], unit,
                    "{label}: unrelated units are untouched"
                );
            }

            activate_go_context(&workspace);
            let rebuilt = open_units(&workspace);
            assert_eq!(
                rebuilt.keys().collect::<Vec<_>>(),
                before.keys().collect::<Vec<_>>()
            );
            assert_eq!(
                rebuilt["util/util.go"].summary_id, before["util/util.go"].summary_id,
                "the header with the same digest is rebuilt in place"
            );
            assert_eq!(
                rebuilt["util/util.go"].output_digest,
                before["util/util.go"].output_digest
            );
            for (label, unit) in &before {
                if label != "util/util.go" {
                    assert_eq!(
                        unit, &rebuilt[label],
                        "{label}: dependents are not derived again"
                    );
                }
            }
            assert_summaries_match_incumbent_readers(&workspace);
        }
        /// The production default context: no Go tool, so the publication is the source
        /// inventory, whose test and external-test files sit in the plain instance. The
        /// summaries must equal the incumbent readers there too, and a body edit must
        /// derive exactly the unit that lists the file.
        #[test]
        fn source_inventory_unit_summaries_equal_the_incumbent_readers_and_cut_off() {
            let mut project = InlineTestProject::with_language(Language::Go);
            for (path, source) in GO_FIXTURE {
                project = project.file(*path, *source);
            }
            let fixture = project.build();
            let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
            let counts = assert_summaries_match_incumbent_readers(&workspace);
            // plain units: api, util, other, blank, cmd; test unit and external-test unit of api.
            assert_eq!(counts.units, 7, "{counts:?}");
            assert!(
                counts.dot_imports >= 1 && counts.blank_imports >= 1,
                "{counts:?}"
            );
            // The standard library is not a package of this publication.
            assert!(counts.unresolved_imports >= 1, "{counts:?}");
            assert!(
                counts.dependency_keys.contains(&hex(&go_unit_key(
                    "example.test/native/other",
                    "",
                    "go"
                ))),
                "{counts:?}"
            );

            let initial = open_units(&workspace);
            let util_source = GO_FIXTURE
                .iter()
                .find(|(path, _)| *path == "util/util.go")
                .unwrap()
                .1;
            let edited = util_source.replace(
                "func private() int { return 1 }",
                "func private() int { return 2 }",
            );
            std::fs::write(fixture.root().join("util/util.go"), &edited).unwrap();
            let file = fixture.file("util/util.go");
            let updated = workspace.update(&std::collections::BTreeSet::from([file]));
            let after = open_units(&updated);
            assert_eq!(
                units_with_a_new_summary(&initial, &after),
                ["util/util.go".to_owned()].into()
            );
            assert_eq!(
                initial["util/util.go"].output_digest,
                after["util/util.go"].output_digest
            );
            assert_summaries_match_incumbent_readers(&updated);

            // An added workspace import is not caller-visible: no importer is derived.
            let with_import = edited.replacen(
                "package util\n",
                "package util\n\nimport _ \"example.test/native/other\"\n",
                1,
            );
            std::fs::write(fixture.root().join("util/util.go"), &with_import).unwrap();
            let file = fixture.file("util/util.go");
            let again = updated.update(&std::collections::BTreeSet::from([file]));
            let imported = open_units(&again);
            assert_eq!(
                units_with_a_new_summary(&after, &imported),
                ["util/util.go".to_owned()].into()
            );
            assert_eq!(
                after["util/util.go"].output_digest,
                imported["util/util.go"].output_digest
            );
        }
        #[test]
        fn a_summary_records_the_profile_of_the_publication_it_derives_from() {
            use brokk_bifrost_analysis::analyzer::store::go_package_context::source_inventory_profile;
            let mut project = InlineTestProject::with_language(Language::Go);
            for (path, source) in GO_FIXTURE {
                project = project.file(*path, *source);
            }
            let fixture = project.build();
            let workspace = fixture.workspace_analyzer(go_full_production_config());
            let inventory = source_inventory_profile();
            let before = open_units(&workspace).len();
            assert_eq!(live_summaries_of_profile(&workspace, inventory), before);
            {
                // The Go validity predicate matches the selected profile: the live
                // summary of the inventory profile is not live for another one.
                let conn = workspace.store().unwrap().read_conn().unwrap();
                let go = resolve_analyzer::<GoAnalyzer>(workspace.analyzer()).unwrap();
                let snapshot = go.selected_snapshot_for_test().unwrap();
                let epoch: String = conn
                    .query_row(
                        "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang = 'go'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                let key = go_unit_key("example.test/native/util", "", "go");
                assert!(
                    go_live_summary(&conn, &snapshot, &epoch, &key, &inventory)
                        .unwrap()
                        .is_some()
                );
                assert!(
                    go_live_summary(&conn, &snapshot, &epoch, &key, &[9; 32])
                        .unwrap()
                        .is_none()
                );
            }
            if !go_toolchain_available() {
                return;
            }
            // Tool and inventory intervals coexist, each recording its own profile.
            activate_go_context(&workspace);
            assert_eq!(open_units(&workspace).len(), 7);
            // Even inventory-only test-unit keys remain live for retained queries.
            assert_eq!(live_summaries_of_profile(&workspace, inventory), before);
        }
        #[brokk_bifrost_test_macros::hardwon(
            "#5147: same-revision tool publication withdrew a retained inventory snapshot's summary"
        )]
        #[test]
        fn go_summary_profiles_survive_same_revision_publication() {
            use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

            use brokk_bifrost_analysis::analyzer::store::go_package_context::source_inventory_profile;

            if !go_toolchain_available() {
                return;
            }
            let fixture = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/isolation\n\ngo 1.22\n")
                .file("api/api.go", "package api\n\nfunc Public() {}\n")
                .file(
                    "cmd/main.go",
                    r#"package main

import "example.test/isolation/api"

func main() { api.Public() }
"#,
                )
                .build();
            let workspace = fixture.workspace_analyzer(go_full_production_config());
            let retained = resolve_analyzer::<GoAnalyzer>(workspace.analyzer())
                .unwrap()
                .clone();
            let snapshot = retained.selected_snapshot_for_test().unwrap();
            let profile = retained.native_context_profile().unwrap();
            assert_eq!(profile, source_inventory_profile());
            let store = workspace.store().unwrap();
            let conn = store.read_conn().unwrap();
            let epoch: String = conn
                .query_row(
                    "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang = 'go'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let key = go_unit_key("example.test/isolation/api", "", "go");
            let before = go_live_summary(&conn, &snapshot, &epoch, &key, &profile)
                .unwrap()
                .unwrap();
            drop(conn);
            activate_go_context(&workspace);
            let tool_profile = resolve_analyzer::<GoAnalyzer>(workspace.analyzer())
                .unwrap()
                .native_context_profile()
                .unwrap();
            assert_ne!(
                tool_profile, profile,
                "the tool context must actually activate"
            );
            assert!(
                go_live_summary(
                    &store.read_conn().unwrap(),
                    &snapshot,
                    &epoch,
                    &key,
                    &tool_profile
                )
                .unwrap()
                .is_some()
            );
            assert_eq!(retained.selected_snapshot_for_test().unwrap(), snapshot);
            assert_eq!(retained.native_context_profile(), Some(profile));
            let conn = store.read_conn().unwrap();
            assert_eq!(
                go_live_summary(&conn, &snapshot, &epoch, &key, &profile).unwrap(),
                Some(before),
                "retained inventory snapshot lost its live summary after tool publication"
            );
            drop(conn);
            let target = retained
                .declarations(&fixture.file("api/api.go"))
                .into_iter()
                .find(|unit| unit.terminal_name() == "Public")
                .unwrap();

            use brokk_bifrost_go_analysis::analyzer::go::selected_reverse::GoSelectedReverseOutcome;

            use brokk_bifrost_go_analysis::analyzer::go::selected_reverse::go_selected_inverse_for;
            let GoSelectedReverseOutcome::Ready(answer) =
                go_selected_inverse_for(&retained, &target, &CancellationToken::new())
            else {
                panic!("retained inventory query must remain available after tool publication");
            };
            assert_eq!(
                answer.completeness,
                brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness::Complete,
                "{answer:#?}"
            );
            assert!(
                answer
                    .edges
                    .iter()
                    .any(|edge| edge.site.file == fixture.file("cmd/main.go")),
                "retained inventory query must find the caller: {answer:#?}"
            );
        }
        #[brokk_bifrost_test_macros::hardwon(
            "#5147: summary replacement, cancellation and revision guards crossed Go context profiles"
        )]
        #[test]
        fn go_summary_profile_interleavings_reopen_and_withdraw() {
            use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId;

            use brokk_bifrost_analysis::analyzer::store::go_package_context::source_inventory_profile;

            use brokk_bifrost_analysis::analyzer::store::go_unit_summaries::GoUnitSummaries;

            if !go_toolchain_available() {
                return;
            }
            let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/isolation\n\ngo 1.22\n")
        .file("api/api.go", "package api\n\nfunc Public() {}\n")
        .file("cmd/main.go", "package main\n\nimport \"example.test/isolation/api\"\n\nfunc main() { api.Public() }\n")
        .with_git()
        .build();
            let workspace = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
                fixture.project_dyn(),
                go_full_production_config(),
            )
            .unwrap();
            let path = workspace.persisted_store_path().unwrap();
            let inventory_go = resolve_analyzer::<GoAnalyzer>(workspace.analyzer())
                .unwrap()
                .clone();
            let snapshot = inventory_go.selected_snapshot_for_test().unwrap();
            let inventory = source_inventory_profile();
            let store = workspace.store().unwrap();
            let key = go_unit_key("example.test/isolation/api", "", "go");
            let epoch: String = store
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang='go'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let read =
                |store: &AnalyzerStore, snapshot: &WorkspaceSnapshotId, profile: &[u8; 32]| {
                    go_live_summary(&store.read_conn().unwrap(), snapshot, &epoch, &key, profile)
                        .unwrap()
                };
            let reconcile = |store: &AnalyzerStore,
                             snapshot: &WorkspaceSnapshotId,
                             profile: [u8; 32],
                             cancellation: &CancellationToken| {
                let context = store
                    .selected_go_context(snapshot, &profile)
                    .unwrap()
                    .unwrap();
                let report = store
                    .reconcile_unit_summaries(
                        snapshot,
                        GoUnitSummaries {
                            context_id: context.context_id,
                            profile,
                        },
                        cancellation,
                    )
                    .unwrap();
                assert!(report.failed.is_empty(), "{report:?}");
                report
            };
            let inventory_first = read(store, &snapshot, &inventory).unwrap();
            activate_go_context(&workspace);
            let tool_go = resolve_analyzer::<GoAnalyzer>(workspace.analyzer())
                .unwrap()
                .clone();
            let tool = tool_go.native_context_profile().unwrap();
            assert_ne!(inventory, tool);
            let tool_first = read(store, &snapshot, &tool).unwrap();
            assert_ne!(inventory_first.0, tool_first.0);
            assert_eq!(
                read(store, &snapshot, &inventory),
                Some(inventory_first.clone())
            );
            let cancellation = CancellationToken::new();

            // Reversing publication order must retain the tool summary too. A cancelled
            // pass withdraws rows opened at this revision; re-publication rebinds the
            // same content-addressed header instead of replacing the other profile.
            for profile in [inventory, tool] {
                let cancelled = CancellationToken::new();
                cancelled.cancel();
                let report = reconcile(store, &snapshot, profile, &cancelled);
                assert!(
                    report.cancelled && report.closed_versions == 2,
                    "{report:?}"
                );
                assert_eq!(read(store, &snapshot, &profile), None);
                let (other, expected) = if profile == inventory {
                    (tool, &tool_first)
                } else {
                    (inventory, &inventory_first)
                };
                assert_eq!(read(store, &snapshot, &other), Some(expected.clone()));
                let report = reconcile(store, &snapshot, profile, &cancellation);
                assert_eq!(report.rebound, 2, "{report:?}");
                assert_eq!(
                    read(store, &snapshot, &inventory),
                    Some(inventory_first.clone())
                );
                assert_eq!(read(store, &snapshot, &tool), Some(tool_first.clone()));
            }

            std::fs::write(
                fixture.root().join("api/api.go"),
                "package api\n\nfunc Public() { println(1) }\n",
            )
            .unwrap();
            let updated = WorkspaceAnalyzer::build_persisted_without_automatic_gc(
                fixture.project_dyn(),
                go_full_production_config(),
            )
            .unwrap();
            let next = resolve_analyzer::<GoAnalyzer>(updated.analyzer())
                .unwrap()
                .selected_snapshot_for_test()
                .unwrap();
            assert_eq!(snapshot.generation, next.generation);
            assert!(snapshot.revision < next.revision);
            let inventory_next = read(store, &next, &inventory).unwrap();
            assert_ne!(inventory_next.0, inventory_first.0);
            // The other profile has no later open interval yet. Its old reconcile must
            // not be rejected by the newer inventory profile's revision guard.
            reconcile(store, &snapshot, tool, &cancellation);
            activate_go_context(&updated);
            let tool_next = read(store, &next, &tool).unwrap();
            assert_ne!(tool_next.0, tool_first.0);
            assert_eq!(inventory_go.native_context_profile(), Some(inventory));
            assert_eq!(tool_go.native_context_profile(), Some(tool));
            assert_eq!(
                read(store, &snapshot, &inventory),
                Some(inventory_first.clone())
            );
            assert_eq!(read(store, &snapshot, &tool), Some(tool_first.clone()));

            // Drop every owner, then reopen actual persisted rows without rebuilding.
            drop(inventory_go);
            drop(tool_go);
            drop(updated);
            drop(workspace);
            let reopened = AnalyzerStore::open_persistent(&path).unwrap();
            assert_eq!(
                read(&reopened, &snapshot, &inventory),
                Some(inventory_first)
            );
            assert_eq!(read(&reopened, &snapshot, &tool), Some(tool_first));
            assert_eq!(
                read(&reopened, &next, &inventory),
                Some(inventory_next.clone())
            );
            assert_eq!(read(&reopened, &next, &tool), Some(tool_next.clone()));

            // At a later revision, cleanup closes earlier intervals instead of deleting
            // them, leaving old readers valid and the other profile untouched.
            let mut withdrawal = next.clone();
            withdrawal.revision += 1;
            let context = reopened.selected_go_context(&next, &tool).unwrap().unwrap();
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            let report = reopened
                .reconcile_unit_summaries(
                    &withdrawal,
                    GoUnitSummaries {
                        context_id: context.context_id,
                        profile: tool,
                    },
                    &cancelled,
                )
                .unwrap();
            assert!(
                report.cancelled && report.closed_versions == 2,
                "{report:?}"
            );
            assert_eq!(read(&reopened, &withdrawal, &tool), None);
            assert_eq!(read(&reopened, &next, &tool), Some(tool_next));
            assert_eq!(
                read(&reopened, &withdrawal, &inventory),
                Some(inventory_next)
            );
            let conn = reopened.read_conn().unwrap();
            assert!(
                !conn
                    .prepare("PRAGMA foreign_key_check")
                    .unwrap()
                    .exists([])
                    .unwrap()
            );
        }
    }
    mod go_move_9 {

        use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

        use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

        use std::sync::Arc;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredSemanticRole;

        use git2::ObjectType;

        use git2::Oid;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::PreloadedFactResolutionService;

        use brokk_bifrost_core::analyzer::model::ProjectFile;

        use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionContentMountRequest;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationInput;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionOverlayMask;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;

        use brokk_bifrost_analysis::analyzer::store::WorkspaceFileRow;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: go_extraction_support_11 :: parsed_operation_source_state ;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: go_extraction_support_11 :: semantic_at ;
        const SPELLING_SOURCE: &str = r#"package consumer
 type Outer struct{ Member int }
 var X Outer
 func beforeAfter() { _ = X.Member; type X struct{}; _ = X.Member }
 func innerValue() { type X struct{}; { var X Outer; _ = X.Member } }
 func invalidValue() { type X int; _ = X }
"#;
        use crate::engine_tests::go_extraction::go_extraction_tests::go_move_11::GO_ROOT_CONSUMER_PATH;
        use crate::engine_tests::go_extraction::go_extraction_tests::go_move_11::GoRootResolutionOperationFixture;
        #[test]
        fn go_spelling_persisted_and_unsaved_content_match_preload() {
            use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionContentPublicationOutcome;

            for unsaved in [false, true] {
                let baseline = if unsaved {
                    "package consumer\nvar X int\nfunc use() { _ = X }\n"
                } else {
                    SPELLING_SOURCE
                };
                let fixture = GoRootResolutionOperationFixture::with_consumer(baseline);
                let cancellation = CancellationToken::default();
                let (state, facts) = parsed_operation_source_state(
                    fixture._project_root.path(),
                    GO_ROOT_CONSUMER_PATH,
                    SPELLING_SOURCE,
                    &GoAdapter,
                );
                let masks = if unsaved {
                    vec![SelectedResolutionOverlayMask::replacement(
                        "go",
                        GO_ROOT_CONSUMER_PATH,
                    )]
                } else {
                    Vec::new()
                };
                if unsaved {
                    fixture.project.set_overlay_content(
                        ProjectFile::new(fixture._project_root.path(), GO_ROOT_CONSUMER_PATH),
                        SPELLING_SOURCE,
                    );
                }
                let open = || {
                    let mut content_mounts = Vec::new();
                    if unsaved {
                        let snapshot = &fixture.snapshots["go"];
                        let oid =
                            Oid::hash_object(ObjectType::Blob, SPELLING_SOURCE.as_bytes()).unwrap();
                        let prepared = AnalyzerStore::prepare_parsed_blob(
                            oid,
                            "go",
                            snapshot.generation,
                            &GoAdapter,
                            Arc::clone(&state),
                        )
                        .unwrap();
                        let ResolutionContentPublicationOutcome::Ready(content) = fixture
                            .store
                            .publish_selected_parsed_content(
                                snapshot,
                                GO_ROOT_CONSUMER_PATH,
                                prepared,
                                &cancellation,
                            )
                            .unwrap()
                        else {
                            panic!("Go edited publication must be ready")
                        };
                        content_mounts.push(
                            SelectedResolutionContentMountRequest::new(
                                content.into_parts().0,
                                WorkspaceFileRow {
                                    rel_path: GO_ROOT_CONSUMER_PATH.to_owned(),
                                    blob_oid: oid,
                                },
                                Vec::new(),
                                Vec::new(),
                                Vec::new(),
                                Vec::new(),
                            )
                            .with_live_overlay_content_digest(
                                brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(
                                    SPELLING_SOURCE.as_bytes(),
                                ),
                            ),
                        );
                    }
                    let SelectedResolutionOperationOpenOutcome::Ready(operation) = fixture
                        .store
                        .open_selected_resolution_operation(
                            SelectedResolutionOperationInput::new(
                                &fixture.project,
                                &fixture.workspace_id,
                                &fixture.snapshots,
                                &fixture.languages,
                                &masks,
                            )
                            .with_content_mounts(content_mounts),
                            &cancellation,
                        )
                        .unwrap()
                    else {
                        panic!("Go spelling operation must open")
                    };
                    *operation
                };
                let operation = open();
                let fragment = operation
                    .mounts()
                    .unwrap()
                    .iter()
                    .find(|mount| mount.persisted_relative_path() == GO_ROOT_CONSUMER_PATH)
                    .unwrap()
                    .fragment();
                drop(operation);
                let lowered = brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                    fragment,
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                    Language::Go,
                    &facts,
                );
                let preload = PreloadedFactResolutionService::from_lowered_fragments(
                    [lowered.lexical().clone()],
                    [lowered.typed().clone()],
                );
                let declarations = facts
                    .identifiers
                    .iter()
                    .filter(|id| {
                        facts.names[id.name.index()].spelling == "X"
                            && id.role == ResolutionIdentifierRole::Declaration
                    })
                    .map(|id| semantic_at(&lowered, id.site, LoweredSemanticRole::Definition))
                    .collect::<Vec<_>>();
                let references = facts
                    .identifiers
                    .iter()
                    .filter(|id| {
                        facts.names[id.name.index()].spelling == "X"
                            && id.role == ResolutionIdentifierRole::Reference
                    })
                    .collect::<Vec<_>>();
                assert_eq!(declarations.len(), 5);
                assert_eq!(references.len(), 4);
                for (reference, target) in references.into_iter().zip([
                    Some(declarations[0]),
                    Some(declarations[1]),
                    Some(declarations[3]),
                    None,
                ]) {
                    let expected = preload
                        .resolve_reference(
                            semantic_at(&lowered, reference.site, LoweredSemanticRole::Reference),
                            &cancellation,
                        )
                        .unwrap();
                    assert_eq!(expected.binding().targets(), target.as_slice());
                    let operation = open();
                    let contexts = operation
                        .empty_contexts(&ResolutionCompletion::Complete)
                        .unwrap();
                    let locator = SelectedSemanticLocator::new(
                        "go",
                        GO_ROOT_CONSUMER_PATH,
                        reference.site,
                        LoweredSemanticRole::Reference,
                    );
                    let SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Found(actual),
                    ) = operation
                        .resolve_reference(
                            contexts,
                            &locator,
                            &cancellation,
                            &mut SelectedResolutionContextMetrics,
                        )
                        .unwrap()
                    else {
                        panic!("Go spelling answer must be native")
                    };
                    assert_eq!(
                        actual, expected,
                        "unsaved={unsaved}, reference={reference:?}"
                    );
                }
                assert_eq!(
                    std::fs::read_to_string(
                        fixture._project_root.path().join(GO_ROOT_CONSUMER_PATH)
                    )
                    .unwrap(),
                    baseline
                );
            }
        }
    }
    mod go_move_10 {

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;

        use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

        use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

        use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

        use brokk_bifrost_analysis::analyzer::store::js_ts_resolution_producer_support::parsed_fixture_state;

        use brokk_bifrost_analysis::analyzer::store::js_ts_resolution_producer_support::persist_alias_fixture;

        use brokk_bifrost_analysis::analyzer::store::resolution::RESOLUTION_MANIFEST_COUNT_COLUMNS;

        use brokk_bifrost_analysis::analyzer::store::resolution_prepare::ResolutionInteriorPreparation;

        use brokk_bifrost_analysis::analyzer::store::resolution_prepare::prepare_resolution_bundle_with_unit_keys;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_producer_tests_go_support :: go_extraction_support_10 :: fixture_project_root ;

        use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_core::analyzer::model::ProjectFile;

        use brokk_bifrost_test_macros::hardwon;

        use std::sync::Arc;
        use tree_sitter::Parser;

        #[test]
        #[hardwon(
            "35bb5be9598c: Go calls inside if conditions lacked persisted inverse lookup headers"
        )]
        fn go_reverse_lookup_headers_include_if_condition_call_callees() {
            let store = AnalyzerStore::open_ephemeral().expect("ephemeral Go resolution store");
            let source = "package pkg\n\ntype Widget struct{}\nfunc New() Widget { return Widget{} }\nfunc use() { if New().Name() == \"\" {} }\n";
            let content = oid(source);
            persist_alias_fixture(&store, content, "go", &GoAdapter, "pkg/pkg_test.go", source);
            let content = content.to_string();
            let names: Vec<String> = store
                .conn
                .execute(move |connection| {
                    let mut statement = connection.prepare(
                        "SELECT DISTINCT identity.spelling
                 FROM main.blobs AS blob
                 JOIN main.resolution_reference_lookup_identities AS lookup
                   ON lookup.blob_id=blob.id
                 JOIN main.resolution_identities AS identity
                   ON identity.id=lookup.identity_id
                 WHERE blob.blob_oid=?1 AND blob.lang='go'
                   AND identity.spelling='New'
                 ORDER BY identity.spelling",
                    )?;
                    statement
                        .query_map([content], |row| row.get(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .expect("read persisted Go lookup-header spellings");
            assert!(
                names.iter().any(|spelling| spelling == "New"),
                "nested `New()` needs a persisted package-reference lookup header: {names:?}"
            );
        }
        #[test]
        fn production_writer_seals_common_visibility_for_a_non_java_fragment() {
            use brokk_bifrost_core::analyzer::resolution_facts::{
                ResolutionDeclarationVisibilityFact, ResolutionSiteKind,
                ResolutionVisibilityEligibilityFact,
            };
            use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;

            let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
            let generation = store
                .ensure_language_epoch_value("go", "resolution-go-visibility-test-v1")
                .expect("Go generation");
            let oid = oid(b"non-java visibility insertion");
            let mut state = parsed_fixture_state(
                &GoAdapter,
                "src/visibility.go",
                "package demo\ntype Owner struct {}\n",
            );
            // Exercise the common writer independently of Go's visibility extraction,
            // while retaining the real declaration's source identity and bridges.
            let facts = &mut Arc::make_mut(&mut state).resolution_facts;
            let declaration = facts
                .sites
                .iter()
                .find(|site| site.kind == ResolutionSiteKind::TypeDeclaration)
                .expect("parsed Go type declaration")
                .id;
            facts
                .visibility_eligibilities
                .push(ResolutionVisibilityEligibilityFact { declaration });
            facts
                .declaration_visibilities
                .push(ResolutionDeclarationVisibilityFact {
                    declaration,
                    visibility: DeclaredVisibility::Public,
                });
            store
                .write_parsed_blob_at_generation(
                    &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                    oid,
                    "go",
                    generation,
                    &GoAdapter,
                    &state,
                )
                .expect("persist Go visibility fixture");
            let counts = store.conn.execute({
        let oid = oid.to_string();
        move |conn| {
            conn.query_row(
                "SELECT interior.expected_declaration_visibility_property_count,
                        (SELECT COUNT(*) FROM resolution_declaration_visibility_properties AS property
                         WHERE property.blob_id = interior.blob_id)
                 FROM blobs AS blob
                 JOIN resolution_fragment_interiors AS interior ON interior.blob_id = blob.id
                 WHERE blob.blob_oid = ?1 AND blob.lang = 'go'",
                [oid],
                |row| {
                    Ok((
                        row.get::<_, usize>(0)?,
                        row.get::<_, usize>(1)?,
                    ))
                },
            )
            .expect("query persisted Go visibility family")
        }
    });
            assert!(counts.0 > 0, "Go fixture must publish visibility metadata");
            assert_eq!(counts.0, counts.1);
        }
        #[test]
        fn go_method_owner_frontier_survives_common_lowering_and_bundle_preparation() {
            let source = "package p\nfunc (value *Remote) Method() *Remote { return value }\n";
            let file = ProjectFile::new(
                fixture_project_root("selected-go-context-does-not-touch-disk"),
                "method.go",
            );
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_go::LANGUAGE.into())
                .expect("configure Go parser");
            let tree = parser.parse(source, None).expect("parse Go method fixture");
            let facts = brokk_bifrost_go::declarations::parse_go_file(&file, source, &tree)
                .resolution_facts;
            assert_eq!(facts.deferred_member_owners.len(), 1);

            let lowered =
                brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                    BindingFragmentId::for_test(b"go-deferred-owner-m6a"),
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                    Language::Go,
                    &facts,
                );
            assert_eq!(lowered.common().deferred_member_owners.len(), 1);
            let ResolutionInteriorPreparation::Prepared(prepared) =
                prepare_resolution_bundle_with_unit_keys(
                    &lowered,
                    None,
                    &CancellationToken::default(),
                )
            else {
                panic!("uncancelled Go deferred-owner preparation must finish");
            };
            // The deferred owner and the frontier it names are both interior detail
            // now; what must survive preparation is the declaration the owner belongs
            // to, which is the tier-1 semantic site.
            let family = RESOLUTION_MANIFEST_COUNT_COLUMNS
                .iter()
                .position(|column| *column == "expected_semantic_site_count")
                .expect("semantic site manifest family");
            assert!(prepared.family_counts()[family] > 0);
        }
    }
    #[doc(hidden)]
    pub mod go_move_11 {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::go_extraction_support_11::assert_empty_context_metrics;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;

        use brokk_bifrost_analysis::analyzer::resolution::fact_source::FactPageVisitor;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::FactReverseResolutionMetrics;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredSemanticRole;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::PreloadedFactResolutionService;

        use brokk_bifrost_analysis::analyzer::resolution::batch::ResolutionBatchMetrics;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::ResolutionLookupSemanticRecipe;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::SelectedFactOperationBlueprintConstruction;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedResolutionContextSet;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedResolutionContextValidationOutcome;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedResolutionMountContext;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedRootBridgeDescriptor;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::reset_selected_fact_operation_construction_count_for_test;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::selected_fact_operation_construction_count_for_test;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::visit_selected_root_export_half_pages;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::visit_selected_root_import_half_pages;

        use brokk_bifrost_analysis::analyzer::store::go_unit_summaries::go_unit_key;

        pub (super) use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: selected_sql_trace :: ProductionSelectedSqlCost ;

        pub (super) use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: selected_sql_trace :: begin_production_selected_sql_trace ;

        pub (super) use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: selected_sql_trace :: begin_production_selected_sql_trace_on_connection ;

        pub (super) use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: selected_sql_trace :: checkpoint_production_selected_sql_trace ;

        pub (super) use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: selected_sql_trace :: finish_production_selected_sql_trace ;

        pub (super) use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: selected_sql_trace :: finish_production_selected_sql_trace_on_connection ;

        use brokk_bifrost_analysis::analyzer::resolution::model::BindingNodeId;

        use brokk_bifrost_analysis::analyzer::resolution::batch::CandidatePathIdentity;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::ContextRegistrationOutcome;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_demand::GoForwardOperationContext;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_named::GoPreparedImportContextOutcome;

        use brokk_bifrost_core::hash::HashMap;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::LocatedSemantic;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: go_extraction_support_11 :: MutableGenerationProject ;

        use brokk_bifrost_analysis::analyzer::resolution::model::PartialPath;

        use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::source_demand::RootSourceHorizon;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedContextIdentities;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

        use brokk_bifrost_analysis::analyzer::store::resolution_lexical::SelectedResolutionLexicalSource;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedResolutionMountOrdinal;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationInput;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

        use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedRootPathHalf;

        use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

        use brokk_bifrost_analysis::analyzer::store::resolution_lexical::UnconditionalCandidateCache;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: go_extraction_support_11 :: assert_store_error_contains ;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: go_extraction_support_11 :: content_mount_request ;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_context;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_named;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::go_same_package;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: go_extraction_support_11 :: mount_lookup ;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: go_extraction_support_11 :: open_ready_operation ;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: go_extraction_support_11 :: parsed_operation_state ;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: go_extraction_support_11 :: persist_test_workspace_snapshot ;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::reset_selected_resolution_boundary_snapshot_for_test;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: go_extraction_support_11 :: selected_operation_input ;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_resolution_boundary_snapshot_for_test;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: go_extraction_support_11 :: semantic_at ;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: go_extraction_support_11 :: site_for_identifier ;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: go_extraction_support_11 :: with_operation_lexical ;

        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;

        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionOverlayMask;

        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionStale;

        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionUnavailable;

        use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

        use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

        use brokk_bifrost_analysis::analyzer::store::PersistBatchTargets;

        use brokk_bifrost_analysis::analyzer::store::workspace_inputs::WorkspaceConfigurationInput;

        use brokk_bifrost_analysis::analyzer::store::WorkspaceFileRow;

        use brokk_bifrost_analysis::analyzer::store::WorkspaceId;

        use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshots;

        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_core::analyzer::project::Project;

        use brokk_bifrost_core::analyzer::model::ProjectFile;

        use brokk_bifrost_core::analyzer::resolution_facts::{
            FileResolutionFacts, ResolutionGapKind, ResolutionIdentifierRole, ResolutionNamespace,
            ResolutionRootImportAnchor,
        };
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
            ReceiverAnalysisBudget, ReceiverAnalysisWork,
        };
        use brokk_bifrost_core::analyzer::usages::resolution_session::{
            BoundedResolution, ResolutionSession,
        };

        use brokk_bifrost_test_macros::hardwon;
        use git2::ObjectType;
        use git2::Oid;

        use std::collections::BTreeMap;
        use std::path::Path;

        use std::sync::Arc;

        const GO_WORKSPACE_ID: &str =
            "7272727272727272727272727272727272727272727272727272727272727272";
        pub(crate) const GO_SOURCE_PATH: &str = "local.go";
        const GO_SOURCE: &str = r#"package local

type Item struct{}

func Echo(input *Item) *Item {
    return input
}

func use(value *Item) *Item {
    return Echo(value)
}
"#;
        pub(crate) fn parsed_go_state(
            project_root: &Path,
            relative_path: &str,
            source: &str,
        ) -> (Arc<FileState>, FileResolutionFacts) {
            parsed_operation_state(project_root, relative_path, source, &GoAdapter)
        }
        pub(crate) struct GoResolutionOperationFixture {
            pub(crate) store: AnalyzerStore,
            pub(crate) _project_root: tempfile::TempDir,
            pub(crate) project: MutableGenerationProject,
            pub(crate) workspace_id: WorkspaceId,
            pub(crate) snapshots: WorkspaceSnapshots,
            pub(crate) languages: Vec<SelectedResolutionLanguage>,
            overlay_masks: Vec<SelectedResolutionOverlayMask>,
            pub(crate) facts: FileResolutionFacts,
        }
        impl GoResolutionOperationFixture {
            fn new() -> Self {
                Self::with_source(GO_SOURCE)
            }

            pub(crate) fn with_source(source: &str) -> Self {
                let project_root = tempfile::tempdir().expect("Go operation test project root");
                let project = MutableGenerationProject::new(project_root.path(), Language::Go);
                let adapter = GoAdapter;
                let (state, facts) = parsed_go_state(project_root.path(), GO_SOURCE_PATH, source);

                let store = AnalyzerStore::open_ephemeral().expect("Go operation test store");
                let generation = store
                    .ensure_language_epoch_value("go", "resolution-operation-go-test-v1")
                    .expect("Go operation test language epoch");
                store
                    .ensure_resolution_producer_epoch("go", Language::Go)
                    .expect("Go operation test producer epoch");
                let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes())
                    .expect("hash the Go operation fixture source");
                let prepared = AnalyzerStore::prepare_parsed_blob(
                    oid,
                    "go",
                    generation,
                    &adapter,
                    Arc::clone(&state),
                )
                .expect("prepare parsed Go blob with resolution bundle");
                assert!(
                    prepared.resolution.logical_rows() > 1,
                    "the real Go producer must prepare a nonempty resolution interior"
                );
                let (outcomes, _) =
                    store.persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
                assert_eq!(outcomes.len(), 1);
                assert!(outcomes[0].error.is_none(), "{:#?}", outcomes[0].error);

                let workspace_id = WorkspaceId(GO_WORKSPACE_ID.to_owned());
                let snapshots = persist_test_workspace_snapshot(
                    &store,
                    &workspace_id,
                    "go",
                    generation,
                    vec![(
                        GO_SOURCE_PATH.to_owned(),
                        oid.to_string(),
                        format!("{:064x}", 701),
                    )],
                );
                Self {
                    store,
                    _project_root: project_root,
                    project,
                    workspace_id,
                    snapshots,
                    languages: vec![SelectedResolutionLanguage::new("go", Language::Go)],
                    overlay_masks: Vec::new(),
                    facts,
                }
            }

            pub(crate) fn open_ready<'a>(
                &'a self,
                cancellation: &CancellationToken,
            ) -> SelectedResolutionOperation<'a, 'a> {
                open_ready_operation(
                    &self.store,
                    selected_operation_input(
                        &self.project,
                        &self.workspace_id,
                        &self.snapshots,
                        &self.languages,
                        &self.overlay_masks,
                        Vec::new(),
                    ),
                    cancellation,
                )
            }
        }
        #[doc(hidden)]
        pub const GO_ROOT_WORKSPACE_ID: &str =
            "7373737373737373737373737373737373737373737373737373737373737373";
        #[doc(hidden)]
        pub const GO_ROOT_CONSUMER_PATH: &str = "consumer/use.go";
        #[doc(hidden)]
        pub const GO_ROOT_PROVIDER_PATH: &str = "provider/item.go";
        #[doc(hidden)]
        pub const GO_ROOT_DECOY_PATH: &str = "other/provider/item.go";
        #[doc(hidden)]
        pub const GO_ROOT_CONSUMER_SOURCE: &str = r#"package consumer

import . "example.test/root/provider"

var Use *Item
"#;
        #[doc(hidden)]
        pub const GO_ROOT_PROVIDER_SOURCE: &str = r#"package provider

type Item struct{}
"#;
        #[doc(hidden)]
        pub const GO_ROOT_DECOY_SOURCE: &str = r#"package provider

type Item struct{ Decoy bool }
"#;
        #[doc(hidden)]
        pub struct GoRootResolutionOperationFixture {
            pub(crate) store: AnalyzerStore,
            pub(crate) _project_root: tempfile::TempDir,
            pub(crate) project: MutableGenerationProject,
            pub(crate) workspace_id: WorkspaceId,
            pub(crate) snapshots: WorkspaceSnapshots,
            pub(crate) languages: Vec<SelectedResolutionLanguage>,
            overlay_masks: Vec<SelectedResolutionOverlayMask>,
            pub(crate) consumer_facts: FileResolutionFacts,
            pub(crate) provider_facts: FileResolutionFacts,
            decoy_facts: FileResolutionFacts,
        }
        #[derive(Debug, Clone, Copy)]
        enum ProductionGoPointKind {
            Definition,
            Type,
        }
        #[derive(Debug)]
        struct ProductionGoPointMeasurement {
            open: ProductionSelectedSqlCost,
            search: ProductionSelectedSqlCost,
            work: ReceiverAnalysisWork,
        }
        fn measure_production_go_point_sql(
            fixture: &GoRootResolutionOperationFixture,
            context_id: i64,
            kind: ProductionGoPointKind,
        ) -> ProductionGoPointMeasurement {
            let cancellation = CancellationToken::default();
            let reference = site_for_identifier(
                &fixture.consumer_facts,
                "Item",
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Type,
            );
            let reference_range = fixture
                .consumer_facts
                .sites
                .iter()
                .find(|site| site.id == reference)
                .expect("Go point-cost reference range");
            let locator = SelectedSemanticLocator::for_reference_range(
                "go",
                GO_ROOT_CONSUMER_PATH,
                reference_range.start_byte,
                reference_range.end_byte,
            );

            begin_production_selected_sql_trace(&fixture.store);
            let mut operation = fixture.open_ready(&cancellation);
            let open = checkpoint_production_selected_sql_trace();
            let GoPreparedImportContextOutcome::Ready(prepared) = operation
                .go_file_import_context(context_id, GO_ROOT_CONSUMER_PATH, &cancellation)
                .expect("build production Go point-cost context")
            else {
                panic!("production Go point-cost context must be ready")
            };
            let _selected_imports = operation
                .go_selected_external_imports(context_id, GO_ROOT_CONSUMER_PATH, &cancellation)
                .expect("read Go point-cost selected imports");
            let _unresolved_imports = operation
                .go_selected_unresolved_imports(context_id, GO_ROOT_CONSUMER_PATH, &cancellation)
                .expect("read Go point-cost unresolved imports");
            let mut artifacts =
                brokk_bifrost_analysis::analyzer::resolution::batch::ForwardCandidateArtifactCache::default();
            let mut context_metrics = SelectedResolutionContextMetrics;
            let mut point_metrics = ResolutionBatchMetrics::default();
            let (work, binding_targets) = match kind {
                ProductionGoPointKind::Definition => {
                    let outcome = operation
                        .resolve_native_reference_units_bounded_for_go_request(
                            *prepared,
                            None,
                            &locator,
                            ReceiverAnalysisBudget::default(),
                            &cancellation,
                            &mut context_metrics,
                            &mut artifacts,
                            &mut point_metrics,
                        )
                        .expect("run production Go definition point-cost search");
                    let BoundedResolution::Complete { value, work } = outcome else {
                        panic!("production Go definition point-cost search completes")
                    };
                    let SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Found(answer),
                    ) = value
                    else {
                        panic!("production Go definition point-cost search finds its provider")
                    };
                    (work, answer.answer.binding().targets().len())
                }
                ProductionGoPointKind::Type => {
                    let outcome = operation
                        .resolve_native_reference_types_bounded_for_go_request(
                            *prepared,
                            None,
                            None,
                            &locator,
                            ReceiverAnalysisBudget::default(),
                            &cancellation,
                            &mut context_metrics,
                            &mut artifacts,
                            &mut point_metrics,
                        )
                        .expect("run production Go type point-cost search");
                    let BoundedResolution::Complete { value, work } = outcome else {
                        panic!("production Go type point-cost search completes")
                    };
                    let SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Found(answer),
                    ) = value
                    else {
                        panic!("production Go type point-cost search finds its provider")
                    };
                    (work, answer.answer.binding().targets().len())
                }
            };
            // The trace is installed on the reader owned by the operation. Return the
            // reader before checking it back out to remove the trace callback.
            drop(operation);
            let search = finish_production_selected_sql_trace(&fixture.store);
            assert_eq!(binding_targets, 1, "Go point has one exact binding target");
            ProductionGoPointMeasurement { open, search, work }
        }
        impl GoRootResolutionOperationFixture {
            pub(crate) fn new() -> Self {
                Self::with_consumer(GO_ROOT_CONSUMER_SOURCE)
            }

            pub(crate) fn with_consumer(consumer_source: &str) -> Self {
                Self::with_sources([
                    consumer_source,
                    GO_ROOT_PROVIDER_SOURCE,
                    GO_ROOT_DECOY_SOURCE,
                ])
            }

            pub(crate) fn with_sources(sources: [&str; 3]) -> Self {
                let project_root =
                    tempfile::tempdir().expect("Go root operation test project root");
                let project = MutableGenerationProject::new(project_root.path(), Language::Go);
                let adapter = GoAdapter;
                let store = AnalyzerStore::open_ephemeral().expect("Go root operation test store");
                let generation = store
                    .ensure_language_epoch_value("go", "resolution-operation-go-root-test-v1")
                    .expect("Go root operation test language epoch");
                store
                    .ensure_resolution_producer_epoch("go", Language::Go)
                    .expect("Go root operation test producer epoch");

                let mut versions = Vec::new();
                let mut prepared = Vec::new();
                let mut facts_by_path = BTreeMap::new();
                for (ordinal, (path, source)) in [
                    (GO_ROOT_CONSUMER_PATH, sources[0]),
                    (GO_ROOT_PROVIDER_PATH, sources[1]),
                    (GO_ROOT_DECOY_PATH, sources[2]),
                ]
                .into_iter()
                .enumerate()
                {
                    let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes())
                        .expect("hash the Go root operation fixture source");
                    let (state, facts) = parsed_go_state(project_root.path(), path, source);
                    prepared.push(
                        AnalyzerStore::prepare_parsed_blob(
                            oid,
                            "go",
                            generation,
                            &adapter,
                            Arc::clone(&state),
                        )
                        .expect("prepare parsed Go root blob with resolution bundle"),
                    );
                    versions.push((
                        path.to_owned(),
                        oid.to_string(),
                        format!("{:064x}", 720 + ordinal),
                    ));
                    assert!(facts_by_path.insert(path, facts).is_none());
                }
                let (outcomes, _) =
                    store.persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION);
                assert_eq!(outcomes.len(), 3);
                assert!(
                    outcomes.iter().all(|outcome| outcome.error.is_none()),
                    "{:#?}",
                    outcomes
                        .iter()
                        .map(|outcome| &outcome.error)
                        .collect::<Vec<_>>()
                );

                let workspace_id = WorkspaceId(GO_ROOT_WORKSPACE_ID.to_owned());
                let snapshots = persist_test_workspace_snapshot(
                    &store,
                    &workspace_id,
                    "go",
                    generation,
                    versions,
                );
                Self {
                    store,
                    _project_root: project_root,
                    project,
                    workspace_id,
                    snapshots,
                    languages: vec![SelectedResolutionLanguage::new("go", Language::Go)],
                    overlay_masks: Vec::new(),
                    consumer_facts: facts_by_path
                        .remove(GO_ROOT_CONSUMER_PATH)
                        .expect("consumer facts"),
                    provider_facts: facts_by_path
                        .remove(GO_ROOT_PROVIDER_PATH)
                        .expect("provider facts"),
                    decoy_facts: facts_by_path
                        .remove(GO_ROOT_DECOY_PATH)
                        .expect("decoy facts"),
                }
            }

            pub(crate) fn open_ready<'a>(
                &'a self,
                cancellation: &CancellationToken,
            ) -> SelectedResolutionOperation<'a, 'a> {
                open_ready_operation(
                    &self.store,
                    selected_operation_input(
                        &self.project,
                        &self.workspace_id,
                        &self.snapshots,
                        &self.languages,
                        &self.overlay_masks,
                        Vec::new(),
                    ),
                    cancellation,
                )
            }

            fn contexts_for(
                &self,
                operation: &SelectedResolutionOperation<'_, '_>,
            ) -> SelectedResolutionContextSet {
                self.contexts_with_bridge(operation, self.root_bridge(operation))
            }

            fn root_bridge(
                &self,
                operation: &SelectedResolutionOperation<'_, '_>,
            ) -> SelectedRootBridgeDescriptor {
                let mounts = operation.mounts().unwrap();
                let source = mounts
                    .iter()
                    .find(|mount| mount.persisted_relative_path() == GO_ROOT_CONSUMER_PATH)
                    .expect("selected Go consumer mount");
                let target = mounts
                    .iter()
                    .find(|mount| mount.persisted_relative_path() == GO_ROOT_PROVIDER_PATH)
                    .expect("selected Go provider mount");
                let import = self
                    .consumer_facts
                    .root_imports
                    .first()
                    .copied()
                    .expect("consumer dot-import root fact");
                let mut segments = self
                    .consumer_facts
                    .root_import_segments
                    .iter()
                    .filter(|segment| segment.import_site == import.site)
                    .copied()
                    .collect::<Vec<_>>();
                segments.sort_unstable_by_key(|segment| segment.position);
                let route = segments
                    .iter()
                    .map(|segment| {
                        ResolutionLookupSemanticRecipe::new(
                            Language::Go,
                            ResolutionNamespace::Type,
                            &self.consumer_facts.names[segment.name.index()].spelling,
                        )
                    })
                    .collect::<Vec<_>>();
                let demand = self
                    .consumer_facts
                    .root_import_demands
                    .iter()
                    .find(|demand| {
                        demand.import_site == import.site
                            && self.consumer_facts.names[demand.name.index()].spelling == "Item"
                    })
                    .copied()
                    .expect("consumer Item root demand");
                let source_demand = ResolutionLookupSemanticRecipe::new(
                    Language::Go,
                    demand.namespace,
                    &self.consumer_facts.names[demand.name.index()].spelling,
                );
                let target_demand = source_demand.clone();
                let mut halves = Vec::new();
                let every_mount = operation
                    .mounts()
                    .unwrap()
                    .iter()
                    .map(|mount| mount.ordinal())
                    .collect::<Vec<_>>();
                with_operation_lexical(operation, |composite, anchors| {
                    for visit in [
                        visit_selected_root_import_half_pages,
                        visit_selected_root_export_half_pages,
                    ] {
                        let outcome = visit(
                            &SelectedContextIdentities::new(),
                            anchors,
                            composite,
                            Some(&every_mount),
                            &CancellationToken::default(),
                            &mut FactPageVisitor::new(&mut |page| {
                                halves.extend_from_slice(page);
                                Ok(true)
                            }),
                        )
                        .expect("read persisted Go root halves");
                        assert!(outcome.is_exhausted());
                    }
                });
                let (source_token, anchor, anchor_semantic) = halves
                    .iter()
                    .find_map(|half| match half {
                        SelectedRootPathHalf::Import {
                            identity,
                            token,
                            anchor,
                            anchor_semantic,
                            demand,
                            ..
                        } if identity.fragment() == source.fragment()
                            && *demand
                                == source_demand.semantic(&operation.ready.shared_names()) =>
                        {
                            Some((*token, *anchor, *anchor_semantic))
                        }
                        _ => None,
                    })
                    .expect("persisted Go import token and anchor");
                let target_token = halves
                    .iter()
                    .find_map(|half| match half {
                        SelectedRootPathHalf::Export {
                            identity,
                            token,
                            demand,
                            ..
                        } if identity.fragment() == target.fragment()
                            && *demand
                                == target_demand.semantic(&operation.ready.shared_names()) =>
                        {
                            Some(*token)
                        }
                        _ => None,
                    })
                    .expect("persisted Go export token");
                SelectedRootBridgeDescriptor::from_selected_path_tokens(
                    source.fragment(),
                    Language::Go,
                    source_token,
                    anchor,
                    anchor_semantic,
                    target.fragment(),
                    Language::Go,
                    target_token,
                    route,
                    source_demand,
                    target_demand,
                    ResolutionCompletion::Complete,
                )
            }

            fn contexts_with_bridge(
                &self,
                operation: &SelectedResolutionOperation<'_, '_>,
                bridge: SelectedRootBridgeDescriptor,
            ) -> SelectedResolutionContextSet {
                let mounts = operation.mounts().unwrap();
                let source = mounts
                    .iter()
                    .find(|mount| mount.fragment() == bridge.source_fragment())
                    .expect("selected bridge source");
                SelectedResolutionContextSet::new(
                    SelectedContextIdentities::new(),
                    vec![
                        SelectedResolutionMountContext::new(
                            source.ordinal(),
                            source.fragment(),
                            source.semantic_language(),
                            vec![bridge],
                            ResolutionCompletion::Complete,
                        )
                        .expect("valid Go root operation context"),
                    ],
                    mounts.len(),
                    &mount_lookup(mounts),
                )
                .expect("exact Go root operation context set")
            }
        }

        #[doc(hidden)]
        pub fn publish_go_root_fixture_context(
            fixture: &GoRootResolutionOperationFixture,
            source_spelling: &'static str,
        ) -> i64 {
            let snapshot = fixture.snapshots["go"].clone();
            fixture.store.conn.execute(move |conn| {
        let tx = conn.transaction().unwrap();
        tx.execute("INSERT INTO go_context_selections(workspace_id,lang,generation,revision,profile_digest,derivation_version)
            VALUES(?1,'go',?2,?3,zeroblob(32),?4)", rusqlite::params![snapshot.workspace_id.as_str(),snapshot.generation.get(),snapshot.revision,brokk_bifrost_analysis::analyzer::store::go_package_context::DERIVATION_VERSION]).unwrap();
        let selection = tx.last_insert_rowid();
        tx.execute("INSERT INTO go_context_publications(selection_id,publication_digest,complete,gaps)
            VALUES(?1,zeroblob(32),0,jsonb('[]'))", [selection]).unwrap();
        let context = tx.last_insert_rowid();
        tx.execute("INSERT INTO go_context_heads(selection_id,context_id) VALUES(?1,?2)", rusqlite::params![selection,context]).unwrap();
        let mut packages = Vec::new();
        for (path, import_path, name) in [
            (GO_ROOT_CONSUMER_PATH,"example.test/root/consumer","consumer"),
            (GO_ROOT_PROVIDER_PATH,"example.test/root/provider","provider"),
            (GO_ROOT_DECOY_PATH,"example.test/root/other/provider","provider"),
        ] {
            let unit_key = go_unit_key(import_path, "", "go");
            tx.execute("INSERT INTO go_package_instances(context_id,tool_import_path,package_name,for_test,provider_directory,provider_digest,complete,gaps,unit_key)
                VALUES(?1,?2,?3,'','',zeroblob(32),0,jsonb('[]'),?4)",rusqlite::params![context,import_path,name,unit_key.as_slice()]).unwrap();
            let package = tx.last_insert_rowid();
            packages.push(package);
            tx.execute("INSERT INTO go_package_files(package_id,file_version_id,source_role)
                SELECT ?1,file_version_id,'go' FROM workspace_file_versions
                WHERE workspace_id=?2 AND lang='go' AND generation=?3 AND rel_path=?4 AND valid_from<=?5
                AND (valid_until IS NULL OR ?5<valid_until)",rusqlite::params![package,snapshot.workspace_id.as_str(),snapshot.generation.get(),path,snapshot.revision]).unwrap();
        }
        tx.execute("INSERT INTO go_package_imports(context_id,importer_package_id,source_spelling,import_role,target_package_id,complete,gaps)
            VALUES(?1,?2,?4,'go',?3,0,jsonb('[]'))",rusqlite::params![context,packages[0],packages[1],source_spelling]).unwrap();
        // Give statistics representative unrelated imports. A one-row table
        // legitimately favors a scan and cannot prove demand-local seeking.
        for index in 0..512 {
            tx.execute("INSERT INTO go_package_imports(context_id,importer_package_id,source_spelling,import_role,target_package_id,complete,gaps)
                VALUES(?1,?2,?3,'go',?4,0,jsonb('[]'))",rusqlite::params![context,packages[0],format!("unrelated/provider{index}"),packages[2]]).unwrap();
        }
        tx.commit().unwrap();
        context
     })
        }
        fn stage_go_import_rows(
            operation: &SelectedResolutionOperation<'_, '_>,
            host: SelectedResolutionMountOrdinal,
            rows: &[brokk_bifrost_analysis::analyzer::resolution::fact_lowering::package::LoweredGoPackageImport],
        ) {
            use brokk_bifrost_analysis::analyzer::store::resolution_stage::codec::encode_node;

            use brokk_bifrost_analysis::analyzer::store::resolution_stage::codec::encode_semantic;
            operation.ready.inventory.with_owned_temp_write(|connection| {
        connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)", rusqlite::params![host.get(), [31_u8;32].as_slice(), [32_u8;32].as_slice()])?;
        let producer = connection.last_insert_rowid();
        for row in rows {
            connection.execute("INSERT INTO temp.selected_resolution_stage_go_package_imports(host_ordinal,producer_id,definition_key,source_site,file_scope_key,spelling_choice_key,start_byte,end_byte,kind) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", rusqlite::params![host.get(),producer,encode_semantic(row.definition),row.source_site.get(),encode_node(row.file_scope),encode_semantic(row.spelling_choice),i64::try_from(row.start_byte).unwrap(),i64::try_from(row.end_byte).unwrap(),row.kind.label()])?;
        }
        Ok(())
    }).unwrap();
        }
        #[test]
        fn production_go_point_statement_decoded_row_and_engine_work_is_repeatable() {
            let measurements = [
        ProductionGoPointKind::Definition,
        ProductionGoPointKind::Type,
    ]
    .map(|kind| {
        let fixture = GoRootResolutionOperationFixture::new();
        let context_id = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
        let cold = measure_production_go_point_sql(&fixture, context_id, kind);
        let first_warm = measure_production_go_point_sql(&fixture, context_id, kind);
        let second_warm = measure_production_go_point_sql(&fixture, context_id, kind);
        eprintln!(
            "production Go point {kind:?} measured tuples: cold=({},{},{},{}) warm=({},{},{},{}) repeat=({},{},{},{})",
            cold.open.statement_count(),
            cold.open.decoded_rows,
            cold.search.statement_count(),
            cold.search.decoded_rows,
            first_warm.open.statement_count(),
            first_warm.open.decoded_rows,
            first_warm.search.statement_count(),
            first_warm.search.decoded_rows,
            second_warm.open.statement_count(),
            second_warm.open.decoded_rows,
            second_warm.search.statement_count(),
            second_warm.search.decoded_rows,
        );
        (kind, cold, first_warm, second_warm)
    });
            // Measure both kinds before checking either pin so a changed reader can
            // report every independent cold/warm tuple in one test run.
            for (kind, cold, first_warm, second_warm) in measurements {
                // Includes the #5243 type-production read and migration 0181 schema statements.
                let expected_scope_nodes = match kind {
                    ProductionGoPointKind::Definition => 438,
                    ProductionGoPointKind::Type => 441,
                };
                // These generic-free fixtures no longer open the optional formal-row
                // table and its indexes during cold point setup. The cold open is
                // +3/+3 over the master pin because the shared selection schema now
                // creates the three Rust unit-summary TEMP views (M5 step 2); the Go
                // search itself is unchanged. Materialized Rust module placements
                // add +8 statements/+5 rows to shared cold selection setup only.
                // #4995 selected units/closure add +14/+8 more to that shared cold
                // setup. Search and retained warm-open work remain unchanged.
                // Canonical bridge inputs resolve three content catalog positions once
                // per selected query (+3 indexed statements and decoded rows).
                // Reusing path header reads and reference path rows within one query
                // removes 10 statements/6 rows from cold Definition and Type searches
                // and 8 statements/4 rows from their warm searches. Migration 0180
                // adds one named-index schema row/statement at cold open only.
                // Request-local immutable endpoint and member-scope reads remove
                // another 7 statements/2 rows from both cold and warm searches.
                // Master #5415 adds the shared type-production TEMP table and its two
                // indexes (+3 cold-open statements/schema rows). Slot preparation now
                // probes the ordinary and staged production relations (+2 search
                // statements, zero rows here) and charges one more scope step. Go
                // answers, rounds, and warm-open work remain unchanged.
                // #5618 uses the stored digest/ID while decoding lookup recipes,
                // removing four cold identity seeks and rows from each point kind here.
                // Cache only the committed IDs in the existing bounded store cache;
                // the first warm search must not inherit the four skipped cold reads.
                // Master's measured warm/repeated pins stay 157/109 for Definition and 175/105
                // for Type. Schema-186 cold Type search measured 218/166.
                // Source-provenance discovery checks transient/overlay inputs once
                // per batch: one scalar statement and row. The shared anchor proof
                // skips impossible source reads and hydration without interning a
                // package domain. Relative to the master pins, both query kinds lose
                // 6 statements/9 rows in cold and warm search, and 3 scope steps.
                // Rounds, target bindings and open work stay unchanged. Each cold
                // tuple and both warm tuples were independently measured. The merged
                // #5618 reader removes four more cold statements/rows from the prior
                // D measurement; warm work, targets and closure rounds do not change.
                // The Go component-projection universe adds the `untyped string`
                // intrinsic entry, so a Type point operation interns one more shared
                // universe identity: +1 indexed statement and no row in cold and warm
                // Type searches. Definition, rows, targets and closure rounds are
                // unchanged.
                // Shared transient placement DDL adds six cold-open statements and three schema rows.
                // #5771 routes endpoint member-owner classification through the operation
                // session: both query kinds lose six search statements and charge three
                // more scope steps.
                // #6020: shared Go publication registration reads exporting-source
                // roles, adding six search statements and two decoded rows per point.
                let (cold_open, cold_search, warm_open, warm_search) = match kind {
                    ProductionGoPointKind::Definition => {
                        ((268, 237), (194, 163), (5, 4), (151, 102))
                    }
                    ProductionGoPointKind::Type => ((268, 237), (213, 159), (5, 4), (170, 98)),
                };
                let production_schema = cold
                    .open
                    .statements
                    .iter()
                    .filter(|sql| {
                        sql.trim_start().starts_with("CREATE")
                            && sql.contains("selected_resolution_stage_type_productions")
                    })
                    .collect::<Vec<_>>();
                assert_eq!(production_schema.len(), 3, "{production_schema:?}");
                for measurement in [&cold, &first_warm, &second_warm] {
                    let production_reads = measurement
                        .search
                        .statements
                        .iter()
                        .zip(&measurement.search.rows_by_statement)
                        .filter(|(sql, _)| sql.contains("type_productions"))
                        .collect::<Vec<_>>();
                    assert_eq!(production_reads.len(), 2, "{production_reads:?}");
                    assert!(
                        production_reads.iter().all(|(_, rows)| **rows == 0),
                        "{production_reads:?}"
                    );
                    assert_eq!(measurement.work.setup_nodes, 0);
                    assert_eq!(measurement.work.resolution_rounds, 7);
                    assert_eq!(measurement.work.summary_expansions, 0);
                    assert_eq!(measurement.work.scope_nodes, expected_scope_nodes);
                }
                assert_eq!(
                    (
                        cold.open.statement_count(),
                        cold.open.decoded_rows,
                        cold.search.statement_count(),
                        cold.search.decoded_rows,
                    ),
                    (cold_open.0, cold_open.1, cold_search.0, cold_search.1),
                    "cold Go point SQL work is pinned"
                );
                for measurement in [&first_warm, &second_warm] {
                    assert_eq!(
                        (
                            measurement.open.statement_count(),
                            measurement.open.decoded_rows,
                            measurement.search.statement_count(),
                            measurement.search.decoded_rows,
                        ),
                        (warm_open.0, warm_open.1, warm_search.0, warm_search.1),
                        "warm Go point SQL work is pinned"
                    );
                }
                assert_eq!(cold.work, first_warm.work);
                assert_eq!(first_warm.work, second_warm.work);
                assert_eq!(
                    (
                        cold.open.statement_count(),
                        cold.open.decoded_rows,
                        cold.search.statement_count(),
                        cold.search.decoded_rows,
                    ),
                    (cold_open.0, cold_open.1, cold_search.0, cold_search.1),
                    "cold Go point SQL work is pinned"
                );
                assert!(
                    first_warm.open.statement_count() < cold.open.statement_count(),
                    "warm Go point opening must reuse selected read work"
                );
                assert!(
                    first_warm.search.statement_count() < cold.search.statement_count(),
                    "warm Go point search must reuse selected read work"
                );
                for measurement in [&first_warm, &second_warm] {
                    assert_eq!(
                        (
                            measurement.open.statement_count(),
                            measurement.open.decoded_rows,
                            measurement.search.statement_count(),
                            measurement.search.decoded_rows,
                        ),
                        (warm_open.0, warm_open.1, warm_search.0, warm_search.1),
                        "warm Go point SQL work is pinned"
                    );
                }
                assert_eq!(
                    (
                        first_warm.open.statement_count(),
                        first_warm.open.decoded_rows,
                        first_warm.search.statement_count(),
                        first_warm.search.decoded_rows,
                    ),
                    (
                        second_warm.open.statement_count(),
                        second_warm.open.decoded_rows,
                        second_warm.search.statement_count(),
                        second_warm.search.decoded_rows,
                    ),
                    "repeated warm Go point SQL work is identical"
                );
                eprintln!(
                    "production Go point {kind:?}: cold=({},{},{},{}, {:?}), warm=({},{},{},{}, {:?}), repeat=({},{},{},{}, {:?})",
                    cold.open.statement_count(),
                    cold.open.decoded_rows,
                    cold.search.statement_count(),
                    cold.search.decoded_rows,
                    cold.work,
                    first_warm.open.statement_count(),
                    first_warm.open.decoded_rows,
                    first_warm.search.statement_count(),
                    first_warm.search.decoded_rows,
                    first_warm.work,
                    second_warm.open.statement_count(),
                    second_warm.open.decoded_rows,
                    second_warm.search.statement_count(),
                    second_warm.search.decoded_rows,
                    second_warm.work,
                );
                assert_eq!(first_warm.work, second_warm.work);
                assert_eq!(
                    (
                        first_warm.open.statement_count(),
                        first_warm.open.decoded_rows,
                        first_warm.search.statement_count(),
                        first_warm.search.decoded_rows,
                    ),
                    (
                        second_warm.open.statement_count(),
                        second_warm.open.decoded_rows,
                        second_warm.search.statement_count(),
                        second_warm.search.decoded_rows,
                    ),
                    "repeated Go point SQL work must be identical"
                );
            }
        }
        #[test]
        fn real_go_bundle_reopens_without_java_placement_and_matches_preload() {
            let fixture = GoResolutionOperationFixture::new();
            let facts = &fixture.facts;
            let point_site = site_for_identifier(
                facts,
                "Item",
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Type,
            );
            let definition_site = site_for_identifier(
                facts,
                "Item",
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Type,
            );
            let call_site = site_for_identifier(
                facts,
                "Echo",
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::TypeOrValue,
            );
            let applicability_gaps = facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedCallApplicability)
                .collect::<Vec<_>>();
            assert_eq!(applicability_gaps.len(), 1);
            assert_eq!(applicability_gaps[0].site, call_site);
            let placement_gaps = facts
                .gaps
                .iter()
                .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedPlacementBoundary)
                .collect::<Vec<_>>();
            assert_eq!(placement_gaps.len(), 1);
            assert_eq!(
                facts.sites[placement_gaps[0].site.index()].scope,
                ResolutionScopeId::new(0),
                "placement uncertainty is owned by the compilation-unit boundary"
            );
            assert_eq!(facts.gaps.len(), 2);
            assert!(facts.reference_enumeration_gaps.is_empty());
            assert!(facts.import_routes.is_empty());

            let cancellation = CancellationToken::default();
            let mounted = fixture.open_ready(&cancellation);
            assert_eq!(mounted.mounts().unwrap().len(), 1);
            let mount = &mounted.mounts().unwrap()[0];
            assert_eq!(mount.storage_language(), "go");
            assert_eq!(mount.persisted_relative_path(), GO_SOURCE_PATH);
            assert_eq!(mount.semantic_language(), Language::Go);
            assert!(
                mounted
                    .ready
                    .inventory
                    .mount_record_by_ordinal(mount.ordinal())
                    .unwrap()
                    .file_version_id()
                    .is_some()
            );
            let fragment = mount.fragment();

            let lowered =
                brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                    fragment,
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                    Language::Go,
                    facts,
                );
            brokk_bifrost_analysis::analyzer::resolution::fact_lowering::fixture_names::record_selected(
                lowered.identities(),
                mounted
                    .ready
                    .inventory
                    .mount_record_by_ordinal(mount.ordinal())
                    .unwrap()
                    .fragment_digest()
                    .as_bytes(),
            );
            drop(mounted);
            assert!(!lowered.typed().frontiers().is_empty());
            let point_reference = semantic_at(&lowered, point_site, LoweredSemanticRole::Reference);
            let reverse_definition =
                semantic_at(&lowered, definition_site, LoweredSemanticRole::Definition);
            let call_reference = semantic_at(&lowered, call_site, LoweredSemanticRole::Reference);
            let go_lookup_spellings = facts
                .identifiers
                .iter()
                .filter(|identifier| identifier.role == ResolutionIdentifierRole::Reference)
                .map(|identifier| {
                    (
                        semantic_at(&lowered, identifier.site, LoweredSemanticRole::Reference),
                        facts.names[identifier.name.index()].spelling.clone(),
                    )
                })
                .collect::<Vec<_>>();
            let preload = PreloadedFactResolutionService::from_lowered_fragments(
                [lowered.lexical().clone()],
                [lowered.typed().clone()],
            )
            .with_go_lookup_spellings(go_lookup_spellings);

            let expected_point = preload
                .resolve_reference(point_reference, &cancellation)
                .expect("preloaded Go point resolution");
            assert!(
                expected_point
                    .binding()
                    .targets()
                    .contains(&reverse_definition)
            );
            assert!(
                !expected_point.projected_frontiers().is_empty(),
                "the point fixture must exercise typed projection hydration"
            );
            let point_site_range = facts
                .sites
                .iter()
                .find(|site| site.id == point_site)
                .expect("Go point site range");
            let point_locator = SelectedSemanticLocator::for_reference_range(
                "go",
                GO_SOURCE_PATH,
                point_site_range.start_byte,
                point_site_range.end_byte,
            );
            let point_operation = fixture.open_ready(&cancellation);
            let point_context = point_operation
                .empty_contexts(&ResolutionCompletion::Complete)
                .unwrap();
            let mut point_context_metrics = SelectedResolutionContextMetrics;
            let point = point_operation
                .resolve_reference(
                    point_context,
                    &point_locator,
                    &cancellation,
                    &mut point_context_metrics,
                )
                .expect("persisted Go point resolution");
            assert_empty_context_metrics(&point_context_metrics);
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(point)) =
                point
            else {
                panic!("persisted Go point operation must return a native found answer")
            };
            assert_eq!(point, expected_point);

            let expected_reverse = preload
                .references_to(reverse_definition, &cancellation)
                .expect("preloaded Go reverse resolution");
            let definition_locator = SelectedSemanticLocator::new(
                "go",
                GO_SOURCE_PATH,
                definition_site,
                LoweredSemanticRole::Definition,
            );
            let reverse_operation = fixture.open_ready(&cancellation);
            let reverse_context = reverse_operation
                .empty_contexts(&ResolutionCompletion::Complete)
                .unwrap();
            let mut reverse_context_metrics = SelectedResolutionContextMetrics;
            let mut reverse_metrics = FactReverseResolutionMetrics::default();
            let reverse = reverse_operation
                .references_to_selected_definition(
                    reverse_context,
                    2,
                    &definition_locator,
                    &cancellation,
                    &mut reverse_context_metrics,
                    &mut reverse_metrics,
                )
                .expect("persisted Go reverse resolution");
            assert_empty_context_metrics(&reverse_context_metrics);
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                reverse,
            )) = reverse
            else {
                panic!("persisted Go reverse operation must return a native found answer")
            };
            assert_eq!(reverse.answer(), &expected_reverse);
            assert!(reverse.references().contains(&point_reference));
            assert!(reverse_metrics.demanded_definition_count() > 0);
            assert!(reverse_metrics.published_reference_count() > 0);

            let expected_call_point = preload
                .resolve_reference(call_reference, &cancellation)
                .expect("preloaded Go call resolution");
            assert_eq!(
                expected_call_point.completion(),
                &ResolutionCompletion::Complete,
                "a unique Go function name and its selected result type resolve without argument filtering"
            );
            let call_locator = SelectedSemanticLocator::new(
                "go",
                GO_SOURCE_PATH,
                call_site,
                LoweredSemanticRole::Reference,
            );
            let call_operation = fixture.open_ready(&cancellation);
            let call_context = call_operation
                .empty_contexts(&ResolutionCompletion::Complete)
                .unwrap();
            let mut call_context_metrics = SelectedResolutionContextMetrics;
            let call = call_operation
                .resolve_reference(
                    call_context,
                    &call_locator,
                    &cancellation,
                    &mut call_context_metrics,
                )
                .expect("persisted Go call resolution");
            assert_empty_context_metrics(&call_context_metrics);
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(call)) =
                call
            else {
                panic!("persisted Go call operation must return a native found answer")
            };
            assert_eq!(call, expected_call_point);
        }
        #[test]
        fn selected_go_root_context_matches_preload_and_excludes_wrong_route() {
            let fixture = GoRootResolutionOperationFixture::new();
            let cancellation = CancellationToken::default();
            let mounted = fixture.open_ready(&cancellation);
            assert_eq!(mounted.mounts().unwrap().len(), 3);
            let mounts = mounted.mounts().unwrap().to_vec();
            let preload_context = fixture.contexts_for(&mounted);

            let artifact_for = |path: &str, facts: &FileResolutionFacts| {
                let mount = mounts
                    .iter()
                    .find(|mount| mount.persisted_relative_path() == path)
                    .unwrap_or_else(|| panic!("missing selected Go mount {path:?}"));
                let artifact = brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                    mount.fragment(),
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                    Language::Go,
                    facts,
                );
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::fixture_names::record_selected(
                    artifact.identities(),
                    mounted
                        .ready
                        .inventory
                        .mount_record_by_ordinal(mount.ordinal())
                        .unwrap()
                        .fragment_digest()
                        .as_bytes(),
                );
                artifact
            };
            let consumer = artifact_for(GO_ROOT_CONSUMER_PATH, &fixture.consumer_facts);
            let provider = artifact_for(GO_ROOT_PROVIDER_PATH, &fixture.provider_facts);
            let decoy = artifact_for(GO_ROOT_DECOY_PATH, &fixture.decoy_facts);
            let reference_site = site_for_identifier(
                &fixture.consumer_facts,
                "Item",
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Type,
            );
            let provider_site = site_for_identifier(
                &fixture.provider_facts,
                "Item",
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Type,
            );
            let decoy_site = site_for_identifier(
                &fixture.decoy_facts,
                "Item",
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Type,
            );
            let reference = semantic_at(&consumer, reference_site, LoweredSemanticRole::Reference);
            let provider_definition =
                semantic_at(&provider, provider_site, LoweredSemanticRole::Definition);
            let decoy_definition = semantic_at(&decoy, decoy_site, LoweredSemanticRole::Definition);

            let preload = PreloadedFactResolutionService::from_lowered_fragments(
                [
                    consumer.lexical().clone(),
                    provider.lexical().clone(),
                    decoy.lexical().clone(),
                ],
                [
                    consumer.typed().clone(),
                    provider.typed().clone(),
                    decoy.typed().clone(),
                ],
            );
            let SelectedResolutionContextValidationOutcome::Ready(preload_context) =
                preload_context
                    .validate_exact_mounts(mounts.len(), &mount_lookup(&mounts), &cancellation)
                    .expect("validate preloaded Go root context")
            else {
                panic!("uncancelled preloaded Go root context must validate")
            };
            let preload_blueprint =
                brokk_bifrost_analysis::analyzer::resolution::fact_resolution::SelectedContextTestOracle::collect_context(
                    preload_context,
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                    &cancellation,
                )
                .expect("compile independent preloaded Go root context oracle");
            drop(mounted);
            let expected_point = preload_blueprint
                .resolve_reference(&preload, &preload, reference, &cancellation)
                .expect("preloaded cross-package Go point resolution");
            assert!(
                expected_point
                    .binding()
                    .targets()
                    .contains(&provider_definition)
            );
            assert!(
                !expected_point
                    .binding()
                    .targets()
                    .contains(&decoy_definition)
            );
            assert_eq!(
                expected_point.completion(),
                &ResolutionCompletion::Complete,
                "the structured dot-import route and export demand are complete"
            );

            let point_locator = SelectedSemanticLocator::new(
                "go",
                GO_ROOT_CONSUMER_PATH,
                reference_site,
                LoweredSemanticRole::Reference,
            );
            let point_operation = fixture.open_ready(&cancellation);
            let point_context = fixture.contexts_for(&point_operation);
            let mut point_metrics = SelectedResolutionContextMetrics;
            let point = point_operation
                .resolve_reference(
                    point_context,
                    &point_locator,
                    &cancellation,
                    &mut point_metrics,
                )
                .expect("persisted cross-package Go point resolution");
            assert_empty_context_metrics(&point_metrics);
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(point)) =
                point
            else {
                panic!("persisted cross-package Go point must return a native found answer")
            };
            assert_eq!(point, expected_point);

            let expected_reverse = preload_blueprint
                .references_to(
                    &preload,
                    &preload,
                    2,
                    provider_definition,
                    &cancellation,
                    &mut FactReverseResolutionMetrics::default(),
                )
                .expect("preloaded cross-package Go reverse resolution");
            assert!(expected_reverse.references().contains(&reference));
            // Reverse inventory still carries independent unsupported-semantic reasons.
            assert!(matches!(
                expected_reverse.completion(),
                ResolutionCompletion::Incomplete(_)
            ));
            let definition_locator = SelectedSemanticLocator::new(
                "go",
                GO_ROOT_PROVIDER_PATH,
                provider_site,
                LoweredSemanticRole::Definition,
            );
            let reverse_operation = fixture.open_ready(&cancellation);
            let reverse_context = fixture.contexts_for(&reverse_operation);
            let mut context_metrics = SelectedResolutionContextMetrics;
            let mut reverse_metrics = FactReverseResolutionMetrics::default();
            let reverse = reverse_operation
                .references_to_selected_definition(
                    reverse_context,
                    2,
                    &definition_locator,
                    &cancellation,
                    &mut context_metrics,
                    &mut reverse_metrics,
                )
                .expect("persisted cross-package Go reverse resolution");
            assert_empty_context_metrics(&context_metrics);
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                reverse,
            )) = reverse
            else {
                panic!("persisted cross-package Go reverse must return a native found answer")
            };
            assert_eq!(reverse.answer(), &expected_reverse);
            assert!(reverse.references().contains(&reference));
        }
        #[test]
        fn selected_go_package_rows_compose_dot_import_without_manual_bridges() {
            let fixture = GoRootResolutionOperationFixture::new();
            let context_id =
                publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            let cancellation = CancellationToken::new();
            // The same demand query must seek persisted membership both before and
            // after statistics, using the operation's real selected mount table.
            for statistics in [false, true] {
                if statistics {
                    fixture.store.refresh_planner_statistics().unwrap();
                } else {
                    fixture.store.clear_planner_statistics().unwrap();
                }
                let operation = fixture.open_ready(&cancellation);
                let mount = operation
                    .mount_table()
                    .mount_for_path("go", GO_ROOT_CONSUMER_PATH)
                    .unwrap()
                    .unwrap();
                let file_version = operation
                    .ready
                    .inventory
                    .mount_record_by_ordinal(mount.ordinal())
                    .unwrap()
                    .file_version_id()
                    .unwrap();
                let mut pin = brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned(
                    "go_dot_import_target_mounts",
                );
                pin.params = vec![
                    rusqlite::types::Value::Integer(context_id),
                    rusqlite::types::Value::Integer(file_version),
                    rusqlite::types::Value::Text("go".to_owned()),
                    rusqlite::types::Value::Text("example.test/root/provider".to_owned()),
                ];
                let plan = brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin(
                    operation.ready.inventory.connection(),
                    &pin,
                );
                assert!(
                    !plan.iter().any(|line| line.contains("SCAN imports")
                        || line.contains("SCAN mounted")
                        || line.contains("AUTOMATIC")
                        || line.contains("TEMP B-TREE")),
                    "statistics={statistics}: {plan:?}"
                );
            }
            let operation = fixture.open_ready(&cancellation);
            let expected = fixture.contexts_for(&operation);
            let go_context::GoDotImportContext::Ready {
                context: derived, ..
            } = operation
                .go_dot_import_context(context_id, GO_ROOT_CONSUMER_PATH, "go", &cancellation)
                .unwrap()
            else {
                panic!("selected package rows must supply dot-import context")
            };
            let reference_site = site_for_identifier(
                &fixture.consumer_facts,
                "Item",
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Type,
            );
            let locator = SelectedSemanticLocator::new(
                "go",
                GO_ROOT_CONSUMER_PATH,
                reference_site,
                LoweredSemanticRole::Reference,
            );
            let actual = operation
                .resolve_reference(
                    derived,
                    &locator,
                    &cancellation,
                    &mut SelectedResolutionContextMetrics,
                )
                .unwrap();
            let baseline = fixture
                .open_ready(&cancellation)
                .resolve_reference(
                    expected,
                    &locator,
                    &cancellation,
                    &mut SelectedResolutionContextMetrics,
                )
                .unwrap();
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                actual,
            )) = actual
            else {
                panic!("native derived result")
            };
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                baseline,
            )) = baseline
            else {
                panic!("native known-map result")
            };
            assert_eq!(actual.binding().targets(), baseline.binding().targets());
            assert!(!actual.binding().targets().is_empty());
            assert!(matches!(
                actual.completion(),
                ResolutionCompletion::Incomplete(_)
            ));
            let operation = fixture.open_ready(&cancellation);
            let go_context::GoDotImportContext::Ready {
                context: derived, ..
            } = operation
                .go_dot_import_context(context_id, GO_ROOT_CONSUMER_PATH, "go", &cancellation)
                .unwrap()
            else {
                panic!("context remains published")
            };
            fixture.store.conn.execute(move |conn| {
                conn.execute(
                    "DELETE FROM go_context_heads WHERE context_id=?1",
                    [context_id],
                )
                .unwrap();
            });
            assert!(matches!(
                operation
                    .resolve_reference(
                        derived,
                        &locator,
                        &cancellation,
                        &mut SelectedResolutionContextMetrics
                    )
                    .unwrap(),
                SelectedResolutionOperationOutcome::Stale(
                    SelectedResolutionStale::NativeContextPublication { .. }
                )
            ));
        }
        #[test]
        fn selected_native_context_requires_matching_configuration_overlay() {
            let mut fixture = GoRootResolutionOperationFixture::new();
            let snapshot = fixture.snapshots["go"].clone();
            let source_rows = [
                (GO_ROOT_CONSUMER_PATH, GO_ROOT_CONSUMER_SOURCE),
                (GO_ROOT_PROVIDER_PATH, GO_ROOT_PROVIDER_SOURCE),
                (GO_ROOT_DECOY_PATH, GO_ROOT_DECOY_SOURCE),
            ]
            .map(|(path, source)| WorkspaceFileRow {
                rel_path: path.into(),
                blob_oid: Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap(),
            });
            let manifest = b"module example.test/root\n";
            let selected = fixture
                .store
                .sync_workspace_inputs_for_workspace(
                    &fixture.workspace_id,
                    "go",
                    snapshot.generation,
                    &source_rows,
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[WorkspaceConfigurationInput::new(
                        "go.mod".into(),
                        manifest.as_slice().into(),
                    )],
                    &[],
                )
                .unwrap();
            fixture.snapshots.insert("go".into(), selected);
            let cancellation = CancellationToken::new();
            let manifest_file = ProjectFile::new(fixture.project.root(), "go.mod");
            fixture.project.set_overlay_content(
                manifest_file.clone(),
                std::str::from_utf8(manifest).unwrap(),
            );
            drop(fixture.open_ready(&cancellation));

            fixture
                .project
                .set_overlay_content(manifest_file, "module example.test/changed\n");
            let input = SelectedResolutionOperationInput::new(
                &fixture.project,
                &fixture.workspace_id,
                &fixture.snapshots,
                &fixture.languages,
                &fixture.overlay_masks,
            );
            assert!(matches!(
                fixture.store.open_selected_resolution_operation(input, &cancellation).unwrap(),
                SelectedResolutionOperationOpenOutcome::Unavailable(
                    SelectedResolutionUnavailable::MissingTransientOverlayInput {
                        storage_language, persisted_relative_path,
                    }
                ) if storage_language == "go" && persisted_relative_path == "go.mod"
            ));
            fixture.project.set_overlay_content(
                ProjectFile::new(fixture.project.root(), "notes.txt"),
                "unrelated overlay",
            );
            drop(fixture.open_ready(&cancellation));
        }
        #[test]
        fn selected_go_root_context_missing_anchor_identity_fails_closed() {
            let fixture = GoRootResolutionOperationFixture::new();
            let cancellation = CancellationToken::default();
            let operation = fixture.open_ready(&cancellation);
            let reference_site = site_for_identifier(
                &fixture.consumer_facts,
                "Item",
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Type,
            );
            let locator = SelectedSemanticLocator::new(
                "go",
                GO_ROOT_CONSUMER_PATH,
                reference_site,
                LoweredSemanticRole::Reference,
            );
            let valid = fixture.root_bridge(&operation);
            let invalid = SelectedRootBridgeDescriptor::from_selected_path_tokens(
                valid.source_fragment(),
                valid.source_language(),
                valid.source_import_token(),
                ResolutionRootImportAnchor::Absolute,
                brokk_bifrost_analysis::analyzer::resolution::model::SemanticId::for_test(
                    b"missing-go-root-anchor",
                ),
                valid.target_fragment(),
                valid.target_language(),
                valid.target_export_token(),
                valid.route().to_vec(),
                valid.source_demand().clone(),
                valid.target_demand().clone(),
                valid.completion().clone(),
            );
            let context = fixture.contexts_with_bridge(&operation, invalid);
            let error = match operation.resolve_reference(
                context,
                &locator,
                &cancellation,
                &mut SelectedResolutionContextMetrics,
            ) {
                Ok(_) => panic!("a missing selected context anchor must fail closed"),
                Err(error) => error,
            };
            // The anchor's runtime id is the position it occupies in its blob's
            // catalog, so the catalog read that answers for it is what fails closed
            // now, before the provenance decode that used to report this.
            assert!(
                error.to_string().contains("is not in its blob's catalog"),
                "unexpected missing-anchor error: {error}"
            );
        }
        #[test]
        fn selected_operation_rejects_inexact_context_before_source_work_and_retries() {
            let fixture = GoResolutionOperationFixture::new();
            let cancellation = CancellationToken::default();
            let facts = &fixture.facts;
            let point_site = site_for_identifier(
                facts,
                "Item",
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Type,
            );
            let point_locator = SelectedSemanticLocator::new(
                "go",
                GO_SOURCE_PATH,
                point_site,
                LoweredSemanticRole::Reference,
            );

            let operation = fixture.open_ready(&cancellation);
            let missing = SelectedResolutionContextSet::new(
                SelectedContextIdentities::new(),
                Vec::<SelectedResolutionMountContext>::new(),
                0,
                &|_| Ok(None),
            )
            .expect("empty context set is locally well-formed");
            let mut metrics = SelectedResolutionContextMetrics;
            reset_selected_fact_operation_construction_count_for_test();
            reset_selected_resolution_boundary_snapshot_for_test();
            assert_store_error_contains(
                operation.resolve_reference(missing, &point_locator, &cancellation, &mut metrics),
                "omits operation mounts",
            );
            assert_eq!(metrics, Default::default());
            assert_eq!(selected_fact_operation_construction_count_for_test(), 0);
            assert!(selected_resolution_boundary_snapshot_for_test().is_none());

            let retry = fixture.open_ready(&cancellation);
            let context = retry
                .empty_contexts(&ResolutionCompletion::Complete)
                .unwrap();
            let mut metrics = SelectedResolutionContextMetrics;
            let retry = retry
                .resolve_reference(context, &point_locator, &cancellation, &mut metrics)
                .expect("exact selected context retry");
            assert_empty_context_metrics(&metrics);
            assert!(matches!(
                retry,
                SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(_))
            ));
        }
        #[test]
        #[hardwon("#5076: cached presumed fmt imports lost their request-owned shared-name digest")]
        fn selected_go_cached_presumed_import_reinterns_shared_lookup_in_second_request() {
            use brokk_bifrost_analysis::analyzer::resolution::local_identity::SharedNameInterner;

            let fixture = GoRootResolutionOperationFixture::with_consumer(
                "package consumer; import \"fmt\"; func Use() { fmt.Println(1) }",
            );
            // No authoritative fmt provider: the source-only context admits a presumed
            // binder whose Package lookup is absent from the persisted name table.
            let context_id =
                publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            let cancellation = CancellationToken::new();
            let prefix = fixture
                .consumer_facts
                .root_references
                .iter()
                .find_map(|reference| reference.prefix_reference)
                .expect("structured fmt package qualifier");
            let mut first_targets = None;
            for restored in [false, true] {
                let operation = fixture.open_ready(&cancellation);
                let unrelated = restored.then(|| operation.ready.shared_names().intern([7; 32]));
                let GoPreparedImportContextOutcome::Ready(prepared) = operation
                    .go_file_import_context_with_role(
                        context_id,
                        GO_ROOT_CONSUMER_PATH,
                        "go",
                        &cancellation,
                    )
                    .unwrap()
                else {
                    panic!("selected fmt import context must be available");
                };
                assert_eq!(
                    operation.go_import_inputs.borrow().is_empty(),
                    restored,
                    "the second request must restore the cached context without loading import inputs"
                );
                if let Some(unrelated) = unrelated {
                    assert_eq!(
                        operation.ready.shared_names().digest_for_id(unrelated),
                        Some([7; 32]),
                        "restoring fmt must preserve names already minted by the new request"
                    );
                }
                let outcome = operation
                    .resolve_reference(
                        prepared.context,
                        &SelectedSemanticLocator::new(
                            "go",
                            GO_ROOT_CONSUMER_PATH,
                            prefix,
                            LoweredSemanticRole::Reference,
                        ),
                        &cancellation,
                        &mut SelectedResolutionContextMetrics,
                    )
                    .unwrap();
                let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                    answer,
                )) = outcome
                else {
                    panic!("the cached fmt qualifier must remain located");
                };
                assert!(!answer.binding().targets().is_empty(), "{answer:?}");
                if let Some(targets) = &first_targets {
                    assert_eq!(answer.binding().targets(), targets);
                } else {
                    first_targets = Some(answer.binding().targets().to_vec());
                }
            }
        }
        #[test]
        fn selected_go_import_names_bind_actual_file_definitions_without_basename_guessing() {
            for staged in [false, true] {
                for (source_text, bound) in [
                    (
                        "package consumer; import \"example.test/root/strange\"; var Item provider.Item",
                        true,
                    ),
                    (
                        "package consumer; import renamed \"example.test/root/strange\"; var Item renamed.Item",
                        true,
                    ),
                    (
                        "package consumer; import _ \"example.test/root/strange\"; var Item provider.Item",
                        false,
                    ),
                ] {
                    let fixture = GoRootResolutionOperationFixture::with_consumer(source_text);
                    let context_id =
                        publish_go_root_fixture_context(&fixture, "example.test/root/strange");
                    let cancellation = CancellationToken::new();
                    let operation = fixture.open_ready(&cancellation);
                    let source = operation
                        .mount_table()
                        .mount_for_path("go", GO_ROOT_CONSUMER_PATH)
                        .unwrap()
                        .unwrap();
                    let lowered = brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                        source.fragment(),
                        &operation.ready.shared_names(),
                        Language::Go,
                        &fixture.consumer_facts,
                    );
                    let definition = lowered.common().go_package_imports[0].definition;
                    if staged {
                        stage_go_import_rows(
                            &operation,
                            source.ordinal(),
                            &lowered.common().go_package_imports,
                        );
                    }

                    let prefix = fixture
                        .consumer_facts
                        .root_references
                        .iter()
                        .find_map(|reference| reference.prefix_reference)
                        .expect("positioned package qualifier");
                    let GoPreparedImportContextOutcome::Ready(prepared) = operation
                        .go_import_binding_context(
                            context_id,
                            GO_ROOT_CONSUMER_PATH,
                            "go",
                            &cancellation,
                        )
                        .unwrap()
                    else {
                        panic!("selected source imports and canonical package names must compose");
                    };
                    let context = prepared.context;
                    let answer = operation
                        .resolve_reference(
                            context,
                            &SelectedSemanticLocator::new(
                                "go",
                                GO_ROOT_CONSUMER_PATH,
                                prefix,
                                LoweredSemanticRole::Reference,
                            ),
                            &cancellation,
                            &mut SelectedResolutionContextMetrics,
                        )
                        .unwrap();
                    let SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Found(answer),
                    ) = answer
                    else {
                        panic!("source package qualifier must remain located");
                    };
                    assert_eq!(
                        answer.binding().targets().contains(&definition),
                        bound,
                        "{source_text}: {answer:?}"
                    );
                }
            }
        }
        #[test]
        fn selected_go_context_rejects_an_obsolete_package_derivation() {
            let fixture = GoRootResolutionOperationFixture::new();
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            fixture.store.conn.execute(move |connection| {
        connection.execute("UPDATE go_context_selections SET derivation_version=derivation_version-1 WHERE selection_id=(SELECT selection_id FROM go_context_publications WHERE context_id=?1)", [context]).unwrap();
    });
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            assert!(matches!(
                operation
                    .go_dot_import_context(context, GO_ROOT_CONSUMER_PATH, "go", &cancellation)
                    .unwrap(),
                go_context::GoDotImportContext::Unavailable
            ));
        }
        #[test]
        fn selected_go_qualified_imports_follow_bound_definitions_and_respect_local_shadowing() {
            for (source_text, bound) in [
                (
                    "package consumer; import \"example.test/root/strange\"; var Use provider.Item",
                    true,
                ),
                (
                    "package consumer; import renamed \"example.test/root/strange\"; var Use renamed.Item",
                    true,
                ),
                (
                    "package consumer; import _ \"example.test/root/strange\"; var Use provider.Item",
                    false,
                ),
                (
                    "package consumer; import renamed \"example.test/root/strange\"; var Use provider.Item",
                    false,
                ),
                (
                    "package consumer; import \"example.test/root/strange\"; func f() { type provider struct{}; var Use provider.Item; _ = Use }",
                    false,
                ),
            ] {
                let fixture = GoRootResolutionOperationFixture::with_consumer(source_text);
                let context_id =
                    publish_go_root_fixture_context(&fixture, "example.test/root/strange");
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                let provider = operation
                    .mount_table()
                    .mount_for_path("go", GO_ROOT_PROVIDER_PATH)
                    .unwrap()
                    .unwrap();
                let artifact = brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                    provider.fragment(),
                    &operation.ready.shared_names(),
                    Language::Go,
                    &fixture.provider_facts,
                );
                let expected = semantic_at(
                    &artifact,
                    site_for_identifier(
                        &fixture.provider_facts,
                        "Item",
                        ResolutionIdentifierRole::Declaration,
                        ResolutionNamespace::Type,
                    ),
                    LoweredSemanticRole::Definition,
                );
                let reference = site_for_identifier(
                    &fixture.consumer_facts,
                    "Item",
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                );
                let go_context::GoDotImportContext::Ready { context, .. } = operation
                    .go_eager_import_binding_context(
                        context_id,
                        GO_ROOT_CONSUMER_PATH,
                        "go",
                        &cancellation,
                    )
                    .unwrap()
                else {
                    panic!("selected named import context");
                };
                let answer = operation
                    .resolve_reference(
                        context,
                        &SelectedSemanticLocator::new(
                            "go",
                            GO_ROOT_CONSUMER_PATH,
                            reference,
                            LoweredSemanticRole::Reference,
                        ),
                        &cancellation,
                        &mut SelectedResolutionContextMetrics,
                    )
                    .unwrap();
                let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                    answer,
                )) = answer
                else {
                    panic!("selected qualified reference");
                };
                if bound {
                    assert_eq!(
                        answer.binding().targets(),
                        &[expected],
                        "{source_text}: {answer:?}"
                    );
                } else {
                    assert!(
                        !answer.binding().targets().contains(&expected),
                        "{source_text}: {answer:?}"
                    );
                }
            }
        }
        #[test]
        fn selected_go_dot_import_excludes_a_test_variant_of_the_same_file() {
            let fixture = GoRootResolutionOperationFixture::new();
            let context_id =
                publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            fixture.store.conn.execute(move |connection| {
        let transaction = connection.transaction().unwrap();
        let unit_key = go_unit_key(
            "example.test/root/consumer [example.test/root/consumer.test]",
            "example.test/root/consumer",
            "test",
        );
        transaction.execute("INSERT INTO go_package_instances(context_id,tool_import_path,package_name,for_test,provider_directory,provider_digest,complete,gaps,unit_key)
            VALUES(?1,'example.test/root/consumer [example.test/root/consumer.test]','consumer','example.test/root/consumer','',zeroblob(32),0,jsonb('[]'),?2)", rusqlite::params![context_id, unit_key.as_slice()]).unwrap();
        let variant = transaction.last_insert_rowid();
        transaction.execute("INSERT INTO go_package_files(package_id,file_version_id,source_role)
            SELECT ?2,files.file_version_id,'go' FROM go_context_source_files files
            JOIN go_package_instances package ON package.package_id=files.package_id
            WHERE files.context_id=?1 AND package.tool_import_path='example.test/root/consumer'", rusqlite::params![context_id,variant]).unwrap();
        transaction.execute("INSERT INTO go_package_imports(context_id,importer_package_id,source_spelling,import_role,target_package_id,complete,gaps)
            SELECT ?1,?2,'example.test/root/provider','go',package_id,0,jsonb('[]') FROM go_package_instances
            WHERE context_id=?1 AND tool_import_path='example.test/root/other/provider'", rusqlite::params![context_id,variant]).unwrap();
        transaction.commit().unwrap();
    });
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let go_context::GoDotImportContext::Ready { context, .. } = operation
                .go_dot_import_context(context_id, GO_ROOT_CONSUMER_PATH, "go", &cancellation)
                .unwrap()
            else {
                panic!("selected ordinary package context");
            };
            let reference = site_for_identifier(
                &fixture.consumer_facts,
                "Item",
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Type,
            );
            let answer = operation
                .resolve_reference(
                    context,
                    &SelectedSemanticLocator::new(
                        "go",
                        GO_ROOT_CONSUMER_PATH,
                        reference,
                        LoweredSemanticRole::Reference,
                    ),
                    &cancellation,
                    &mut SelectedResolutionContextMetrics,
                )
                .unwrap();
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                answer,
            )) = answer
            else {
                panic!("selected dot-import reference");
            };
            assert_eq!(
                answer.binding().targets().len(),
                1,
                "test variant must not add the decoy: {answer:?}"
            );
        }
        #[test]
        fn go_reverse_inventory_completeness_requires_live_unit_summaries() {
            use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

            use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;
            use rusqlite::types::Value;

            fn inventory_complete(
                fixture: &GoRootResolutionOperationFixture,
                context_id: i64,
                file_version: i64,
                include_tests: bool,
            ) -> bool {
                let snapshot = fixture.snapshots["go"].clone();
                let workspace_id = snapshot.workspace_id.as_str().to_owned();
                let generation = snapshot.generation.get();
                let revision = snapshot.revision;
                fixture.store.conn.execute(move |connection| {
            brokk_bifrost_analysis::analyzer::store::go_unit_summaries::register_go_summary_sql_functions(connection).unwrap();
            let producer_epoch: String = connection
                .query_row(
                    "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang='go'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            connection
                .query_row(
                    brokk_bifrost_analysis::analyzer::store::resolution_operation::go_reverse_rows::GO_REVERSE_INVENTORY_COMPLETE_SQL,
                    rusqlite::params![
                        context_id,
                        file_version,
                        true,
                        include_tests,
                        "[[1,\"type\"]]",
                        workspace_id,
                        generation,
                        revision,
                        producer_epoch,
                        vec![0u8; 32],
                        brokk_bifrost_analysis::analyzer::store::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION,
                        "[]",
                    ],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap()
        })
            }

            let fixture = GoRootResolutionOperationFixture::with_consumer(
                "package consumer; import \"example.test/root/provider\"; var Use provider.Item",
            );
            let context_id =
                publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            let file_workspace_id = fixture.workspace_id.as_str().to_owned();
            let file_generation = fixture.snapshots["go"].generation.get();
            let file_version = fixture.store.conn.execute(move |connection| {
                connection
                    .query_row(
                        "SELECT file_version_id FROM workspace_file_versions
             WHERE workspace_id=?1 AND lang='go' AND generation=?2 AND rel_path=?3",
                        rusqlite::params![
                            file_workspace_id,
                            file_generation,
                            GO_ROOT_PROVIDER_PATH
                        ],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap()
            });
            assert!(
                !inventory_complete(&fixture, context_id, file_version, false),
                "a Go reverse inventory without live summaries must remain incomplete"
            );

            let mut pin = pinned("go_reverse_inventory_complete");
            pin.params = vec![
                Value::Integer(context_id),
                Value::Integer(file_version),
                Value::Integer(1),
                Value::Integer(0),
                Value::Text("[[1,\"type\"]]".into()),
                Value::Text(fixture.workspace_id.as_str().to_owned()),
                Value::Integer(fixture.snapshots["go"].generation.get()),
                Value::Integer(fixture.snapshots["go"].revision),
                Value::Text("go-epoch".into()),
                Value::Blob(vec![0; 32]),
                Value::Integer(brokk_bifrost_analysis::analyzer::store::go_unit_summaries::GO_UNIT_SUMMARY_DERIVATION_VERSION),
                Value::Text("[]".into()),
            ];
            fixture.store.conn.execute(move |connection| {
                brokk_bifrost_analysis::analyzer::store::go_unit_summaries::register_go_summary_sql_functions(
                    connection,
                )
                .unwrap();
                for statistics in brokk_bifrost_core::cache_gc::PlannerStatisticsState::BOTH {
                    statistics.install(connection);
                    let plan = explain_pin(connection, &pin);
                    assert!(
                        plan.iter()
                            .any(|detail| detail
                                .contains("resolution_unit_summary_dependencies_unit")),
                        "reverse package closure must seek summary dependents: {plan:?}"
                    );
                    assert!(
                        plan.iter()
                            .any(|detail| detail.contains("resolution_unit_summary_versions")),
                        "reverse package closure must seek live summary versions: {plan:?}"
                    );
                    assert!(
                        !plan
                            .iter()
                            .any(|detail| detail
                                .contains("SCAN resolution_unit_summary_dependencies")),
                        "reverse completeness must not scan summary dependency rows: {plan:?}"
                    );
                }
            });
        }
        #[test]
        fn selected_go_external_tests_can_name_exports_from_the_selected_internal_test_variant() {
            // Independent compiler control: package provider's export_test.go declares
            // TestItem, and package provider_test refers to provider.TestItem. `go test`
            // accepts it: import authority is the exact ForTest package, not only its
            // ordinary Go files. The decoy package is never part of that import.
            for source in [
                "package consumer_test; import \"example.test/root/provider\"; var Use provider.Item",
                "package consumer_test; import . \"example.test/root/provider\"; var Use Item",
            ] {
                let fixture = GoRootResolutionOperationFixture::with_consumer(source);
                let context =
                    publish_go_root_fixture_context(&fixture, "example.test/root/provider");
                fixture.store.conn.execute(move |connection| {
            let transaction = connection.transaction().unwrap();
            transaction.execute("UPDATE go_package_instances SET for_test='example.test/root/provider' WHERE context_id=?1 AND tool_import_path IN ('example.test/root/consumer','example.test/root/provider')", [context]).unwrap();
            transaction.execute("UPDATE go_package_files SET source_role='xtest' WHERE package_id IN (SELECT package_id FROM go_package_instances WHERE context_id=?1 AND tool_import_path='example.test/root/consumer')", [context]).unwrap();
            transaction.execute("UPDATE go_package_files SET source_role='test' WHERE package_id IN (SELECT package_id FROM go_package_instances WHERE context_id=?1 AND tool_import_path='example.test/root/provider')", [context]).unwrap();
            transaction.execute("UPDATE go_package_imports SET import_role='xtest' WHERE context_id=?1", [context]).unwrap();
            transaction.execute("UPDATE go_package_instances SET package_name='consumer_test' WHERE context_id=?1 AND tool_import_path='example.test/root/consumer'", [context]).unwrap();
            transaction.commit().unwrap();
        });
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                let provider = operation
                    .mount_table()
                    .mount_for_path("go", GO_ROOT_PROVIDER_PATH)
                    .unwrap()
                    .unwrap();
                let artifact = brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                    provider.fragment(),
                    &operation.ready.shared_names(),
                    Language::Go,
                    &fixture.provider_facts,
                );
                let expected = semantic_at(
                    &artifact,
                    site_for_identifier(
                        &fixture.provider_facts,
                        "Item",
                        ResolutionIdentifierRole::Declaration,
                        ResolutionNamespace::Type,
                    ),
                    LoweredSemanticRole::Definition,
                );
                let go_context::GoDotImportContext::Ready { context, .. } = operation
                    .go_eager_import_binding_context(
                        context,
                        GO_ROOT_CONSUMER_PATH,
                        "xtest",
                        &cancellation,
                    )
                    .unwrap()
                else {
                    panic!("selected external test package context");
                };
                let reference = site_for_identifier(
                    &fixture.consumer_facts,
                    "Item",
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                );
                let answer = operation
                    .resolve_reference(
                        context,
                        &SelectedSemanticLocator::new(
                            "go",
                            GO_ROOT_CONSUMER_PATH,
                            reference,
                            LoweredSemanticRole::Reference,
                        ),
                        &cancellation,
                        &mut SelectedResolutionContextMetrics,
                    )
                    .unwrap();
                let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                    answer,
                )) = answer
                else {
                    panic!("selected test-variant import reference");
                };
                assert_eq!(
                    answer.binding().targets(),
                    &[expected],
                    "{source}: {answer:?}"
                );
            }
        }
        #[test]
        #[hardwon(
            "#5699+#5700: scheduled literal owners and remote absence lost selected package closure"
        )]
        fn selected_go_package_proofs_close_scheduled_literal_and_remote_absence() {
            let consumer = r#"package consumer
import "example.test/root/provider"
type Local struct { Field string }
var local = Local{Field: "local"}
type Dictionary map[provider.Key]int
const Key = "key"
var dictionary = Dictionary{Key: 1}
func use() { provider.Rewrites.ReadFile() }
"#;
            let provider = "package provider\ntype FS struct{}\nvar Rewrites FS\ntype Key string\n";
            for complete in [false, true] {
                let fixture = GoRootResolutionOperationFixture::with_sources([
                    consumer,
                    provider,
                    GO_ROOT_DECOY_SOURCE,
                ]);
                let context_id =
                    publish_go_root_fixture_context(&fixture, "example.test/root/provider");
                fixture.store.conn.execute(move |connection| {
            connection.execute(
                "UPDATE go_context_publications SET complete=1,gaps=jsonb('[]') WHERE context_id=?1",
                [context_id],
            ).unwrap();
            connection.execute(
                "UPDATE go_package_instances SET complete=CASE WHEN tool_import_path='example.test/root/provider' THEN ?2 ELSE 1 END,gaps=jsonb('[]') WHERE context_id=?1",
                rusqlite::params![context_id, complete],
            ).unwrap();
            connection.execute(
                "UPDATE go_package_imports SET complete=1,gaps=jsonb('[]') WHERE context_id=?1",
                [context_id],
            ).unwrap();
        });
                let mut queries = vec![
                    ("Field", ResolutionNamespace::Value, true),
                    ("ReadFile", ResolutionNamespace::Callable, false),
                ];
                if complete {
                    // A named map keeps bare keys in the expression namespace while
                    // the selected provider's key type closes through ordinary demand.
                    queries.push(("Key", ResolutionNamespace::Value, true));
                }
                for (name, namespace, has_definition) in queries {
                    // Each lookup starts its own request, so remote proof publication
                    // cannot be supplied accidentally by the preceding query.
                    let cancellation = CancellationToken::new();
                    let operation = fixture.open_ready(&cancellation);
                    let site = site_for_identifier(
                        &fixture.consumer_facts,
                        name,
                        ResolutionIdentifierRole::Reference,
                        namespace,
                    );
                    let lexical = operation.ready.lexical_source();
                    let locator = SelectedSemanticLocator::new(
                        "go",
                        GO_ROOT_CONSUMER_PATH,
                        site,
                        LoweredSemanticRole::Reference,
                    );
                    let LocatedSemantic::Found(reference) = operation
                        .ready
                        .lookup_locator(&lexical, &locator, &cancellation)
                        .unwrap()
                    else {
                        panic!("selected Go reference is available");
                    };
                    let GoPreparedImportContextOutcome::Ready(prepared) = operation
                        .go_file_import_context(context_id, GO_ROOT_CONSUMER_PATH, &cancellation)
                        .unwrap()
                    else {
                        panic!("selected Go file context is available");
                    };
                    let SelectedResolutionContextValidationOutcome::Ready(context) = operation
                        .prepare_context(
                            prepared.context,
                            &cancellation,
                            &SelectedResolutionContextMetrics,
                        )
                        .unwrap()
                    else {
                        panic!("selected Go context validates");
                    };
                    let SelectedFactOperationBlueprintConstruction::Ready(blueprint) = operation
                        .ready
                        .collect_blueprint(context, &cancellation)
                        .unwrap()
                    else {
                        panic!("selected Go blueprint is available");
                    };
                    assert!(matches!(
                        operation
                            .ready
                            .register_context(&blueprint, &cancellation)
                            .unwrap(),
                        ContextRegistrationOutcome::Ready
                    ));
                    let typed = operation.ready.typed_source();
                    let session = ResolutionSession::unbounded();
                    let answer = operation
                        .with_go_forward_operation(
                            GoForwardOperationContext {
                                blueprint: &blueprint,
                                demand: prepared.demand,
                                caller_path: GO_ROOT_CONSUMER_PATH,
                                lexical: &lexical,
                                typed: &typed,
                                cancellation: &cancellation,
                                session: &session,
                            },
                            None,
                            |resolver| {
                                resolver.resolve_reference_with_metrics(
                                    reference,
                                    &mut ResolutionBatchMetrics::default(),
                                )
                            },
                        )
                        .unwrap();
                    assert_eq!(
                        answer.binding().completion() == &ResolutionCompletion::Complete,
                        has_definition || complete,
                        "{name}, complete provider inventory={complete}: {answer:?}",
                    );
                    if has_definition || complete {
                        assert_eq!(
                            !answer.binding().targets().is_empty(),
                            has_definition,
                            "{name}: {answer:?}",
                        );
                    }
                }
            }
        }
        #[test]
        fn selected_go_demand_qualified_imports_match_the_eager_oracle_in_targets_and_completion() {
            let mut saw_complete_eager_answer = false;
            let mut saw_incomplete_eager_binding = false;
            for (source_text, import_path, complete_inventory, member_name, member_namespace) in [
                (
                    "package consumer; import \"example.test/root/strange\"; var Use provider.Item",
                    "example.test/root/strange",
                    false,
                    "Item",
                    ResolutionNamespace::Type,
                ),
                (
                    "package consumer; import renamed \"example.test/root/strange\"; var Use renamed.Item",
                    "example.test/root/strange",
                    false,
                    "Item",
                    ResolutionNamespace::Type,
                ),
                (
                    "package consumer; import _ \"example.test/root/strange\"; var Use provider.Item",
                    "example.test/root/strange",
                    false,
                    "Item",
                    ResolutionNamespace::Type,
                ),
                (
                    "package consumer; import renamed \"example.test/root/strange\"; var Use provider.Item",
                    "example.test/root/strange",
                    false,
                    "Item",
                    ResolutionNamespace::Type,
                ),
                (
                    "package consumer; import \"example.test/root/strange\"; func f() { type provider struct{}; var Use provider.Item; _ = Use }",
                    "example.test/root/strange",
                    false,
                    "Item",
                    ResolutionNamespace::Type,
                ),
                (
                    "package consumer; import \"example.test/root/provider\"; var Use provider.Item",
                    "example.test/root/provider",
                    true,
                    "Item",
                    ResolutionNamespace::Type,
                ),
                (
                    "package consumer; import \"example.test/root/provider\"; var Use provider.Missing",
                    "example.test/root/provider",
                    true,
                    "Missing",
                    ResolutionNamespace::Type,
                ),
                (
                    "package consumer; import \"example.test/root/provider\"; func Use() { var _ = provider.Missing }",
                    "example.test/root/provider",
                    true,
                    "Missing",
                    ResolutionNamespace::Value,
                ),
                (
                    "package consumer; import missing \"example.test/root/missing\"; var Use missing.Item",
                    "example.test/root/strange",
                    false,
                    "Item",
                    ResolutionNamespace::Type,
                ),
            ] {
                let fixture = GoRootResolutionOperationFixture::with_consumer(source_text);
                let context_id = publish_go_root_fixture_context(&fixture, import_path);
                if complete_inventory {
                    fixture.store.conn.execute(move |connection| {
                connection.execute(
                    "UPDATE go_context_publications SET complete=1,gaps=jsonb('[]') WHERE context_id=?1",
                    [context_id],
                ).unwrap();
                connection.execute(
                    "UPDATE go_package_instances SET complete=1,gaps=jsonb('[]') WHERE context_id=?1",
                    [context_id],
                ).unwrap();
                connection.execute(
                    "UPDATE go_package_imports SET complete=1,gaps=jsonb('[]') WHERE context_id=?1",
                    [context_id],
                ).unwrap();
            });
                }
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                let reference_site = site_for_identifier(
                    &fixture.consumer_facts,
                    member_name,
                    ResolutionIdentifierRole::Reference,
                    member_namespace,
                );
                let locator = SelectedSemanticLocator::new(
                    "go",
                    GO_ROOT_CONSUMER_PATH,
                    reference_site,
                    LoweredSemanticRole::Reference,
                );
                let lexical = operation.ready.lexical_source();
                let LocatedSemantic::Found(reference) = operation
                    .ready
                    .lookup_locator(&lexical, &locator, &cancellation)
                    .unwrap()
                else {
                    panic!("qualified Go reference remains in selected source");
                };
                let prepared = match operation
                    .go_import_binding_context(
                        context_id,
                        GO_ROOT_CONSUMER_PATH,
                        "go",
                        &cancellation,
                    )
                    .unwrap()
                {
                    GoPreparedImportContextOutcome::Ready(context) => *context,
                    _ => panic!("selected Go import context is available"),
                };
                let eager = match operation
                    .go_eager_import_binding_context(
                        context_id,
                        GO_ROOT_CONSUMER_PATH,
                        "go",
                        &cancellation,
                    )
                    .unwrap()
                {
                    go_context::GoDotImportContext::Ready { context, .. } => context,
                    _ => panic!("eager Go oracle context is available"),
                };
                let prepare_blueprint = |context| {
                    let metrics = SelectedResolutionContextMetrics;
                    let SelectedResolutionContextValidationOutcome::Ready(context) = operation
                        .prepare_context(context, &cancellation, &metrics)
                        .unwrap()
                    else {
                        panic!("selected Go context validates");
                    };
                    let SelectedFactOperationBlueprintConstruction::Ready(blueprint) = operation
                        .ready
                        .collect_blueprint(context, &cancellation)
                        .unwrap()
                    else {
                        panic!("selected Go context blueprint is available");
                    };
                    assert!(matches!(
                        operation
                            .ready
                            .register_context(&blueprint, &cancellation)
                            .unwrap(),
                        ContextRegistrationOutcome::Ready
                    ));
                    blueprint
                };
                let prepared_blueprint = prepare_blueprint(prepared.context);
                let eager_blueprint = prepare_blueprint(eager);
                let typed = operation.ready.typed_source();
                let eager_answer = eager_blueprint
                    .with_forward_operation_in_session(
                        &lexical,
                        &lexical,
                        &typed,
                        &cancellation,
                        &ResolutionSession::unbounded(),
                        |resolver| {
                            resolver.resolve_reference_with_metrics(
                                reference,
                                &mut ResolutionBatchMetrics::default(),
                            )
                        },
                    )
                    .unwrap();
                let demand_answer = operation
                    .with_go_forward_operation(
                        GoForwardOperationContext {
                            blueprint: &prepared_blueprint,
                            demand: prepared.demand,
                            caller_path: GO_ROOT_CONSUMER_PATH,
                            lexical: &lexical,
                            typed: &typed,
                            cancellation: &cancellation,
                            session: &ResolutionSession::unbounded(),
                        },
                        None,
                        |resolver| {
                            resolver.resolve_reference_with_metrics(
                                reference,
                                &mut ResolutionBatchMetrics::default(),
                            )
                        },
                    )
                    .unwrap();
                assert_eq!(
                    demand_answer.binding().targets(),
                    eager_answer.binding().targets(),
                    "{source_text}: demand={demand_answer:?}, eager={eager_answer:?}"
                );
                assert_eq!(
                    demand_answer.binding().completion(),
                    eager_answer.binding().completion(),
                    "{source_text}: binding completion demand={demand_answer:?}, eager={eager_answer:?}"
                );
                assert_eq!(
                    demand_answer.completion(),
                    eager_answer.completion(),
                    "{source_text}: answer completion"
                );
                if complete_inventory {
                    assert_eq!(
                        eager_answer.completion(),
                        &ResolutionCompletion::Complete,
                        "the complete selected inventory has a complete eager answer: {eager_answer:?}"
                    );
                    assert_eq!(
                        demand_answer.completion(),
                        &ResolutionCompletion::Complete,
                        "the demand provider preserves the eager complete answer: {demand_answer:?}"
                    );
                    saw_complete_eager_answer = true;
                }
                if eager_answer.completion() == &ResolutionCompletion::Complete {
                    saw_complete_eager_answer = true;
                    assert_eq!(
                        demand_answer.completion(),
                        &ResolutionCompletion::Complete,
                        "the demand provider preserves the eager complete answer: {source_text}"
                    );
                }
                if matches!(
                    eager_answer.binding().completion(),
                    ResolutionCompletion::Incomplete(_)
                ) {
                    saw_incomplete_eager_binding = true;
                    assert!(
                        matches!(
                            demand_answer.binding().completion(),
                            ResolutionCompletion::Incomplete(_)
                        ),
                        "an incomplete eager prefix binding remains incomplete on demand: {source_text}"
                    );
                }
                if source_text.contains("root/missing") {
                    assert_eq!(
                        demand_answer.binding().completion(),
                        &ResolutionCompletion::Complete,
                        "the eager path also treats an unresolved imported package as a complete binding"
                    );
                    assert_eq!(
                        eager_answer.binding().completion(),
                        &ResolutionCompletion::Complete
                    );
                }
            }
            assert!(
                saw_complete_eager_answer,
                "the qualified-import fixtures include a complete eager answer"
            );
            assert!(
                saw_incomplete_eager_binding,
                "the qualified-import fixtures include an incomplete eager prefix binding"
            );
        }
        #[test]
        fn selected_go_import_readers_seek_populated_selected_rows() {
            use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

            use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;
            use rusqlite::types::Value::{Integer, Text};
            let consumer = "package consumer; import renamed \"example.test/root/provider\"; var Item renamed.Item";
            let mut decoy = String::from("package provider;\n");
            for index in 0..129 {
                decoy.push_str(&format!(
                    "import unrelated{index} \"example.test/unrelated/{index}\";\n"
                ));
            }
            decoy.push_str("type Item struct {}\n");
            let fixture = GoRootResolutionOperationFixture::with_sources([
                consumer,
                GO_ROOT_PROVIDER_SOURCE,
                &decoy,
            ]);
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            // Populate unrelated canonical variants so membership indexes are tested
            // against a real choice of plans, not a three-row table that favors scans.
            fixture.store.conn.execute(move |connection| {
        let transaction = connection.transaction().unwrap();
        let version: i64 = transaction.query_row("SELECT file_version_id FROM go_context_source_files WHERE context_id=?1 AND rel_path=?2", rusqlite::params![context, GO_ROOT_PROVIDER_PATH], |row| row.get(0)).unwrap();
        for index in 0..512 {
            let path = format!("example.test/variant{index}");
            let unit_key = go_unit_key(&path, &path, "test");
            transaction.execute("INSERT INTO go_package_instances(context_id,tool_import_path,package_name,for_test,provider_directory,provider_digest,complete,gaps,unit_key) VALUES(?1,?2,'provider',?2,'',zeroblob(32),0,jsonb('[]'),?3)", rusqlite::params![context, path, unit_key.as_slice()]).unwrap();
            let package = transaction.last_insert_rowid();
            transaction.execute("INSERT INTO go_package_files(package_id,file_version_id,source_role) VALUES(?1,?2,'go')", rusqlite::params![package,version]).unwrap();
        }
        transaction.commit().unwrap();
    });
            let cancellation = CancellationToken::new();
            for statistics in [false, true] {
                if statistics {
                    fixture.store.refresh_planner_statistics().unwrap();
                } else {
                    fixture.store.clear_planner_statistics().unwrap();
                }
                let operation = fixture.open_ready(&cancellation);
                for (path, facts) in [
                    (GO_ROOT_CONSUMER_PATH, &fixture.consumer_facts),
                    (GO_ROOT_DECOY_PATH, &fixture.decoy_facts),
                ] {
                    let source = operation
                        .mount_table()
                        .mount_for_path("go", path)
                        .unwrap()
                        .unwrap();
                    let lowered = brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                        source.fragment(),
                        &operation.ready.shared_names(),
                        Language::Go,
                        facts,
                    );
                    stage_go_import_rows(
                        &operation,
                        source.ordinal(),
                        &lowered.common().go_package_imports,
                    );
                }
                let source = operation
                    .mount_table()
                    .mount_for_path("go", GO_ROOT_CONSUMER_PATH)
                    .unwrap()
                    .unwrap();
                let version = operation
                    .ready
                    .inventory
                    .mount_record_by_ordinal(source.ordinal())
                    .unwrap()
                    .file_version_id()
                    .unwrap();
                let connection = operation.ready.inventory.connection();
                if statistics {
                    connection.execute_batch("ANALYZE temp").unwrap();
                }
                let caller: i64 = connection
                    .query_row(
                        go_same_package::CALLER_PACKAGE,
                        rusqlite::params![context, version, "go"],
                        |row| row.get(0),
                    )
                    .unwrap();
                let requested = format!("[[{},{version},\"go\"]]", source.ordinal().get());
                let (provider_name, target): (String, i64) = connection
                    .query_row(
                        go_named::GO_FILE_IMPORT_ROWS,
                        rusqlite::params![context, requested],
                        |row| Ok((row.get(4)?, row.get(5)?)),
                    )
                    .unwrap();
                assert_eq!(provider_name, "provider");
                for (label, parameters, sought) in [
                    (
                        "go_named_import_bindings",
                        vec![Text(format!("[{}]", source.ordinal().get()))],
                        "p",
                    ),
                    (
                        "go_named_stage_import_bindings",
                        vec![Text(format!("[{}]", source.ordinal().get()))],
                        "p",
                    ),
                    (
                        "go_file_import_rows",
                        vec![Integer(context), Text(requested.clone())],
                        "imports",
                    ),
                    (
                        "go_named_import_target_mounts",
                        vec![Integer(context), Integer(target)],
                        "members",
                    ),
                    (
                        "go_caller_source_role",
                        vec![Integer(context), Integer(version)],
                        "members",
                    ),
                    (
                        "go_caller_package",
                        vec![Integer(context), Integer(version), Text("go".into())],
                        "members",
                    ),
                    (
                        "go_package_peer_mounts",
                        vec![Integer(context), Integer(caller), Text("go".into())],
                        "members",
                    ),
                ] {
                    let mut pin = pinned(label);
                    pin.params = parameters;
                    let count = connection
                        .prepare(&pin.sql)
                        .unwrap()
                        .query_map(rusqlite::params_from_iter(pin.params.iter()), |_| Ok(()))
                        .unwrap()
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .unwrap()
                        .len();
                    assert_eq!(count, 1, "{label} must read the relevant populated row");
                    let plan = explain_pin(connection, &pin);
                    assert!(
                        plan.iter()
                            .any(|line| line.contains(&format!("SEARCH {sought} "))),
                        "{label}, statistics={statistics}: {plan:?}"
                    );
                    assert!(
                        !plan.iter().any(|line| line.contains("AUTOMATIC")
                            || line.contains("TEMP B-TREE")
                            || line.contains(&format!("SCAN {sought}"))),
                        "{label}, statistics={statistics}: {plan:?}"
                    );
                }
            }
        }
        #[test]
        fn go_definition_package_anchor_seeks_exact_selected_version() {
            use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

            use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;
            let fixture = GoRootResolutionOperationFixture::new();
            let version = fixture.store.conn.execute(|connection| {
        let transaction = connection.transaction().unwrap();
        let version: i64 = transaction.query_row(
            "SELECT file_version_id FROM workspace_file_versions WHERE lang='go' AND rel_path=?1",
            [GO_ROOT_PROVIDER_PATH], |row| row.get(0),
        ).unwrap();
        transaction.execute("INSERT INTO workspace_file_anchor_rows(file_version_id,anchor_kind,anchor_pop,package_name) VALUES(?1,'own_module',0,'example.test/root/provider')", [version]).unwrap();
        for index in 0..512 {
            transaction.execute(
                "INSERT INTO workspace_file_versions(workspace_id,lang,generation,rel_path,blob_oid,projection_digest,valid_from)
                 SELECT workspace_id,lang,generation,?2,blob_oid,projection_digest,valid_from
                 FROM workspace_file_versions WHERE file_version_id=?1",
                rusqlite::params![version,format!("unrelated{index}/provider.go")],
            ).unwrap();
            let unrelated = transaction.last_insert_rowid();
            transaction.execute("INSERT INTO workspace_file_anchor_rows(file_version_id,anchor_kind,anchor_pop,package_name) VALUES(?1,'own_module',0,?2)",rusqlite::params![unrelated,format!("example.test/root/unrelated{index}")]).unwrap();
        }
        transaction.commit().unwrap();
        version
    });
            for statistics in [false, true] {
                if statistics {
                    fixture.store.refresh_planner_statistics().unwrap();
                } else {
                    fixture.store.clear_planner_statistics().unwrap();
                }
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                let connection = operation.ready.inventory.connection();
                let mut pin = pinned("go_definition_package_anchor");
                pin.params = vec![rusqlite::types::Value::Integer(version)];
                let package: String = connection
                    .query_row(&pin.sql, [version], |row| row.get(0))
                    .unwrap();
                assert_eq!(package, "example.test/root/provider");
                let plan = explain_pin(connection, &pin);
                assert!(
                    plan.iter().any(|line| line.contains("SEARCH anchors")
                        && line.contains("file_version_id=?")
                        && line.contains("anchor_kind=?")
                        && line.contains("anchor_pop=?")),
                    "statistics={statistics}: {plan:?}"
                );
                for forbidden in ["SCAN anchors", "AUTOMATIC", "TEMP B-TREE"] {
                    assert!(
                        !plan.iter().any(|line| line.contains(forbidden)),
                        "statistics={statistics}: {plan:?}"
                    );
                }
            }
        }

        use brokk_bifrost_analysis::native_resolution_test_support::BatchResolutionFragmentSource;
        #[test]
        #[brokk_bifrost_test_macros::hardwon(
            "#5316: Go context snapshots and hydration reread identical request facts"
        )]
        fn go_context_reads_reuse_only_one_request_revision_and_stage() {
            use brokk_bifrost_analysis::analyzer::resolution::model::EndpointSignature;

            use brokk_bifrost_analysis::analyzer::resolution::model::PartialPathId;

            use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedContextPathSource;

            use brokk_bifrost_analysis::analyzer::resolution::model::StackPattern;

            use brokk_bifrost_analysis::analyzer::store::resolution_selection::selection_test_support::SelectionFixture as SelectionFixture;

            use brokk_bifrost_analysis::analyzer::store::resolution_stage::SelectedResolutionStage;

            let fixture = SelectionFixture::new(1);
            let selection = fixture.open_ready(&[]);
            let live = CancellationToken::new();
            let cache = std::rc::Rc::new(UnconditionalCandidateCache::for_go_operation());
            let source = SelectedResolutionLexicalSource::new_on_demand_with_unconditional_cache(
                &selection,
                std::rc::Rc::clone(&cache),
            );
            let fragment = selection.mounts().unwrap()[0].fragment_id();
            let identity = CandidatePathIdentity::new(fragment, PartialPathId::context_local(900));
            let endpoint = EndpointSignature::new(
                BindingNodeId::universal_root(),
                StackPattern::closed([]),
                StackPattern::closed([]),
            );
            let path = PartialPath::new(
                endpoint.clone(),
                endpoint,
                vec![],
                vec![],
                ResolutionCompletion::Complete,
            );
            let context = SelectedResolutionStage::new(&selection)
                .publish_context_paths(&live, |writer| writer.insert(identity, &path))
                .unwrap()
                .unwrap();
            begin_production_selected_sql_trace_on_connection(selection.connection());
            for _ in 0..3 {
                assert_eq!(
                    source.context_paths(context, &live).unwrap().unwrap().len(),
                    1
                );
                assert_eq!(
                    source
                        .hydrate_context_paths(context, &[identity], &live)
                        .unwrap()
                        .unwrap()
                        .len(),
                    1
                );
            }
            let first = checkpoint_production_selected_sql_trace();
            assert_eq!(
                first
                    .statements
                    .iter()
                    .filter(|sql| sql
                        .contains("json(body) FROM temp.selected_resolution_context_paths"))
                    .count(),
                1,
                "{first:?}"
            );
            assert_eq!(
                first
                    .statements
                    .iter()
                    .filter(|sql| sql.contains("json(p.body) FROM json_each"))
                    .count(),
                1,
                "{first:?}"
            );
            // A committed stage change must not reuse the previous stage's read.
            selection.note_stage_content_commit();
            assert_eq!(
                source.context_paths(context, &live).unwrap().unwrap().len(),
                1
            );
            assert_eq!(
                source
                    .hydrate_context_paths(context, &[identity], &live)
                    .unwrap()
                    .unwrap()
                    .len(),
                1
            );
            let changed = checkpoint_production_selected_sql_trace();
            assert_eq!(changed.statements.len(), 2, "{changed:?}");
            selection.with_owned_temp_write(|_| Ok(())).unwrap();
            assert_eq!(
                source.context_paths(context, &live).unwrap().unwrap().len(),
                1
            );
            assert_eq!(
                source
                    .hydrate_context_paths(context, &[identity], &live)
                    .unwrap()
                    .unwrap()
                    .len(),
                1
            );
            let direct_write = checkpoint_production_selected_sql_trace();
            assert_eq!(direct_write.statements.len(), 2, "{direct_write:?}");
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            assert!(source.context_paths(context, &cancelled).unwrap().is_none());
            assert!(
                source
                    .hydrate_context_paths(context, &[identity], &cancelled)
                    .unwrap()
                    .is_none()
            );
            let cancelled =
                finish_production_selected_sql_trace_on_connection(selection.connection());
            assert!(cancelled.statements.is_empty());
            let other_selection = fixture.open_ready(&[]);
            let other = SelectedResolutionLexicalSource::new_on_demand_with_unconditional_cache(
                &other_selection,
                cache,
            );
            assert!(
                other.context_paths(context, &live).is_err(),
                "context tokens cannot cross requests"
            );
            assert!(other.hydrate_context_paths(context, &[], &live).is_err());
            // The immutable main rows are reused, but classification is still assembled
            // against this read's stage overlays. Include an absent catalog key as well.
            let go = GoRootResolutionOperationFixture::new();
            let operation = go.open_ready(&live);
            let lexical = operation.ready.lexical_source();
            let mounts = operation.ready.inventory.mounts().unwrap();
            let mut nodes = Vec::new();
            let mut absent = Vec::new();
            for mount in mounts {
                let mut statement = operation
            .ready
            .inventory
            .connection()
            .prepare_cached(
                "SELECT local_key FROM main.resolution_node_catalog WHERE blob_id=?1 LIMIT 8",
            )
            .unwrap();
                let keys = statement
                    .query_map([mount.blob_id()], |row| row.get::<_, u32>(0))
                    .unwrap();
                for key in keys {
                    nodes.push(BindingNodeId::local(mount.ordinal().get(), key.unwrap()));
                }
                absent.push(BindingNodeId::local(mount.ordinal().get(), u32::MAX));
            }
            let connection = operation.ready.inventory.connection();
            begin_production_selected_sql_trace_on_connection(connection);
            let first = lexical.classify_endpoint_nodes(&nodes, &live).unwrap();
            let missing = lexical
                .classify_endpoint_nodes(&absent, &live)
                .unwrap_err()
                .to_string();
            assert!(missing.contains("cannot classify unknown selected endpoint"));
            let cold = checkpoint_production_selected_sql_trace();
            assert!(
                cold.statements
                    .iter()
                    .any(|sql| sql.contains("main.resolution_node_catalog node"))
            );
            assert_eq!(
                first,
                lexical.classify_endpoint_nodes(&nodes, &live).unwrap()
            );
            assert_eq!(
                missing,
                lexical
                    .classify_endpoint_nodes(&absent, &live)
                    .unwrap_err()
                    .to_string()
            );
            let repeated = finish_production_selected_sql_trace_on_connection(connection);
            assert!(
                !repeated
                    .statements
                    .iter()
                    .any(|sql| sql.contains("main.resolution_node_catalog node")
                        || sql.contains("main.resolution_member_scope_properties")),
                "{repeated:?}"
            );
        }
        #[test]
        #[brokk_bifrost_test_macros::hardwon(
            "658ae20982ef: Go member lookup demanded unrelated same-name receiver frontiers"
        )]
        fn go_owner_proof_reads_exact_source_receivers_and_reuses_only_the_current_stage() {
            use brokk_bifrost_analysis::analyzer::resolution::fact_source::DeferredMemberOwnerProof;

            use brokk_bifrost_analysis::analyzer::resolution::fact_source::SelectedTypedFactSource;
            let fixture = GoRootResolutionOperationFixture::with_sources([
                "package consumer; type Good struct {}; func (Good) Name() string { return \"good\" }",
                "package provider; type Decoy struct {}; func (Decoy) Name() string { return \"decoy\" }",
                "package provider; type Generic[T any] struct {}; func (Generic[T]) Name() string { return \"generic\" }",
            ]);
            let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            fixture.store.conn.execute(move |connection| {
                connection
                    .execute(
                        "UPDATE go_package_instances SET complete=1 WHERE context_id=?1",
                        [context],
                    )
                    .unwrap();
            });
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let inventory = &operation.ready.inventory;
            let mut candidates = Vec::new();
            for path in [
                GO_ROOT_CONSUMER_PATH,
                GO_ROOT_PROVIDER_PATH,
                GO_ROOT_DECOY_PATH,
            ] {
                let mount = operation
                    .mount_table()
                    .mount_for_path("go", path)
                    .unwrap()
                    .unwrap();
                let blob = inventory
                    .mount_record_by_ordinal(mount.ordinal())
                    .unwrap()
                    .blob_id();
                let (definition, frontier): (u32, u32) = inventory
                    .connection()
                    .query_row(
                        "SELECT deferred.definition,json_extract(deferred.body,'$[0]')
             FROM resolution_deferred_member_owners deferred
             JOIN resolution_semantic_sites semantic ON semantic.blob_id=deferred.blob_id
               AND semantic.semantic_key=deferred.definition AND semantic.semantic_role='definition'
             JOIN source_native_declaration_bridges bridge ON bridge.blob_id=semantic.blob_id
               AND bridge.source_site=semantic.source_site
             JOIN source_go_callables method ON method.blob_id=bridge.blob_id
               AND method.declaration_id=bridge.declaration_id
             WHERE deferred.blob_id=?1 AND method.name='Name'",
                        [blob],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                candidates.push((
                    SemanticId::local(mount.ordinal().get(), definition),
                    SemanticId::local(mount.ordinal().get(), frontier),
                ));
            }
            let good_mount = operation
                .mount_table()
                .mount_for_path("go", GO_ROOT_CONSUMER_PATH)
                .unwrap()
                .unwrap();
            let good_blob = inventory
                .mount_record_by_ordinal(good_mount.ordinal())
                .unwrap()
                .blob_id();
            let key: u32 = inventory
                .connection()
                .query_row(
                    "SELECT semantic.semantic_key FROM source_go_type_declarations nominal
         JOIN source_native_declaration_bridges bridge ON bridge.blob_id=nominal.blob_id
           AND bridge.declaration_id=nominal.declaration_id
         JOIN resolution_semantic_sites semantic ON semantic.blob_id=bridge.blob_id
           AND semantic.source_site=bridge.source_site AND semantic.semantic_role='definition'
         WHERE nominal.blob_id=?1 AND nominal.name='Good'",
                    [good_blob],
                    |row| row.get(0),
                )
                .unwrap();
            let owners = [SemanticId::local(good_mount.ordinal().get(), key)];
            let source = operation.ready.typed_source();
            let expected = vec![
                DeferredMemberOwnerProof::Matches,
                DeferredMemberOwnerProof::DoesNotMatch,
                DeferredMemberOwnerProof::Unknown,
            ];
            assert_eq!(
                source
                    .deferred_member_owner_proofs(&owners, &candidates, &cancellation)
                    .unwrap(),
                Some(expected.clone())
            );
            begin_production_selected_sql_trace_on_connection(inventory.connection());
            assert_eq!(
                source
                    .deferred_member_owner_proofs(&owners, &candidates, &cancellation)
                    .unwrap(),
                Some(expected.clone())
            );
            let repeated = checkpoint_production_selected_sql_trace();
            assert!(
                !repeated
                    .statements
                    .iter()
                    .any(|sql| sql.contains("selected_go_deferred_member_owner_proofs")),
                "one immutable proof projection per stage; retain ordinary read-stamp validation: {repeated:?}"
            );
            inventory.note_stage_content_commit();
            assert_eq!(
                source
                    .deferred_member_owner_proofs(&owners, &candidates, &cancellation)
                    .unwrap(),
                Some(expected)
            );
            let changed =
                finish_production_selected_sql_trace_on_connection(inventory.connection());
            assert!(
                changed
                    .statements
                    .iter()
                    .any(|sql| sql.contains("selected_go_deferred_member_owner_proofs")),
                "a stage change invalidates the proof read: {changed:?}"
            );
            // The projection must seek the existing file-version membership indexes;
            // correct scalar answers alone did not catch a workspace placement scan.
            let sql = changed
                .statements
                .iter()
                .find(|sql| sql.contains("selected_go_deferred_member_owner_proofs"))
                .expect("the changed stage rereads the projection");
            let coordinates = candidates
                .iter()
                .map(|(definition, frontier)| {
                    [
                        i64::from(definition.ordinal().unwrap()),
                        i64::from(definition.local_key().unwrap()),
                        i64::from(frontier.local_key().unwrap()),
                    ]
                })
                .collect::<Vec<_>>();
            let plan = inventory
                .connection()
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map([serde_json::to_string(&coordinates).unwrap()], |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                plan.iter().any(|line| line.contains("SEARCH method_file")
                    && line.contains("idx_go_package_files_file_role")),
                "{plan:?}"
            );
            assert!(
        plan.iter()
            .any(|line| line.contains("SEARCH owner") && line.contains("file_version_id=?")),
        "{plan:?}"
    );
        }
        #[test]
        #[hardwon(
            "#5600: root source discovery must keep the universal path for unsaved package inputs"
        )]
        fn go_context_reads_root_source_horizon_retains_unsaved_package_answer() {
            use brokk_bifrost_analysis::analyzer::resolution::model::EndpointSignature;

            use brokk_bifrost_analysis::analyzer::resolution::local_identity::SharedNameInterner;

            use brokk_bifrost_analysis::analyzer::resolution::model::StackPattern;

            use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionContentPublicationOutcome;

            let fixture = GoRootResolutionOperationFixture::new();
            let context_id =
                publish_go_root_fixture_context(&fixture, "example.test/root/provider");
            let cancellation = CancellationToken::new();
            let snapshot = &fixture.snapshots["go"];
            let (state, _) = parsed_go_state(
                fixture.project.root(),
                GO_ROOT_CONSUMER_PATH,
                GO_ROOT_CONSUMER_SOURCE,
            );
            let oid =
                Oid::hash_object(ObjectType::Blob, GO_ROOT_CONSUMER_SOURCE.as_bytes()).unwrap();
            let prepared = AnalyzerStore::prepare_parsed_blob(
                oid,
                "go",
                snapshot.generation,
                &GoAdapter,
                state,
            )
            .unwrap();
            let ResolutionContentPublicationOutcome::Ready(content) = fixture
                .store
                .publish_selected_parsed_content(
                    snapshot,
                    GO_ROOT_CONSUMER_PATH,
                    prepared,
                    &cancellation,
                )
                .unwrap()
            else {
                panic!("publish the unsaved consumer");
            };
            let content = content_mount_request(content.into_parts().0, GO_ROOT_CONSUMER_PATH, oid)
                .with_counterfactual_base_content_digest(
                    brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(
                        GO_ROOT_CONSUMER_SOURCE.as_bytes(),
                    ),
                );
            let masks = [SelectedResolutionOverlayMask::replacement(
                "go",
                GO_ROOT_CONSUMER_PATH,
            )];
            for overlay in [false, true] {
                let operation = open_ready_operation(
                    &fixture.store,
                    selected_operation_input(
                        &fixture.project,
                        &fixture.workspace_id,
                        &fixture.snapshots,
                        &fixture.languages,
                        if overlay { &masks } else { &[] },
                        if overlay {
                            vec![content.clone()]
                        } else {
                            Vec::new()
                        },
                    ),
                    &cancellation,
                );
                let source = operation
                    .mount_table()
                    .mount_for_path("go", GO_ROOT_CONSUMER_PATH)
                    .unwrap()
                    .unwrap();
                let lexical = operation.ready.lexical_source();
                let mut root_anchor = None;
                let outcome = visit_selected_root_import_half_pages(
                    &operation.ready.context_identities,
                    &lexical,
                    &lexical,
                    Some(&[source.ordinal()]),
                    &cancellation,
                    &mut FactPageVisitor::new(&mut |page| {
                        for half in page {
                            if let SelectedRootPathHalf::Import {
                                anchor_semantic, ..
                            } = half
                            {
                                root_anchor = Some(*anchor_semantic);
                            }
                        }
                        Ok(true)
                    }),
                )
                .unwrap();
                assert!(outcome.is_exhausted());
                let endpoint = EndpointSignature::new(
                    BindingNodeId::universal_root(),
                    StackPattern::closed(vec![root_anchor.expect("consumer root import")]),
                    StackPattern::closed([]),
                );
                let horizon = brokk_bifrost_analysis::analyzer::store::resolution_operation::source_demand::root_source_horizon(
            &operation.ready,
            &endpoint,
            &cancellation,
            &mut HashMap::default(),
        )
        .unwrap();
                assert_eq!(matches!(horizon, RootSourceHorizon::Universal), overlay);
                // A shared package domain is not a source anchor, even with an
                // overlay. Both source-half classifiers reject any unanchored Shared
                // head; the proof does not depend on its language or stack shape.
                for language in [Language::Go, Language::Java] {
                    let shared = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::package::package_domain_semantic(
                        language,
                        &operation.ready.shared_names(),
                    );
                    let lookup =
                        SemanticId::shared_name(operation.ready.shared_names().intern([7; 32]));
                    for symbols in [
                        vec![shared],
                        // Indexed package-member declaration roots start with a
                        // shared lookup, then the package domain and a local token.
                        vec![lookup, shared, root_anchor.unwrap()],
                    ] {
                        let shared_endpoint = EndpointSignature::new(
                            BindingNodeId::universal_root(),
                            StackPattern::closed(symbols),
                            StackPattern::closed([]),
                        );
                        let shared_horizon = brokk_bifrost_analysis::analyzer::store::resolution_operation::source_demand::root_source_horizon(
                    &operation.ready,
                    &shared_endpoint,
                    &cancellation,
                    &mut HashMap::default(),
                )
                .unwrap();
                        match shared_horizon {
                            RootSourceHorizon::Bounded(mounts) => assert!(mounts.is_empty()),
                            RootSourceHorizon::Universal => {
                                panic!("an unanchored Shared head has no source halves")
                            }
                        }
                    }
                }
                let go_context::GoDotImportContext::Ready { context, .. } = operation
                    .go_dot_import_context(context_id, GO_ROOT_CONSUMER_PATH, "go", &cancellation)
                    .unwrap()
                else {
                    panic!("selected consumer context");
                };
                let reference = site_for_identifier(
                    &fixture.consumer_facts,
                    "Item",
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                );
                let provider = operation
                    .mount_table()
                    .mount_for_path("go", GO_ROOT_PROVIDER_PATH)
                    .unwrap()
                    .unwrap()
                    .ordinal()
                    .get();
                let outcome = operation
                    .resolve_reference(
                        context,
                        &SelectedSemanticLocator::new(
                            "go",
                            GO_ROOT_CONSUMER_PATH,
                            reference,
                            LoweredSemanticRole::Reference,
                        ),
                        &cancellation,
                        &mut SelectedResolutionContextMetrics,
                    )
                    .unwrap();
                let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                    answer,
                )) = outcome
                else {
                    panic!("the unsaved consumer still resolves its imported type");
                };
                assert_eq!(answer.binding().targets().len(), 1, "{answer:?}");
                assert_eq!(
                    answer.binding().targets()[0].ordinal(),
                    Some(provider),
                    "the overlay must preserve the intended provider: {answer:?}"
                );
            }
        }
    }

    mod go_move_13 {
        use rusqlite::params;

        use std::collections::BTreeSet;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::store::go_package_context::DERIVATION_VERSION;

        use brokk_bifrost_analysis::analyzer::store::go_package_context::go_extraction_support_13::Fixture;

        use brokk_bifrost_analysis::analyzer::store::go_package_context::GoContextHeadStatus;

        use brokk_bifrost_analysis::analyzer::store::go_package_context::GoContextPublicationOutcome;

        use brokk_bifrost_analysis::analyzer::store::go_package_context::GoInputObservationOutcome;

        use brokk_bifrost_core::analyzer::model::Language;

        use git2::ObjectType;

        use git2::Oid;

        use brokk_bifrost_analysis::analyzer::store::go_unit_summaries::go_unit_key;

        use brokk_bifrost_analysis::analyzer::store::go_package_context::profile_digest;

        use brokk_bifrost_analysis::analyzer::store::go_package_context::source_inventory_profile;

        use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
        use serde_json::json;
        fn test_variant_fixture() -> Fixture {
            Fixture::from_project(
                InlineTestProject::with_language(Language::Go)
                    .file("go.mod", "module example.test/root\n\ngo 1.22\n")
                    .file("consumer/use.go", "package consumer\nvar Value int\n")
                    .file(
                        "consumer/use_test.go",
                        "package consumer\nvar Internal int\n",
                    )
                    .file(
                        "consumer/external_test.go",
                        "package consumer_test\nvar External int\n",
                    )
                    .file("provider/item.go", "package provider\ntype Item struct{}\n")
                    .build(),
            )
        }
        #[test]
        #[brokk_bifrost_test_macros::hardwon(
            "#5020: failed Go tool roots erased inventory placements while explicit exclusions must survive"
        )]
        fn failed_tool_root_keeps_inventory_without_overriding_file_records() {
            let fixture = Fixture::from_project(
            InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/root\n\ngo 1.22\n")
                .file("consumer/use.go", "package consumer\nvar Use int\n")
                .file("provider/item.go", "package provider\ntype Item struct{}\n")
                .file(
                    "provider/ignored.go",
                    "//go:build ignore\n\npackage provider\nimport _ \"not-selected.test/ignored\"\nvar Ignored int\n",
                )
                .file(
                    "provider/item_test.go",
                    "package provider\nvar TestOnly int\n",
                )
                .build(),
        );
            let mut discovery = fixture.discovery();
            discovery.workspace_patterns = vec!["./...".into()];
            discovery.packages.remove(0);
            discovery.packages[0]
                .ignored_go_files
                .push("ignored.go".into());
            discovery.packages[0]
                .test_go_files
                .push("item_test.go".into());
            discovery.packages.push(
                serde_json::from_value(json!({
                    "ImportPath":"./...", "Dir":fixture.project.root(),
                    "Error":{"Err":"root package discovery failed"}, "Incomplete":true
                }))
                .unwrap(),
            );
            let identity = fixture.publish(discovery, None);
            let conn = fixture.store().read_conn().unwrap();
            let placements = conn
                .prepare(
                    "SELECT f.rel_path,p.provider_provenance,p.complete,json(p.gaps),pf.source_role
             FROM go_package_instances p JOIN go_package_files pf USING(package_id)
             JOIN workspace_file_versions f USING(file_version_id)
             WHERE p.context_id=?1 ORDER BY f.rel_path",
                )
                .unwrap()
                .query_map([identity.context_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(
                placements
                    .iter()
                    .map(|row| (row.0.as_str(), row.4.as_str()))
                    .collect::<Vec<_>>(),
                [
                    ("consumer/use.go", "go"),
                    ("provider/ignored.go", "ignored"),
                    ("provider/item.go", "go")
                ]
            );
            assert_eq!(placements[0].1, "source_inventory");
            assert!(
                placements[0].2,
                "root failure keeps the source-only provider completeness"
            );
            assert_eq!(placements[0].3, "[]");
            let (failure_rows, context_evidence): (i64, String) = conn.query_row(
            "SELECT (SELECT count(*) FROM go_package_instances WHERE context_id=?1 AND tool_import_path='./...'), json(gaps)
             FROM go_context_publications WHERE context_id=?1",
            [identity.context_id], |row| Ok((row.get(0)?,row.get(1)?)),
        ).unwrap();
            assert_eq!(
                failure_rows, 0,
                "a failed root pattern is not a package provider"
            );
            assert!(context_evidence.contains("build_selection_unavailable"));
            assert!(context_evidence.contains("root package discovery failed"));
            let excluded_imports: i64 = conn.query_row(
            "SELECT count(*) FROM go_package_imports WHERE context_id=?1 AND source_spelling='not-selected.test/ignored'",
            [identity.context_id], |row| row.get(0),
        ).unwrap();
            assert_eq!(
                excluded_imports, 0,
                "an excluded file cannot contribute import rows"
            );
            assert_eq!(placements[2].1, "go_tool");
            assert!(
                placements[2].2,
                "another failed root must not poison a file the tool placed"
            );
        }
        #[test]
        fn go_context_canonical_test_variants_use_compiled_files_and_exact_package_clauses() {
            let fixture = test_variant_fixture();
            let mut discovery = fixture.discovery();
            let base = &mut discovery.packages[0];
            base.test_go_files = vec!["use_test.go".into()];
            base.x_test_go_files = vec!["external_test.go".into()];
            base.test_imports = vec!["not-selected.test/description-only".into()];
            let mut internal = base.clone();
            internal.import_path =
                "example.test/root/consumer [example.test/root/consumer.test]".into();
            internal.for_test = "example.test/root/consumer".into();
            internal.go_files.push("use_test.go".into());
            let mut external = base.clone();
            external.import_path =
                "example.test/root/consumer_test [example.test/root/consumer.test]".into();
            external.name = "consumer_test".into();
            external.for_test = "example.test/root/consumer".into();
            external.go_files = vec!["external_test.go".into()];
            external.imports = vec![internal.import_path.clone()];
            external.import_map.insert(
                "example.test/root/consumer".into(),
                internal.import_path.clone(),
            );
            discovery.packages.extend([internal, external]);
            let identity = fixture.publish(discovery, None);
            let conn = fixture.store().read_conn().unwrap();
            let mut query = conn.prepare("SELECT p.tool_import_path,f.rel_path,f.source_role,p.package_name,p.for_test FROM go_context_source_files f JOIN go_package_instances p USING(package_id) WHERE f.context_id=?1 ORDER BY p.tool_import_path,f.rel_path").unwrap();
            let rows = query
                .query_map([identity.context_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(rows.len(), 5, "{rows:?}");
            let base = rows
                .iter()
                .filter(|row| row.0 == "example.test/root/consumer")
                .collect::<Vec<_>>();
            assert_eq!(
                base.len(),
                1,
                "incidental test inventories are not package membership: {rows:?}"
            );
            assert_eq!(base[0].1, "consumer/use.go");
            assert_eq!(base[0].2, "go");
            let internal = rows
                .iter()
                .filter(|row| {
                    row.0 == "example.test/root/consumer [example.test/root/consumer.test]"
                })
                .collect::<Vec<_>>();
            assert_eq!(
                internal
                    .iter()
                    .map(|row| row.2.as_str())
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from(["go", "test"])
            );
            let external = rows.iter().find(|row| row.2 == "xtest").unwrap();
            assert_eq!(external.3, "consumer_test");
            assert_eq!(external.4, "example.test/root/consumer");
            assert!(external.0.starts_with("example.test/root/consumer_test ["));
            let mapped: (String,String) = conn.query_row("SELECT target.tool_import_path,imports.source_spelling FROM go_package_imports imports JOIN go_package_instances target ON target.package_id=imports.target_package_id WHERE imports.context_id=?1 AND imports.import_role='xtest'",[identity.context_id],|row|Ok((row.get(0)?,row.get(1)?))).unwrap();
            assert_eq!(
                mapped.0,
                "example.test/root/consumer [example.test/root/consumer.test]"
            );
            assert_eq!(mapped.1, "example.test/root/consumer");
            let description_only: i64 = conn.query_row("SELECT count(*) FROM go_package_imports WHERE context_id=?1 AND source_spelling='not-selected.test/description-only'",[identity.context_id],|row|row.get(0)).unwrap();
            assert_eq!(description_only, 0);
            // The reverse qualified-import read seeks packages by this stored key, so
            // it must be the key the summaries hash for the same package and role.
            let mut keys = conn
            .prepare("SELECT p.tool_import_path,p.for_test,p.unit_key,(SELECT group_concat(f.source_role) FROM go_package_files f WHERE f.package_id=p.package_id) FROM go_package_instances p WHERE p.context_id=?1")
            .unwrap();
            let stored = keys
                .query_map([identity.context_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(stored.len() >= 3, "{stored:?}");
            for (import_path, for_test, unit_key, roles) in stored {
                let roles = roles.unwrap_or_default();
                let role = if for_test.is_empty() {
                    "go"
                } else if roles.split(',').any(|role| role == "xtest") {
                    "xtest"
                } else {
                    "test"
                };
                assert_eq!(
                    unit_key,
                    go_unit_key(&import_path, &for_test, role).to_vec(),
                    "{import_path} [{for_test}] {role}"
                );
            }
        }
        #[test]
        fn go_context_rejects_unproven_test_variants_and_conflicting_package_clauses() {
            let fixture = test_variant_fixture();
            let mut discovery = fixture.discovery();
            discovery.packages[0]
                .go_files
                .extend(["use_test.go".into(), "external_test.go".into()]);
            let identity = fixture.publish(discovery, None);
            let conn = fixture.store().read_conn().unwrap();
            let gaps:String = conn.query_row("SELECT json(gaps) FROM go_package_instances WHERE context_id=?1 AND tool_import_path='example.test/root/consumer'",[identity.context_id],|row|row.get(0)).unwrap();
            assert!(gaps.contains("test_variant_unselected"), "{gaps}");
            assert!(gaps.contains("package_source_identity_mismatch"), "{gaps}");
            let count:i64 = conn.query_row("SELECT count(*) FROM go_context_source_files WHERE context_id=?1 AND source_role IN ('test','xtest')",[identity.context_id],|row|row.get(0)).unwrap();
            assert_eq!(count, 0);
        }
        #[test]
        fn go_context_publication_preserves_aba_retry_and_cancellation() {
            let fixture = Fixture::new();
            let first = fixture.publish(fixture.discovery(), None);
            let mut partial = fixture.discovery();
            partial.packages[1].incomplete = true;
            let second = fixture.publish(partial, Some(first.clone()));
            assert_ne!(first, second);
            assert_eq!(
                fixture
                    .store()
                    .go_context_head_status(&first, &CancellationToken::new())
                    .unwrap(),
                GoContextHeadStatus::Withdrawn
            );
            let before = fixture.observe();
            assert!(matches!(
                fixture
                    .store()
                    .publish_go_package_context(
                        fixture.snapshot.clone(),
                        fixture.project.root().to_path_buf(),
                        Some(first.clone()),
                        &before,
                        &before,
                        fixture.discovery(),
                        &CancellationToken::new()
                    )
                    .unwrap(),
                GoContextPublicationOutcome::InputsChanged
            ));
            let third = fixture.publish(fixture.discovery(), Some(second));
            assert_eq!(first, third, "A/B/A reuses immutable A publication");
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            assert!(matches!(
                fixture
                    .store()
                    .publish_go_package_context(
                        fixture.snapshot.clone(),
                        fixture.project.root().to_path_buf(),
                        Some(third.clone()),
                        &before,
                        &before,
                        fixture.discovery(),
                        &cancelled
                    )
                    .unwrap(),
                GoContextPublicationOutcome::Cancelled
            ));
            assert_eq!(
                fixture
                    .store()
                    .go_context_head_status(&third, &cancelled)
                    .unwrap(),
                GoContextHeadStatus::Cancelled
            );
            assert_eq!(
                fixture
                    .store()
                    .go_context_head_status(&third, &CancellationToken::new())
                    .unwrap(),
                GoContextHeadStatus::Current
            );
            fixture
                .project
                .file("provider/item.go")
                .write("package provider\ntype Changed struct{}\n")
                .unwrap();
            assert!(matches!(
                fixture
                    .store()
                    .observe_go_context_inputs(
                        &fixture.snapshot,
                        fixture.workspace.analyzer().project(),
                        &CancellationToken::new()
                    )
                    .unwrap(),
                GoInputObservationOutcome::InputsChanged
            ));
        }
        #[test]
        fn go_context_source_inventory_is_partial_selected_and_incremental() {
            let fixture = Fixture::new();
            let profile = source_inventory_profile();
            let first = fixture
                .store()
                .selected_go_context(&fixture.snapshot, &profile)
                .unwrap()
                .unwrap();
            {
                let conn = fixture.store().read_conn().unwrap();
                let (complete, gaps): (bool, String) = conn
                .query_row(
                    "SELECT complete,json(gaps) FROM go_context_publications WHERE context_id=?1",
                    [first.context_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
                assert!(!complete);
                assert!(gaps.contains("build_selection_unavailable"));
                let (package_complete, provenance): (bool, String) = conn
                .query_row(
                    "SELECT complete,provider_provenance FROM go_package_instances WHERE context_id=?1 AND tool_import_path='example.test/root/provider'",
                    [first.context_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
                assert!(
                    package_complete,
                    "source-only package has exact local placement"
                );
                assert_eq!(provenance, "source_inventory");
                let import_complete: bool = conn
                .query_row(
                    "SELECT complete FROM go_package_imports WHERE context_id=?1 AND source_spelling='example.test/root/provider'",
                    [first.context_id],
                    |row| row.get(0),
                )
                .unwrap();
                assert!(
                    import_complete,
                    "workspace source import has an exact provider"
                );
                let target:String=conn.query_row("SELECT target.tool_import_path FROM go_package_imports i JOIN go_package_instances target ON target.package_id=i.target_package_id WHERE i.context_id=?1 AND i.source_spelling='example.test/root/provider'",[first.context_id],|row|row.get(0)).unwrap();
                assert_eq!(target, "example.test/root/provider");
            }
            let changed = fixture.project.file("provider/item.go");
            changed
                .write("package provider\ntype Changed struct{}\n")
                .unwrap();
            let GoContextPublicationOutcome::Published(retained) = fixture
                .store()
                .publish_go_source_context(
                    fixture.snapshot.clone(),
                    fixture.project.root(),
                    &CancellationToken::new(),
                )
                .unwrap()
            else {
                panic!("selected source inventory publishes");
            };
            assert_eq!(
                retained, first,
                "new disk text cannot contaminate the old selection"
            );
            let updated = fixture.workspace.update(&BTreeSet::from([changed]));
            let store = updated.store().unwrap();
            let mut next = fixture.snapshot.clone();
            next.revision = store
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT revision FROM workspace_heads WHERE workspace_id=?1 AND lang='go'",
                    [next.workspace_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(next.revision > fixture.snapshot.revision);
            let second = store.selected_go_context(&next, &profile).unwrap().unwrap();
            assert_ne!(first.publication_digest, second.publication_digest);
            assert_eq!(
                store
                    .go_context_head_status(&first, &CancellationToken::new())
                    .unwrap(),
                GoContextHeadStatus::Current
            );
            let fresh = WorkspaceAnalyzer::build_ephemeral_footgun(
                fixture.project.project_dyn(),
                AnalyzerConfig::default(),
            )
            .unwrap();
            let fresh_store = fresh.store().unwrap();
            let mut fresh_snapshot = fixture.snapshot.clone();
            fresh_snapshot.revision = fresh_store
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT revision FROM workspace_heads WHERE workspace_id=?1 AND lang='go'",
                    [fresh_snapshot.workspace_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                second.publication_digest,
                fresh_store
                    .selected_go_context(&fresh_snapshot, &profile)
                    .unwrap()
                    .unwrap()
                    .publication_digest
            );
        }
        #[test]
        fn go_source_inventory_separates_external_test_package_clause() {
            let fixture = test_variant_fixture();
            let context = fixture
                .store()
                .selected_go_context(&fixture.snapshot, &source_inventory_profile())
                .unwrap()
                .expect("source inventory is selected");
            let conn = fixture.store().read_conn().unwrap();
            let external: (String, String, String, bool) = conn
            .query_row(
                "SELECT package.tool_import_path,package.package_name,file.rel_path,package.complete FROM go_context_source_files source JOIN workspace_file_versions file USING(file_version_id) JOIN go_package_instances package USING(package_id) WHERE source.context_id=?1 AND source.source_role='xtest'",
                [context.context_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
            assert_eq!(external.0, "example.test/root/consumer_test");
            assert_eq!(external.1, "consumer_test");
            assert_eq!(external.2, "consumer/external_test.go");
            assert!(
                external.3,
                "the external package clause has source-only identity"
            );
            let base_external_files: i64 = conn
            .query_row(
                "SELECT count(*) FROM go_context_source_files source JOIN go_package_instances package USING(package_id) WHERE source.context_id=?1 AND package.tool_import_path='example.test/root/consumer' AND source.rel_path='consumer/external_test.go'",
                [context.context_id],
                |row| row.get(0),
            )
            .unwrap();
            assert_eq!(base_external_files, 0);
        }
        #[test]
        #[brokk_bifrost_test_macros::hardwon(
            "#2771: build-constrained Go files must not mark a provider inventory incomplete"
        )]
        fn go_source_inventory_keeps_build_constrained_files_without_an_inventory_gap() {
            let fixture = Fixture::from_project(
                InlineTestProject::with_language(Language::Go)
                    .file("go.mod", "module example.test/root\n\ngo 1.22\n")
                    .file("pkg/plain.go", "package pkg\nvar Plain = 1\n")
                    .file(
                        "pkg/tagged.go",
                        "//go:build linux\n\npackage pkg\nvar Tagged = 2\n",
                    )
                    .file("pkg/platform_arm64.go", "package pkg\nvar Platform = 3\n")
                    .file("other/plain.go", "package other\nvar Known = 4\n")
                    .build(),
            );
            let context = fixture
                .store()
                .selected_go_context(&fixture.snapshot, &source_inventory_profile())
                .unwrap()
                .expect("source inventory is selected");
            let conn = fixture.store().read_conn().unwrap();
            let (constrained_complete, constrained_gaps): (bool, String) = conn
            .query_row(
                "SELECT package.complete,json(package.gaps) FROM go_package_instances package WHERE package.context_id=?1 AND package.tool_import_path='example.test/root/pkg'",
                [context.context_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
            assert!(
                constrained_complete,
                "selected package build constraints do not make the provider unavailable"
            );
            assert!(!constrained_gaps.contains("source_file_build_selection_unavailable"));
            let constrained_files: Vec<String> = conn
            .prepare(
                "SELECT file.rel_path FROM go_context_source_files source JOIN workspace_file_versions file USING(file_version_id) JOIN go_package_instances package USING(package_id) WHERE source.context_id=?1 AND package.tool_import_path='example.test/root/pkg' ORDER BY file.rel_path",
            )
            .unwrap()
            .query_map([context.context_id], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
            assert_eq!(
                constrained_files,
                vec![
                    "pkg/plain.go".to_owned(),
                    "pkg/platform_arm64.go".to_owned(),
                    "pkg/tagged.go".to_owned(),
                ],
                "build constraints preserve every positively placed file"
            );
            let other_complete: bool = conn
            .query_row(
                "SELECT complete FROM go_package_instances WHERE context_id=?1 AND tool_import_path='example.test/root/other'",
                [context.context_id],
                |row| row.get(0),
            )
            .unwrap();
            assert!(
                other_complete,
                "constraints do not lower an unrelated package"
            );
        }
        #[test]
        fn go_context_source_inventory_preserves_roles_and_vendor_ambiguity() {
            let project = InlineTestProject::with_language(Language::Go)
                .file("go.mod", "module example.test/root\n")
                .file(
                    "consumer/use.go",
                    "package consumer\nimport . \"example.test/shared\"\nvar Value Item\n",
                )
                .file("consumer/use_test.go", "package consumer\n")
                .file("consumer/external_test.go", "package consumer_test\n")
                .file(
                    "left/vendor/example.test/shared/empty.go",
                    "package shared\n",
                )
                .file(
                    "right/vendor/example.test/shared/empty.go",
                    "package shared\n",
                )
                .build();
            let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
                project.project_dyn(),
                AnalyzerConfig::default(),
            )
            .unwrap();
            let conn = workspace.store().unwrap().read_conn().unwrap();
            let context: i64 = conn
                .query_row("SELECT context_id FROM go_context_heads", [], |row| {
                    row.get(0)
                })
                .unwrap();
            let (complete, gaps): (bool, String) = conn
                .query_row(
                    "SELECT complete,json(gaps) FROM go_context_publications WHERE context_id=?1",
                    [context],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert!(!complete);
            assert!(
                gaps.contains("source_import_provider_unavailable"),
                "{gaps}"
            );
            assert!(
                gaps.contains("left/vendor/example.test/shared")
                    && gaps.contains("right/vendor/example.test/shared"),
                "{gaps}"
            );
            let target:Option<i64>=conn.query_row("SELECT target_package_id FROM go_package_imports WHERE context_id=?1 AND source_spelling='example.test/shared'",[context],|row|row.get(0)).unwrap();
            assert_eq!(target, None);
            for (path, role) in [
                ("consumer/use.go", "go"),
                ("consumer/use_test.go", "test"),
                ("consumer/external_test.go", "xtest"),
                ("left/vendor/example.test/shared/empty.go", "go"),
            ] {
                let actual:String=conn.query_row("SELECT source_role FROM go_context_source_files WHERE context_id=?1 AND rel_path=?2",rusqlite::params![context,path],|row|row.get(0)).unwrap();
                assert_eq!(actual, role);
            }
        }
        #[test]
        fn go_context_active_tool_profile_never_falls_back_after_source_update() {
            let fixture = Fixture::new();
            let discovery = fixture.discovery();
            let profile = profile_digest(&discovery);
            let original = fixture.publish(discovery, None);
            let go = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                brokk_bifrost_go_analysis::GoAnalyzer,
            >(fixture.workspace.analyzer())
            .unwrap();
            assert!(go.activate_native_context_profile(&fixture.snapshot, profile));
            let changed = fixture.project.file("provider/item.go");
            changed
                .write("package provider\ntype Updated struct{}\n")
                .unwrap();
            let updated = fixture.workspace.update(&BTreeSet::from([changed]));
            let go = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                brokk_bifrost_go_analysis::GoAnalyzer,
            >(updated.analyzer())
            .unwrap();
            assert_eq!(go.native_context_profile(), Some(profile));
            let store = updated.store().unwrap();
            let mut next = fixture.snapshot.clone();
            next.revision = store
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT revision FROM workspace_heads WHERE workspace_id=?1 AND lang='go'",
                    [next.workspace_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(next.revision > fixture.snapshot.revision);
            assert_eq!(store.selected_go_context(&next, &profile).unwrap(), None);
            assert_eq!(
                store
                    .selected_go_context(&next, &source_inventory_profile())
                    .unwrap(),
                None
            );
            assert_eq!(
                store
                    .selected_go_context(&fixture.snapshot, &profile)
                    .unwrap(),
                Some(original)
            );
            assert!(
                !go.activate_native_context_profile(&fixture.snapshot, source_inventory_profile())
            );
            assert_eq!(go.native_context_profile(), Some(profile));
        }
        #[test]
        fn go_context_profile_is_explicit_and_clone_local() {
            let fixture = Fixture::new();
            let first_discovery = fixture.discovery();
            let first_profile = profile_digest(&first_discovery);
            let first = fixture.publish(first_discovery, None);
            let mut second_discovery = fixture.discovery();
            second_discovery.build_tags.push("another-profile".into());
            let second_profile = profile_digest(&second_discovery);
            fixture.publish(second_discovery, None);
            let go = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                brokk_bifrost_go_analysis::GoAnalyzer,
            >(fixture.workspace.analyzer())
            .unwrap();
            assert_eq!(
                go.native_context_profile(),
                Some(source_inventory_profile())
            );
            assert!(go.activate_native_context_profile(&fixture.snapshot, first_profile));
            let cloned = go.clone();
            assert!(cloned.activate_native_context_profile(&fixture.snapshot, second_profile));
            assert_eq!(go.native_context_profile(), Some(first_profile));
            assert_eq!(cloned.native_context_profile(), Some(second_profile));
            assert_eq!(
                fixture
                    .store()
                    .selected_go_context(&fixture.snapshot, &go.native_context_profile().unwrap())
                    .unwrap(),
                Some(first)
            );
            let mut wrong = fixture.snapshot.clone();
            wrong.revision += 1;
            assert!(!go.activate_native_context_profile(&wrong, second_profile));
            assert_eq!(go.native_context_profile(), Some(first_profile));
        }
        #[test]
        fn go_context_source_membership_view_excludes_wrong_selection_domains() {
            let fixture = Fixture::new();
            let identity = fixture.publish(fixture.discovery(), None);
            let conn = fixture.store().conn.lock().unwrap();
            let package: i64 = conn
                .query_row(
                    "SELECT package_id FROM go_package_instances WHERE context_id=?1 LIMIT 1",
                    [identity.context_id],
                    |row| row.get(0),
                )
                .unwrap();
            let selected_workspace = fixture.snapshot.workspace_id.as_str();
            let selected_generation = fixture.snapshot.generation.get();
            let selected_revision = fixture.snapshot.revision;
            let oid = Oid::hash_object(ObjectType::Blob, b"package invalid")
                .unwrap()
                .to_string();
            let projection = "a".repeat(64);
            for (index, (workspace, lang, generation, from, until, kind)) in [
                (
                    "b".repeat(64),
                    "go",
                    selected_generation,
                    selected_revision,
                    None::<i64>,
                    "source",
                ),
                (
                    selected_workspace.to_owned(),
                    "java",
                    selected_generation,
                    selected_revision,
                    None,
                    "source",
                ),
                (
                    selected_workspace.to_owned(),
                    "go",
                    selected_generation + 1,
                    selected_revision,
                    None,
                    "source",
                ),
                (
                    selected_workspace.to_owned(),
                    "go",
                    selected_generation,
                    selected_revision + 1,
                    None,
                    "source",
                ),
                (
                    selected_workspace.to_owned(),
                    "go",
                    selected_generation,
                    selected_revision,
                    None,
                    "configuration",
                ),
            ]
            .into_iter()
            .enumerate()
            {
                conn.execute("INSERT OR IGNORE INTO workspace_revisions(workspace_id,lang,generation,revision) VALUES(?1,?2,?3,?4)",rusqlite::params![workspace,lang,generation,from]).unwrap();
                conn.execute("INSERT INTO workspace_file_versions(workspace_id,lang,generation,rel_path,blob_oid,input_kind,projection_digest,valid_from,valid_until) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",rusqlite::params![workspace,lang,generation,format!("invalid{index}.go"),oid,kind,(kind=="source").then_some(&projection),from,until]).unwrap();
                conn.execute("INSERT INTO go_package_files(package_id,file_version_id,source_role) VALUES(?1,?2,'go')",rusqlite::params![package,conn.last_insert_rowid()]).unwrap();
            }
            let visible: i64 = conn
                .query_row(
                    "SELECT count(*) FROM go_context_source_files WHERE context_id=?1",
                    [identity.context_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                visible, 2,
                "wrong workspace/language/generation/revision/kind must never join"
            );
            // A row whose interval ended at this revision is likewise excluded.
            conn.execute("UPDATE workspace_file_versions SET valid_until=?1 WHERE rel_path='provider/item.go' AND workspace_id=?2",rusqlite::params![selected_revision+1,selected_workspace]).unwrap();
            let shifted = selected_revision + 1;
            conn.execute("INSERT OR IGNORE INTO workspace_revisions(workspace_id,lang,generation,revision) VALUES(?1,'go',?2,?3)",rusqlite::params![selected_workspace,selected_generation,shifted]).unwrap();
            conn.execute(
                "UPDATE go_context_selections SET revision=?1 WHERE selection_id=?2",
                rusqlite::params![shifted, identity.selection_id],
            )
            .unwrap();
            let ended: i64 = conn.query_row("SELECT count(*) FROM go_context_source_files WHERE context_id=?1 AND rel_path='provider/item.go'",[identity.context_id],|row|row.get(0)).unwrap();
            assert_eq!(ended, 0);
        }
        #[test]
        fn go_context_readers_use_indexed_selection_and_input_access() {
            use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

            use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;
            use rusqlite::types::Value;
            let fixture = Fixture::new();
            let mut identities = Vec::new();
            for index in 0..48 {
                let mut discovery = fixture.discovery();
                discovery.build_tags.push(format!("profile{index}"));
                let profile = profile_digest(&discovery);
                identities.push((profile, fixture.publish(discovery, None)));
            }
            let (profile, identity) = &identities[24];
            let conn = fixture.store().conn.lock().unwrap();
            let mut selection = pinned("go_native_selected_context");
            selection.params = vec![
                Value::Text(fixture.snapshot.workspace_id.as_str().into()),
                Value::Integer(fixture.snapshot.generation.get()),
                Value::Integer(fixture.snapshot.revision),
                Value::Blob(profile.to_vec()),
                Value::Integer(DERIVATION_VERSION),
            ];
            let mut head = pinned("go_native_context_head");
            head.params = vec![
                Value::Integer(identity.selection_id),
                Value::Integer(identity.context_id),
                Value::Blob(identity.publication_digest.to_vec()),
            ];
            let mut inputs = pinned("go_native_observed_inputs");
            inputs.params = selection.params[..3].to_vec();
            let mut source_inventory = pinned("go_native_source_inventory");
            source_inventory.params = inputs.params.clone();
            let mut canonical_source = pinned("go_native_canonical_source");
            canonical_source.params = vec![
                inputs.params[0].clone(),
                inputs.params[1].clone(),
                Value::Text("consumer/use.go".into()),
                inputs.params[2].clone(),
            ];
            let mut prior = pinned("go_native_prior_heads");
            prior.params = inputs.params.clone();
            prior.params.push(Value::Integer(DERIVATION_VERSION));
            for state in brokk_bifrost_core::cache_gc::PlannerStatisticsState::BOTH {
                state.install(&conn);
                for query in [
                    &selection,
                    &head,
                    &inputs,
                    &prior,
                    &source_inventory,
                    &canonical_source,
                ] {
                    let plan = explain_pin(&conn, query);
                    assert!(
                        !plan.iter().any(|line| line.contains("SCAN s")
                            || line.contains("SCAN h")
                            || line.contains("SCAN p")
                            || line.contains("SCAN workspace_file_versions")
                            || line.contains("AUTOMATIC")
                            || line.contains("TEMP B-TREE")),
                        "{} {state:?}: {plan:?}",
                        query.name
                    );
                    if query.name == "go_native_canonical_source" {
                        assert!(
                            !plan.iter().any(|line| line.contains("SCAN f")),
                            "{state:?}: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|line| line.contains("SEARCH f")),
                            "{state:?}: {plan:?}"
                        );
                    }
                    if query.name == "go_native_observed_inputs" {
                        assert!(
                            plan.iter().any(|line| line
                                .contains("idx_workspace_file_versions_snapshot_kind")
                                || line.contains("sqlite_autoindex_workspace_file_versions_1")),
                            "{state:?}: {plan:?}"
                        );
                    }
                }
            }
        }
        #[test]
        fn go_context_publishes_fileless_standard_and_module_import_targets() {
            let fixture = Fixture::new();
            let mut discovery = fixture.discovery();
            discovery.packages[0].imports = vec!["strings".into(), "example.com/dep/pkg".into()];
            let standard_dir = fixture.project.root().join("external/stdlib/strings");
            let module_dir = fixture.project.root().join("external/module-cache/dep/pkg");
            discovery.packages.push(
                serde_json::from_value(json!({
                    "ImportPath": "strings",
                    "Name": "strings",
                    "Dir": standard_dir,
                    "Standard": true,
                    "GoFiles": ["strings.go"]
                }))
                .unwrap(),
            );
            discovery.packages.push(
                serde_json::from_value(json!({
                    "ImportPath": "example.com/dep/pkg",
                    "Name": "pkg",
                    "Dir": module_dir,
                    "Module": {
                        "Path": "example.com/dep",
                        "Version": "v1.2.3",
                        "Sum": "h1:dep",
                        "Dir": fixture.project.root().join("external/module-cache/dep"),
                        "GoMod": fixture.project.root().join("external/module-cache/dep/go.mod"),
                        "Main": false
                    },
                    "GoFiles": ["dep.go"]
                }))
                .unwrap(),
            );

            let identity = fixture.publish(discovery, None);
            let conn = fixture.store().read_conn().unwrap();
            let providers = conn
            .prepare("SELECT tool_import_path,package_name,provider_kind,provider_module_path,provider_module_version,complete,json(gaps) FROM go_package_instances WHERE context_id=?1 AND provider_kind<>'workspace' ORDER BY tool_import_path")
            .unwrap()
            .query_map([identity.context_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, bool>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
            assert_eq!(
                providers,
                vec![
                    (
                        "example.com/dep/pkg".into(),
                        "pkg".into(),
                        "module".into(),
                        Some("example.com/dep".into()),
                        Some("v1.2.3".into()),
                        true,
                        "[]".into(),
                    ),
                    (
                        "strings".into(),
                        "strings".into(),
                        "standard".into(),
                        None,
                        None,
                        true,
                        "[]".into(),
                    ),
                ]
            );
            let external_file_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM go_package_files files JOIN go_package_instances packages USING(package_id) WHERE packages.context_id=?1 AND packages.provider_kind<>'workspace'",
                [identity.context_id],
                |row| row.get(0),
            )
            .unwrap();
            assert_eq!(external_file_count, 0);
            let complete: bool = conn
                .query_row(
                    "SELECT complete FROM go_context_publications WHERE context_id=?1",
                    [identity.context_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(complete);
            for spelling in ["strings", "example.com/dep/pkg"] {
                let (name, import_path, complete): (String, String, bool) = conn
                .query_row(
                    "SELECT target.package_name,target.tool_import_path,imports.complete FROM go_package_imports imports JOIN go_package_instances target ON target.package_id=imports.target_package_id WHERE imports.context_id=?1 AND imports.source_spelling=?2",
                    rusqlite::params![identity.context_id, spelling],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
                assert!(complete, "{spelling}");
                assert_eq!(
                    name,
                    if spelling == "strings" {
                        "strings"
                    } else {
                        "pkg"
                    }
                );
                assert_eq!(import_path, spelling);
            }
        }

        #[brokk_bifrost_test_macros::hardwon(
            "4ac3ba049d81: go list ordered DepsErrors differently on every run, so an unchanged tree republished with new digests"
        )]
        #[test]
        fn go_context_publication_does_not_depend_on_the_tool_order_of_dependency_errors() {
            let fixture = Fixture::new();
            let errors = |order: [&str; 2]| {
                let mut discovery = fixture.discovery();
                discovery.packages[0].deps_errors = order
                    .into_iter()
                    .map(|err| {
                        serde_json::from_value(
                            json!({"Err": err, "ImportStack": ["example.test/root/consumer", err]}),
                        )
                        .unwrap()
                    })
                    .collect();
                discovery
            };
            let first = fixture.publish(errors(["first failure", "second failure"]), None);
            let second = fixture.publish(
                errors(["second failure", "first failure"]),
                Some(first.clone()),
            );
            assert_eq!(
                first.publication_digest, second.publication_digest,
                "the order of the tool's dependency errors is not an input"
            );
        }
        #[test]
        fn go_context_maps_source_spelling_and_keeps_missing_provider_partial() {
            let fixture = Fixture::new();
            let mut discovery = fixture.discovery();
            discovery.packages[0].import_map.insert(
                "visible/provider".into(),
                "example.test/root/provider".into(),
            );
            discovery.packages[0]
                .imports
                .push("external/missing".into());
            let identity = fixture.publish(discovery, None);
            let conn = fixture.store().read_conn().unwrap();
            let target: (String,bool) = conn.query_row("SELECT target.package_name,i.complete FROM go_package_imports i JOIN go_package_instances target ON target.package_id=i.target_package_id WHERE i.context_id=?1 AND i.source_spelling='visible/provider'",[identity.context_id],|row|Ok((row.get(0)?,row.get(1)?))).unwrap();
            assert_eq!(target, ("provider".into(), true));
            let missing: (Option<i64>,bool,String) = conn.query_row("SELECT target_package_id,complete,json(gaps) FROM go_package_imports WHERE context_id=?1 AND source_spelling='external/missing'",[identity.context_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
            assert_eq!(missing.0, None);
            assert!(!missing.1);
            assert!(missing.2.contains("incomplete_import_provider"));
            let member_count: i64 = conn
                .query_row(
                    "SELECT count(*) FROM go_context_source_files WHERE context_id=?1",
                    [identity.context_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(member_count, 2);
        }
        #[test]
        fn go_context_foreign_keys_reject_cross_context_imports() {
            let fixture = Fixture::new();
            let first = fixture.publish(fixture.discovery(), None);
            let mut partial = fixture.discovery();
            partial.packages[0].incomplete = true;
            let second = fixture.publish(partial, Some(first.clone()));
            let conn = fixture.store().conn.lock().unwrap();
            let package = |context| {
                conn.query_row(
                    "SELECT package_id FROM go_package_instances WHERE context_id=?1 LIMIT 1",
                    [context],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
            };
            let result = conn.execute("INSERT INTO go_package_imports(context_id,importer_package_id,source_spelling,import_role,target_package_id,complete,gaps) VALUES(?1,?2,'wrong','go',?3,0,jsonb('[]'))",params![first.context_id,package(first.context_id),package(second.context_id)]);
            assert!(
                matches!(result,Err(rusqlite::Error::SqliteFailure(error,_)) if error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY)
            );
        }
        #[test]
        fn go_context_conflicting_tool_identities_are_withheld() {
            let fixture = Fixture::new();
            let mut discovery = fixture.discovery();
            discovery.packages.push(discovery.packages[1].clone());
            let identity = fixture.publish(discovery, None);
            let conn = fixture.store().read_conn().unwrap();
            let count: i64 = conn.query_row("SELECT count(*) FROM go_package_instances WHERE context_id=?1 AND tool_import_path='example.test/root/provider'",[identity.context_id],|row|row.get(0)).unwrap();
            assert_eq!(count, 0);
            let complete: bool = conn
                .query_row(
                    "SELECT complete FROM go_context_publications WHERE context_id=?1",
                    [identity.context_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(!complete);
        }
    }
    mod go_move_14 {
        use crate::engine_tests::go_extraction::go_extraction_tests::go_move_11::{
            GO_SOURCE_PATH, GoResolutionOperationFixture,
        };

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredSemanticRole;

        use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::PreloadedFactResolutionService;

        use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated;

        use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: go_extraction_support_11 :: semantic_at ;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_operation :: resolution_operation_tests_go_support :: go_extraction_support_11 :: site_for_identifier ;

        use crate::engine_tests::go_extraction::go_extraction_tests::go_move_11::GO_ROOT_CONSUMER_PATH;
        use crate::engine_tests::go_extraction::go_extraction_tests::go_move_11::GoRootResolutionOperationFixture;
        use brokk_bifrost_analysis::native_resolution_test_support::SelectedTypedFactSource;
        #[test]
        fn selected_go_member_metadata_preserves_embeddings_receivers_and_indexed_access() {
            use brokk_bifrost_analysis::analyzer::resolution::fact_source::GoMemberDeclarationKind;

            use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

            use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;
            use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

            let mut source = String::from(
                "package consumer; type Contract interface { Call() }; type Base struct{}; type Box struct{ *Base; Method Base }; func (b Base) Value() {}; func (b *Base) Pointer() {}; ",
            );
            for index in 0..513 {
                source.push_str(&format!("type F{index} struct{{ Base }}; "));
            }
            for statistics in PlannerStatisticsState::BOTH {
                let fixture = GoRootResolutionOperationFixture::with_consumer(&source);
                fixture
                    .store
                    .conn
                    .execute(move |connection| statistics.install(connection));
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                let mount = operation
                    .mount_table()
                    .mount_for_path("go", GO_ROOT_CONSUMER_PATH)
                    .unwrap()
                    .unwrap();
                let lowered = brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                    mount.fragment(),
                    &operation.ready.shared_names(),
                    Language::Go,
                    &fixture.consumer_facts,
                );
                let definition = |name, namespace| {
                    semantic_at(
                        &lowered,
                        site_for_identifier(
                            &fixture.consumer_facts,
                            name,
                            ResolutionIdentifierRole::Declaration,
                            namespace,
                        ),
                        LoweredSemanticRole::Definition,
                    )
                };
                let contract = definition("Contract", ResolutionNamespace::Type);
                let base = definition("Base", ResolutionNamespace::Type);
                let boxed = definition("Box", ResolutionNamespace::Type);
                let contract_call = definition("Call", ResolutionNamespace::Callable);
                let value = definition("Value", ResolutionNamespace::Callable);
                let pointer = definition("Pointer", ResolutionNamespace::Callable);
                let mut definitions = lowered
                    .lexical()
                    .semantics()
                    .iter()
                    .filter(|row| row.role() == LoweredSemanticRole::Definition)
                    .map(|row| row.semantic())
                    .collect::<Vec<_>>();
                // Duplicate requests spanning batches must not duplicate embedding paths.
                definitions.push(boxed);
                let typed = operation.ready.typed_source();
                let lookup = |namespace| {
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::ResolutionLookupSemanticRecipe::new(
                        Language::Go,
                        namespace,
                        "Method",
                    )
                    .semantic(&operation.ready.shared_names())
                };
                let value_lookup = lookup(ResolutionNamespace::Value);
                let callable_lookup = lookup(ResolutionNamespace::Callable);
                let lookup_requests = [(mount.fragment(), value_lookup)];
                assert_eq!(
                    typed
                        .go_callable_lookups(&lookup_requests, &cancellation)
                        .unwrap()
                        .unwrap(),
                    vec![(value_lookup, callable_lookup)]
                );
                for requested in [
                    &[base, boxed, value, pointer, contract][..],
                    definitions.as_slice(),
                ] {
                    let rows = typed
                        .go_member_declarations(requested, &cancellation)
                        .unwrap()
                        .unwrap();
                    assert_eq!(rows.len(), if requested.len() == 5 { 5 } else { 519 });
                    let find = |definition| {
                        &rows
                            .iter()
                            .find(|row| row.definition == definition)
                            .unwrap()
                            .kind
                    };
                    let GoMemberDeclarationKind::Interface { methods } = find(contract) else {
                        panic!("Contract interface metadata")
                    };
                    let call_lookup =
                        brokk_bifrost_analysis::analyzer::resolution::local_identity::ResolutionLookupSemanticRecipe::new(
                            Language::Go,
                            ResolutionNamespace::Callable,
                            "Call",
                        )
                        .semantic(&operation.ready.shared_names());
                    assert!(methods.iter().any(|method| {
                        method.callable_lookup == call_lookup
                            && method.definition == Some(contract_call)
                    }));
                    assert_eq!(
                        find(base),
                        &GoMemberDeclarationKind::Struct { fields: vec![] }
                    );
                    let GoMemberDeclarationKind::Struct { fields } = find(boxed) else {
                        panic!("Box struct metadata")
                    };
                    assert_eq!(fields.len(), 2);
                    for (name, embedded) in [("Base", true), ("Method", false)] {
                        let lookup =
                            brokk_bifrost_analysis::analyzer::resolution::local_identity::ResolutionLookupSemanticRecipe::new(
                                Language::Go,
                                ResolutionNamespace::Callable,
                                name,
                            )
                            .semantic(&operation.ready.shared_names());
                        let field = fields
                            .iter()
                            .find(|field| field.callable_lookup == lookup)
                            .unwrap();
                        assert_eq!(field.embedded, embedded);
                        assert!(field.field.is_some());
                        assert!(field.value_type.is_some());
                    }
                    assert_eq!(
                        find(value),
                        &GoMemberDeclarationKind::Method {
                            pointer_receiver: Some(false)
                        }
                    );
                    assert_eq!(
                        find(pointer),
                        &GoMemberDeclarationKind::Method {
                            pointer_receiver: Some(true)
                        }
                    );
                    let plan = explain_pin(
                        operation.ready.inventory.connection(),
                        &pinned("go_member_declarations"),
                    );
                    for alias in [
                        "mount",
                        "interior",
                        "semantic",
                        "source",
                        "go_source",
                        "bridge",
                        "declaration",
                        "owner_type",
                        "field",
                        "field_bridge",
                        "field_semantic",
                        "value",
                        "callable",
                        "receiver",
                    ] {
                        assert!(
                            plan.iter()
                                .any(|detail| detail.starts_with(&format!("SEARCH {alias} "))),
                            "{alias} must use selected keys with {statistics}: {plan:#?}"
                        );
                    }
                    assert!(
                        plan.iter()
                            .any(|detail| detail.contains("source_go_fields_by_owner")),
                        "{statistics}: {plan:#?}"
                    );
                    assert!(
                        plan.iter().all(|detail| !detail.contains("AUTOMATIC")
                            && !detail.contains("TEMP B-TREE")),
                        "{statistics}: {plan:#?}"
                    );
                }
                let cancelled = CancellationToken::new();
                cancelled.cancel();
                assert!(
                    typed
                        .go_callable_lookups(&lookup_requests, &cancelled)
                        .unwrap()
                        .is_none()
                );
                assert!(
                    typed
                        .go_member_declarations(&definitions, &cancelled)
                        .unwrap()
                        .is_none()
                );
                assert_eq!(
                    typed
                        .go_member_declarations(&definitions, &cancellation)
                        .unwrap()
                        .unwrap()
                        .len(),
                    519
                );
            }
        }
        #[test]
        fn go_pointer_transfer_reopened_selection_matches_preload() {
            for binding in ["value := *p", "var value = *p"] {
                let source = format!(
                    "package sample; type Item struct{{}}; func f(p *Item) Item {{ {binding}; return value }}"
                );
                let fixture = GoResolutionOperationFixture::with_source(&source);
                let cancellation = CancellationToken::new();
                let operation = fixture.open_ready(&cancellation);
                let fragment = operation.mounts().unwrap()[0].fragment();
                drop(operation);
                let lowered = brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                    fragment,
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                    Language::Go,
                    &fixture.facts,
                );
                let site = site_for_identifier(
                    &fixture.facts,
                    "value",
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Value,
                );
                let reference = semantic_at(&lowered, site, LoweredSemanticRole::Reference);
                let item = semantic_at(
                    &lowered,
                    site_for_identifier(
                        &fixture.facts,
                        "Item",
                        ResolutionIdentifierRole::Declaration,
                        ResolutionNamespace::Type,
                    ),
                    LoweredSemanticRole::Definition,
                );
                let preload = PreloadedFactResolutionService::from_lowered_fragments(
                    [lowered.lexical().clone()],
                    [lowered.typed().clone()],
                );
                let expected = preload.resolve_reference(reference, &cancellation).unwrap();
                assert!(
                    expected.projected_frontiers().iter().any(|frontier| {
                        frontier.possible_values().iter().any(|value| {
                            value.ty().identity() == item && value.ty().indirection() == 0
                        })
                    }),
                    "dereference must retain the selected Item identity: {expected:?}"
                );
                let locator = SelectedSemanticLocator::new(
                    "go",
                    GO_SOURCE_PATH,
                    site,
                    LoweredSemanticRole::Reference,
                );
                // Independent selected operations hydrate the persisted transform rows each time.
                for _ in 0..2 {
                    let operation = fixture.open_ready(&cancellation);
                    let context = operation
                        .empty_contexts(&ResolutionCompletion::Complete)
                        .unwrap();
                    let mut metrics = SelectedResolutionContextMetrics;
                    let actual = operation
                        .resolve_reference(context, &locator, &cancellation, &mut metrics)
                        .unwrap();
                    let SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Found(actual),
                    ) = actual
                    else {
                        panic!("selected pointer fixture must resolve from its persisted bundle");
                    };
                    assert_eq!(actual, expected);
                }
            }
        }
    }
    mod go_move_15 {

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_analysis::analyzer::structural::qualified_paths::js_ts_tests_support::Fixture;

        use brokk_bifrost_analysis::analyzer::structural::qualified_paths::QualifiedPathDerivationOptions;

        use brokk_bifrost_core::analyzer::structural::routes::ALL_IDENTITY_AXES;

        #[test]
        fn unclaimed_language_reports_incomplete_axes() {
            let fixture = Fixture::new(Language::Go, "main.go", "package main\n\nfunc main() {}\n");
            let result = fixture.rows(QualifiedPathDerivationOptions::WITH_SEGMENT_RESOLUTION);

            assert!(result.paths.is_empty());
            assert!(!result.completeness.is_complete());
            for &axis in ALL_IDENTITY_AXES {
                assert!(
                    !result.completeness.covers(axis),
                    "an unclaimed adapter must not cover {axis}"
                );
            }
        }
    }
    mod go_move_16 {

        use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::structural::provider::StructuralFactsLimitedOutcome;

        use brokk_bifrost_analysis::analyzer::structural::provider::js_ts_tests_support::assert_limited_source_and_syntax_unavailable;

        use crate::inline_project::InlineTestProject;

        #[test]
        fn structural_provider_fanout_refuses_foreign_files_before_reading_or_parsing() {
            let sources = [
                ("A.java", "class A {}\n", Language::Java),
                ("a.go", "package a\nfunc run() {}\n", Language::Go),
                ("A.kt", "class A\n", Language::Kotlin),
                ("A.scala", "class A\n", Language::Scala),
            ];
            let mut project = InlineTestProject::new();
            for (path, source, _) in sources {
                project = project.file(path, source);
            }
            let fixture = project.build();
            let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
                fixture.project_dyn(),
                AnalyzerConfig::default(),
            )
            .expect("mixed-language workspace");
            let cancellation = CancellationToken::default();
            cancellation.cancel();
            for provider in workspace.analyzer().structural_fact_providers() {
                let before = provider.structural_extraction_count();
                for (path, source, language) in sources {
                    if provider.structural_language() == language {
                        continue;
                    }
                    let file = fixture.file(path);
                    assert!(provider.structural_source(&file).is_none());
                    assert!(provider.structural_facts(&file).is_none());
                    assert_limited_source_and_syntax_unavailable(provider, &file, 0);
                    assert!(matches!(
                        provider.structural_facts_limited(&file, source, 0, None),
                        StructuralFactsLimitedOutcome::Unavailable
                    ));
                    assert!(matches!(
                        provider.structural_facts_limited(&file, source, 0, Some(&cancellation)),
                        StructuralFactsLimitedOutcome::Cancelled
                    ));
                }
                assert_eq!(provider.structural_extraction_count(), before);
                let (path, source, _) = sources
                    .iter()
                    .find(|(_, _, language)| *language == provider.structural_language())
                    .expect("provider has an owned fixture");
                let facts = provider
                    .structural_facts(&fixture.file(path))
                    .expect("owning provider must still supply facts");
                assert_eq!(facts.source(), *source);
            }
        }
    }
    mod go_move_17 {

        use brokk_bifrost_analysis::analyzer::structural::reference_edges::test_support::Fixture;

        use brokk_bifrost_core::analyzer::structural::edges::OwnerRelation;

        use brokk_bifrost_analysis::analyzer::structural::reference_edges::classify_owner_relation;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_test_macros::hardwon;

        #[test]
        #[hardwon("#1645: named namespace owners were not compared by identity")]
        fn namespace_owners_are_compared_by_name() {
            let fixture = Fixture::new(
                Language::Go,
                &[
                    (
                        "main.go",
                        "package main\n\nfunc Drive() int { return Helper() }\n\nfunc Helper() int { return 1 }\n",
                    ),
                    (
                        "util/util.go",
                        "package util\n\nfunc Assist() int { return 1 }\n",
                    ),
                ],
            );
            let analyzer = fixture.analyzer();
            let drive = fixture.declaration("main.Drive");
            let helper = fixture.declaration("main.Helper");
            let assist = fixture.declaration("util.Assist");
            assert_eq!(
                classify_owner_relation(analyzer, Some(&drive), &helper),
                OwnerRelation::SameOwner,
                "both funcs hang off package `main`"
            );
            assert_eq!(
                classify_owner_relation(analyzer, Some(&drive), &assist),
                OwnerRelation::External,
                "`main` and `util` are different packages"
            );
        }
    }
    mod go_move_18 {

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_core::analyzer::structural::occurrences::ALL_OCCURRENCE_ROLES;

        use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::js_ts_tests_support::Fixture;

        use brokk_bifrost_analysis::analyzer::structural::occurrence_rows::OccurrenceCompleteness;

        use brokk_bifrost_core::analyzer::structural::occurrences::OccurrenceRole;

        /// An adapter that classifies some roles and not others reports incomplete
        /// for the roles it cannot name, and covers exactly the ones it can.
        ///
        /// Go declares `member_position` and `binder` (as of #3547) and nothing
        /// else, so the roles it stays silent about must never come back as a
        /// clean empty answer. This guard used to point at Scala, which declared no
        /// roles at all until #1597 graduated it, and then at PHP, which classifies
        /// every role its grammar establishes as of #2962.
        #[test]
        fn an_adapter_with_a_partial_role_table_reports_incomplete_not_empty_complete() {
            let source = concat!(
                "package widget\n",
                "\n",
                "type Helper struct{}\n",
                "\n",
                "func (h Helper) Build() int { return 1 }\n",
                "\n",
                "func Render(h Helper) int {\n",
                "\treturn h.Build()\n",
                "}\n",
            );
            let fixture = Fixture::new(Language::Go, "widget/widget.go", source);
            let result = fixture.result();

            let declared = [OccurrenceRole::MemberPosition, OccurrenceRole::Binder];
            assert!(
                result.rows.iter().all(|row| declared.contains(&row.role)),
                "go must publish only the roles it declares: {:?}",
                result.rows
            );
            match &result.completeness {
                OccurrenceCompleteness::Incomplete {
                    unsupported_roles, ..
                } => {
                    assert_eq!(
                        unsupported_roles.len(),
                        ALL_OCCURRENCE_ROLES.len() - declared.len()
                    );
                    for role in declared {
                        assert!(result.completeness.covers(role), "{role} is declared");
                    }
                    for role in ALL_OCCURRENCE_ROLES
                        .iter()
                        .filter(|role| !declared.contains(role))
                    {
                        assert!(!result.completeness.covers(*role), "{role} claimed covered");
                    }
                }
                OccurrenceCompleteness::Complete => {
                    panic!("an adapter with unsupported roles must never report Complete")
                }
            }
        }
    }
    mod go_move_19 {

        pub(super) use brokk_bifrost_analysis::analyzer::semantic_model::overlay::test_support::class;

        use brokk_bifrost_analysis::analyzer::semantic_model::model::Visibility;

        use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelSymbolKind;

        pub(super) use brokk_bifrost_analysis::analyzer::semantic_model::overlay::test_support::overlay;

        use brokk_bifrost_core::analyzer::model::Language;

        #[test]
        fn go_modeled_package_identity_uses_exact_declared_name_and_pack_provenance() {
            use brokk_bifrost_analysis::analyzer::languages::ModeledExternalPackageIdentity;

            use brokk_bifrost_analysis::analyzer::languages::language_support;

            let mut package = class("example.com/acme/codec", "go");
            package.kind = SemanticModelSymbolKind::Module;
            package.aliases = vec!["wire".to_owned()];
            package.provenance.pack_id = "go.api.codec".to_owned();
            package.provenance.pack_digest = "a1b2".to_owned();
            package.provenance.record_id = "package:codec".to_owned();
            let symbol_id = package.id.clone();
            let selected_overlay = overlay(vec![package.clone()], Vec::new());
            let go_support = language_support(Language::Go).expect("Go support is registered");
            let rejects = |package| {
                go_support
                    .modeled_external_package_identity(
                        &overlay(vec![package], Vec::new()),
                        "example.com/acme/codec",
                    )
                    .is_none()
            };

            assert_eq!(
                go_support
                    .modeled_external_package_identity(&selected_overlay, "example.com/acme/codec"),
                Some(ModeledExternalPackageIdentity {
                    package_name: "wire".to_owned(),
                    symbol_id,
                    pack_id: "go.api.codec".to_owned(),
                    pack_digest: "a1b2".to_owned(),
                    record_id: "package:codec".to_owned(),
                })
            );
            assert!(
                go_support
                    .modeled_external_package_identity(&selected_overlay, "example.com/acme/other")
                    .is_none(),
                "a different import path has no package authority"
            );

            let mut private_package = package.clone();
            private_package.visibility = Visibility::Private;
            assert!(
                rejects(private_package),
                "private package records do not authorize imports"
            );

            let mut other_language_package = package.clone();
            other_language_package.language = "rust".to_owned();
            assert!(
                rejects(other_language_package),
                "a package record owned by another language is not Go import authority"
            );

            let mut ambiguous_package = package;
            ambiguous_package.provenance.ambiguous = true;
            assert!(
                rejects(ambiguous_package),
                "ambiguous package provenance does not authorize imports"
            );
        }
    }
    mod go_move_20 {

        use brokk_bifrost_go_analysis::GoDependencyPackAdapter;

        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::test_support::HookBehavior;

        use crate::inline_project::InlineTestProject;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCoordinate;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogError;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogGoSourceReadLimits;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogGoSourceRequest;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogOptions;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackSelectorQuery;
        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::ArtifactSourceIdentity;
        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyArtifactRole;

        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyPackLimits;
        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyPackPreparationStatus;
        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyProvenance;
        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::ExactDependencyArtifact;
        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::ResolvedDependency;
        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::ResolvedDependencyArtifact;
        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::compile_exact_dependency_production;
        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepare_dependency_semantic_packs;
        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::prepared_exact_go_source;

        use brokk_bifrost_analysis::analyzer::semantic_model::dependency::test_support::HookFixture;

        use brokk_bifrost_analysis::analyzer::semantic_model::model::GoPinnedPackage;
        use brokk_bifrost_analysis::analyzer::semantic_model::producer::ExternalArtifactKind;
        use brokk_bifrost_analysis::analyzer::semantic_model::producer::read_exact_source_set;
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelActivationEvidence;
        use brokk_bifrost_core::cancellation::CancellationToken;
        use semver::Version;
        use std::path::Path;
        use std::path::PathBuf;
        const GO_SOURCE: &str = "package api\nfunc Value() int { return 7 }\n";
        const GO_SOURCE_SHA256: &str =
            "99d5982dbaecccf3d40d87607f92fd75f49e4e196cc664d61b96d85bf5c2d98b";
        fn selected_go_dependency(root: &Path) -> ResolvedDependency {
            ResolvedDependency::undeclared_scope(
                "go:module:example.test/source@v1.0.0".to_owned(),
                SemanticModelActivationEvidence {
                    language: "go".to_owned(),
                    ecosystem: "go-module".to_owned(),
                    package: None,
                    module: Some(CatalogCoordinate {
                        name: "example.test/source".to_owned(),
                        version: Some(Version::new(1, 0, 0)),
                    }),
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                },
                vec![DependencyProvenance {
                    key: "go.packages".to_owned(),
                    value: serde_json::json!([{
                        "import_path": "example.test/source/api",
                        "name": "api",
                        "directory": ".",
                        "files": ["api.go"],
                        "ignored_go_files": [],
                        "cgo_files": []
                    }])
                    .to_string(),
                }],
                vec![
                    ResolvedDependencyArtifact::source_set(
                        DependencyArtifactRole::Sources,
                        ExternalArtifactKind::GoSourceSet,
                        root.to_path_buf(),
                        vec![PathBuf::from("api.go")],
                    )
                    .with_source_identity(ArtifactSourceIdentity::from_digest("a".repeat(64))),
                ],
            )
        }
        #[test]
        fn prepared_exact_go_source_requires_package_name() {
            let project = InlineTestProject::new().file("api.go", GO_SOURCE).build();
            let limits = DependencyPackLimits::default();
            let artifact = read_exact_source_set(
                project.root(),
                &[PathBuf::from("api.go")],
                1,
                8,
                &limits.producer,
            )
            .unwrap();
            assert_eq!(artifact.sha256(), GO_SOURCE_SHA256);
            let artifacts = [ExactDependencyArtifact::from_exact(
                DependencyArtifactRole::Sources,
                ExternalArtifactKind::GoSourceSet,
                None,
                artifact,
            )];
            let valid = selected_go_dependency(project.root());
            let prepared = prepared_exact_go_source(&valid, &artifacts)
                .unwrap()
                .expect("named package metadata is accepted");
            assert_eq!(prepared.packages[0].name, "api");

            for name in [None, Some("")] {
                let mut dependency = valid.clone();
                let mut metadata: serde_json::Value =
                    serde_json::from_str(&dependency.provenance[0].value).unwrap();
                if let Some(name) = name {
                    metadata[0]["name"] = serde_json::json!(name);
                } else {
                    metadata[0].as_object_mut().unwrap().remove("name");
                }
                dependency.provenance[0].value = metadata.to_string();
                let error = match prepared_exact_go_source(&dependency, &artifacts) {
                    Err(CatalogError::Integrity(message)) => message,
                    _ => panic!("missing or empty Go package name must fail source preparation"),
                };
                assert!(error.contains("name"), "{error}");

                let catalog =
                    SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
                let outcome = prepare_dependency_semantic_packs(
                    &catalog,
                    &GoDependencyPackAdapter,
                    &[dependency],
                    &limits,
                    None,
                );
                assert!(!outcome.complete);
                assert!(outcome.packs.is_empty());
                assert!(outcome.evidence.is_empty());
                assert_eq!(outcome.profile.generated_packs, 0);
                assert!(
                    outcome.diagnostics.iter().any(|diagnostic| {
                        diagnostic.code == "go.source_registration"
                            && diagnostic.message.contains("name")
                    }),
                    "{:#?}",
                    outcome.diagnostics
                );
            }
        }
        #[test]
        fn exact_go_preparation_preserves_source_digest_through_reader_and_reuse() {
            let _hook = HookFixture::install(HookBehavior::RecordOnly);
            let project = InlineTestProject::new()
                .file("api.go", GO_SOURCE)
                .file("unselected.go", "package api\nfunc Unselected() {}\n")
                .build();
            let dependency = selected_go_dependency(project.root());
            let limits = DependencyPackLimits::default();
            let artifact = read_exact_source_set(
                project.root(),
                &[PathBuf::from("api.go")],
                1,
                8,
                &limits.producer,
            )
            .unwrap();
            assert_eq!(artifact.sha256(), GO_SOURCE_SHA256);
            let artifacts = [ExactDependencyArtifact::from_exact(
                DependencyArtifactRole::Sources,
                ExternalArtifactKind::GoSourceSet,
                None,
                artifact,
            )];
            let compiled = compile_exact_dependency_production(
                &GoDependencyPackAdapter,
                &dependency,
                &artifacts,
                &limits,
                None,
            )
            .unwrap();
            assert_ne!(compiled.key.input_digest(), GO_SOURCE_SHA256);
            assert_ne!(compiled.key.production_digest(), GO_SOURCE_SHA256);
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
            let reader = catalog.runtime_source_reader();

            for status in [
                DependencyPackPreparationStatus::Generated,
                DependencyPackPreparationStatus::Reused,
            ] {
                let outcome = prepare_dependency_semantic_packs(
                    &catalog,
                    &GoDependencyPackAdapter,
                    std::slice::from_ref(&dependency),
                    &limits,
                    None,
                );
                assert!(outcome.complete, "{outcome:#?}");
                assert!(outcome.diagnostics.is_empty(), "{outcome:#?}");
                assert_eq!(outcome.profile.artifacts_read, 1);
                assert_eq!(outcome.packs.len(), 1);
                let prepared = &outcome.packs[0];
                assert_eq!(prepared.status, status);
                assert_eq!(prepared.production.key, compiled.key);
                assert_eq!(
                    prepared.production.manifest_digest,
                    compiled.compiled.manifest.content_sha256
                );
                assert_eq!(
                    prepared.evidence.artifact_sha256.as_deref(),
                    Some(GO_SOURCE_SHA256)
                );
                assert_eq!(outcome.evidence, vec![prepared.evidence.clone()]);

                let query = SemanticPackSelectorQuery {
                    language: prepared.evidence.language.clone(),
                    ecosystem: prepared.evidence.ecosystem.clone(),
                    package: prepared.evidence.package.clone(),
                    module: prepared.evidence.module.clone(),
                    toolchain: prepared.evidence.toolchain.clone(),
                    target: prepared.evidence.target.clone(),
                    configuration: prepared.evidence.configuration.clone(),
                    artifact_sha256: prepared.evidence.artifact_sha256.clone(),
                    bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                };
                let candidates = catalog.candidates(&query).unwrap();
                assert_eq!(candidates.len(), 1);
                let loaded = catalog.load(&candidates[0]).unwrap();
                assert_eq!(
                    loaded.shard.activation()[0].artifact_sha256.as_deref(),
                    Some(GO_SOURCE_SHA256)
                );
                assert!(
                    catalog
                        .candidates(&SemanticPackSelectorQuery {
                            artifact_sha256: Some(compiled.key.input_digest().to_owned()),
                            ..query
                        })
                        .unwrap()
                        .is_empty()
                );

                let request = CatalogGoSourceRequest {
                    manifest_digest: &prepared.production.manifest_digest,
                    shard_id: &compiled.compiled.manifest.shards[0].shard_id,
                    artifact_sha256: GO_SOURCE_SHA256,
                    package_import_path: "example.test/source/api",
                    file: "api.go",
                };
                let selected = reader
                    .read_go_source(
                        &request,
                        CatalogGoSourceReadLimits::default(),
                        &CancellationToken::new(),
                    )
                    .unwrap()
                    .expect("prepared source is SQL-readable");
                assert_eq!(selected.artifact.sha256(), GO_SOURCE_SHA256);
                assert_eq!(selected.artifact.source_entries().len(), 1);
                assert_eq!(
                    selected.artifact.source_entries()[0].relative_path(),
                    "api.go"
                );
                assert_eq!(
                    selected.artifact.source_entries()[0].bytes(),
                    GO_SOURCE.as_bytes()
                );
                assert_eq!(
                    selected.packages,
                    vec![GoPinnedPackage {
                        import_path: "example.test/source/api".to_owned(),
                        name: "api".to_owned(),
                        files: vec!["api.go".to_owned()],
                    }]
                );
                assert!(
                    reader
                        .read_go_source(
                            &CatalogGoSourceRequest {
                                artifact_sha256: compiled.key.input_digest(),
                                ..request
                            },
                            CatalogGoSourceReadLimits::default(),
                            &CancellationToken::new(),
                        )
                        .unwrap()
                        .is_none()
                );
            }

            // The read-free metadata identity stays fixed as the selected bytes
            // change; another exact acquisition must produce a different key.
            let changed_source = "package api\nfunc Value() int { return 9 }\n";
            project.file("api.go").write(changed_source).unwrap();
            let changed_artifact = read_exact_source_set(
                project.root(),
                &[PathBuf::from("api.go")],
                1,
                8,
                &limits.producer,
            )
            .unwrap();
            assert_ne!(changed_artifact.sha256(), GO_SOURCE_SHA256);
            let changed = prepare_dependency_semantic_packs(
                &catalog,
                &GoDependencyPackAdapter,
                &[dependency],
                &limits,
                None,
            );
            assert!(changed.complete, "{changed:#?}");
            assert_eq!(changed.profile.artifacts_read, 1);
            assert_eq!(changed.packs.len(), 1);
            assert_eq!(
                changed.packs[0].status,
                DependencyPackPreparationStatus::Generated
            );
            assert_ne!(changed.packs[0].production.key, compiled.key);
            assert_eq!(
                changed.evidence[0].artifact_sha256.as_deref(),
                Some(changed_artifact.sha256())
            );
            let selected = reader
                .read_go_source(
                    &CatalogGoSourceRequest {
                        manifest_digest: &changed.packs[0].production.manifest_digest,
                        shard_id: &compiled.compiled.manifest.shards[0].shard_id,
                        artifact_sha256: changed_artifact.sha256(),
                        package_import_path: "example.test/source/api",
                        file: "api.go",
                    },
                    CatalogGoSourceReadLimits::default(),
                    &CancellationToken::new(),
                )
                .unwrap()
                .expect("changed selected source is SQL-readable");
            assert_eq!(
                selected.artifact.source_entries()[0].bytes(),
                changed_source.as_bytes()
            );
        }
    }
    mod go_move_21 {

        use brokk_bifrost_analysis :: analyzer :: semantic_model :: callable_values :: go_extraction_support_21 :: limits ;

        #[test]
        fn activated_sql_preserves_target_identity_from_another_selector_as_a_gap() {
            use brokk_bifrost_analysis::analyzer::semantic_model::*;

            use brokk_bifrost_analysis::analyzer::semantic_model::callable_values::ActivatedCallableValuesGap;

            use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesFact;

            use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesPayload;

            use brokk_bifrost_core::cancellation::CancellationToken;

            use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesPayload;

            use brokk_bifrost_analysis::analyzer::semantic_model::callable_values::activated_returned_callable_targets;

            use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

            use crate::inline_project::InlineTestProject;
            use brokk_bifrost_core::analyzer::model::Language;

            let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(include_bytes!(
                "../../../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
            ))
            .unwrap();
            authored.schema_version = CALLABLE_VALUES_MIN_SCHEMA_VERSION;
            authored.language = "go".to_owned();
            authored.ecosystem = "go".to_owned();
            authored.compatibility.bifrost = None;
            authored.compatibility.toolchains.clear();
            authored.shards[0].activation[0].package = Some(NameSelector {
                name: "example.test/module/pkg".to_owned(),
                version: None,
            });
            authored.shards[0].activation[0].targets.clear();
            authored.shards[0].activation[0].configurations.clear();
            let artifact_a = "a".repeat(64);
            let artifact_b = "b".repeat(64);
            authored.shards[0].activation[0].artifact_sha256 = Some(artifact_a.clone());
            let mut other_selector = authored.shards[0].activation[0].clone();
            other_selector.artifact_sha256 = Some(artifact_b.clone());
            authored.shards[0].activation.push(other_selector);
            let target_id = "go.literal.target".to_owned();
            authored.shards[0].callable_values = Some(CallableValuesPayload {
            facts: vec![CallableValuesFact {
                payload: CsmiCallableValuesPayload::ReturnedCallable {
                    callable: "member.widget.create".to_owned(),
                    result: 0,
                    target: target_id.clone(),
                },
                provenance: vec!["source-review".to_owned()],
            }],
            coverage: Vec::new(),
            anonymous_callables: vec![brokk_bifrost_analysis::analyzer::semantic_model::model::AnonymousCallableIdentity {
                id: target_id.clone(),
                artifact_sha256: artifact_b,
                package_identity: "example.test/module/pkg".to_owned(),
                anchor: brokk_bifrost_analysis::analyzer::semantic_model::model::SourceAnchor {
                    file: "callbacks.go".to_owned(),
                    byte_range: brokk_bifrost_analysis::analyzer::semantic_model::model::SourceByteRange {
                        start: 20,
                        end: 50,
                    },
                    kind: brokk_bifrost_analysis::analyzer::semantic_model::SourceDeclarationKind::FunctionLiteral,
                },
                lexical_owner_chain: Vec::new(),
                signature: brokk_bifrost_analysis::analyzer::semantic_model::model::SourceCallableShape {
                    function_type: brokk_bifrost_analysis::analyzer::semantic_model::model::SourceTypeNode {
                        file: "callbacks.go".to_owned(),
                        byte_range: brokk_bifrost_analysis::analyzer::semantic_model::model::SourceByteRange {
                            start: 20,
                            end: 30,
                        },
                    },
                    parameters: Vec::new(),
                    results: Vec::new(),
                    declaration_chain: Vec::new(),
                },
            }],
        });
            let compiled = compile_pack(&authored, &CompilerOptions::default()).unwrap();
            let root = tempfile::tempdir().unwrap();
            let catalog = SemanticPackCatalog::open(
                root.path(),
                CatalogOpenMode::ReadWrite,
                CatalogOptions::default(),
            )
            .unwrap();
            catalog
                .install(
                    &compiled,
                    &DurablePackSource {
                        kind: DurablePackSourceKind::Installed,
                        source_id: "fixture-go-publication".to_owned(),
                    },
                )
                .unwrap();
            let cancellation = CancellationToken::new();
            let active = match resolve_active_semantic_models(
                &catalog,
                &SemanticModelActivationRequest {
                    bifrost_version: semver::Version::new(0, 12, 0),
                    evidence: vec![SemanticModelActivationEvidence {
                        language: "go".to_owned(),
                        ecosystem: "go".to_owned(),
                        package: Some(CatalogCoordinate {
                            name: "example.test/module/pkg".to_owned(),
                            version: None,
                        }),
                        module: None,
                        toolchain: None,
                        target: None,
                        configuration: None,
                        artifact_sha256: Some(artifact_a),
                    }],
                    controls: Vec::new(),
                    limits: SemanticModelRuntimeLimits::default(),
                },
                &cancellation,
            ) {
                SemanticModelResolutionOutcome::Ready(active) => active,
                other => panic!("fixture activation must finish: {other:?}"),
            };
            let project = InlineTestProject::with_language(Language::Go)
                .file("probe.go", "package probe\n")
                .build();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let overlay =
                SemanticModelOverlay::build(workspace.analyzer(), &active, &cancellation, 1 << 26)
                    .unwrap();
            let factory = overlay
                .symbols()
                .iter()
                .find(|symbol| symbol.provenance.record_id == "member.widget.create")
                .expect("activated factory symbol");
            let query = activated_returned_callable_targets(
                &catalog,
                &active,
                factory,
                0,
                limits(64),
                &cancellation,
            )
            .unwrap();
            assert_eq!(
                query.gap,
                Some(ActivatedCallableValuesGap::TargetArtifactMismatch)
            );
            assert_eq!(query.publications.len(), 1);
            let row = &query.publications[0].rows.facts[0];
            let foreign_target_artifact = "b".repeat(64);
            assert_eq!(
                row.anonymous_callable
                    .as_ref()
                    .map(|identity| identity.artifact_sha256.as_str()),
                Some(foreign_target_artifact.as_str())
            );
            assert!(matches!(
                &row.fact.payload,
                CsmiCallableValuesPayload::ReturnedCallable { target, .. } if target == &target_id
            ));
        }
    }
    mod go_move_22 {

        use brokk_bifrost_go_analysis::analyze_go_package_source_identities;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::go_extraction_support_22::CALLABLE;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::go_extraction_support_22::DECLARATIONS;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::go_extraction_support_22::callback_location;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::go_extraction_support_22::install_fixture;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::go_extraction_support_22::query;

        use brokk_bifrost_analysis::analyzer::semantic_model::artifact::CompiledSemanticModelPack;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::ANONYMOUS_CALLABLE_IDENTITY_ANCHORS_SQL;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::ANONYMOUS_CALLABLE_IDENTITY_SHAPES_SQL;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCallableValuesQueryLimits;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCallableValuesQuestion;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogError;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogGoSourceReadLimits;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogGoSourceRequest;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogOptions;

        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::DurablePackSource;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::DurablePackSourceKind;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SessionPackSource;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SessionPackSourceKind;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::*;
        use brokk_bifrost_analysis::analyzer::semantic_model::compiler::CompilerOptions;
        use brokk_bifrost_analysis::analyzer::semantic_model::compiler::compile_pack;

        use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesPayload;

        use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCoverageStatus;

        use brokk_bifrost_analysis::analyzer::semantic_model::model::AnonymousCallableIdentity;
        use brokk_bifrost_analysis::analyzer::semantic_model::model::AuthoredSemanticModelPack;
        use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesCoverage;
        use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesFact;
        use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesFamily;
        use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesPayload;
        use brokk_bifrost_analysis::analyzer::semantic_model::model::GoPinnedPackage;
        use brokk_bifrost_analysis::analyzer::semantic_model::model::SourceAnchor;
        use brokk_bifrost_analysis::analyzer::semantic_model::producer::ArtifactProducerLimits;
        use brokk_bifrost_analysis::analyzer::semantic_model::producer::ExactArtifact;
        use brokk_bifrost_analysis::analyzer::semantic_model::producer::read_exact_source_set;
        use brokk_bifrost_core::cancellation::CancellationToken;
        use rusqlite::TransactionBehavior;

        use std::fs;
        use std::path::Path;
        use std::path::PathBuf;

        fn anonymous_source_fixture() -> (
            tempfile::TempDir,
            ExactArtifact,
            GoPinnedPackage,
            AnonymousCallableIdentity,
        ) {
            let directory = tempfile::tempdir().expect("Go source fixture directory");
            let root = directory
                .path()
                .canonicalize()
                .expect("canonical Go source root");
            fs::write(
            root.join("callbacks.go"),
            "package pkg\nfunc factory() func(int) int {\n return func(value int) int { return value }\n}\n",
        )
        .expect("write Go source fixture");
            let artifact = read_exact_source_set(
                &root,
                &[PathBuf::from("callbacks.go")],
                1,
                8,
                &ArtifactProducerLimits::default(),
            )
            .expect("exact Go source set");
            let package = GoPinnedPackage {
                import_path: "example.test/module/pkg".to_owned(),
                name: "pkg".to_owned(),
                files: vec!["callbacks.go".to_owned()],
            };
            let analysis = analyze_go_package_source_identities(&artifact, &package, 10_000, None);
            assert!(analysis.is_source_discovery_complete(), "{analysis:#?}");
            let literal = analysis
                .identities
                .iter()
                .find(|identity| {
                    identity.anchor.kind
                        == brokk_bifrost_go_analysis::GoSourceDeclarationKind::FunctionLiteral
                })
                .expect("anonymous callback literal is present");
            let identity = literal
                .anonymous_callable_identity("go.literal.returned-callback")
                .expect("literal signature is AST-backed");
            (directory, artifact, package, identity)
        }
        fn anonymous_callable_pack(
            identity: AnonymousCallableIdentity,
        ) -> CompiledSemanticModelPack {
            let mut authored: AuthoredSemanticModelPack =
                serde_json::from_slice(DECLARATIONS).expect("declaration fixture is valid");
            authored.schema_version = 10;
            authored.compatibility.bifrost = None;
            authored.language = "go".to_owned();
            authored.ecosystem = "go-module".to_owned();
            for selector in &mut authored.shards[0].activation {
                selector.artifact_sha256 = Some(identity.artifact_sha256.clone());
            }
            authored.shards[0].callable_values = Some(CallableValuesPayload {
                facts: vec![CallableValuesFact {
                    payload: CsmiCallableValuesPayload::ReturnedCallable {
                        callable: CALLABLE.to_owned(),
                        result: 0,
                        target: identity.id.clone(),
                    },
                    provenance: vec!["exact-go-source-fixture".to_owned()],
                }],
                coverage: vec![CallableValuesCoverage {
                    family: CallableValuesFamily::ReturnedCallables,
                    callable: CALLABLE.to_owned(),
                    status: CsmiCoverageStatus::Partial,
                    limitations: Vec::new(),
                    provenance: vec!["source-coverage".to_owned()],
                }],
                anonymous_callables: vec![identity],
            });
            compile_pack(&authored, &CompilerOptions::default()).expect("Go callable pack compiles")
        }
        #[test]
        fn anonymous_sql_rows_rebind_to_fresh_exact_go_ast_and_reject_bad_query_evidence() {
            let (_directory, artifact, package, identity) = anonymous_source_fixture();
            let pack = anonymous_callable_pack(identity.clone());
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
            catalog
                .install(
                    &pack,
                    &DurablePackSource {
                        kind: DurablePackSourceKind::Installed,
                        source_id: "anonymous-go-fixture".to_owned(),
                    },
                )
                .unwrap();
            catalog
                .install(
                    &pack,
                    &DurablePackSource {
                        kind: DurablePackSourceKind::Installed,
                        source_id: "anonymous-go-fixture-second".to_owned(),
                    },
                )
                .expect("repeated publication replaces anonymous identities and child anchors");
            let rows = catalog
                .query_callable_values(
                    &query(
                        &pack,
                        CatalogCallableValuesQuestion::ReturnedCallable { result: 0 },
                    ),
                    CatalogCallableValuesQueryLimits { max_records: 16 },
                    &CancellationToken::new(),
                )
                .unwrap();
            assert_eq!(rows.facts.len(), 1);
            let returned = &rows.facts[0];
            assert_eq!(returned.anonymous_callable.as_ref(), Some(&identity));
            let bound = brokk_bifrost_go_analysis::bind_catalog_go_anonymous_callable_target(
                returned,
                &artifact,
                &package,
                10_000,
                &CancellationToken::new(),
            )
            .expect("SQL-carried identity rebinds against the exact artifact");
            assert_eq!(bound.id(), identity.id);
            assert_eq!(SourceAnchor::from(&bound.source().anchor), identity.anchor);

            let mut missing_identity = returned.clone();
            missing_identity.anonymous_callable = None;
            assert_eq!(
                brokk_bifrost_go_analysis::bind_catalog_go_anonymous_callable_target(
                    &missing_identity,
                    &artifact,
                    &package,
                    10_000,
                    &CancellationToken::new(),
                ),
                Err(
                    brokk_bifrost_go_analysis::GoCatalogAnonymousCallableBindingError::MissingAnonymousTarget
                )
            );

            let mut wrong_target = returned.clone();
            let CsmiCallableValuesPayload::ReturnedCallable { target, .. } =
                &mut wrong_target.fact.payload
            else {
                panic!("returned-callable query produced another fact kind");
            };
            *target = "go.literal.unbound".to_owned();
            assert_eq!(
                brokk_bifrost_go_analysis::bind_catalog_go_anonymous_callable_target(
                    &wrong_target,
                    &artifact,
                    &package,
                    10_000,
                    &CancellationToken::new(),
                ),
                Err(brokk_bifrost_go_analysis::GoCatalogAnonymousCallableBindingError::TargetMismatch)
            );

            let canceled = CancellationToken::new();
            canceled.cancel();
            assert_eq!(
                brokk_bifrost_go_analysis::bind_catalog_go_anonymous_callable_target(
                    returned, &artifact, &package, 10_000, &canceled,
                ),
                Err(
                    brokk_bifrost_go_analysis::GoCatalogAnonymousCallableBindingError::Source(
                        brokk_bifrost_go_analysis::GoAnonymousCallableIdentityBindingError::Cancelled {
                            visited_nodes: 0
                        }
                    )
                )
            );
        }
        #[test]
        fn runtime_source_reader_reconstructs_exact_go_source_after_catalog_drop() {
            let (_directory, artifact, package, identity) = anonymous_source_fixture();
            let pack = anonymous_callable_pack(identity);
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
            catalog
                .install(
                    &pack,
                    &DurablePackSource {
                        kind: DurablePackSourceKind::Installed,
                        source_id: "exact-go-source-reader".to_owned(),
                    },
                )
                .unwrap();
            catalog
                .register_exact_go_source(
                    &pack.manifest.content_sha256,
                    &artifact,
                    std::slice::from_ref(&package),
                )
                .unwrap();
            let reader = catalog.runtime_source_reader();
            let request = CatalogGoSourceRequest {
                manifest_digest: &pack.manifest.content_sha256,
                shard_id: &pack.manifest.shards[0].shard_id,
                artifact_sha256: artifact.sha256(),
                package_import_path: &package.import_path,
                file: &package.files[0],
            };
            let canceled = CancellationToken::new();
            canceled.cancel();
            assert!(matches!(
                reader.read_go_source(&request, CatalogGoSourceReadLimits::default(), &canceled,),
                Err(CatalogError::Cancelled)
            ));
            let budget = reader.read_go_source(
                &request,
                CatalogGoSourceReadLimits {
                    max_files: 0,
                    ..CatalogGoSourceReadLimits::default()
                },
                &CancellationToken::new(),
            );
            assert!(matches!(
                budget,
                Err(CatalogError::SourceBudgetExhausted { max_files: 0, .. })
            ));
            let missing_file = reader
                .read_go_source(
                    &CatalogGoSourceRequest {
                        file: "missing.go",
                        ..request
                    },
                    CatalogGoSourceReadLimits::default(),
                    &CancellationToken::new(),
                )
                .unwrap();
            assert!(missing_file.is_none());
            let foreign_artifact = ExactArtifact::from_source_entries(
                PathBuf::from("<foreign exact Go source set>"),
                vec![("foreign.go".to_owned(), b"package foreign\n".to_vec())],
                8,
                &ArtifactProducerLimits::default(),
            )
            .unwrap();
            let foreign_package = GoPinnedPackage {
                import_path: "example.test/foreign/pkg".to_owned(),
                name: "foreign".to_owned(),
                files: vec!["foreign.go".to_owned()],
            };
            catalog
                .register_exact_go_source(
                    &pack.manifest.content_sha256,
                    &foreign_artifact,
                    std::slice::from_ref(&foreign_package),
                )
                .unwrap();
            assert!(
                reader
                    .read_go_source(
                        &CatalogGoSourceRequest {
                            artifact_sha256: foreign_artifact.sha256(),
                            package_import_path: &foreign_package.import_path,
                            file: &foreign_package.files[0],
                            ..request
                        },
                        CatalogGoSourceReadLimits::default(),
                        &CancellationToken::new(),
                    )
                    .unwrap()
                    .is_none(),
                "a source set registered under the manifest is unreadable without shard activation"
            );
            drop(catalog);

            let selected = reader
                .read_go_source(
                    &request,
                    CatalogGoSourceReadLimits::default(),
                    &CancellationToken::new(),
                )
                .unwrap()
                .expect("registered exact source set");
            assert_eq!(selected.artifact.sha256(), artifact.sha256());
            assert_eq!(selected.artifact.bytes(), artifact.bytes());
            assert_eq!(selected.packages, vec![package]);
            assert_eq!(
                selected.artifact.path(),
                Path::new("<catalog exact Go source set>")
            );
        }
        #[test]
        fn runtime_source_reader_bounds_stored_package_metadata_before_reconstruction() {
            for column in ["package_name", "import_path"] {
                let (_directory, artifact, package, identity) = anonymous_source_fixture();
                let pack = anonymous_callable_pack(identity);
                let catalog =
                    SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
                catalog
                    .install(
                        &pack,
                        &DurablePackSource {
                            kind: DurablePackSourceKind::Installed,
                            source_id: "bounded-go-source-metadata".to_owned(),
                        },
                    )
                    .unwrap();
                catalog
                    .register_exact_go_source(
                        &pack.manifest.content_sha256,
                        &artifact,
                        std::slice::from_ref(&package),
                    )
                    .unwrap();
                // A damaged catalog must be bounded before allocating or attempting
                // to validate this metadata as a package/source identity.
                catalog
                    .connection
                    .lock()
                    .unwrap()
                    .execute(
                        &format!("UPDATE catalog_exact_go_packages SET {column} = ?1"),
                        rusqlite::params!["x".repeat(4096)],
                    )
                    .unwrap();
                assert!(matches!(
                    catalog.runtime_source_reader().read_go_source(
                        &CatalogGoSourceRequest {
                            manifest_digest: &pack.manifest.content_sha256,
                            shard_id: &pack.manifest.shards[0].shard_id,
                            artifact_sha256: artifact.sha256(),
                            package_import_path: &package.import_path,
                            file: &package.files[0],
                        },
                        CatalogGoSourceReadLimits {
                            max_files: 8,
                            max_source_bytes: 2048,
                            ..CatalogGoSourceReadLimits::default()
                        },
                        &CancellationToken::new(),
                    ),
                    Err(CatalogError::SourceBudgetExhausted {
                        max_source_bytes: 2048,
                        ..
                    })
                ));
            }
        }
        #[test]
        fn session_compiled_pack_registration_publishes_exact_go_source_rows() {
            let (_directory, artifact, package, identity) = anonymous_source_fixture();
            let pack = anonymous_callable_pack(identity);
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
            catalog
                .register_compiled_pack_with_exact_go_source(
                    &pack,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::EphemeralWorkspace,
                        source_id: "exact-go-source-session".to_owned(),
                    },
                    &artifact,
                    std::slice::from_ref(&package),
                )
                .unwrap();
            let reader = catalog.runtime_source_reader();
            let selected = reader
                .read_go_source(
                    &CatalogGoSourceRequest {
                        manifest_digest: &pack.manifest.content_sha256,
                        shard_id: &pack.manifest.shards[0].shard_id,
                        artifact_sha256: artifact.sha256(),
                        package_import_path: &package.import_path,
                        file: &package.files[0],
                    },
                    CatalogGoSourceReadLimits::default(),
                    &CancellationToken::new(),
                )
                .unwrap()
                .expect("session exact source rows");
            assert_eq!(selected.artifact.sha256(), artifact.sha256());
            assert_eq!(selected.packages, vec![package]);
        }
        #[test]
        fn populated_callable_queries_pin_their_exact_lookup_indexes_with_and_without_statistics() {
            for state in brokk_bifrost_core::cache_gc::PlannerStatisticsState::BOTH {
                let (catalog, pack) = install_fixture();
                let manifest = &pack.manifest.content_sha256;
                let shard = &pack.manifest.shards[0].shard_id;
                let callback = callback_location(0);
                let callback_json = serde_json::to_string(&callback).unwrap();
                let source_artifact = "a".repeat(64);
                {
                    let mut connection = catalog.connection.lock().unwrap();
                    let transaction = connection
                        .transaction_with_behavior(TransactionBehavior::Immediate)
                        .unwrap();
                    {
                        let mut insert = transaction
                            .prepare_cached(
                                "INSERT INTO catalog_callable_value_facts(
                               manifest_digest, shard_id, fact_ordinal, family,
                               callable, result_ordinal, target, provenance_json
                             ) VALUES(?1, ?2, ?3, 'returned-callables', ?4, ?5, ?6, '[]')",
                            )
                            .unwrap();
                        for ordinal in 0_i64..2_048 {
                            let callable = if ordinal % 16 == 0 {
                                CALLABLE.to_owned()
                            } else {
                                format!("member.distractor.{}", ordinal % 127)
                            };
                            insert
                                .execute(rusqlite::params![
                                    manifest,
                                    shard,
                                    10_000 + ordinal,
                                    callable,
                                    ordinal % 4,
                                    CALLABLE,
                                ])
                                .unwrap();
                        }
                    }
                    {
                        let mut insert = transaction
                            .prepare_cached(
                                "INSERT INTO catalog_callable_value_facts(
                               manifest_digest, shard_id, fact_ordinal, family,
                               callable, callback_location_json, callback_parameters,
                               callback_results, arguments_json, timing, modality,
                               provenance_json
                             ) VALUES(?1, ?2, ?3, 'callback-invocations', ?4, ?5,
                                      ?6, ?7, '[]', 'during-call', 'may', '[]')",
                            )
                            .unwrap();
                        for ordinal in 0_i64..2_048 {
                            let callable = if ordinal % 16 == 0 {
                                CALLABLE.to_owned()
                            } else {
                                format!("member.distractor.{}", ordinal % 127)
                            };
                            insert
                                .execute(rusqlite::params![
                                    manifest,
                                    shard,
                                    20_000 + ordinal,
                                    callable,
                                    callback_json,
                                    ordinal % 4,
                                    ordinal % 3,
                                ])
                                .unwrap();
                        }
                    }
                    {
                        let mut insert = transaction
                            .prepare_cached(
                                "INSERT INTO catalog_callable_value_coverage(
                               manifest_digest, shard_id, coverage_ordinal, family,
                               callable, status, limitations_json, provenance_json
                             ) VALUES(?1, ?2, ?3, ?4, ?5, 'unknown', '[]', '[]')",
                            )
                            .unwrap();
                        for ordinal in 0_i64..512 {
                            let family = if ordinal % 2 == 0 {
                                "returned-callables"
                            } else {
                                "callback-invocations"
                            };
                            let callable = if ordinal % 16 == 0 {
                                CALLABLE.to_owned()
                            } else {
                                format!("member.distractor.{}", ordinal % 127)
                            };
                            insert
                                .execute(rusqlite::params![
                                    manifest,
                                    shard,
                                    10_000 + ordinal,
                                    family,
                                    callable
                                ])
                                .unwrap();
                        }
                    }
                    for ordinal in 0_i64..256 {
                        let identity_id = format!("go.literal.plan.{ordinal}");
                        let artifact_sha256 = format!("{ordinal:064x}");
                        transaction
                            .execute(
                                "INSERT INTO catalog_anonymous_callable_identities(
                               manifest_digest, shard_id, callable_id, artifact_sha256,
                               package_import_path, anchor_file, anchor_start, anchor_end,
                               anchor_kind, signature_file, signature_start, signature_end
                             ) VALUES(?1, ?2, ?3, ?4, 'example.test/module/pkg',
                                      'callbacks.go', 10, 50, 'function-literal',
                                      'callbacks.go', 10, 20)",
                                rusqlite::params![manifest, shard, identity_id, artifact_sha256],
                            )
                            .unwrap();
                        transaction
                            .execute(
                                "INSERT INTO catalog_anonymous_callable_identity_anchors(
                               manifest_digest, shard_id, callable_id, chain_kind,
                               ordinal, file, byte_start, byte_end, declaration_kind
                             ) VALUES(?1, ?2, ?3, 'signature_declaration', 0,
                                      'callbacks.go', 10, 20, 'function')",
                                rusqlite::params![manifest, shard, identity_id],
                            )
                            .unwrap();
                        transaction
                            .execute(
                                "INSERT INTO catalog_anonymous_callable_signature_shapes(
                               manifest_digest, shard_id, callable_id, shape_kind,
                               ordinal, file, byte_start, byte_end, variadic, arity
                             ) VALUES(?1, ?2, ?3, 'parameter', 0,
                                      'callbacks.go', 11, 15, 0, 1)",
                                rusqlite::params![manifest, shard, identity_id],
                            )
                            .unwrap();
                    }
                    transaction
                        .execute(
                            "INSERT INTO catalog_exact_go_source_sets(
                           manifest_digest, artifact_sha256
                         ) VALUES(?1, ?2)",
                            rusqlite::params![manifest, &source_artifact],
                        )
                        .unwrap();
                    transaction
                        .execute(
                            "INSERT INTO catalog_exact_go_packages(
                           manifest_digest, artifact_sha256, package_ordinal,
                           import_path, package_name
                         ) VALUES(?1, ?2, 0, 'example.test/module/pkg', 'pkg')",
                            rusqlite::params![manifest, &source_artifact],
                        )
                        .unwrap();
                    let mut source_insert = transaction
                        .prepare_cached(
                            "INSERT INTO catalog_exact_go_source_files(
                           manifest_digest, artifact_sha256, relative_path, source_text
                         ) VALUES(?1, ?2, ?3, 'package pkg\\n')",
                        )
                        .unwrap();
                    let mut membership_insert = transaction
                        .prepare_cached(
                            "INSERT INTO catalog_exact_go_package_files(
                           manifest_digest, artifact_sha256, package_ordinal,
                           file_ordinal, relative_path
                         ) VALUES(?1, ?2, 0, ?3, ?4)",
                        )
                        .unwrap();
                    for ordinal in 0_i64..256 {
                        let path = format!("pkg/{ordinal:04}.go");
                        source_insert
                            .execute(rusqlite::params![manifest, &source_artifact, &path])
                            .unwrap();
                        membership_insert
                            .execute(rusqlite::params![
                                manifest,
                                &source_artifact,
                                ordinal,
                                &path
                            ])
                            .unwrap();
                    }
                    drop(source_insert);
                    drop(membership_insert);
                    transaction.commit().unwrap();
                    state.install(&connection);
                    if state == brokk_bifrost_core::cache_gc::PlannerStatisticsState::Representative
                    {
                        // Catalog tables have no captured analyzer-store samples;
                        // analyze this populated catalog to exercise its own plans.
                        connection.execute_batch("ANALYZE;").unwrap();
                    }

                    let source_files_plan = connection
                        .prepare(
                            "EXPLAIN QUERY PLAN
                         SELECT relative_path, source_text
                         FROM catalog_exact_go_source_files
                              INDEXED BY catalog_exact_go_source_files_read
                         WHERE manifest_digest = ?1 AND artifact_sha256 = ?2
                         ORDER BY relative_path",
                        )
                        .unwrap()
                        .query_map(rusqlite::params![manifest, &source_artifact], |row| {
                            row.get::<_, String>(3)
                        })
                        .unwrap()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();
                    assert!(
                        source_files_plan
                            .iter()
                            .any(|line| line.contains("catalog_exact_go_source_files_read")),
                        "{state}: {source_files_plan:?}"
                    );
                    assert!(
                        !source_files_plan
                            .iter()
                            .any(|line| { line.contains("SCAN ") || line.contains("AUTOMATIC") }),
                        "{state}: {source_files_plan:?}"
                    );

                    let source_activation_plan = connection
                        .prepare(
                            "EXPLAIN QUERY PLAN
                         SELECT EXISTS(
                           SELECT 1
                           FROM catalog_selectors INDEXED BY catalog_selectors_artifact
                           WHERE manifest_digest = ?1
                             AND shard_id = ?2
                             AND artifact_sha256 = ?3)",
                        )
                        .unwrap()
                        .query_map(
                            rusqlite::params![manifest, shard, &source_artifact],
                            |row| row.get::<_, String>(3),
                        )
                        .unwrap()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();
                    assert!(
                    source_activation_plan
                        .iter()
                        .any(|line| {
                            line.starts_with(
                                "SEARCH catalog_selectors USING COVERING INDEX catalog_selectors_artifact ",
                            ) && line.contains(
                                "(artifact_sha256=? AND manifest_digest=? AND shard_id=?)",
                            )
                        }),
                    "{state}: {source_activation_plan:?}"
                );
                    assert!(
                        !source_activation_plan.iter().any(|line| {
                            (line.contains("SCAN ") && line != "SCAN CONSTANT ROW")
                                || line.contains("AUTOMATIC")
                        }),
                        "{state}: {source_activation_plan:?}"
                    );

                    let package_plan = connection
                        .prepare(
                            "EXPLAIN QUERY PLAN
                         SELECT package_ordinal, import_path, package_name
                         FROM catalog_exact_go_packages
                              INDEXED BY catalog_exact_go_packages_read
                         WHERE manifest_digest = ?1 AND artifact_sha256 = ?2
                         ORDER BY package_ordinal",
                        )
                        .unwrap()
                        .query_map(rusqlite::params![manifest, &source_artifact], |row| {
                            row.get::<_, String>(3)
                        })
                        .unwrap()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();
                    assert!(
                        package_plan
                            .iter()
                            .any(|line| line.contains("catalog_exact_go_packages_read")),
                        "{state}: {package_plan:?}"
                    );
                    assert!(
                        !package_plan
                            .iter()
                            .any(|line| { line.contains("SCAN ") || line.contains("AUTOMATIC") }),
                        "{state}: {package_plan:?}"
                    );

                    let package_files_plan = connection
                        .prepare(
                            "EXPLAIN QUERY PLAN
                         SELECT package_ordinal, file_ordinal, relative_path
                         FROM catalog_exact_go_package_files
                              INDEXED BY catalog_exact_go_package_files_ordered_read
                         WHERE manifest_digest = ?1 AND artifact_sha256 = ?2
                         ORDER BY package_ordinal, file_ordinal",
                        )
                        .unwrap()
                        .query_map(rusqlite::params![manifest, &source_artifact], |row| {
                            row.get::<_, String>(3)
                        })
                        .unwrap()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();
                    assert!(
                        package_files_plan.iter().any(|line| {
                            line.contains("catalog_exact_go_package_files_ordered_read")
                        }),
                        "{state}: {package_files_plan:?}"
                    );
                    assert!(
                        !package_files_plan
                            .iter()
                            .any(|line| { line.contains("SCAN ") || line.contains("AUTOMATIC") }),
                        "{state}: {package_files_plan:?}"
                    );

                    let returned = connection
                        .prepare(&format!(
                            "EXPLAIN QUERY PLAN {CALLABLE_VALUES_RETURNED_SQL}"
                        ))
                        .unwrap()
                        .query_map(
                            rusqlite::params![manifest, shard, CALLABLE, 0_i64, 16_i64],
                            |row| row.get::<_, String>(3),
                        )
                        .unwrap()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();
                    assert!(
                        returned.iter().any(|line| line.contains(
                            "SEARCH fact USING INDEX catalog_callable_value_returned_lookup"
                        )),
                        "{state}: {returned:?}"
                    );
                    assert!(
                        !returned.iter().any(|line| {
                            line.contains("SCAN fact") || line.contains("AUTOMATIC")
                        }),
                        "{state}: {returned:?}"
                    );

                    let callbacks = connection
                        .prepare(&format!(
                            "EXPLAIN QUERY PLAN {CALLABLE_VALUES_CALLBACK_SQL}"
                        ))
                        .unwrap()
                        .query_map(
                            rusqlite::params![
                                manifest,
                                shard,
                                CALLABLE,
                                callback_json,
                                1_i64,
                                1_i64,
                                16_i64
                            ],
                            |row| row.get::<_, String>(3),
                        )
                        .unwrap()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();
                    assert!(
                        callbacks.iter().any(|line| line.contains(
                            "SEARCH fact USING INDEX catalog_callable_value_callback_lookup"
                        )),
                        "{state}: {callbacks:?}"
                    );
                    assert!(
                        !callbacks.iter().any(|line| {
                            line.contains("SCAN fact") || line.contains("AUTOMATIC")
                        }),
                        "{state}: {callbacks:?}"
                    );

                    let coverage = connection
                        .prepare(&format!(
                            "EXPLAIN QUERY PLAN {CALLABLE_VALUES_COVERAGE_SQL}"
                        ))
                        .unwrap()
                        .query_map(
                            rusqlite::params![
                                manifest,
                                shard,
                                "returned-callables",
                                CALLABLE,
                                16_i64
                            ],
                            |row| row.get::<_, String>(3),
                        )
                        .unwrap()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();
                    assert!(
                        coverage.iter().any(|line| line.contains(
                            "SEARCH coverage USING INDEX catalog_callable_value_coverage_lookup"
                        )),
                        "{state}: {coverage:?}"
                    );
                    assert!(
                        !coverage.iter().any(|line| {
                            line.contains("SCAN coverage") || line.contains("AUTOMATIC")
                        }),
                        "{state}: {coverage:?}"
                    );

                    let anonymous_base = connection
                        .prepare(&format!(
                            "EXPLAIN QUERY PLAN {ANONYMOUS_CALLABLE_IDENTITY_SQL}"
                        ))
                        .unwrap()
                        .query_map(
                            rusqlite::params![manifest, shard, "go.literal.plan.0"],
                            |row| row.get::<_, String>(3),
                        )
                        .unwrap()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap();
                    assert!(
                    anonymous_base.iter().any(|line| line.contains(
                        "SEARCH identity USING INDEX sqlite_autoindex_catalog_anonymous_callable_identities_1"
                    )),
                    "{state}: {anonymous_base:?}"
                );
                    assert!(
                        !anonymous_base.iter().any(|line| {
                            line.contains("SCAN ")
                                || line.contains("AUTOMATIC")
                                || line.contains("TEMP B-TREE")
                                || line.contains("CO-ROUTINE")
                        }),
                        "{state}: {anonymous_base:?}"
                    );

                    for (reader_sql, table_name) in [
                        (
                            ANONYMOUS_CALLABLE_IDENTITY_ANCHORS_SQL,
                            "catalog_anonymous_callable_identity_anchors",
                        ),
                        (
                            ANONYMOUS_CALLABLE_IDENTITY_SHAPES_SQL,
                            "catalog_anonymous_callable_signature_shapes",
                        ),
                    ] {
                        let children = connection
                            .prepare(&format!("EXPLAIN QUERY PLAN {reader_sql}"))
                            .unwrap()
                            .query_map(
                                rusqlite::params![manifest, shard, "go.literal.plan.0", 16_i64],
                                |row| row.get::<_, String>(3),
                            )
                            .unwrap()
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap();
                        let expected_index = format!(
                            "SEARCH {table_name} USING INDEX sqlite_autoindex_{table_name}_1"
                        );
                        assert!(
                            children.iter().any(|line| line.contains(&expected_index)),
                            "{state}: {children:?}"
                        );
                        assert!(
                            !children.iter().any(|line| {
                                line.contains("SCAN ")
                                    || line.contains("AUTOMATIC")
                                    || line.contains("TEMP B-TREE")
                                    || line.contains("CO-ROUTINE")
                            }),
                            "{state}: {children:?}"
                        );
                    }
                }
            }
        }
    }
    mod go_move_23 {

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_analysis::analyzer::store::resolution_selection::selection_test_support::SelectionFixture;

        use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredDeclarationTypeProperty;

        use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredIntrinsicSeed;

        use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredTypeTransfer;

        use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredTypedFragment;

        use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredTypedFrontier;

        use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

        use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionIncompleteReason;

        use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionSlotValue;

        use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionTypeRef;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedResolutionMountOrdinal;

        use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

        use brokk_bifrost_analysis::analyzer::resolution::model::TypeTransferRule;

        use brokk_bifrost_analysis::analyzer::resolution::model::TypeTransferValueTransform;

        use brokk_bifrost_analysis::analyzer::resolution::fact_source::TypedFactRequest;

        use brokk_bifrost_analysis::analyzer::resolution::model::TypedFrontierState;

        use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::VISIT_TYPE_TRANSFER_PAGES_FROM_SOURCES_SQL;

        use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::VISIT_TYPE_TRANSFER_PAGES_TO_TARGETS_SQL;

        use brokk_bifrost_analysis :: analyzer :: store :: resolution_stage :: typed :: typed_tests_go_support :: go_extraction_support_23 :: begin_projection ;

        use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::decode_declaration_type;

        use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::decode_transfer;

        use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::insert_typed_fragment;

        use brokk_bifrost_analysis::analyzer::store::resolution_stage::typed::semantic_request_json;

        use brokk_bifrost_test_macros::hardwon;

        use brokk_bifrost_core::analyzer::resolution_facts::DeclarationTypeRole;
        use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotRole;
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeTransferKind;
        #[test]
        #[hardwon(
            "#5015: local writes need one multi-input value producer without weakening Assignment exclusivity"
        )]
        fn value_join_stage_roundtrip_retains_inputs_completion_and_exclusive_assignment() {
            let collection = SemanticId::context_local(5009);
            let borrowed_operand = SemanticId::context_local(5008);
            let initializer = SemanticId::context_local(5010);
            let write = SemanticId::context_local(5011);
            let joined = SemanticId::context_local(5012);
            let assignment = SemanticId::context_local(5013);
            let unsupported = SemanticId::context_local(5014);
            let initializer_assignment = SemanticId::context_local(5024);
            let joined_definition = SemanticId::context_local(5025);
            let initializer_definition = SemanticId::context_local(5026);
            let declaration_types = vec![
                LoweredDeclarationTypeProperty::new(
                    joined_definition,
                    assignment,
                    DeclarationTypeRole::ObservedValue,
                ),
                LoweredDeclarationTypeProperty::new(
                    joined_definition,
                    SemanticId::context_local(5027),
                    DeclarationTypeRole::Value,
                ),
                LoweredDeclarationTypeProperty::new(
                    initializer_definition,
                    initializer_assignment,
                    DeclarationTypeRole::ObservedValue,
                ),
            ];
            let frontiers = vec![
                LoweredTypedFrontier::new(collection, ResolutionTypeSlotRole::TargetTypeIdentity),
                LoweredTypedFrontier::new(
                    borrowed_operand,
                    ResolutionTypeSlotRole::ExpressionValue,
                ),
                LoweredTypedFrontier::new(initializer, ResolutionTypeSlotRole::ExpressionValue),
                LoweredTypedFrontier::new(write, ResolutionTypeSlotRole::CallResult),
                LoweredTypedFrontier::new(joined, ResolutionTypeSlotRole::ExpressionValue),
                LoweredTypedFrontier::new(assignment, ResolutionTypeSlotRole::AssignmentValue),
                LoweredTypedFrontier::new(
                    initializer_assignment,
                    ResolutionTypeSlotRole::AssignmentValue,
                ),
                LoweredTypedFrontier::new(
                    SemanticId::context_local(5027),
                    ResolutionTypeSlotRole::DeclaredValue,
                ),
            ];
            let seed = LoweredIntrinsicSeed::new(
                IntrinsicTypeKind::Primitive,
                "int",
                TypedFrontierState::new(
                    collection,
                    vec![ResolutionSlotValue::type_object(ResolutionTypeRef::new(
                        SemanticId::context_local(5015),
                        0,
                    ))],
                    ResolutionCompletion::Complete,
                ),
            );
            let rebuild = |transfers| {
                LoweredTypedFragment::new(
                    BindingFragmentId::at_ordinal(7),
                    Language::Go,
                    frontiers.clone(),
                    transfers,
                    vec![seed.clone()],
                    vec![],
                    vec![],
                    declaration_types.clone(),
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                )
            };
            for completion in [
                ResolutionCompletion::Complete,
                ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(unsupported),
                ]),
            ] {
                let fragment = rebuild(vec![
                    LoweredTypeTransfer::new(
                        borrowed_operand,
                        ResolutionTypeTransferKind::AddressOf,
                        TypeTransferRule::new_with_reference_indirection(
                            SemanticId::context_local(5029),
                            write,
                            1,
                            1,
                            TypeTransferValueTransform::ToRuntime { addressable: false },
                            ResolutionCompletion::Complete,
                        ),
                    ),
                    LoweredTypeTransfer::new(
                        collection,
                        ResolutionTypeTransferKind::ComponentValue,
                        TypeTransferRule::new(
                            SemanticId::context_local(5019),
                            initializer,
                            0,
                            TypeTransferValueTransform::ToRuntime { addressable: true },
                            ResolutionCompletion::Complete,
                        ),
                    ),
                    LoweredTypeTransfer::new(
                        initializer,
                        ResolutionTypeTransferKind::Assignment,
                        TypeTransferRule::new(
                            SemanticId::context_local(5028),
                            initializer_assignment,
                            0,
                            TypeTransferValueTransform::Preserve,
                            ResolutionCompletion::Complete,
                        ),
                    ),
                    LoweredTypeTransfer::new(
                        initializer,
                        ResolutionTypeTransferKind::ValueJoin,
                        TypeTransferRule::new(
                            SemanticId::context_local(5020),
                            joined,
                            0,
                            TypeTransferValueTransform::Preserve,
                            ResolutionCompletion::Complete,
                        ),
                    ),
                    LoweredTypeTransfer::new(
                        write,
                        ResolutionTypeTransferKind::ValueJoin,
                        TypeTransferRule::new(
                            SemanticId::context_local(5021),
                            joined,
                            0,
                            TypeTransferValueTransform::Preserve,
                            completion.clone(),
                        ),
                    ),
                    LoweredTypeTransfer::new(
                        joined,
                        ResolutionTypeTransferKind::Assignment,
                        TypeTransferRule::new(
                            SemanticId::context_local(5022),
                            assignment,
                            0,
                            TypeTransferValueTransform::Preserve,
                            ResolutionCompletion::Complete,
                        ),
                    ),
                ]);
                let fixture = SelectionFixture::shared_blob(16);
                let selection = fixture.open_ready(&[]);
                let connection = begin_projection(&selection);
                assert!(
                    insert_typed_fragment(
                        connection,
                        1,
                        SelectedResolutionMountOrdinal::new(7),
                        &fragment,
                        &CancellationToken::new(),
                    )
                    .unwrap()
                );
                let mut statement = connection
            .prepare("SELECT *,json(completion) AS completion_json FROM temp.selected_resolution_stage_type_transfers ORDER BY sequence")
            .unwrap();
                let decoded = statement
                    .query_map([], |row| Ok(decode_transfer(row).unwrap()))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(decoded, fragment.transfers());
                let mut statement = connection
            .prepare(
                "SELECT * FROM temp.selected_resolution_stage_declaration_types ORDER BY sequence",
            )
            .unwrap();
                let decoded_properties = statement
                    .query_map([], |row| Ok(decode_declaration_type(row).unwrap()))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(decoded_properties, fragment.declaration_types());
                assert!(decoded_properties.iter().any(|property| {
                    property.definition() == initializer_definition
                        && property.slot() == initializer_assignment
                        && property.role() == DeclarationTypeRole::ObservedValue
                }));
                assert!(decoded_properties.iter().any(|property| {
                    property.definition() == joined_definition
                        && property.slot() == SemanticId::context_local(5027)
                        && property.role() == DeclarationTypeRole::Value
                }));
                let hydrated = rebuild(decoded);
                assert_eq!(hydrated, fragment);
                for (sql, slots, expected_count) in [
                    (
                        VISIT_TYPE_TRANSFER_PAGES_FROM_SOURCES_SQL,
                        vec![initializer, write, borrowed_operand],
                        4,
                    ),
                    (VISIT_TYPE_TRANSFER_PAGES_TO_TARGETS_SQL, vec![joined], 2),
                    (
                        VISIT_TYPE_TRANSFER_PAGES_TO_TARGETS_SQL,
                        vec![initializer],
                        1,
                    ),
                    (
                        VISIT_TYPE_TRANSFER_PAGES_TO_TARGETS_SQL,
                        vec![initializer_assignment],
                        1,
                    ),
                    (
                        VISIT_TYPE_TRANSFER_PAGES_TO_TARGETS_SQL,
                        vec![assignment],
                        1,
                    ),
                ] {
                    let mut statement = connection.prepare(sql).unwrap();
                    let rows = statement
                        .query_map(
                            [semantic_request_json(TypedFactRequest::new(&slots))],
                            |row| Ok(decode_transfer(row).unwrap()),
                        )
                        .unwrap()
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .unwrap();
                    assert_eq!(rows.len(), expected_count);
                    for row in rows {
                        assert!(fragment.transfers().contains(&row));
                        if row.source_slot() == write {
                            assert_eq!(row.rule().completion(), &completion);
                        }
                    }
                }
                for (source, target, kind) in [
                    (write, assignment, ResolutionTypeTransferKind::Assignment),
                    (write, joined, ResolutionTypeTransferKind::ExpressionResult),
                ] {
                    let mut invalid = hydrated.transfers().to_vec();
                    invalid.push(LoweredTypeTransfer::new(
                        source,
                        kind,
                        TypeTransferRule::new(
                            SemanticId::context_local(5023),
                            target,
                            0,
                            TypeTransferValueTransform::Preserve,
                            ResolutionCompletion::Complete,
                        ),
                    ));
                    assert!(
                        std::panic::catch_unwind(|| rebuild(invalid)).is_err(),
                        "hydration must reject a second producer: {kind:?}"
                    );
                }
                let invalid_address_of = hydrated
                    .transfers()
                    .iter()
                    .cloned()
                    .map(|transfer| {
                        if transfer.kind() != ResolutionTypeTransferKind::AddressOf {
                            return transfer;
                        }
                        LoweredTypeTransfer::new(
                            transfer.source_slot(),
                            transfer.kind(),
                            TypeTransferRule::new_with_reference_indirection(
                                transfer.rule().semantic(),
                                transfer.rule().target_slot(),
                                1,
                                1,
                                TypeTransferValueTransform::RuntimeOnly,
                                transfer.rule().completion().clone(),
                            ),
                        )
                    })
                    .collect();
                assert!(
                    std::panic::catch_unwind(|| rebuild(invalid_address_of)).is_err(),
                    "address-of must reject a cross-product of pointer and reference transforms"
                );
                connection.execute_batch("ROLLBACK").unwrap();
            }
        }
    }
    mod go_move_26 {

        use brokk_bifrost_go_analysis::GoArtifactCallableTarget;

        use crate::analyzer::semantic::capabilities::SemanticCapability;

        use brokk_bifrost_semantic::analyzer::semantic::ids::EvidenceId;

        use brokk_bifrost_semantic::analyzer::semantic::ids::ProcedureId;

        use brokk_bifrost_semantic::analyzer::semantic::ids::SourceMappingId;

        use brokk_bifrost_semantic::analyzer::semantic::ids::ValueId;

        use brokk_bifrost_analysis::analyzer::semantic::ir::go_extraction_support_26::capabilities;

        use brokk_bifrost_analysis::analyzer::semantic::ir::go_extraction_support_26::key;

        use brokk_bifrost_analysis::analyzer::semantic::ir::go_extraction_support_26::minimal_procedure;

        use brokk_bifrost_analysis::analyzer::semantic::ir::artifact::SemanticArtifact;

        use brokk_bifrost_analysis::analyzer::semantic::ir::model::ArtifactCallableTarget;

        use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableReferenceKind;
        use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableTarget;
        use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableTargetResolution;
        use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableValue;

        use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticEffect;
        use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticEvent;

        use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticIrErrorKind;
        use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticValue;
        use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticValueKind;

        #[test]
        fn artifact_callable_identity_is_bound_source_evidence_and_not_lexical_creation() {
            use brokk_bifrost_go_analysis::analyzer::go::GoPinnedPackage;

            use brokk_bifrost_go_analysis::analyzer::go::GoSourceDeclarationKind;

            use brokk_bifrost_go_analysis::analyzer::go::analyze_go_package_source_identities;

            use brokk_bifrost_go_analysis::analyzer::go::bind_go_anonymous_callable_identity;

            use brokk_bifrost_semantic::analyzer::semantic_model::producer::ArtifactProducerLimits;

            use brokk_bifrost_semantic::analyzer::semantic_model::producer::read_exact_source_set;
            let root = tempfile::tempdir().unwrap();
            std::fs::write(
                root.path().join("factory.go"),
                "package external\nfunc Factory() func() int { return func() int { return 1 } }\n",
            )
            .unwrap();
            let source = read_exact_source_set(
                root.path(),
                &["factory.go".into()],
                1,
                1,
                &ArtifactProducerLimits::default(),
            )
            .unwrap();
            let package = GoPinnedPackage {
                import_path: "example.test/external".into(),
                name: "external".into(),
                files: vec!["factory.go".into()],
            };
            let analysis = analyze_go_package_source_identities(&source, &package, 10_000, None);
            assert!(analysis.gaps.is_empty(), "{:?}", analysis.gaps);
            let literal = analysis
                .identities
                .iter()
                .find(|declaration| {
                    declaration.anchor.kind == GoSourceDeclarationKind::FunctionLiteral
                })
                .unwrap();
            let identity = literal.anonymous_callable_identity("literal").unwrap();
            let bound =
                bind_go_anonymous_callable_identity(&source, &package, &identity, 10_000, None)
                    .unwrap();
            let target = ArtifactCallableTarget::from_bound_go_identity(&bound);
            assert_eq!(target.identity(), &identity);

            let key = key();
            let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
            parts.values.push(SemanticValue {
                id: ValueId::new(0),
                kind: SemanticValueKind::Callable,
                source: SourceMappingId::new(0),
                evidence: EvidenceId::new(0),
            });
            let callable = CallableValue {
                kind: CallableReferenceKind::Function,
                targets: CallableTargetResolution::Proven(CallableTarget::Artifact(target)),
                target_evidence: EvidenceId::new(0),
                bound_receiver: None,
                environment: None,
            };
            let mut events = parts.points[0].events.to_vec();
            events.push(SemanticEvent::new(
                SemanticEffect::CallableReference {
                    result: ValueId::new(0),
                    callable: callable.clone(),
                },
                SourceMappingId::new(0),
                EvidenceId::new(0),
            ));
            parts.points[0].events = events.into_boxed_slice();
            let capabilities = capabilities(&[
                SemanticCapability::Values,
                SemanticCapability::CallableReferences,
            ]);
            let artifact =
                SemanticArtifact::try_new(key.clone(), capabilities.clone(), vec![parts.clone()])
                    .unwrap();
            assert!(
                artifact.work().owned_text_bytes
                    >= identity.artifact_sha256.len() + identity.package_identity.len()
            );

            let mut creation = callable;
            creation.kind = CallableReferenceKind::Lambda;
            parts.points[0].events.last_mut().unwrap().effect = SemanticEffect::CallableCreation {
                result: ValueId::new(0),
                callable: creation,
            };
            assert_eq!(
                SemanticArtifact::try_new(key, capabilities, vec![parts])
                    .unwrap_err()
                    .kind(),
                SemanticIrErrorKind::CallableContract,
            );
        }
    }

    mod go_move_28 {
        use crate::analyzer::semantic::HeapOracle;

        use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticEffect;

        use brokk_bifrost_analysis::analyzer::semantic::ir::model::TransferKind;

        use brokk_bifrost_analysis::analyzer::semantic::ir::model::ValueFlowKind;
        use brokk_bifrost_analysis::analyzer::semantic::ir::model::ValueTransfer;

        use brokk_bifrost_analysis::analyzer::semantic::oracle::model::AbstractObjectIdentity;

        use brokk_bifrost_analysis::analyzer::semantic::oracle::model::ObservationPhase;
        use brokk_bifrost_analysis::analyzer::semantic::oracle::model::OracleCallContext;
        use brokk_bifrost_analysis::analyzer::semantic::oracle::model::ValueAtPoint;
        use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::CandidateCoverage;
        use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticBudget;
        use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
        use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;

        use brokk_bifrost_analysis::test_support::AnalyzerFixture;
        use brokk_bifrost_core::analyzer::model::Language;
        use brokk_bifrost_core::analyzer::model::ProjectFile;
        use brokk_bifrost_core::cancellation::CancellationToken;
        use brokk_bifrost_test_macros::hardwon;

        #[test]
        #[hardwon("#2662: a Go array copy inherited its source allocation identity")]
        fn go_array_copy_does_not_reuse_the_source_allocation_identity() {
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[(
                    "main.go",
                    r#"package main

func inspect() {
    first := [1]int{}
    second := first
    _ = second
}
"#,
                )],
            );
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let cancellation = CancellationToken::default();
            let mut materialization_budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                )
                .expect("Go semantic materialization runs")
                .available_value()
                .cloned()
                .expect("Go semantic artifact is available");
            let (semantics, point, target) = artifact
                .procedures()
                .iter()
                .find_map(|semantics| {
                    semantics.points().iter().find_map(|point| {
                        point.events.iter().find_map(|event| match event.effect {
                            SemanticEffect::ValueFlow {
                                kind:
                                    ValueFlowKind::Transfer(ValueTransfer {
                                        kind: TransferKind::AggregateCopy,
                                        ..
                                    }),
                                target,
                                ..
                            } => Some((semantics, point.id, target)),
                            _ => None,
                        })
                    })
                })
                .expect("array assignment publishes an aggregate-copy boundary");
            let procedure = artifact
                .procedure_handle(semantics.id())
                .expect("inspect procedure handle");
            let query = ValueAtPoint::new(
                procedure
                    .value_handle(target)
                    .expect("array-copy target value"),
                procedure.point_handle(point).expect("array-copy point"),
                ObservationPhase::AfterEffects,
                OracleCallContext::empty(),
            )
            .expect("array-copy observation");
            let mut budget = SemanticBudget::default();
            let outcome = fixture
                .analyzer
                .semantic_oracle_provider()
                .pointees(
                    &query,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("array-copy points-to query runs");
            let objects = outcome
                .available_value()
                .expect("open array-copy result retains its symbolic candidate")
                .objects();
            assert_eq!(objects.coverage(), CandidateCoverage::Open);
            assert!(
                objects.candidates().iter().all(|candidate| !matches!(
                    candidate.value().identity(),
                    AbstractObjectIdentity::Allocation(_)
                )),
                "a by-value array copy must not reuse its source allocation: {outcome:#?}"
            );
        }
        #[test]
        fn unresolved_field_location_does_not_open_its_base_pointees() {
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[(
                    "main.go",
                    r#"package main

type Resource struct{}

func OpenResource() *Resource { return &Resource{} }
func (*Resource) Close() {}

func inspect() {
    resource := OpenResource()
    resource.Close()
}
"#,
                )],
            );
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let cancellation = CancellationToken::default();
            let mut materialization_budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                )
                .expect("Go semantic materialization runs")
                .available_value()
                .cloned()
                .expect("Go semantic artifact is available");
            let semantics = artifact
                .procedures()
                .iter()
                .find(|procedure| {
                    procedure
                        .call_sites()
                        .iter()
                        .any(|call| call.receiver.is_some())
                })
                .expect("inspect procedure has a receiver call");
            let call = semantics
                .call_sites()
                .iter()
                .find(|call| call.receiver.is_some())
                .expect("resource.Close call");
            let procedure = artifact
                .procedure_handle(semantics.id())
                .expect("inspect procedure handle");
            let point = procedure
                .point_handle(call.point)
                .expect("call program point");
            let receiver = procedure
                .value_handle(call.receiver.expect("receiver value"))
                .expect("receiver handle");
            let callee = procedure
                .value_handle(call.callee)
                .expect("callee value handle");
            let oracle = fixture.analyzer.semantic_oracle_provider();

            let mut receiver_budget = SemanticBudget::default();
            let receiver_outcome = oracle
                .pointees(
                    &ValueAtPoint::new(
                        receiver,
                        point.clone(),
                        ObservationPhase::AfterEffects,
                        OracleCallContext::empty(),
                    )
                    .expect("receiver observation"),
                    &mut SemanticRequest::new(&mut receiver_budget, &cancellation),
                )
                .expect("receiver points-to query runs");
            let SemanticOutcome::Complete {
                value: receiver_result,
                ..
            } = receiver_outcome
            else {
                panic!("the field-location gap must not open its base: {receiver_outcome:#?}");
            };
            assert_eq!(
                receiver_result.objects().coverage(),
                CandidateCoverage::Exhaustive
            );

            let mut callee_budget = SemanticBudget::default();
            let callee_outcome = oracle
                .pointees(
                    &ValueAtPoint::new(
                        callee,
                        point,
                        ObservationPhase::AfterEffects,
                        OracleCallContext::empty(),
                    )
                    .expect("callee observation"),
                    &mut SemanticRequest::new(&mut callee_budget, &cancellation),
                )
                .expect("callee points-to query runs");
            assert!(
                matches!(
                    &callee_outcome,
                    SemanticOutcome::Unknown {
                        partial: Some(result),
                        ..
                    } if result.objects().coverage() == CandidateCoverage::Open
                ),
                "the unresolved field load itself remains open: {callee_outcome:#?}"
            );
        }
    }
    mod go_move_29 {
        use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::assert_declared_binding_shortcut_is_skipped;

        use brokk_bifrost_go_analysis::GoAnalyzer;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_core::analyzer::model::ProjectFile;

        use crate::analyzer::semantic::SemanticBudget;
        use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

        pub (super) use brokk_bifrost_analysis :: analyzer :: semantic :: workspace_oracle :: dispatch :: test_support :: assert_proven_local_dispatch ;

        pub (super) use brokk_bifrost_analysis :: analyzer :: semantic :: workspace_oracle :: dispatch :: test_support :: first_call_in_artifact ;

        pub (super) use brokk_bifrost_analysis :: analyzer :: semantic :: workspace_oracle :: dispatch :: test_support :: semantic_call_fixture_for_language ;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::semantic::capabilities::SemanticCapability;
        use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableTarget;
        use brokk_bifrost_analysis::analyzer::semantic::ir::model::CallableTargetResolution;

        use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProofStatus;
        use brokk_bifrost_analysis::analyzer::semantic::ir::model::SemanticGapKind;

        use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::UnmaterializedExternalTarget;

        use brokk_bifrost_analysis::analyzer::semantic::oracle::model::DispatchBoundaryKind;
        use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::CandidateCoverage;
        use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
        use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;

        use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::PreparedCallDispatch;

        use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::scoped_call_dispatch_gap;
        use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::synthetic_unmaterialized_external;
        use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::virtual_dispatch_implementor_targets;
        use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind;
        use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLookup;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind;
        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;
        use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;
        use brokk_bifrost_analysis::test_support::AnalyzerFixture;
        use brokk_bifrost_core::analyzer::model::DispatchExtensibility;
        use brokk_bifrost_core::analyzer::model::LanguageDialect as SemanticLanguage;
        use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

        use std::sync::Arc;
        fn go_interface_implementors(
            fixture: &AnalyzerFixture,
            interface_member: &str,
        ) -> Vec<String> {
            let analyzer = fixture.analyzer.analyzer();
            let declaration = analyzer
                .get_all_declarations()
                .into_iter()
                .find(|declaration| declaration.fq_name() == interface_member)
                .expect("interface method declaration");
            virtual_dispatch_implementor_targets(
                analyzer,
                &declaration,
                &CancellationToken::default(),
            )
            .expect("Go method-family provider")
            .into_iter()
            .map(|implementor| implementor.fq_name().to_owned())
            .collect()
        }
        use brokk_bifrost_analysis::analyzer::semantic::DispatchOracle as _;
        #[test]
        fn go_adapter_proven_local_callback_bypasses_source_rediscovery() {
            let source = "package sample\nfunc caller() { callback := func() {}; callback() }\n";
            let (fixture, call) =
                semantic_call_fixture_for_language(Language::Go, "callback.go", source);
            let declared_target = match &call
                .procedure()
                .semantics()
                .call_site(call.id())
                .expect("call belongs to its procedure")
                .declared_targets
            {
                CallableTargetResolution::Proven(CallableTarget::Local(target)) => *target,
                other => panic!("expected one adapter-proven Go local callback, got {other:?}"),
            };
            let artifact = Arc::clone(call.procedure().artifact());
            let mut session = fixture
                .analyzer
                .semantic_oracle_provider()
                .prepare_call_dispatch_session(artifact);
            let cancellation = CancellationToken::default();
            let mut budget = SemanticBudget::default();
            let outcome = session
                .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
                .expect("adapter-proven Go callback dispatch");
            let SemanticOutcome::Complete { value, .. } = outcome else {
                panic!("adapter-proven Go local dispatch must be complete: {outcome:?}");
            };

            assert_proven_local_dispatch(&value, declared_target);
            assert!(!value.candidates()[0].provenance().is_empty());
            assert_eq!(budget.used().source_bytes, source.len());
            assert!(session.retained_bytes() >= source.len());
        }
        #[test]
        fn go_package_proof_overrides_a_lowered_receiver_for_declared_package_name() {
            let source = r#"package main
import "example.com/driver"
func caller() { db.Open() }
"#;
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let cancellation = CancellationToken::default();
            let mut budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("Go semantic materialization")
                .available_value()
                .cloned()
                .expect("Go semantic artifact");
            let call = first_call_in_artifact(&artifact);
            let semantic_call = call
                .procedure()
                .semantics()
                .call_site(call.id())
                .expect("call belongs to its procedure");
            assert!(
                semantic_call.receiver.is_some(),
                "the syntax-only lowering treats the non-terminal package name as a receiver"
            );

            let proof = ExactExternalCallProof::go_package_function("example.com/driver.Open", 0);
            let target = synthetic_unmaterialized_external(
                "example.com/driver.Open",
                SemanticLanguage::Standard(Language::Go),
                semantic_call,
                Some(&proof),
                None,
            )
            .expect("resolver-owned package proof");

            assert_eq!(target.owner_fqn(), "example.com/driver");
            assert_eq!(target.member(), "Open");
            assert_eq!(target.arity(), 0);
            assert!(
                !target.has_receiver(),
                "staticness comes from exact package resolution, not selector lowering"
            );

            let gap = scoped_call_dispatch_gap(call.procedure().semantics(), semantic_call)
                .expect("syntax-only receiver lowering carries a dispatch gap");
            assert_eq!(gap.capability, SemanticCapability::DynamicDispatch);
            let oracle = fixture.analyzer.semantic_oracle_provider();
            let mut dispatch_budget = SemanticBudget::default();
            let resolved = oracle
                .resolve_prepared_call(
                    &call,
                    PreparedCallDispatch {
                        lookup: CallDispatchLookup {
                            status: Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                            boundary: Some(BoundaryStatus::ExternalIndexed),
                            boundaries: vec![CallDispatchBoundaryKind::External {
                                callee_text: Some("example.com/driver.Open".into()),
                                normalized_static_owner: None,
                                external_callee_identity: None,
                            }],
                            call_application: CallApplicationKind::PackageFunction,
                            exact_external_call: Some(proof),
                            ..CallDispatchLookup::default()
                        },
                    },
                    &mut SemanticRequest::new(&mut dispatch_budget, &cancellation),
                )
                .expect("resolver-owned package dispatch");
            let SemanticOutcome::Complete {
                value: resolved, ..
            } = resolved
            else {
                panic!("the exact static package proof closes the syntax-only gap: {resolved:#?}");
            };
            let [boundary] = resolved.boundaries() else {
                panic!("one external package boundary: {resolved:#?}");
            };
            let target = boundary
                .unmaterialized_external_target
                .as_ref()
                .expect("external package identity");
            assert!(!target.has_receiver());
            assert_eq!(target.arity(), 0);
            assert_eq!(
                boundary.proven_external_receiver_shape(),
                Some(false),
                "the resolver-owned static call shape is exact even though the external body is absent"
            );

            let mut handcrafted = boundary.clone();
            handcrafted.unmaterialized_external_target = Some(UnmaterializedExternalTarget::new(
                target.owner_fqn(),
                target.member(),
                target.arity(),
                target.has_receiver(),
                target.locator().clone(),
            ));
            assert!(
                handcrafted.validate_for_call(&call).is_err(),
                "an ordinary Go target cannot bypass a mismatched lowered receiver merely by naming Go"
            );
            assert_eq!(
                handcrafted.proven_external_receiver_shape(),
                None,
                "a syntax-derived unmaterialized target has no independent receiver authority"
            );
            let mut unresolved = boundary.clone();
            unresolved.kind = DispatchBoundaryKind::Unresolved;
            unresolved.unmaterialized_external_target = None;
            assert_eq!(unresolved.proven_external_receiver_shape(), None);
            let mut unproven = boundary.clone();
            unproven.proof = ProofStatus::Unproven("test near miss".into());
            assert_eq!(unproven.proven_external_receiver_shape(), None);
        }
        #[test]
        fn only_closed_exact_go_receiver_dispatch_discharges_the_dynamic_gap() {
            let source = r#"package main
import "testing"
func caller(t *testing.T) { t.Fatal("stop") }
"#;
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("main.go", source)]);
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let cancellation = CancellationToken::default();
            let mut materialization_budget = SemanticBudget::default();
            let artifact = fixture
                .analyzer
                .materialize_program_semantics(
                    &file,
                    &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
                )
                .expect("Go semantic materialization")
                .available_value()
                .cloned()
                .expect("Go semantic artifact");
            let call = first_call_in_artifact(&artifact);
            let semantic_call = call
                .procedure()
                .semantics()
                .call_site(call.id())
                .expect("call belongs to its procedure");
            assert!(semantic_call.receiver.is_some(), "receiver call fixture");
            let gap = scoped_call_dispatch_gap(call.procedure().semantics(), semantic_call)
                .expect("Go receiver call carries a dynamic-dispatch gap");
            assert_eq!(gap.capability, SemanticCapability::DynamicDispatch);
            assert!(matches!(
                gap.kind,
                SemanticGapKind::Unknown | SemanticGapKind::Unproven
            ));

            let oracle = fixture.analyzer.semantic_oracle_provider();
            let lookup = |exact_external_call, dispatch_extensibility| {
                CallDispatchLookup {
                status: Some(DefinitionLookupStatus::UnresolvableImportBoundary),
                boundary: Some(BoundaryStatus::ExternalIndexed),
                boundaries: vec![CallDispatchBoundaryKind::External {
                    callee_text: Some("testing.T.Fatal".into()),
                    normalized_static_owner: None,
                    external_callee_identity: None,
                }],
                call_application:
                    brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind::BoundReceiver,
                dispatch_extensibility,
                exact_external_call,
                ..CallDispatchLookup::default()
            }
            };

            let mut closed_budget = SemanticBudget::default();
            let closed = oracle
                .resolve_prepared_call(
                    &call,
                    PreparedCallDispatch {
                        lookup: lookup(
                            Some(ExactExternalCallProof::go_concrete_receiver(
                                "testing.T.Fatal",
                                1,
                            )),
                            Some(DispatchExtensibility::Closed),
                        ),
                    },
                    &mut SemanticRequest::new(&mut closed_budget, &cancellation),
                )
                .expect("closed Go receiver dispatch");
            let SemanticOutcome::Complete { value: closed, .. } = closed else {
                panic!("closed exact Go dispatch must be complete: {closed:#?}");
            };
            assert_eq!(closed.coverage(), CandidateCoverage::Exhaustive);
            assert!(closed.candidates().is_empty(), "{closed:#?}");
            let [boundary] = closed.boundaries() else {
                panic!("closed dispatch keeps one external summary arm: {closed:#?}");
            };
            assert!(matches!(
                boundary.kind,
                DispatchBoundaryKind::External(Some(_))
            ));
            assert_eq!(boundary.proof, ProofStatus::Proven);
            let target = boundary
                .unmaterialized_external_target
                .as_ref()
                .expect("external receiver identity");
            assert_eq!(target.owner_fqn(), "testing.T");
            assert_eq!(target.member(), "Fatal");
            assert_eq!(target.arity(), 1);
            assert!(target.has_receiver());
            assert_eq!(boundary.proven_external_receiver_shape(), Some(true));

            for dispatch_extensibility in [None, Some(DispatchExtensibility::Open)] {
                let mut budget = SemanticBudget::default();
                let open = oracle
                    .resolve_prepared_call(
                        &call,
                        PreparedCallDispatch {
                            lookup: lookup(None, dispatch_extensibility),
                        },
                        &mut SemanticRequest::new(&mut budget, &cancellation),
                    )
                    .expect("open Go receiver dispatch");
                let SemanticOutcome::Unproven { partial: open, .. } = open else {
                    panic!("unproven extensibility must keep dispatch open: {open:#?}");
                };
                assert_eq!(open.coverage(), CandidateCoverage::Open);
                assert!(open.candidates().is_empty(), "{open:#?}");
                assert_eq!(
                    open.boundaries()
                        .iter()
                        .filter(|boundary| matches!(
                            boundary.kind,
                            DispatchBoundaryKind::External(_)
                        ))
                        .count(),
                    1,
                    "{open:#?}"
                );
                assert!(
                    open.boundaries()
                        .iter()
                        .any(|boundary| matches!(boundary.kind, DispatchBoundaryKind::Unresolved)),
                    "{open:#?}"
                );
                assert!(
                    open.boundaries()
                        .iter()
                        .all(|boundary| !matches!(boundary.kind, DispatchBoundaryKind::Truncated)),
                    "{open:#?}"
                );
            }
        }
        #[test]
        fn go_interface_dispatch_lists_only_structural_candidates_and_stays_open() {
            let source = r#"package main

type Resizer interface { Resize(int) }
type ResizerAlias = Resizer
type valid struct{}
func (valid) Resize(int) {}
type wrongSignature struct{}
func (wrongSignature) Resize(string) {}

func caller(value ResizerAlias) { value.Resize(1) }
"#;
            let (fixture, call) =
                semantic_call_fixture_for_language(Language::Go, "main.go", source);
            let analyzer = fixture.analyzer.analyzer();
            let go = resolve_analyzer::<GoAnalyzer>(analyzer).expect("Go analyzer");
            assert_eq!(
                go.usage_edge_index()
                    .expect("complete Go type alias graph")
                    .resolve_type_alias("main.ResizerAlias"),
                "main.Resizer"
            );
            let oracle = fixture.analyzer.semantic_oracle_provider();
            let cancellation = CancellationToken::default();
            let mut budget = SemanticBudget::default();
            let outcome = oracle
                .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
                .expect("typed interface dispatch");
            let SemanticOutcome::Unproven {
                partial: result, ..
            } = outcome
            else {
                panic!("interface implementation census must stay open: {outcome:#?}");
            };
            assert_eq!(result.coverage(), CandidateCoverage::Open, "{result:#?}");
            assert_eq!(result.candidates().len(), 1, "{result:#?}");
            let candidate = &result.candidates()[0];
            assert!(matches!(candidate.proof(), ProofStatus::Unproven(_)));
            assert_eq!(
                go_interface_implementors(&fixture, "main.Resizer.Resize"),
                ["main.valid.Resize"],
                "the exact method signature admits valid and rejects wrongSignature"
            );
            assert!(
                result.boundaries().iter().any(|boundary| {
                    matches!(boundary.kind, DispatchBoundaryKind::Unresolved)
                        && format!("{:?}", boundary.completeness)
                            .contains("Go interface implementations are not closed")
                }),
                "{result:#?}"
            );
        }
        #[test]
        fn go_interface_dispatch_closes_an_exhaustive_concrete_allocation_set() {
            let source = r#"package main

type Resizer interface { Resize(int) }
type concrete struct{}
func (concrete) Resize(int) {}

func caller() {
	var value Resizer = concrete{}
	value.Resize(1)
}
"#;
            let (fixture, call) =
                semantic_call_fixture_for_language(Language::Go, "main.go", source);
            let oracle = fixture.analyzer.semantic_oracle_provider();
            let cancellation = CancellationToken::default();
            let mut budget = SemanticBudget::default();
            let outcome = oracle
                .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
                .expect("typed interface dispatch");
            let SemanticOutcome::Complete { value, .. } = outcome else {
                panic!("an exhaustive allocation type proves the interface target: {outcome:#?}");
            };
            assert_eq!(
                value.coverage(),
                CandidateCoverage::Exhaustive,
                "{value:#?}"
            );
            assert_eq!(value.candidates().len(), 1, "{value:#?}");
            let candidate = &value.candidates()[0];
            assert!(
                matches!(candidate.proof(), ProofStatus::Proven),
                "{value:#?}"
            );
            assert_eq!(
                go_interface_implementors(&fixture, "main.Resizer.Resize"),
                ["main.concrete.Resize"]
            );
            assert!(
                !value
                    .boundaries()
                    .iter()
                    .any(|boundary| matches!(boundary.kind, DispatchBoundaryKind::Unresolved))
            );
        }

        #[test]
        fn direct_go_callable_syntax_stays_on_source_resolver_route() {
            assert_declared_binding_shortcut_is_skipped(
                Language::Go,
                "call.go",
                "package sample\nfunc caller() { defer func() {}() }\n",
            );
        }
    }
}
