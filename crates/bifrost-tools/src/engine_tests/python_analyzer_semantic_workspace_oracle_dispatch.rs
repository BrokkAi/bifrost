#[cfg(test)]
mod python_extraction_tests {
    use brokk_bifrost_analysis::analyzer::semantic::DispatchOracle;

    use brokk_bifrost_analysis::analyzer::semantic::ir::artifact::CallSiteHandle;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::EvidenceCompleteness;
    use brokk_bifrost_analysis::analyzer::semantic::ir::model::ProofStatus;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::UnmaterializedExternalTarget;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::model::DispatchBoundaryKind;
    use brokk_bifrost_analysis::analyzer::semantic::oracle::relation::CandidateCoverage;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticOutcome;
    use brokk_bifrost_analysis::analyzer::semantic::provider::SemanticRequest;
    use brokk_bifrost_analysis::analyzer::semantic::type_flow::DispatchHintProof;
    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::heuristic_external_boundary_without_resolver_authority;

    use brokk_bifrost_semantic::analyzer::semantic::type_flow::ClassIdentity;

    use brokk_bifrost_semantic::analyzer::semantic::type_flow::DispatchHint;

    use brokk_bifrost_semantic::analyzer::semantic::type_flow::DispatchHintCallSiteKey;

    use brokk_bifrost_semantic::analyzer::semantic::type_flow::DispatchHintSet;

    use brokk_bifrost_semantic::analyzer::semantic::type_flow::DispatchHints;

    use brokk_bifrost_semantic::analyzer::semantic::type_flow::MemberDeclaration;

    use crate::analyzer::semantic::SemanticBudget;

    use brokk_bifrost_semantic::analyzer::semantic::type_flow::SourceSite;

    use brokk_bifrost_semantic::analyzer::semantic::type_flow::SourceSiteKind;

    use brokk_bifrost_analysis::analyzer::semantic::icfg::WorkspaceIcfgProvider;

    use crate::analyzer::semantic_model::CatalogOptions;

    use brokk_bifrost_analysis::analyzer::semantic_model::CompilerOptions;

    use crate::analyzer::semantic_model::SemanticModelActivationEvidence;

    use crate::analyzer::semantic_model::SemanticModelActivationRequest;

    use crate::analyzer::semantic_model::SemanticModelRuntimeLimits;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelRuntimeOutcome;

    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::SemanticPackCatalog;

    use crate::analyzer::semantic_model::SessionPackSource;

    use crate::analyzer::semantic_model::SessionPackSourceKind;

    use brokk_bifrost_analysis::analyzer::semantic_model::SourceFormat;

    use brokk_bifrost_analysis::analyzer::semantic_model::runtime::acquire_active_semantic_models;

    use brokk_bifrost_analysis::analyzer::semantic_model::compile_source;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::dispatch_target_shape;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::first_call_in_artifact;

    use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::dispatch::test_support::semantic_call_fixture_for_language;
    fn python_workspace_member_hints(
        fixture: &AnalyzerFixture,
        call: &CallSiteHandle,
        file_name: &str,
        class_name: &str,
        member_name: &str,
        exhaustive: bool,
    ) -> DispatchHints {
        let analyzer = fixture.analyzer.analyzer();
        let file = ProjectFile::new(fixture.project_root(), file_name);
        let declarations = analyzer.get_declarations(&file);
        let class = declarations
            .iter()
            .find(|declaration| declaration.is_class() && declaration.terminal_name() == class_name)
            .cloned()
            .expect("hint receiver class declaration");
        let member = declarations
            .into_iter()
            .find(|definition| definition.terminal_name() == member_name)
            .expect("hint member declaration");
        let mapping = call
            .procedure()
            .semantics()
            .source_mapping(
                call.procedure()
                    .semantics()
                    .call_site(call.id())
                    .expect("live call")
                    .source,
            )
            .expect("call source mapping");
        DispatchHints::new(vec![DispatchHintSet::new(
            DispatchHintCallSiteKey::for_call(call.procedure(), call.id()),
            vec![DispatchHint::new(
                MemberDeclaration::Workspace(member),
                ClassIdentity::Workspace(class),
                SourceSite {
                    file,
                    span: mapping.locator.anchor().span(),
                    kind: SourceSiteKind::DeclaredParameter,
                },
            )],
            exhaustive,
            if exhaustive {
                DispatchHintProof::Proven
            } else {
                DispatchHintProof::Unproven
            },
        )])
    }
    fn activate_python_external_summary(workspace: &WorkspaceAnalyzer) {
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral semantic-pack catalog");
        let source = br#"{
          "schema_version": 11,
          "pack_id": "test.python.heuristic-external",
          "version": "1.0.0",
          "producer": {"name": "test", "version": "1.0.0"},
          "language": "python",
          "ecosystem": "python",
          "compatibility": {"toolchains": []},
          "provenance": {"source": "test:python-heuristic-external"},
          "license": "Apache-2.0",
          "completeness": "complete",
          "safety": {"generated_code_only": false, "review_required": false},
          "shards": [{
            "id": "summaries",
            "activation": [{}],
            "payload": {
              "kind": "procedure_summaries",
              "summaries": [{
                "id": "test.python.holder-value-foo",
                "target": {
                  "path": "external.py",
                  "symbol": "holder.value.foo",
                  "has_receiver": true,
                  "parameter_count": 0
                },
                "completeness": "complete",
                "transfers": [],
                "effects": [{
                  "kind": "unknown_call_boundary",
                  "event": "test.python.holder-value-foo-boundary"
                }]
              }, {
                "id": "test.python.mongosanitizer-sanitize",
                "target": {
                  "path": "mongosanitizer/sanitizer.py",
                  "symbol": "mongosanitizer.sanitizer.sanitize(value)",
                  "has_receiver": false,
                  "parameter_count": 1,
                  "formals": [{ "name": "value" }]
                },
                "completeness": "complete",
                "transfers": [],
                "effects": []
              }, {
                "id": "test.python.xml-etree-fromstring",
                "target": {
                  "path": "xml/etree/ElementTree.pyi",
                  "symbol": "xml.etree.ElementTree.fromstring(text, parser)",
                  "has_receiver": false,
                  "parameter_count": 2,
                  "formals": [
                    { "name": "text" },
                    { "name": "parser", "optional": true }
                  ]
                },
                "completeness": "complete",
                "transfers": [],
                "effects": []
              }]
            }
          }]
        }"#;
        let pack = compile_source(SourceFormat::Json, source, &CompilerOptions::default())
            .unwrap_or_else(|diagnostics| panic!("external summary fixture: {diagnostics:#?}"));
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:python-heuristic-external".to_owned(),
                },
            )
            .expect("register external summary fixture");
        let request = SemanticModelActivationRequest {
            bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                .expect("package version"),
            evidence: vec![SemanticModelActivationEvidence {
                language: "python".to_owned(),
                ecosystem: "python".to_owned(),
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
        let outcome = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &request,
            &CancellationToken::default(),
        );
        assert!(
            matches!(outcome, SemanticModelRuntimeOutcome::Ready { .. }),
            "external summary fixture activates: {outcome:#?}"
        );
    }
    #[test]
    fn resolved_receiver_feedback_requires_complete_matching_declarations() {
        let (fixture, call) = semantic_call_fixture_for_language(
            Language::Python,
            "resolved.py",
            "class Maker:\n    def text(self):\n        return 'a'\n    def other(self):\n        return 'b'\n\ndef caller(maker: Maker):\n    return maker.text()\n",
        );
        let cancellation = CancellationToken::default();
        let ordinary = WorkspaceIcfgProvider::new(&fixture.analyzer);
        let baseline = ordinary
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
            )
            .expect("ordinary dispatch");
        let baseline_result = baseline.available_value().expect("resolved method");
        assert_eq!(
            baseline_result.candidates().len(),
            1,
            "{baseline_result:#?}"
        );
        assert!(
            baseline_result
                .boundaries()
                .iter()
                .any(|boundary| boundary.kind == DispatchBoundaryKind::Unresolved)
        );

        for (member, exhaustive, expected) in [
            ("text", true, CandidateCoverage::Exhaustive),
            ("text", false, CandidateCoverage::Open),
            ("other", true, CandidateCoverage::Open),
        ] {
            let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
                &fixture.analyzer,
                None,
                python_workspace_member_hints(
                    &fixture,
                    &call,
                    "resolved.py",
                    "Maker",
                    member,
                    exhaustive,
                ),
            );
            let outcome = provider
                .resolve_call(
                    &call,
                    &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
                )
                .expect("hinted dispatch");
            let result = outcome.available_value().expect("hinted result");
            assert_eq!(
                result.coverage(),
                expected,
                "{member}, {exhaustive}: {result:#?}"
            );
            assert_eq!(
                dispatch_target_shape(&outcome),
                dispatch_target_shape(&baseline),
                "feedback preserves the resolver-selected method"
            );
            assert_eq!(
                result.boundaries().is_empty(),
                exhaustive && member == "text"
            );

            let cancelled = CancellationToken::default();
            cancelled.cancel();
            let outcome = provider
                .resolve_call(
                    &call,
                    &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancelled),
                )
                .expect("cancelled hinted dispatch");
            assert!(
                matches!(outcome, SemanticOutcome::Cancelled { .. }),
                "{outcome:#?}"
            );
        }
    }
    #[test]
    fn complete_receiver_hint_displaces_only_a_syntax_derived_python_external_arm() {
        let source = "class A:\n    def foo(self):\n        return 1\n\ndef caller(holder):\n    return holder.value.foo()\n";
        let (fixture, call) =
            semantic_call_fixture_for_language(Language::Python, "heuristic.py", source);
        let cancellation = CancellationToken::default();

        let unhinted = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            &fixture.analyzer,
            None,
            DispatchHints::default(),
        );
        let mut unhinted_budget = SemanticBudget::default();
        let unhinted_outcome = unhinted
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut unhinted_budget, &cancellation),
            )
            .expect("unhinted dispatch");
        let unhinted_result = unhinted_outcome.available_value().expect("unhinted answer");
        assert_eq!(unhinted_result.coverage(), CandidateCoverage::Truncated);
        assert!(unhinted_result.complete_receiver_hint_refinable());
        assert!(
            unhinted_result
                .boundaries()
                .iter()
                .any(heuristic_external_boundary_without_resolver_authority),
            "{unhinted_result:#?}"
        );

        let complete = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            &fixture.analyzer,
            None,
            python_workspace_member_hints(&fixture, &call, "heuristic.py", "A", "foo", true),
        );
        let mut complete_budget = SemanticBudget::default();
        let complete_outcome = complete
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut complete_budget, &cancellation),
            )
            .expect("completely hinted dispatch");
        let complete_result = complete_outcome
            .available_value()
            .expect("completely hinted answer");
        assert_eq!(complete_result.coverage(), CandidateCoverage::Exhaustive);
        assert_eq!(
            complete_result.candidates().len(),
            1,
            "{complete_result:#?}"
        );
        assert!(
            complete_result
                .boundaries()
                .iter()
                .all(|boundary| !heuristic_external_boundary_without_resolver_authority(boundary)),
            "{complete_result:#?}"
        );

        let incomplete = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            &fixture.analyzer,
            None,
            python_workspace_member_hints(&fixture, &call, "heuristic.py", "A", "foo", false),
        );
        let mut incomplete_budget = SemanticBudget::default();
        let incomplete_outcome = incomplete
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut incomplete_budget, &cancellation),
            )
            .expect("incompletely hinted dispatch");
        let incomplete_result = incomplete_outcome
            .available_value()
            .expect("incompletely hinted answer");
        assert_eq!(incomplete_result.coverage(), CandidateCoverage::Truncated);
        assert_eq!(
            incomplete_result.candidates().len(),
            1,
            "{incomplete_result:#?}"
        );
        assert!(matches!(
            incomplete_result.candidates()[0].proof(),
            ProofStatus::Unproven(_)
        ));
        assert!(matches!(
            incomplete_result.candidates()[0].completeness(),
            EvidenceCompleteness::Partial(_)
        ));
        assert!(
            incomplete_result
                .boundaries()
                .iter()
                .any(heuristic_external_boundary_without_resolver_authority),
            "{incomplete_result:#?}"
        );
    }
    #[test]
    fn complete_receiver_hint_does_not_displace_a_resolver_owned_python_external_arm() {
        let source = "import subprocess\n\nclass A:\n    def run(self):\n        return 1\n\ndef caller():\n    return subprocess.run()\n";
        let (fixture, call) =
            semantic_call_fixture_for_language(Language::Python, "imported.py", source);
        let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            &fixture.analyzer,
            None,
            python_workspace_member_hints(&fixture, &call, "imported.py", "A", "run", true),
        );
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let outcome = provider
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("resolver-owned external dispatch");
        let result = outcome
            .available_value()
            .expect("resolver-owned external answer");

        assert!(result.candidates().is_empty(), "{result:#?}");
        assert!(!result.complete_receiver_hint_refinable());
        assert!(
            result.boundaries().iter().any(|boundary| {
                boundary
                    .unmaterialized_external_target()
                    .is_some_and(UnmaterializedExternalTarget::has_resolver_owned_call_shape)
            }),
            "{result:#?}"
        );
    }
    #[test]
    fn python_module_function_summary_closes_an_exact_applicable_external_boundary() {
        let source = concat!(
            "from xml.etree.ElementTree import fromstring\n",
            "\ndef caller(payload):\n",
            "    return fromstring(payload)\n",
        );
        let fixture =
            AnalyzerFixture::new_for_language(Language::Python, &[("xml_call.py", source)]);
        activate_python_external_summary(&fixture.analyzer);
        let snapshot = fixture
            .analyzer
            .analyzer()
            .active_semantic_model_snapshot()
            .expect("external summary activation publishes a snapshot");
        let file = ProjectFile::new(fixture.project_root(), "xml_call.py");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("semantic materialization")
            .available_value()
            .cloned()
            .expect("semantic artifact");
        let call = first_call_in_artifact(&artifact);
        let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            &fixture.analyzer,
            Some(snapshot),
            DispatchHints::default(),
        );
        let mut budget = SemanticBudget::default();
        let outcome = provider
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("modeled module-function dispatch");
        let result = outcome.available_value().expect("external dispatch answer");

        assert_eq!(
            result.coverage(),
            CandidateCoverage::Exhaustive,
            "{result:#?}"
        );
        assert!(result.candidates().is_empty(), "{result:#?}");
        assert!(
            result.boundaries().iter().any(|boundary| {
                matches!(boundary.kind, DispatchBoundaryKind::External(Some(_)))
                    && boundary.completeness == EvidenceCompleteness::Complete
                    && boundary
                        .unmaterialized_external_target()
                        .is_some_and(|target| {
                            target.owner_fqn() == "xml.etree.ElementTree"
                                && target.member() == "fromstring"
                        })
            }),
            "{result:#?}"
        );
    }
    #[test]
    fn python_activated_third_party_module_summary_closes_exact_boundary() {
        let source = concat!(
            "from mongosanitizer.sanitizer import sanitize\n",
            "\ndef caller(payload):\n",
            "    return sanitize(payload)\n",
        );
        let fixture =
            AnalyzerFixture::new_for_language(Language::Python, &[("sanitize_call.py", source)]);
        activate_python_external_summary(&fixture.analyzer);
        let snapshot = fixture
            .analyzer
            .analyzer()
            .active_semantic_model_snapshot()
            .expect("external summary activation publishes a snapshot");
        let file = ProjectFile::new(fixture.project_root(), "sanitize_call.py");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("semantic materialization")
            .available_value()
            .cloned()
            .expect("semantic artifact");
        let call = first_call_in_artifact(&artifact);
        let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            &fixture.analyzer,
            Some(snapshot),
            DispatchHints::default(),
        );
        let outcome = provider
            .resolve_call(
                &call,
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
            )
            .expect("modeled third-party module-function dispatch");
        let result = outcome.available_value().expect("external dispatch answer");

        assert_eq!(
            result.coverage(),
            CandidateCoverage::Exhaustive,
            "{result:#?}"
        );
        assert!(result.candidates().is_empty(), "{result:#?}");
        assert!(
            result.boundaries().iter().any(|boundary| {
                matches!(boundary.kind, DispatchBoundaryKind::External(Some(_)))
                    && boundary.completeness == EvidenceCompleteness::Complete
                    && boundary
                        .unmaterialized_external_target()
                        .is_some_and(|target| {
                            target.owner_fqn() == "mongosanitizer.sanitizer"
                                && target.member() == "sanitize"
                        })
            }),
            "{result:#?}"
        );
    }
    #[test]
    fn complete_receiver_hint_does_not_displace_an_active_modeled_external_arm() {
        let source = "class A:\n    def foo(self):\n        return 1\n\ndef caller(holder):\n    return holder.value.foo()\n";
        let fixture =
            AnalyzerFixture::new_for_language(Language::Python, &[("modeled.py", source)]);
        activate_python_external_summary(&fixture.analyzer);
        let snapshot = fixture
            .analyzer
            .analyzer()
            .active_semantic_model_snapshot()
            .expect("external summary activation publishes a snapshot");
        let file = ProjectFile::new(fixture.project_root(), "modeled.py");
        let cancellation = CancellationToken::default();
        let mut materialization_budget = SemanticBudget::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut materialization_budget, &cancellation),
            )
            .expect("semantic materialization")
            .available_value()
            .cloned()
            .expect("semantic artifact");
        let call = first_call_in_artifact(&artifact);
        let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            &fixture.analyzer,
            Some(snapshot),
            python_workspace_member_hints(&fixture, &call, "modeled.py", "A", "foo", true),
        );
        let mut budget = SemanticBudget::default();
        let outcome = provider
            .resolve_call(&call, &mut SemanticRequest::new(&mut budget, &cancellation))
            .expect("modeled external dispatch");
        let result = outcome.available_value().expect("modeled external answer");

        assert!(result.candidates().is_empty(), "{result:#?}");
        assert!(!result.complete_receiver_hint_refinable());
        assert!(
            result.boundaries().iter().any(|boundary| {
                boundary
                    .unmaterialized_external_target()
                    .is_some_and(|target| {
                        target.owner_fqn() == "holder.value" && target.member() == "foo"
                    })
            }),
            "{result:#?}"
        );
    }
}
