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
            approximate_standard_libraries: Vec::new(),
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
        assert_eq!(unhinted_result.coverage(), CandidateCoverage::Open);
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
        assert_eq!(incomplete_result.coverage(), CandidateCoverage::Open);
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
        let mut fixture =
            AnalyzerFixture::new_for_language(Language::Python, &[("imported.py", source)]);
        super::runtime_fixture::activate(&mut fixture, "imported.py", &["subprocess"], "run", &[]);
        let cancellation = CancellationToken::default();
        let artifact = fixture
            .analyzer
            .materialize_program_semantics(
                &ProjectFile::new(fixture.project_root(), "src/imported.py"),
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
            )
            .unwrap()
            .available_value()
            .cloned()
            .unwrap();
        let call = first_call_in_artifact(&artifact);
        let provider = WorkspaceIcfgProvider::with_active_semantic_model_snapshot_and_hints(
            &fixture.analyzer,
            fixture.analyzer.analyzer().active_semantic_model_snapshot(),
            python_workspace_member_hints(&fixture, &call, "src/imported.py", "A", "run", true),
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
        let mut fixture =
            AnalyzerFixture::new_for_language(Language::Python, &[("xml_call.py", source)]);
        super::runtime_fixture::activate(
            &mut fixture,
            "xml_call.py",
            &["xml", "etree", "ElementTree"],
            "fromstring",
            &["text", "parser"],
        );
        let snapshot = fixture
            .analyzer
            .analyzer()
            .active_semantic_model_snapshot()
            .expect("external summary activation publishes a snapshot");
        let file = ProjectFile::new(fixture.project_root(), "src/xml_call.py");
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
        let mut fixture =
            AnalyzerFixture::new_for_language(Language::Python, &[("sanitize_call.py", source)]);
        super::runtime_fixture::activate(
            &mut fixture,
            "sanitize_call.py",
            &["mongosanitizer", "sanitizer"],
            "sanitize",
            &["value"],
        );
        let snapshot = fixture
            .analyzer
            .analyzer()
            .active_semantic_model_snapshot()
            .expect("external summary activation publishes a snapshot");
        let file = ProjectFile::new(fixture.project_root(), "src/sanitize_call.py");
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

// Exact installed-wheel fixtures for the normalized call-dispatch contract.
#[cfg(test)]
pub(super) mod runtime_fixture {
    use brokk_bifrost_analysis::analyzer::semantic_model::csmi::{
        CSMI_PACK_FORMAT_VERSION, CSMI_PYTHON_PROFILE_ID, CSMI_PYTHON_PROFILE_SCHEMA,
        CSMI_PYTHON_PROFILE_VERSION, CSMI_SCHEMA_URI, CSMI_SEMANTIC_DOCUMENT_MEDIA_TYPE,
        CsmiContentDigest, CsmiContentDigestAlgorithm, CsmiLogicalPack, CsmiPackManifest,
        CsmiProducerIdentity, CsmiResourceDescriptor, CsmiResourceRole, CsmiVocabularySupport,
        InMemoryCsmiResourceResolver, canonical_json_bytes, import_logical_csmi_pack, sha256_hex,
    };
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        CatalogOptions, CompilerOptions, DependencyPackLimits, SemanticModelActivationRequest,
        SemanticModelRuntimeOutcome, SemanticPackCatalog, SessionPackSource, SessionPackSourceKind,
    };
    use brokk_bifrost_analysis::analyzer::{
        DependencyPackEcosystem, DependencyPackWorkspaceContext, PythonAnalyzerConfig,
    };
    use brokk_bifrost_analysis::test_support::AnalyzerFixture;
    use brokk_bifrost_analysis::{
        AnalyzerConfig, CancellationToken, FilesystemProject, WorkspaceAnalyzer,
    };
    use brokk_bifrost_core::analyzer::config::{
        PythonDeclaredConfigInput, PythonDeclaredConfigInputRole,
        PythonDeclaredEditableInstallMode, PythonDeclaredEntryMode, PythonDeclaredEntryPoint,
        PythonDeclaredEnvironmentConfig, PythonDeclaredEnvironmentMode, PythonDeclaredFinderMode,
        PythonDeclaredImportPathMode, PythonDeclaredInterpreter, PythonDeclaredIsolationMode,
        PythonDeclaredLaunchSemantics, PythonDeclaredNativeExtensionMode, PythonDeclaredRootRole,
        PythonDeclaredRootSlot, PythonDeclaredSiteStartupMode, PythonRuntimeArtifactConfig,
        PythonRuntimeEnvironmentConfig,
    };
    use serde_json::{Value, json};
    use std::{
        io::Write,
        path::{Path, PathBuf},
        sync::Arc,
    };
    use zip::write::SimpleFileOptions;
    struct Root {
        path: PathBuf,
        entry: PathBuf,
    }
    impl Root {
        fn root(&self) -> &Path {
            &self.path
        }
    }
    fn write_passive_evidence_file(project: &Root, relative_path: &str, bytes: &[u8]) -> String {
        // These opaque interpreter and configuration bytes are hashed as evidence only.
        let path = project.root().join(relative_path);
        std::fs::create_dir_all(path.parent().expect("evidence file parent"))
            .expect("create evidence file directory");
        std::fs::write(&path, bytes)
            .unwrap_or_else(|error| panic!("write passive evidence {}: {error}", path.display()));
        sha256_hex(bytes)
    }

    fn declared_runtime_environment(project: &Root) -> PythonRuntimeEnvironmentConfig {
        use brokk_bifrost_python_analysis::analyzer::python_runtime_artifact::{
            SUPPORTED_PYTHON_DECLARED_ENVIRONMENT_PRODUCER_VERSION,
            SUPPORTED_PYTHON_DECLARED_FILESYSTEM_RESOLVER_VERSION,
        };

        std::fs::create_dir_all(project.root().join(".runtime-evidence/stdlib"))
            .expect("create empty declared standard-library root");
        let interpreter_path = PathBuf::from(".runtime-evidence/python/interpreter.bin");
        let interpreter_sha256 = write_passive_evidence_file(
            project,
            interpreter_path.to_str().expect("UTF-8 fixture path"),
            b"opaque interpreter evidence; never execute\n",
        );
        let resolver_path = PathBuf::from(".runtime-evidence/config/resolver.toml");
        let resolver_sha256 = write_passive_evidence_file(
            project,
            resolver_path.to_str().expect("UTF-8 fixture path"),
            b"import_path = declared_roots_only\nfinder = standard_filesystem\n",
        );
        let entry_config_path = PathBuf::from(".runtime-evidence/config/entry.json");
        let entry_config_sha256 = write_passive_evidence_file(
            project,
            entry_config_path.to_str().expect("UTF-8 fixture path"),
            b"{\"mode\":\"script\",\"root\":\"source\",\"path\":\"app.py\"}\n",
        );

        let mut config_inputs = vec![
            PythonDeclaredConfigInput {
                ordinal: 0,
                input_id: "resolver".to_owned(),
                role: PythonDeclaredConfigInputRole::ResolverConfiguration,
                path: resolver_path,
                sha256: resolver_sha256,
            },
            PythonDeclaredConfigInput {
                ordinal: 1,
                input_id: "entry".to_owned(),
                role: PythonDeclaredConfigInputRole::EntryConfiguration,
                path: entry_config_path,
                sha256: entry_config_sha256,
            },
        ];
        for (input_id, role, bytes) in [
            (
                "startup",
                PythonDeclaredConfigInputRole::StartupConfiguration,
                b"site_startup = disabled\n".as_slice(),
            ),
            (
                "environment",
                PythonDeclaredConfigInputRole::EnvironmentConfiguration,
                b"environment = cleared\n".as_slice(),
            ),
            (
                "extras",
                PythonDeclaredConfigInputRole::ExtrasConfiguration,
                b"enabled_extras = []\n".as_slice(),
            ),
        ] {
            let path = PathBuf::from(".runtime-evidence/config").join(format!("{input_id}.toml"));
            let sha256 = write_passive_evidence_file(
                project,
                path.to_str().expect("UTF-8 fixture path"),
                bytes,
            );
            config_inputs.push(PythonDeclaredConfigInput {
                ordinal: u32::try_from(config_inputs.len()).expect("five fixture inputs"),
                input_id: input_id.to_owned(),
                role,
                path,
                sha256,
            });
        }

        PythonRuntimeEnvironmentConfig {
            source_root: PathBuf::from("src"),
            artifacts: vec![PythonRuntimeArtifactConfig {
                archive_path: PathBuf::from(".runtime-evidence/wheels/fixture.whl"),
                installed_root: PathBuf::from(".runtime-evidence/site"),
            }],
            declared_environment: Some(PythonDeclaredEnvironmentConfig {
                producer_version: SUPPORTED_PYTHON_DECLARED_ENVIRONMENT_PRODUCER_VERSION.to_owned(),
                resolver_version: SUPPORTED_PYTHON_DECLARED_FILESYSTEM_RESOLVER_VERSION.to_owned(),
                interpreter: PythonDeclaredInterpreter {
                    path: interpreter_path,
                    sha256: interpreter_sha256,
                    implementation: "cpython".to_owned(),
                    python_version: "3.12.0".to_owned(),
                    abi: "cp312".to_owned(),
                    platform: match std::env::consts::OS {
                        "macos" => "darwin",
                        "windows" => "win32",
                        other => other,
                    }
                    .to_owned(),
                },
                launch: PythonDeclaredLaunchSemantics {
                    isolation: PythonDeclaredIsolationMode::Isolated,
                    site_startup: PythonDeclaredSiteStartupMode::Disabled,
                    environment: PythonDeclaredEnvironmentMode::Cleared,
                    import_path: PythonDeclaredImportPathMode::DeclaredRootsOnly,
                    finder: PythonDeclaredFinderMode::StandardFilesystem,
                    editable_installs: PythonDeclaredEditableInstallMode::Disabled,
                    native_extensions: PythonDeclaredNativeExtensionMode::Disabled,
                },
                entry_point: PythonDeclaredEntryPoint {
                    mode: PythonDeclaredEntryMode::Script,
                    root_slot_id: "source".to_owned(),
                    relative_path: project.entry.clone(),
                    working_directory_root_slot_id: "source".to_owned(),
                    working_directory: PathBuf::new(),
                },
                extras: Vec::new(),
                config_inputs,
                root_slots: vec![
                    PythonDeclaredRootSlot {
                        ordinal: 0,
                        slot_id: "source".to_owned(),
                        role: PythonDeclaredRootRole::Source,
                        path: PathBuf::from("src"),
                        artifact_index: None,
                    },
                    PythonDeclaredRootSlot {
                        ordinal: 1,
                        slot_id: "stdlib".to_owned(),
                        role: PythonDeclaredRootRole::StandardLibrary,
                        path: PathBuf::from(".runtime-evidence/stdlib"),
                        artifact_index: None,
                    },
                    PythonDeclaredRootSlot {
                        ordinal: 2,
                        slot_id: "installed-beautifulsoup".to_owned(),
                        role: PythonDeclaredRootRole::InstalledDistribution,
                        path: PathBuf::from(".runtime-evidence/site"),
                        artifact_index: Some(0),
                    },
                ],
            }),
        }
    }

    fn compile_profile(
        document: &Value,
    ) -> brokk_bifrost_analysis::analyzer::semantic_model::CompiledSemanticModelPack {
        let source = serde_json::to_vec(&document).expect("serialize adapted CSMI fixture");
        let semantic_bytes = canonical_json_bytes(&source).expect("canonicalize semantic fixture");
        let resource_path = "models/beautifulsoup.csmi.json".to_owned();
        let resources =
            InMemoryCsmiResourceResolver::new([(resource_path.clone(), semantic_bytes.clone())])
                .expect("resource path is valid");
        let logical = CsmiLogicalPack::new(
            CsmiPackManifest {
                document_type: "pack-manifest".to_owned(),
                schema: CSMI_SCHEMA_URI.to_owned(),
                pack_format_version: CSMI_PACK_FORMAT_VERSION.to_owned(),
                assembler: CsmiProducerIdentity {
                    identifier: "https://example.org/tools/csmi-pack".to_owned(),
                    version: "1.0.0".to_owned(),
                },
                license: "Apache-2.0".to_owned(),
                created_at: None,
                resources: vec![CsmiResourceDescriptor {
                    path: resource_path,
                    role: CsmiResourceRole::SemanticDocument,
                    media_type: CSMI_SEMANTIC_DOCUMENT_MEDIA_TYPE.to_owned(),
                    size: semantic_bytes.len() as u64,
                    digest: CsmiContentDigest {
                        algorithm: CsmiContentDigestAlgorithm::Sha256,
                        value: sha256_hex(&semantic_bytes),
                    },
                    license: None,
                    schema_identifier: None,
                    license_reference: None,
                }],
                derived_from: Vec::new(),
            },
            resources,
        );
        let support = CsmiVocabularySupport::support(
            CSMI_PYTHON_PROFILE_ID,
            CSMI_PYTHON_PROFILE_VERSION,
            CSMI_PYTHON_PROFILE_SCHEMA,
        );
        import_logical_csmi_pack(&logical, &support, &CompilerOptions::default())
            .expect("import the validated Python CSMI fixture")
            .compile(&CompilerOptions::default())
            .expect("compile imported CSMI fixture")
    }

    pub fn activate(
        fixture: &mut AnalyzerFixture,
        entry: &str,
        module: &[&str],
        member: &str,
        parameters: &[&str],
    ) {
        // Match the production artifact-binding suite: a named source root and ignored installed tree.
        std::fs::create_dir_all(fixture.project_root().join("src")).unwrap();
        std::fs::rename(
            fixture.project_root().join(entry),
            fixture.project_root().join("src").join(entry),
        )
        .unwrap();
        let project = Root {
            path: fixture.project_root(),
            entry: PathBuf::from(entry),
        };
        std::fs::write(
            project.root().join(".bifrostignore"),
            ".runtime-evidence/\n",
        )
        .unwrap();
        let mut members = Vec::new();
        for end in 1..module.len() {
            members.push((
                format!("{}/__init__.py", module[..end].join("/")),
                format!("from . import {}\n", module[end]),
            ));
        }
        members.push((
            format!("{}.py", module.join("/")),
            format!(
                "def {member}({}):\n    pass\n",
                parameters
                    .iter()
                    .enumerate()
                    .map(|(index, name)| {
                        if index == 0 {
                            (*name).to_owned()
                        } else {
                            format!("{name}=None")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
        let wheel = project.root().join(".runtime-evidence/wheels/fixture.whl");
        std::fs::create_dir_all(wheel.parent().unwrap()).unwrap();
        let mut archive = zip::ZipWriter::new(std::fs::File::create(&wheel).unwrap());
        archive
            .start_file(
                "fixture-1.0.0.dist-info/METADATA",
                SimpleFileOptions::default(),
            )
            .unwrap();
        archive
            .write_all(b"Metadata-Version: 2.1\nName: fixture\nVersion: 1.0.0\n\n")
            .unwrap();
        for (path, source) in &members {
            archive
                .start_file(path, SimpleFileOptions::default())
                .unwrap();
            archive.write_all(source.as_bytes()).unwrap();
            let installed = project.root().join(".runtime-evidence/site").join(path);
            std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
            std::fs::write(installed, source).unwrap();
        }
        archive.finish().unwrap();
        let environment = declared_runtime_environment(&project);
        let project_config = brokk_bifrost_python_analysis::analyzer::python_runtime_artifact::python_declared_environment_project_config(
            project.root(), &environment, &DependencyPackLimits::default(), None,
        ).unwrap();
        let verified = brokk_bifrost_python_analysis::analyzer::python_runtime_artifact::verify_python_runtime_artifacts(
            project.root(), std::slice::from_ref(&environment), &DependencyPackLimits::default(), None,
        );
        assert!(verified.complete(), "{verified:#?}");
        let config = AnalyzerConfig {
            python: PythonAnalyzerConfig {
                runtime_environments: vec![environment],
                ..Default::default()
            },
            ..Default::default()
        };
        fixture.analyzer = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(FilesystemProject::new(project.root()).unwrap()),
            config.clone(),
        )
        .unwrap();
        let digest = sha256_hex(&std::fs::read(wheel).unwrap());
        let module_name = module.join(".");
        let descriptors = module
            .iter()
            .map(|name| json!({"role":"namespace","name":name}))
            .collect::<Vec<_>>();
        let mut callable_descriptors = descriptors.clone();
        callable_descriptors.push(json!({"role":"callable", "name":member}));
        let purl = "pkg:pypi/fixture@1.0.0";
        let mut document = json!({
          "documentType":"semantic-document", "schema":CSMI_SCHEMA_URI, "semanticModelVersion":"0.1", "serializationVersion":"0.1-json",
          "provenanceRecords":[{"id":"resolver", "producer":{"identifier":"https://example.org/python-resolver","version":"1.0.0"}, "generationMethod":"source-analysis", "inputs":[{"role":"target-artifact","purl":purl,"digest":{"algorithm":"sha-256","coverage":"artifact","value":digest}}]}],
          "defaultProvenance":"resolver",
          "semanticModels":[{
            "artifactSelectors":[{"purl":purl,"digests":[{"algorithm":"sha-256","coverage":"artifact","value":digest}]}],
            "vocabularyUses":[{"identifier":CSMI_PYTHON_PROFILE_ID,"version":CSMI_PYTHON_PROFILE_VERSION,"schema":CSMI_PYTHON_PROFILE_SCHEMA,"requirement":"required","affects":[
              {"kind":"core-slot","slot":"symbol-identity-scheme","target":{"model":"self"}},
              {"kind":"fact-family","family":"distribution-imports","scope":{"artifact":"model"}},
              {"kind":"fact-family","family":"import-bindings","scope":{"module":"module"}}
            ]}],
            "symbols":[{"id":"module","scheme":"csmi.python","schemeVersion":"0.1.0","stability":"portable","descriptors":descriptors}, {"id":"callable","scheme":"csmi.python","schemeVersion":"0.1.0","stability":"portable","descriptors":callable_descriptors}],
            "declarations":[{"symbol":"module","category":"namespace"},{"symbol":"callable","category":"callable","owner":"module","callable":{"kind":"function","parameters":parameters.iter().enumerate().map(|(i,p)| json!({"position":i,"binding":"positional-or-named","label":p,"required":i == 0})).collect::<Vec<_>>(),"results":[]}}],
            "procedureSummaries":[{"callable":"callable","transfers":[]}],
            "extensionFacts":[
              {"vocabulary":"csmi.python","version":"0.1.0","family":"distribution-imports","scope":{"artifact":"model"},"payload":{"kind":"distribution-imports","importRoots":[[module[0]]]},"provenance":["resolver"]},
              {"vocabulary":"csmi.python","version":"0.1.0","family":"import-bindings","scope":{"module":"module"},"payload":{"kind":"import-bindings","bindings":[{"name":member,"bindingKind":"definition","target":"callable"}]},"provenance":["resolver"]}
            ],
            "completenessStatements":[
              {"family":"declaration-records","scope":{"scheme":"csmi.python","schemeVersion":"0.1.0"},"status":"complete"},
              {"family":"declaration-aspects","scope":{"symbol":"callable","aspect":"callable-shape"},"status":"complete"},
              {"family":"procedure-summaries","scope":{"callable":"callable"},"status":"complete"},
              {"vocabulary":"csmi.python","version":"0.1.0","family":"distribution-imports","scope":{"artifact":"model"},"status":"complete","provenance":["resolver"]},
              {"vocabulary":"csmi.python","version":"0.1.0","family":"import-bindings","scope":{"module":"module"},"status":"complete","provenance":["resolver"]}
            ]
          }]
        });
        // Parent initializer inventories are part of exact child-module admission.
        for end in 1..module.len() {
            let parent = format!("parent{end}");
            let descriptors = module[..end]
                .iter()
                .map(|name| json!({"role":"namespace", "name":name}))
                .collect::<Vec<_>>();
            let model = &mut document["semanticModels"][0];
            model["symbols"].as_array_mut().unwrap().push(json!({"id":parent,"scheme":"csmi.python","schemeVersion":"0.1.0","stability":"portable","descriptors":descriptors}));
            model["declarations"]
                .as_array_mut()
                .unwrap()
                .push(json!({"symbol":parent,"category":"namespace"}));
            model["vocabularyUses"][0]["affects"].as_array_mut().unwrap().push(json!({"kind":"fact-family","family":"import-bindings","scope":{"module":parent}}));
            model["extensionFacts"].as_array_mut().unwrap().push(json!({"vocabulary":"csmi.python","version":"0.1.0","family":"import-bindings","scope":{"module":parent},"payload":{"kind":"import-bindings","bindings":[{"name":module[end],"bindingKind":"definition","target":if end + 1 == module.len() { "module".to_owned() } else { format!("parent{}", end + 1) }}]},"provenance":["resolver"]}));
            model["completenessStatements"].as_array_mut().unwrap().push(json!({"vocabulary":"csmi.python","version":"0.1.0","family":"import-bindings","scope":{"module":parent},"status":"complete","provenance":["resolver"]}));
        }
        let model = &mut document["semanticModels"][0];
        model["vocabularyUses"][0]["affects"].as_array_mut().unwrap().push(json!({
            "kind":"core-slot", "slot":"artifact-compatibility", "target":{"semanticModel":"current"}
        }));
        model["compatibilityConstraints"] = json!([{
            "vocabulary":CSMI_PYTHON_PROFILE_ID, "version":CSMI_PYTHON_PROFILE_VERSION,
            "value":{"kind":"compatibility", "projectConfig":project_config}
        }]);
        let pack = compile_profile(&document);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: format!("fixture:{module_name}"),
                },
            )
            .unwrap();
        let activation = SemanticModelActivationRequest {
            approximate_standard_libraries: vec![],
            bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: vec![],
            controls: vec![],
            limits: Default::default(),
        };
        let result = fixture.analyzer.activate_dependency_packs(
            &config,
            &[DependencyPackEcosystem::Python],
            DependencyPackWorkspaceContext {
                catalog: &catalog,
                persistence: None,
                activation: &activation,
                limits: DependencyPackLimits::default(),
                cancellation: &CancellationToken::default(),
            },
        );
        assert!(
            matches!(
                result.runtime,
                Some(SemanticModelRuntimeOutcome::Ready { .. })
            ),
            "{result:#?}"
        );
    }
}
