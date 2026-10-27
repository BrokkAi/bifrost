#[cfg(test)]
mod jvm_registry_tests {

    #[test]
    fn activated_sql_contracts_require_current_factory_and_keep_coverage_unknown() {
        use brokk_bifrost_analysis::analyzer::semantic_model::*;

        use brokk_bifrost_analysis::analyzer::semantic_model::callable_values::ActivatedCallableValuesGap;

        use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesCoverage;

        use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesFact;

        use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesFamily;

        use brokk_bifrost_analysis::analyzer::semantic_model::model::CallableValuesPayload;

        use brokk_bifrost_analysis::analyzer::semantic_model::callable_values::CallableValuesQueryLimits;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCallableValuesPayload;

        use brokk_bifrost_analysis::analyzer::semantic_model::csmi::model::CsmiCoverageStatus;

        use brokk_bifrost_analysis::analyzer::semantic_model::callable_values::activated_returned_callable_targets;

        use brokk_bifrost_analysis::analyzer::semantic_model::callable_values::activated_returned_callable_targets_from_reader;

        use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_core::analyzer::model::Language;

        let mut authored: AuthoredSemanticModelPack = serde_json::from_slice(include_bytes!(
            "../../../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
        ))
        .unwrap();
        authored.schema_version = CALLABLE_VALUES_MIN_SCHEMA_VERSION;
        authored.compatibility.bifrost = None;
        authored.compatibility.toolchains.clear();
        authored.shards[0].callable_values = Some(CallableValuesPayload {
            facts: vec![CallableValuesFact {
                payload: CsmiCallableValuesPayload::ReturnedCallable {
                    callable: "member.widget.create".to_owned(),
                    result: 0,
                    target: "member.widget.create".to_owned(),
                },
                provenance: vec!["source-review".to_owned()],
            }],
            coverage: vec![CallableValuesCoverage {
                family: CallableValuesFamily::ReturnedCallables,
                callable: "member.widget.create".to_owned(),
                status: CsmiCoverageStatus::Complete,
                limitations: Vec::new(),
                provenance: vec!["independent-coverage".to_owned()],
            }],
            anonymous_callables: Vec::new(),
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
                    source_id: "fixture-publication".to_owned(),
                },
            )
            .unwrap();
        let cancellation = CancellationToken::new();
        let active = match resolve_active_semantic_models(
            &catalog,
            &SemanticModelActivationRequest {
                approximate_standard_libraries: Vec::new(),
                bifrost_version: semver::Version::new(0, 12, 0),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "java".to_owned(),
                    ecosystem: "maven".to_owned(),
                    package: Some(CatalogCoordinate {
                        name: "com.acme:widget".to_owned(),
                        version: Some(semver::Version::new(1, 2, 0)),
                    }),
                    module: None,
                    toolchain: None,
                    target: Some("jvm".to_owned()),
                    configuration: Some("release".to_owned()),
                    artifact_sha256: Some("a".repeat(64)),
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            &cancellation,
        ) {
            SemanticModelResolutionOutcome::Ready(active) => active,
            other => panic!("fixture activation must finish: {other:?}"),
        };
        let project = InlineTestProject::with_language(Language::Java)
            .file("Probe.java", "class Probe {}")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let active = std::sync::Arc::new(active);
        let overlay =
            SemanticModelOverlay::build(workspace.analyzer(), &active, &cancellation, 1 << 26)
                .unwrap();
        let factory = overlay
            .symbols()
            .into_iter()
            .find(|symbol| symbol.provenance.record_id == "member.widget.create")
            .unwrap();
        let limits = CallableValuesQueryLimits { max_records: 64 };
        let query = activated_returned_callable_targets(
            &catalog,
            &active,
            &factory,
            0,
            limits,
            &cancellation,
        )
        .unwrap();
        assert!(query.gap.is_none(), "{query:?}");
        assert_eq!(query.publications.len(), 1);
        assert_eq!(query.publications[0].rows.facts.len(), 1);
        assert_eq!(query.publications[0].rows.coverage_claims.len(), 1);
        assert_eq!(query.executable_coverage, CsmiCoverageStatus::Unknown);
        assert_eq!(
            query.publications[0].rows.executable_coverage,
            CsmiCoverageStatus::Unknown
        );
        let reader = active.source_reader().unwrap();
        let reader_query = activated_returned_callable_targets_from_reader(
            reader,
            &active,
            &factory,
            0,
            limits,
            &cancellation,
        )
        .unwrap();
        assert_eq!(reader_query.gap, query.gap);
        assert_eq!(reader_query.publications.len(), query.publications.len());
        assert_eq!(
            reader_query.publications[0].rows.facts.len(),
            query.publications[0].rows.facts.len()
        );
        assert_eq!(
            reader_query.publications[0].rows.coverage_claims.len(),
            query.publications[0].rows.coverage_claims.len()
        );
        let missing = activated_returned_callable_targets(
            &catalog,
            &active,
            &factory,
            1,
            limits,
            &cancellation,
        )
        .unwrap();
        assert!(missing.publications[0].rows.facts.is_empty());
        assert_eq!(missing.publications[0].rows.coverage_claims.len(), 1);
        assert_eq!(missing.executable_coverage, CsmiCoverageStatus::Unknown);
        let mut stale = factory.clone();
        std::sync::Arc::make_mut(&mut stale)
            .provenance
            .active_model_set_hash = "different-activation".to_owned();
        let rejected = activated_returned_callable_targets(
            &catalog,
            &active,
            &stale,
            0,
            limits,
            &cancellation,
        )
        .unwrap();
        assert_eq!(
            rejected.gap,
            Some(ActivatedCallableValuesGap::FactoryUnbound)
        );
        assert!(rejected.publications.is_empty());
        let mut foreign_artifact = factory.clone();
        std::sync::Arc::make_mut(&mut foreign_artifact)
            .provenance
            .activation
            .matched_evidence
            .artifact_sha256 = Some("b".repeat(64));
        let rejected = activated_returned_callable_targets(
            &catalog,
            &active,
            &foreign_artifact,
            0,
            limits,
            &cancellation,
        )
        .unwrap();
        assert_eq!(
            rejected.gap,
            Some(ActivatedCallableValuesGap::FactoryUnbound)
        );
        assert!(rejected.publications.is_empty());
        let mut foreign_configuration = factory.clone();
        std::sync::Arc::make_mut(&mut foreign_configuration)
            .provenance
            .activation
            .matched_evidence
            .configuration = Some("another-configuration".to_owned());
        let rejected = activated_returned_callable_targets(
            &catalog,
            &active,
            &foreign_configuration,
            0,
            limits,
            &cancellation,
        )
        .unwrap();
        assert_eq!(
            rejected.gap,
            Some(ActivatedCallableValuesGap::FactoryUnbound)
        );
        assert!(rejected.publications.is_empty());
        let bounded = activated_returned_callable_targets(
            &catalog,
            &active,
            &factory,
            0,
            CallableValuesQueryLimits { max_records: 0 },
            &cancellation,
        )
        .unwrap();
        assert_eq!(
            bounded.gap,
            Some(ActivatedCallableValuesGap::RecordBudgetExhausted)
        );
        cancellation.cancel();
        let stopped = activated_returned_callable_targets(
            &catalog,
            &active,
            &factory,
            0,
            limits,
            &cancellation,
        )
        .unwrap();
        assert_eq!(stopped.gap, Some(ActivatedCallableValuesGap::Cancelled));
    }
}
