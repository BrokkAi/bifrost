use std::sync::Arc;

use brokk_bifrost::analyzer::semantic_model::*;
use brokk_bifrost::analyzer::{
    DependencyPackEcosystem, DependencyPackWorkspaceContext, JsTsDependencyDiscoveryConfig,
    JvmDependencyDiscoveryMode,
};
use brokk_bifrost::{AnalyzerConfig, CancellationToken, Language};
use semver::Version;

use crate::common::InlineTestProject;

const DECLARATIONS_JSON: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/declarations-v1.json");

fn activation_request(
    evidence: Vec<SemanticModelActivationEvidence>,
) -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence,
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}

fn context<'a>(
    catalog: &'a SemanticPackCatalog,
    activation: &'a SemanticModelActivationRequest,
    cancellation: &'a CancellationToken,
) -> DependencyPackWorkspaceContext<'a> {
    DependencyPackWorkspaceContext {
        catalog,
        persistence: None,
        activation,
        limits: DependencyPackLimits::default(),
        cancellation,
    }
}

#[test]
fn all_supported_ecosystems_use_one_complete_activation_contract() {
    let project = InlineTestProject::with_language(Language::Java)
        .file("src/Main.java", "final class Main {}")
        .build();
    let mut config = AnalyzerConfig::default();
    config.jvm.dependency_discovery.mode = JvmDependencyDiscoveryMode::Disabled;
    config.jvm.standard_library_discovery.discover_java_home = false;
    config.js_ts.dependency_discovery = JsTsDependencyDiscoveryConfig {
        discover_workspace_lockfiles: false,
        ..Default::default()
    };
    let analyzer = project.workspace_analyzer(config.clone());
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let activation = activation_request(Vec::new());
    let cancellation = CancellationToken::default();
    let ecosystems = [
        DependencyPackEcosystem::Jvm,
        DependencyPackEcosystem::DotNet,
        DependencyPackEcosystem::Npm,
        DependencyPackEcosystem::Python,
        DependencyPackEcosystem::Go,
        DependencyPackEcosystem::Cargo,
        DependencyPackEcosystem::Ruby,
    ];

    let outcome = analyzer.activate_dependency_packs(
        &config,
        &ecosystems,
        context(&catalog, &activation, &cancellation),
    );

    assert!(outcome.complete(), "{outcome:#?}");
    assert!(outcome.diagnostic_refresh_required);
    assert_eq!(
        outcome
            .ecosystems
            .iter()
            .map(|outcome| outcome.ecosystem)
            .collect::<Vec<_>>(),
        ecosystems
    );
    for ecosystem in ecosystems {
        for language in ecosystem.languages() {
            assert!(
                analyzer
                    .analyzer()
                    .dependency_discovery_evidence(*language)
                    .is_some()
            );
        }
    }
}

#[test]
fn cancellation_preserves_complete_state_then_invalidation_and_recovery_refresh_it() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", "value = 1\n")
        .build();
    let config = AnalyzerConfig::default();
    let analyzer = project.workspace_analyzer(config.clone());
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let compiled = compile_source(
        SourceFormat::Json,
        DECLARATIONS_JSON,
        &CompilerOptions::default(),
    )
    .unwrap();
    catalog
        .register_session_pack(
            &compiled,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "lifecycle-fixture".to_owned(),
            },
        )
        .unwrap();
    let evidence = SemanticModelActivationEvidence {
        language: "java".to_owned(),
        ecosystem: "maven".to_owned(),
        package: Some(CatalogCoordinate {
            name: "com.acme:widget".to_owned(),
            version: Some(Version::parse("1.5.0").unwrap()),
        }),
        module: None,
        toolchain: None,
        target: None,
        configuration: None,
        artifact_sha256: None,
    };
    let active_request = activation_request(vec![evidence]);
    let live = CancellationToken::default();
    assert!(matches!(
        acquire_active_semantic_models(analyzer.analyzer(), &catalog, None, &active_request, &live,),
        SemanticModelRuntimeOutcome::Ready { .. }
    ));
    let prior = analyzer.analyzer().semantic_model_overlay().unwrap();

    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let empty_request = activation_request(Vec::new());
    let outcome = analyzer.activate_dependency_packs(
        &config,
        &[DependencyPackEcosystem::Python],
        context(&catalog, &empty_request, &cancelled),
    );
    assert!(!outcome.complete());
    assert!(!outcome.diagnostic_refresh_required);
    assert!(Arc::ptr_eq(
        &prior,
        &analyzer.analyzer().semantic_model_overlay().unwrap()
    ));

    let mut unavailable_request = empty_request.clone();
    unavailable_request
        .controls
        .push(SemanticModelActivationControl {
            scope: SemanticModelControlScope::Workspace,
            action: SemanticModelControlAction::Enable,
            selector: SemanticModelPackSelector {
                pack_id: "missing.pack".to_owned(),
                version: None,
                manifest_digest: None,
            },
        });
    unavailable_request.limits.max_controls = 0;
    let unavailable = analyzer.activate_dependency_packs(
        &config,
        &[DependencyPackEcosystem::Python],
        context(&catalog, &unavailable_request, &live),
    );
    assert!(matches!(
        unavailable.runtime,
        Some(SemanticModelRuntimeOutcome::Unavailable(_))
    ));
    assert!(!unavailable.diagnostic_refresh_required);
    assert!(Arc::ptr_eq(
        &prior,
        &analyzer.analyzer().semantic_model_overlay().unwrap()
    ));

    assert!(analyzer.invalidate_dependency_pack_state(&[DependencyPackEcosystem::Python]));
    assert!(analyzer.analyzer().semantic_model_overlay().is_none());
    assert!(
        analyzer
            .analyzer()
            .dependency_discovery_evidence(Language::Python)
            .is_none()
    );

    let recovered = analyzer.activate_dependency_packs(
        &config,
        &[DependencyPackEcosystem::Python],
        context(&catalog, &empty_request, &live),
    );
    assert!(recovered.complete(), "{recovered:#?}");
    assert!(recovered.diagnostic_refresh_required);
    assert!(analyzer.analyzer().semantic_model_overlay().is_some());
    assert!(
        analyzer
            .analyzer()
            .dependency_discovery_evidence(Language::Python)
            .is_some()
    );
}
