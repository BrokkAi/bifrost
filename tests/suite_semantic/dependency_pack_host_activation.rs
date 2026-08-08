//! Host-path conformance for dependency-pack activation (#1628).
//!
//! `dependency_pack_lifecycle.rs` pins the activation transaction itself. This
//! pins what a host must be able to rely on around it: a diagnostic request
//! never activates anything, and an activation that did not publish proof
//! leaves the collectors reporting typed suppressions rather than a complete
//! answer they cannot support.

use brokk_bifrost::analyzer::semantic_model::{
    CatalogOptions, DependencyPackLimits, SemanticModelActivationRequest,
    SemanticModelRuntimeLimits, SemanticPackCatalog,
};
use brokk_bifrost::analyzer::{
    DependencyPackEcosystem, DependencyPackWorkspaceContext, SemanticDiagnosticIncompleteReason,
    SemanticDiagnosticOutcome, SemanticDiagnosticReport, SemanticDiagnosticReportStatus,
};
use brokk_bifrost::{AnalyzerConfig, CancellationToken, Language};
use semver::Version;

use crate::common::InlineTestProject;

const EXTERNAL_SOURCE: &str =
    "import external_pkg\n\n\ndef run():\n    return external_pkg.helper()\n";

fn activation_request() -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}

fn incomplete_reasons(
    report: &SemanticDiagnosticReport,
) -> Vec<&SemanticDiagnosticIncompleteReason> {
    report
        .outcomes()
        .iter()
        .filter_map(|outcome| match outcome {
            SemanticDiagnosticOutcome::Incomplete { reasons, .. } => Some(reasons),
            _ => None,
        })
        .flatten()
        .collect()
}

#[test]
fn a_cancelled_activation_leaves_reports_incomplete_and_publishes_nothing() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", EXTERNAL_SOURCE)
        .build();
    let config = AnalyzerConfig::default();
    let analyzer = project.workspace_analyzer(config.clone());
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let activation = activation_request();

    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let outcome = analyzer.activate_dependency_packs(
        &config,
        &[DependencyPackEcosystem::Python],
        DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &activation,
            limits: DependencyPackLimits::default(),
            cancellation: &cancelled,
        },
    );
    assert!(!outcome.complete(), "{outcome:#?}");
    assert!(
        !outcome.diagnostic_refresh_required,
        "a cancelled activation published nothing, so it must not ask a host to refresh: {outcome:#?}"
    );
    assert!(
        analyzer
            .analyzer()
            .dependency_discovery_evidence(Language::Python)
            .is_none()
    );

    let file = project.file("app.py");
    let source = std::fs::read_to_string(file.abs_path()).unwrap();
    let report = analyzer.analyzer().semantic_diagnostics(&file, &source);

    assert_eq!(
        report.status(),
        SemanticDiagnosticReportStatus::Incomplete,
        "without published proof the report must stay incomplete: {report:#?}"
    );
    assert!(
        incomplete_reasons(&report).iter().any(|reason| matches!(
            reason,
            SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { .. }
        )),
        "the suppression must name the missing evidence: {report:#?}"
    );
    assert!(
        report.diagnostics().is_empty(),
        "an incomplete report must publish no error: {report:#?}"
    );
}

#[test]
fn a_diagnostic_request_never_activates_dependency_packs() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", EXTERNAL_SOURCE)
        .build();
    let config = AnalyzerConfig::default();
    let analyzer = project.workspace_analyzer(config);
    let file = project.file("app.py");
    let source = std::fs::read_to_string(file.abs_path()).unwrap();

    let report = analyzer.analyzer().semantic_diagnostics(&file, &source);

    assert_eq!(report.status(), SemanticDiagnosticReportStatus::Incomplete);
    assert!(
        analyzer.analyzer().semantic_model_overlay().is_none(),
        "serving a diagnostic must not publish a semantic model overlay"
    );
    assert!(
        analyzer
            .analyzer()
            .dependency_discovery_evidence(Language::Python)
            .is_none(),
        "serving a diagnostic must not run dependency discovery"
    );
}

/// A complete activation is not by itself proof about a name.
///
/// A host activates every ecosystem whose languages are present, and an
/// ecosystem that finds no manifest still activates completely: it publishes
/// evidence that says the build declares nothing. That evidence must not be
/// read as proof that an undeclared module is absent, because the more likely
/// explanation is that the session cannot see the build at all. This is the
/// property that keeps a rollout from turning every unconfigured workspace
/// into a wall of false positives, so it is pinned across the whole
/// activate/invalidate/re-activate cycle a host drives.
#[test]
fn an_activation_that_declares_nothing_never_manufactures_an_absence_proof() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("app.py", EXTERNAL_SOURCE)
        .build();
    let config = AnalyzerConfig::default();
    let analyzer = project.workspace_analyzer(config.clone());
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let activation = activation_request();
    let live = CancellationToken::default();
    let context = DependencyPackWorkspaceContext {
        catalog: &catalog,
        persistence: None,
        activation: &activation,
        limits: DependencyPackLimits::default(),
        cancellation: &live,
    };
    let file = project.file("app.py");
    let source = std::fs::read_to_string(file.abs_path()).unwrap();

    let activated =
        analyzer.activate_dependency_packs(&config, &[DependencyPackEcosystem::Python], context);
    assert!(activated.complete(), "{activated:#?}");
    assert!(
        activated.diagnostic_refresh_required,
        "published evidence obliges a host to refresh: {activated:#?}"
    );
    assert!(
        analyzer
            .analyzer()
            .dependency_discovery_evidence(Language::Python)
            .is_some()
    );

    let after_activation = analyzer.analyzer().semantic_diagnostics(&file, &source);
    assert_eq!(
        after_activation.status(),
        SemanticDiagnosticReportStatus::Incomplete,
        "an undeclared module stays unproven after an empty activation: {after_activation:#?}"
    );
    assert!(
        incomplete_reasons(&after_activation)
            .iter()
            .any(|reason| matches!(
                reason,
                SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { .. }
            )),
        "{after_activation:#?}"
    );
    assert!(after_activation.diagnostics().is_empty());

    // What a host does when a declared dependency input changes.
    assert!(analyzer.invalidate_dependency_pack_state(&[DependencyPackEcosystem::Python]));
    assert!(
        analyzer
            .analyzer()
            .dependency_discovery_evidence(Language::Python)
            .is_none()
    );
    let withdrawn = analyzer.analyzer().semantic_diagnostics(&file, &source);
    assert_eq!(
        withdrawn.status(),
        SemanticDiagnosticReportStatus::Incomplete
    );
    assert!(withdrawn.diagnostics().is_empty());

    let reactivated =
        analyzer.activate_dependency_packs(&config, &[DependencyPackEcosystem::Python], context);
    assert!(reactivated.complete(), "{reactivated:#?}");
    assert!(reactivated.diagnostic_refresh_required);
    let recovered = analyzer.analyzer().semantic_diagnostics(&file, &source);
    assert_eq!(
        recovered, after_activation,
        "re-activation must reproduce the same answer, not a stronger one"
    );
}
