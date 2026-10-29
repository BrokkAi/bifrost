//! Shared selected-build setup for Go integration and differential tests.

use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
use brokk_bifrost_core::cancellation::CancellationToken;
use std::path::Path;
use std::sync::Arc;

pub fn go_discovery_analyzer(
    project: Arc<dyn brokk_bifrost_core::analyzer::project::Project>,
    config: brokk_bifrost_core::analyzer::config::AnalyzerConfig,
) -> (crate::analyzer::go::GoAnalyzer, Arc<AnalyzerStore>) {
    use crate::analyzer::go::GoAnalyzer;

    use brokk_bifrost_analysis::analyzer::store::go_package_context::GoContextPublicationOutcome;

    use brokk_bifrost_analysis::analyzer::store::go_package_context::GoInputObservationOutcome;

    use brokk_bifrost_analysis::analyzer::store::go_package_context::profile_digest;

    use brokk_bifrost_analysis::analyzer::store::go_package_context::source_inventory_profile;
    let context = brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::ephemeral_store_context(
        project.as_ref(),
    )
    .unwrap();
    let store = Arc::clone(&context.store);
    let go = GoAnalyzer::new_with_config_store_context(
        Arc::clone(&project),
        config.clone(),
        context,
        None,
    )
    .unwrap();
    // Construction already persists source facts and reconciles inventory
    // summaries. Re-persisting every file repeats the entire cold write.
    let snapshot = go
        .selected_snapshot_for_test()
        .expect("selected Go snapshot");
    let cancellation = CancellationToken::default();
    let GoInputObservationOutcome::Ready(before) = store
        .observe_go_context_inputs(&snapshot, project.as_ref(), &cancellation)
        .unwrap()
    else {
        panic!("fixture Go inputs must be selected");
    };
    let mut discovery = crate::analyzer::go::dependency_discovery::discover_go_packages(
        &config.go,
        project.as_ref(),
        &brokk_bifrost_analysis::analyzer::semantic_model::DependencyPackLimits::default(),
        Some(&cancellation),
    );
    go.record_build_selection(&discovery).unwrap();
    if config.go.dependency_discovery.mode
        == brokk_bifrost_core::analyzer::config::GoDependencyDiscoveryMode::Disabled
    {
        assert!(
            discovery.canonical.is_none(),
            "disabled discovery has no tool authority"
        );
    }
    if discovery.canonical.is_none() {
        // As with existing Go-tool tests, macOS may have no Go executable.
        // An installed tool that failed discovery must still fail this gate.
        assert!(
            config.go.dependency_discovery.mode
                == brokk_bifrost_core::analyzer::config::GoDependencyDiscoveryMode::Disabled
                || std::process::Command::new(
                    config
                        .go
                        .dependency_discovery
                        .go_executable
                        .as_deref()
                        .unwrap_or_else(|| Path::new("go"))
                )
                .arg("version")
                .output()
                .is_err(),
            "Go-tool discovery is required: {:?}",
            discovery.semantic_packs
        );
        assert_eq!(
            go.context_profile_for_test(),
            Some(source_inventory_profile())
        );
        assert!(go.build_selection_error().is_some());
        eprintln!(
            "Go discovery authority=source-inventory, build_selection_unavailable={:?}",
            go.build_selection_error()
        );
        return (go, store);
    }
    let mut canonical = discovery
        .canonical
        .take()
        .expect("the unavailable branch returned");
    // This helper publishes only the root invocation. Give it the
    // same structural module membership as the production producer.
    canonical.domain.modules = brokk_bifrost_go::packages::go_module_roots(project.as_ref())
        .into_iter()
        .filter(|module| module.workspace_dir.as_os_str().is_empty())
        .map(|module| (String::new(), module.import_path))
        .collect();
    let profile = profile_digest(&canonical);
    assert_ne!(
        profile,
        source_inventory_profile(),
        "the tool authority is distinct"
    );
    let GoInputObservationOutcome::Ready(after) = store
        .observe_go_context_inputs(&snapshot, project.as_ref(), &cancellation)
        .unwrap()
    else {
        panic!("fixture Go inputs must remain selected");
    };
    let GoContextPublicationOutcome::Published(publication) = store
        .publish_go_package_context(
            snapshot.clone(),
            project.root().to_path_buf(),
            None,
            &before,
            &after,
            canonical,
            &cancellation,
        )
        .unwrap()
    else {
        panic!("Go-tool context publication must succeed");
    };
    assert!(go.activate_native_context_profile(&snapshot, profile));
    let report = store
        .reconcile_unit_summaries(
            &snapshot,
            brokk_bifrost_analysis::analyzer::store::go_unit_summaries::GoUnitSummaries {
                context_id: publication.context_id,
                profile,
            },
            &cancellation,
        )
        .unwrap();
    assert!(
        report.failed.is_empty(),
        "Go-tool summary derivations: {:?}",
        report.failed
    );
    eprintln!("Go discovery authority=tool, profile={profile:?}");
    (go, store)
}
